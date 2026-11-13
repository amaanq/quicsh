use std::{
   io::{
      self,
      Write,
   },
   os::fd::{
      AsFd,
      BorrowedFd,
      OwnedFd,
   },
   sync::{
      Arc,
      Condvar,
      Mutex,
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         Receiver,
         TryRecvError,
         channel,
         sync_channel,
      },
   },
   thread,
};

use misstep::{
   OptionExt as _,
   Result,
   bail,
};
use quicsh::{
   control::{
      Message,
      Size,
   },
   pipe::{
      Waker,
      writer,
   },
   relay::Relay,
};
use quinn_proto::{
   Connection,
   Dir,
   StreamId,
   VarInt,
};
use rustix::{
   net::{
      Shutdown,
      shutdown,
   },
   termios::Winsize,
};

use crate::hold::{
   DATA_LIMIT,
   PACKET_LIMIT,
   Packet,
};

/// Exit status reported when none arrived.
const NO_STATUS: u32 = 255;
/// Chunks of session output queued for a stream before the holder waits.
const QUEUE: usize = 16;
/// How much input a holder may have beyond what its session accepted. More
/// waits in the stream, which makes the client wait in turn.
const INPUT_WINDOW: u64 = 1 << 20;
/// How much more input the session accepts before the client hears of it.
const REPORT_STEP: u64 = 256 << 10;

/// The terminal size in the form the kernel takes.
pub const fn winsize(size: Size) -> Winsize {
   Winsize {
      ws_col:    size.columns,
      ws_row:    size.rows,
      ws_xpixel: 0,
      ws_ypixel: 0,
   }
}

/// How many input bytes a holder's session accepted, as the holder last
/// reported it.
#[derive(Default)]
struct Credit {
   /// The count. `u64::MAX` once the holder is gone.
   written: Mutex<u64>,
   /// Signals a change of the count.
   changed: Condvar,
}

impl Credit {
   /// Records a report from the holder.
   fn set(&self, written: u64) {
      if let Ok(mut current) = self.written.lock() {
         *current = written.max(*current);
      }

      self.changed.notify_all();
   }

   /// The last report.
   fn get(&self) -> u64 {
      self.written.lock().map_or(u64::MAX, |current| *current)
   }

   /// Waits until the holder has room for input after the first `sent`
   /// bytes.
   fn wait(&self, sent: u64) {
      let Ok(current) = self.written.lock() else {
         return;
      };

      let _room = self.changed.wait_while(current, |written| {
         sent.saturating_sub(*written) >= INPUT_WINDOW
      });
   }
}

/// Sends what a relay writes to a holder as session input.
struct Input {
   /// The connection to the holder.
   link:     OwnedFd,
   /// How many input bytes the holder got, over every connection.
   sent:     u64,
   /// How far the session got with them.
   credit:   Arc<Credit>,
   /// Set once the session lets go of the holder. The writer then ends
   /// without the client's input having ended.
   released: Arc<AtomicBool>,
}

impl Write for Input {
   fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
      self.credit.wait(self.sent);

      let count = bytes.len().min(DATA_LIMIT);
      Packet::send_data(&self.link, &bytes[..count])?;
      self.sent += count as u64;

      Ok(count)
   }

   fn flush(&mut self) -> io::Result<()> {
      Ok(())
   }
}

impl AsFd for Input {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.link.as_fd()
   }
}

impl Drop for Input {
   fn drop(&mut self) {
      if !self.released.load(Ordering::Relaxed) {
         let _ = Packet::End.send(&self.link);
      }
   }
}

/// What a client that takes a session over says it has.
#[derive(Clone, Copy)]
pub struct Had {
   /// Output bytes.
   pub received: u64,
   /// Standard error bytes.
   pub errors:   u64,
}

/// The network process's side of a session, which runs in a holder.
pub struct Session {
   /// Standard input and output.
   relay:    Relay,
   /// Standard error, for a session without a terminal.
   errors:   Option<Relay>,
   /// The connection to the holder.
   link:     OwnedFd,
   /// Whether the session goes on when this side lets go of it.
   keep:     bool,
   /// Tells the input writer that its end is not the end of input.
   released: Arc<AtomicBool>,
   /// How far the session got with its input.
   credit:   Arc<Credit>,
   /// The count of accepted input the client last heard.
   told:     u64,
   /// Yields programs that want the client's SSH agent.
   agents:   Receiver<OwnedFd>,
   /// Yields the exit status once.
   exit:     Receiver<u32>,
   /// The exit status.
   status:   Option<u32>,
   /// Whether [`Session::pump`] returned the status.
   reported: bool,
}

impl Session {
   /// Joins `stream` to a holder. `label` is the client's number for the
   /// session. A client that takes the session over says in `had` what it
   /// has, and is first told how much input the holder has and how much
   /// output it missed for good. `buffered` and `finished` describe input
   /// already read from `stream`.
   pub fn attach(
      link: OwnedFd,
      label: u32,
      had: Option<Had>,
      stream: StreamId,
      (buffered, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<Self> {
      let Had { received, errors } = had.unwrap_or(Had {
         received: 0,
         errors:   0,
      });

      Packet::Attach { received, errors }.send(&link)?;

      let mut buffer = vec![0; PACKET_LIMIT];

      let Some((
         Packet::Attached {
            taken,
            skipped,
            piped,
         },
         _,
      )) = Packet::receive(&link, &mut buffer)?
      else {
         bail!("the session holder did not answer");
      };

      let (chunks, outbound) = sync_channel(QUEUE);
      let (lines, stderr) = sync_channel(QUEUE);
      let (status, exit) = channel();
      let (wanted, agents) = channel();
      let source = link.try_clone()?;
      let signal = Arc::clone(waker);
      let credit = Arc::new(Credit::default());
      let report = Arc::clone(&credit);

      // The thread stops at the exit status, which closes the channels and
      // so tells the relays that no more output follows.
      thread::spawn(move || {
         while let Ok(Some((packet, descriptor))) = Packet::receive(&source, &mut buffer) {
            let delivered = match packet {
               Packet::Data(bytes) => chunks.send(bytes).is_ok(),
               Packet::Errors(bytes) => lines.send(bytes).is_ok(),
               Packet::Written(count) => {
                  report.set(count);
                  true
               },
               Packet::Agent => descriptor.is_none_or(|socket| wanted.send(socket).is_ok()),
               Packet::Exit(code) => {
                  let _ = status.send(code);
                  false
               },
               _ => true,
            };

            signal.wake();

            if !delivered {
               break;
            }
         }

         report.set(u64::MAX);
         signal.wake();
      });

      let released = Arc::new(AtomicBool::new(false));

      let input = Input {
         link:     link.try_clone()?,
         sent:     taken,
         credit:   Arc::clone(&credit),
         released: Arc::clone(&released),
      };

      let (inbound, _) = writer(input, Arc::clone(waker));

      let side = if piped {
         let side = connection
            .streams()
            .open(Dir::Uni)
            .context("no stream credit for stderr")?;

         let mut relay = Relay::new(side, Some(stderr), None, Vec::new(), false);
         relay.prefix(label.to_be_bytes().to_vec());
         Some(relay)
      } else {
         connection.send_stream(stream).set_priority(1)?;
         None
      };

      let mut relay = Relay::new(stream, Some(outbound), Some(inbound), buffered, finished);

      if had.is_some() {
         let answer = Message::Resumed {
            received: taken,
            skipped,
         };
         relay.prefix(answer.encode());
      }

      Ok(Self {
         relay,
         errors: side,
         link,
         keep: false,
         released,
         credit,
         told: 0,
         agents,
         exit,
         status: None,
         reported: false,
      })
   }

   /// The next program that wants the client's SSH agent.
   pub fn agent(&self) -> Option<OwnedFd> {
      self.agents.try_recv().ok()
   }

   /// Sets the terminal's size.
   pub fn resize(&self, size: Size) -> Result<()> {
      Packet::Resize(size).send(&self.link)?;
      Ok(())
   }

   /// Lets the holder forget the output the client has.
   pub fn release(&self, output: u64, errors: u64) -> Result<()> {
      Packet::Received { output, errors }.send(&self.link)?;
      Ok(())
   }

   /// How many input bytes the session accepted, when that is news the
   /// client should hear so that it can forget them.
   pub fn progress(&mut self) -> Option<u64> {
      let written = self.credit.get();
      let news = written != u64::MAX && written >= self.told + REPORT_STEP;

      news.then(|| {
         self.told = written;
         written
      })
   }

   /// Ends the session's streams for a client that is done with it. A
   /// connection that goes on would otherwise keep them.
   pub fn close(self, connection: &mut Connection) {
      Relay::abort(connection, self.relay.stream());

      if let Some(ref errors) = self.errors {
         let _ = connection
            .send_stream(errors.stream())
            .reset(VarInt::from_u32(0));
      }
   }

   /// Lets the session go on after this side is dropped, for a client that
   /// may come back for it.
   pub const fn keep(&mut self) {
      self.keep = true;
   }

   /// Moves data and returns the exit status once, when the session is over
   /// and all of its output is on the streams.
   pub fn pump(&mut self, connection: &mut Connection) -> Result<Option<u32>> {
      self.relay.pump(connection)?;

      if let Some(ref mut errors) = self.errors {
         errors.pump(connection)?;
      }

      let drained = self.relay.sent_all() && self.errors.as_ref().is_none_or(Relay::sent_all);

      if self.status.is_none() {
         self.status = match self.exit.try_recv() {
            Ok(code) => Some(code),
            // A holder that another connection took over sends no status.
            Err(TryRecvError::Disconnected) if drained => Some(NO_STATUS),
            Err(TryRecvError::Disconnected | TryRecvError::Empty) => None,
         };
      }

      if self.reported || !drained {
         return Ok(None);
      }

      self.reported = self.status.is_some();
      Ok(self.status)
   }
}

impl Drop for Session {
   fn drop(&mut self) {
      self.released.store(true, Ordering::Relaxed);

      if !self.keep {
         let _ = Packet::Hangup.send(&self.link);
      }

      // The thread that reads the link holds a copy of it, so closing this
      // one would not end the connection.
      let _ = shutdown(&self.link, Shutdown::Both);
   }
}
