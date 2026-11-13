use std::{
   fs::File,
   io::{
      self,
      Write,
   },
   os::fd::OwnedFd,
   sync::{
      Arc,
      mpsc::{
         Receiver,
         TryRecvError,
         channel,
         sync_channel,
      },
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use bytes::Bytes;
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
      reader,
      writer,
   },
   relay::Relay,
};
use quinn_proto::{
   Connection,
   Dir,
   StreamId,
};
use rustix::{
   net::{
      Shutdown,
      shutdown,
   },
   termios::Winsize,
};

use crate::{
   hold::{
      DATA_LIMIT,
      PACKET_LIMIT,
      Packet,
   },
   privsep::{
      Helper,
      Spawned,
   },
};

/// How long output may keep flowing after the command exits. A background
/// process that inherited the pipes would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);
/// Exit status reported when none arrived.
const NO_STATUS: u32 = 255;
/// Chunks of terminal output queued for the stream before the holder waits.
const QUEUE: usize = 16;

/// The terminal size in the form the kernel takes.
pub const fn winsize(size: Size) -> Winsize {
   Winsize {
      ws_col:    size.columns,
      ws_row:    size.rows,
      ws_xpixel: 0,
      ws_ypixel: 0,
   }
}

/// Sends what a relay writes to a holder as terminal input.
struct Input(OwnedFd);

impl Write for Input {
   fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
      let count = bytes.len().min(DATA_LIMIT);
      Packet::Data(bytes[..count].to_vec()).send(&self.0)?;
      Ok(count)
   }

   fn flush(&mut self) -> io::Result<()> {
      Ok(())
   }
}

/// What a session runs on.
enum Backing {
   /// Pipes that the monitor made. The monitor hangs the session up.
   Pipes {
      /// The monitor's number for the session.
      id:     u64,
      /// Reaches the monitor.
      helper: Helper,
   },
   /// A holder process with the terminal.
   Holder {
      /// The connection to the holder.
      link: OwnedFd,
      /// Whether the session goes on when this side lets go of it.
      keep: bool,
   },
}

/// The network process's side of a session.
pub struct Session {
   /// Standard input and output.
   relay:   Relay,
   /// Standard error, for a session without a terminal.
   errors:  Option<Relay>,
   /// Where the session runs.
   backing: Backing,
   /// Yields the exit status once, as four bytes.
   exit:    Receiver<Bytes>,
   /// Exit status and when it arrived.
   exited:  Option<(u32, Instant)>,
}

impl Session {
   /// Joins `stream` to the pipes of a started session. `label` is the
   /// client's number for the session, and `buffered` and `finished` describe
   /// input already read from `stream`.
   pub fn adopt(
      label: u32,
      spawned: Spawned,
      helper: Helper,
      stream: StreamId,
      (buffered, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<Self> {
      let Ok([input, output, stderr, status]) = <[OwnedFd; 4]>::try_from(spawned.descriptors)
      else {
         bail!("monitor sent an unexpected set of descriptors");
      };

      let side = connection
         .streams()
         .open(Dir::Uni)
         .context("no stream credit for stderr")?;

      let lines = reader(File::from(stderr), Arc::clone(waker));
      let mut errors = Relay::new(side, Some(lines), None, Vec::new(), false);
      errors.prefix(label.to_be_bytes().to_vec());

      let outbound = reader(File::from(output), Arc::clone(waker));
      let (inbound, _) = writer(File::from(input), Arc::clone(waker));

      Ok(Self {
         relay:   Relay::new(stream, Some(outbound), Some(inbound), buffered, finished),
         errors:  Some(errors),
         backing: Backing::Pipes {
            id: spawned.session,
            helper,
         },
         exit:    reader(File::from(status), Arc::clone(waker)),
         exited:  None,
      })
   }

   /// Joins `stream` to a holder. `received` is how much output the client
   /// already has, and a client that resumes is first told how much input
   /// the holder has and how much output it missed for good.
   pub fn attach(
      link: OwnedFd,
      (received, resumed): (u64, bool),
      stream: StreamId,
      (buffered, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<Self> {
      Packet::Attach { received }.send(&link)?;

      let mut buffer = vec![0; PACKET_LIMIT];

      let Some(Packet::Attached { taken, skipped }) = Packet::receive(&link, &mut buffer)? else {
         bail!("the session holder did not answer");
      };

      let (chunks, outbound) = sync_channel(QUEUE);
      let (status, exit) = channel();
      let source = link.try_clone()?;
      let signal = Arc::clone(waker);

      thread::spawn(move || {
         while let Ok(Some(packet)) = Packet::receive(&source, &mut buffer) {
            let delivered = match packet {
               Packet::Data(bytes) => chunks.send(Bytes::from(bytes)).is_ok(),
               Packet::Exit(code) => {
                  status
                     .send(Bytes::copy_from_slice(&code.to_be_bytes()))
                     .is_ok()
               },
               _ => true,
            };

            signal.wake();

            if !delivered {
               break;
            }
         }

         signal.wake();
      });

      let (inbound, _) = writer(Input(link.try_clone()?), Arc::clone(waker));

      connection.send_stream(stream).set_priority(1)?;

      let mut relay = Relay::new(stream, Some(outbound), Some(inbound), buffered, finished);

      if resumed {
         let answer = Message::Resumed {
            received: taken,
            skipped,
         };
         relay.prefix(answer.encode());
      }

      Ok(Self {
         relay,
         errors: None,
         backing: Backing::Holder { link, keep: false },
         exit,
         exited: None,
      })
   }

   /// Sets the terminal's size.
   pub fn resize(&self, size: Size) -> Result<()> {
      if let Backing::Holder { ref link, .. } = self.backing {
         Packet::Resize(size).send(link)?;
      }

      Ok(())
   }

   /// Lets the session go on after this side is dropped, for a client that
   /// may come back for it.
   pub const fn keep(&mut self) {
      if let Backing::Holder { ref mut keep, .. } = self.backing {
         *keep = true;
      }
   }

   /// Moves data and returns the exit status once the session is over.
   pub fn pump(&mut self, now: Instant, connection: &mut Connection) -> Result<Option<u32>> {
      self.relay.pump(connection)?;

      if let Some(ref mut errors) = self.errors {
         errors.pump(connection)?;
      }

      if self.exited.is_none() {
         let status = match self.exit.try_recv() {
            Ok(bytes) => {
               Some(
                  bytes
                     .first_chunk()
                     .map_or(NO_STATUS, |raw| u32::from_be_bytes(*raw)),
               )
            },
            // A holder that another connection took over sends no status.
            Err(TryRecvError::Disconnected) if self.relay.sent_all() => Some(NO_STATUS),
            Err(TryRecvError::Disconnected | TryRecvError::Empty) => None,
         };

         self.exited = status.map(|code| (code, now));
      }

      let Some((status, at)) = self.exited else {
         return Ok(None);
      };

      let drained = self.relay.sent_all() && self.errors.as_ref().is_none_or(Relay::sent_all);

      if !drained && now < at + EXIT_GRACE {
         return Ok(None);
      }

      for relay in [Some(&mut self.relay), self.errors.as_mut()]
         .into_iter()
         .flatten()
      {
         relay.finish(connection);
      }

      Ok(Some(status))
   }

   /// When [`Session::pump`] must run again even if nothing else happens.
   pub fn deadline(&self) -> Option<Instant> {
      self.exited.map(|(_, at)| at + EXIT_GRACE)
   }
}

impl Drop for Session {
   fn drop(&mut self) {
      match self.backing {
         Backing::Pipes { id, ref helper } => {
            if self.exited.is_none() {
               helper.hangup(id);
            }
         },
         Backing::Holder { ref link, keep } => {
            if !keep && self.exited.is_none() {
               let _ = Packet::Hangup.send(link);
            }

            // The thread that reads the link holds a copy of it, so closing
            // this one would not end the connection.
            let _ = shutdown(link, Shutdown::Both);
         },
      }
   }
}
