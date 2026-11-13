use std::{
   fs::File,
   os::fd::OwnedFd,
   sync::{
      Arc,
      mpsc::{
         Receiver,
         TryRecvError,
      },
   },
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
use rustix::termios::{
   Winsize,
   tcsetwinsize,
};

use crate::privsep::{
   Helper,
   Spawned,
};

/// How long output may keep flowing after the command exits. A background
/// process that inherited the terminal would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);
/// Exit status reported when the monitor sent none.
const NO_STATUS: u32 = 255;

/// The terminal size in the form the kernel takes.
pub const fn winsize(size: Size) -> Winsize {
   Winsize {
      ws_col:    size.columns,
      ws_row:    size.rows,
      ws_xpixel: 0,
      ws_ypixel: 0,
   }
}

/// The network process's side of a session that the monitor started.
pub struct Session {
   /// Standard input and output.
   relay:    Relay,
   /// Standard error, for a session without a terminal.
   errors:   Option<Relay>,
   /// The terminal, kept to resize it.
   terminal: Option<OwnedFd>,
   /// The monitor's number for the session.
   id:       u64,
   /// Reaches the monitor.
   helper:   Helper,
   /// Yields the exit status once, as four bytes.
   exit:     Receiver<Bytes>,
   /// Exit status and when it arrived.
   exited:   Option<(u32, Instant)>,
}

impl Session {
   /// Joins `stream` to the descriptors of a started session. `label` is
   /// the client's number for the session, and `buffered` and `finished`
   /// describe input already read from `stream`.
   pub fn adopt(
      label: u32,
      spawned: Spawned,
      helper: Helper,
      stream: StreamId,
      (buffered, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<Self> {
      let mut descriptors = spawned.descriptors.into_iter();
      let count = descriptors.len();
      let mut next = || {
         descriptors
            .next()
            .context("monitor sent too few descriptors")
      };

      let (input, output, errors, terminal, status) = match count {
         2 => {
            let master = next()?;
            let input = master.try_clone()?;
            let output = master.try_clone()?;

            connection.send_stream(stream).set_priority(1)?;
            (input, output, None, Some(master), next()?)
         },
         4 => {
            let (input, output, stderr) = (next()?, next()?, next()?);

            let side = connection
               .streams()
               .open(Dir::Uni)
               .context("no stream credit for stderr")?;

            let lines = reader(File::from(stderr), Arc::clone(waker));
            let mut errors = Relay::new(side, Some(lines), None, Vec::new(), false);
            errors.prefix(label.to_be_bytes().to_vec());

            (input, output, Some(errors), None, next()?)
         },
         _ => bail!("monitor sent an unexpected set of descriptors"),
      };

      let outbound = reader(File::from(output), Arc::clone(waker));
      let (inbound, _) = writer(File::from(input), Arc::clone(waker));

      let mut relay = Relay::new(stream, Some(outbound), Some(inbound), buffered, finished);

      if terminal.is_some() {
         relay.remember();
      }

      Ok(Self {
         relay,
         errors,
         terminal,
         id: spawned.session,
         helper,
         exit: reader(File::from(status), Arc::clone(waker)),
         exited: None,
      })
   }

   /// Sets the terminal's size.
   pub fn resize(&self, size: Size) -> Result<()> {
      if let Some(ref terminal) = self.terminal {
         tcsetwinsize(terminal, winsize(size))?;
      }

      Ok(())
   }

   /// Whether the session can wait for a client whose connection died. A
   /// session on pipes cannot, because its peer is a program that would take
   /// replayed bytes as new ones.
   pub const fn resumable(&self) -> bool {
      self.terminal.is_some() && self.exited.is_none() && !self.relay.sent_all()
   }

   /// Runs the session while it has no connection and returns whether it is
   /// over.
   pub fn idle(&mut self, now: Instant) -> bool {
      self.relay.idle();
      self.reap(now);

      !self.resumable()
   }

   /// Joins the session to `stream` on a new connection. `received` is how
   /// much output the client has, and `pending` is input already read from
   /// `stream`.
   pub fn resume(
      &mut self,
      connection: &mut Connection,
      stream: StreamId,
      received: u64,
      pending: (Vec<u8>, bool),
   ) -> Result<()> {
      connection.send_stream(stream).set_priority(1)?;

      let answer = Message::Resumed {
         received: self.relay.taken(),
      };

      self
         .relay
         .resume(connection, stream, answer.encode(), received, pending);
      Ok(())
   }

   /// Notes the exit status once the monitor reports it.
   fn reap(&mut self, now: Instant) {
      if self.exited.is_none() {
         let status = match self.exit.try_recv() {
            Ok(bytes) => {
               Some(
                  bytes
                     .first_chunk()
                     .map_or(NO_STATUS, |raw| u32::from_be_bytes(*raw)),
               )
            },
            Err(TryRecvError::Disconnected) => Some(NO_STATUS),
            Err(TryRecvError::Empty) => None,
         };

         self.exited = status.map(|code| (code, now));
      }
   }

   /// Moves data and returns the exit status once the session is over.
   pub fn pump(&mut self, now: Instant, connection: &mut Connection) -> Result<Option<u32>> {
      self.relay.pump(connection)?;

      if let Some(ref mut errors) = self.errors {
         errors.pump(connection)?;
      }

      self.reap(now);

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
      if self.exited.is_none() {
         self.helper.hangup(self.id);
      }
   }
}
