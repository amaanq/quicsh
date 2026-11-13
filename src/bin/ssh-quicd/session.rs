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
use quinn_proto::{
   Connection,
   Dir,
   StreamId,
};
use rustix::termios::{
   Winsize,
   tcsetwinsize,
};
use ssh_quic::{
   control::Size,
   pipe::{
      Waker,
      reader,
      writer,
   },
   relay::Relay,
};

use crate::privsep::{
   Helper,
   Spawned,
};

/// How long output may keep flowing after the command exits. A background
/// process that inherited the terminal would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);
const NO_STATUS: u32 = 255;

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
   relay:    Relay,
   errors:   Option<Relay>,
   terminal: Option<OwnedFd>,
   id:       u64,
   helper:   Helper,
   /// Yields the exit status once, as four bytes.
   exit:     Receiver<Bytes>,
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
            let (input, output, errors) = (next()?, next()?, next()?);

            let side = connection
               .streams()
               .open(Dir::Uni)
               .context("no stream credit for stderr")?;

            let errors = reader(File::from(errors), Arc::clone(waker));
            let mut errors = Relay::new(side, Some(errors), None, Vec::new(), false);
            errors.prefix(label.to_be_bytes().to_vec());

            (input, output, Some(errors), None, next()?)
         },
         _ => bail!("monitor sent an unexpected set of descriptors"),
      };

      let output = reader(File::from(output), Arc::clone(waker));
      let (input, _) = writer(File::from(input), Arc::clone(waker));

      Ok(Self {
         relay: Relay::new(stream, Some(output), Some(input), buffered, finished),
         errors,
         terminal,
         id: spawned.session,
         helper,
         exit: reader(File::from(status), Arc::clone(waker)),
         exited: None,
      })
   }

   pub fn resize(&self, size: Size) -> Result<()> {
      if let Some(terminal) = &self.terminal {
         tcsetwinsize(terminal, winsize(size))?;
      }

      Ok(())
   }

   /// Moves data and returns the exit status once the session is over.
   pub fn pump(&mut self, now: Instant, connection: &mut Connection) -> Result<Option<u32>> {
      self.relay.pump(connection)?;

      if let Some(errors) = &mut self.errors {
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
            Err(TryRecvError::Disconnected) => Some(NO_STATUS),
            Err(TryRecvError::Empty) => None,
         };

         self.exited = status.map(|status| (status, now));
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
      if self.exited.is_none() {
         self.helper.hangup(self.id);
      }
   }
}
