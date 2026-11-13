use std::{
   env,
   fs::File,
   os::{
      fd::OwnedFd,
      unix::process::ExitStatusExt as _,
   },
   process::{
      Command,
      Stdio,
   },
   sync::{
      Arc,
      mpsc::{
         Receiver,
         channel,
      },
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use eyre::{
   OptionExt as _,
   Result,
   WrapErr as _,
};
use quinn_proto::{
   Connection,
   Dir,
   StreamId,
};
use rustix::{
   process::{
      Pid,
      Signal,
      kill_process_group,
   },
   pty::{
      OpenptFlags,
      grantpt,
      ioctl_tiocgptpeer,
      openpt,
      unlockpt,
   },
   termios::{
      Winsize,
      tcsetwinsize,
   },
};
use ssh_quic::{
   control::{
      Open,
      Size,
   },
   pipe::{
      Waker,
      reader,
      writer,
   },
   relay::Relay,
};

/// How long output may keep flowing after the command exits. A background
/// process that inherited the terminal would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);

const fn winsize(size: Size) -> Winsize {
   Winsize {
      ws_col:    size.columns,
      ws_row:    size.rows,
      ws_xpixel: 0,
      ws_ypixel: 0,
   }
}

pub struct Session {
   relay:    Relay,
   errors:   Option<Relay>,
   terminal: Option<OwnedFd>,
   group:    Pid,
   exit:     Receiver<u32>,
   exited:   Option<(u32, Instant)>,
}

impl Session {
   /// Starts the command or login shell that `open` asks for as `user`.
   /// `buffered` and `finished` describe input already read from `stream`.
   pub fn spawn(
      open: &Open,
      user: &str,
      stream: StreamId,
      (buffered, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<Self> {
      let mut command = Command::new(env::current_exe()?);
      command.arg("--session").arg(user);

      if let Some(text) = &open.command {
         command.arg("--command").arg(text);
      }

      let (mut child, output, input, errors, terminal) = if let Some(terminal) = &open.terminal {
         let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
         let master = openpt(flags).wrap_err("opening a terminal")?;
         grantpt(&master)?;
         unlockpt(&master)?;
         tcsetwinsize(&master, winsize(terminal.size))?;

         let slave = ioctl_tiocgptpeer(&master, flags)?;

         command
            .arg("--term")
            .arg(&terminal.name)
            .stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave);

         let child = command.spawn().wrap_err("starting the session process")?;
         let output = File::from(master.try_clone()?);
         let input = File::from(master.try_clone()?);

         connection.send_stream(stream).set_priority(1)?;
         (child, output, input, None, Some(master))
      } else {
         command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

         let mut child = command.spawn().wrap_err("starting the session process")?;
         let output = child.stdout.take().ok_or_eyre("child has no stdout")?;
         let input = child.stdin.take().ok_or_eyre("child has no stdin")?;
         let errors = child.stderr.take().ok_or_eyre("child has no stderr")?;

         let side = connection
            .streams()
            .open(Dir::Uni)
            .ok_or_eyre("no stream credit for stderr")?;
         connection
            .send_stream(side)
            .write(&open.session.to_be_bytes())?;

         let errors = reader(File::from(OwnedFd::from(errors)), Arc::clone(waker));
         let errors = Relay::new(side, Some(errors), None, Vec::new(), false);

         (
            child,
            File::from(OwnedFd::from(output)),
            File::from(OwnedFd::from(input)),
            Some(errors),
            None,
         )
      };

      // The parent's copies of the terminal's child side live in `command`,
      // and the terminal reports end of output only once they are closed.
      drop(command);

      let output = reader(output, Arc::clone(waker));
      let (input, _) = writer(input, Arc::clone(waker));
      let group = Pid::from_child(&child);

      let (status, exit) = channel();
      let reaper = Arc::clone(waker);

      thread::spawn(move || {
         let code = child.wait().map_or(255, |status| {
            status
               .code()
               .or_else(|| status.signal().map(|signal| 128 + signal))
               .and_then(|code| u32::try_from(code).ok())
               .unwrap_or(255)
         });

         let _ = status.send(code);
         reaper.wake();
      });

      Ok(Self {
         relay: Relay::new(stream, Some(output), Some(input), buffered, finished),
         errors,
         terminal,
         group,
         exit,
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

      if self.exited.is_none()
         && let Ok(status) = self.exit.try_recv()
      {
         self.exited = Some((status, now));
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
      // The session process leads its own process group, so this reaches the
      // command and its foreground children when the client goes away.
      if self.exited.is_none() {
         let _ = kill_process_group(self.group, Signal::HUP);
      }
   }
}
