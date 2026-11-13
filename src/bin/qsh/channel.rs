//! One session of a client and the standard streams it runs on.

use std::{
   fs::File,
   io::{
      self,
      Write as _,
   },
   os::fd::OwnedFd,
   sync::Arc,
   thread::JoinHandle,
};

use misstep::{
   OptionExt as _,
   Result,
   bail,
};
use quicsh::{
   control::{
      Deframer,
      Message,
      Open,
      Outbox,
      Size,
      Token,
   },
   pipe::{
      Waker,
      reader_until,
      writer,
   },
   relay::{
      Relay,
      Tail,
   },
   transport::drain,
};
use quinn_proto::{
   Connection,
   Dir,
   StreamId,
   VarInt,
};
use rustix::termios::{
   OptionalActions,
   Termios,
   tcgetattr,
   tcgetwinsize,
   tcsetattr,
};

use crate::mux::Notice;

/// How much more session output arrives before the server hears of it.
const CONFIRM_STEP: u64 = 256 << 10;

/// Puts the local terminal in raw mode and restores it when dropped.
pub struct RawMode(Termios);

impl RawMode {
   /// Switches the terminal to raw mode and remembers the old settings.
   pub fn enable() -> Result<Self> {
      let saved = tcgetattr(io::stdin())?;

      let mut raw = saved.clone();
      raw.make_raw();
      tcsetattr(io::stdin(), OptionalActions::Now, &raw)?;

      Ok(Self(saved))
   }
}

impl Drop for RawMode {
   fn drop(&mut self) {
      let _ = tcsetattr(io::stdin(), OptionalActions::Now, &self.0);
   }
}

/// The current size of the terminal behind `descriptor`.
pub fn window(descriptor: &File) -> Result<Size> {
   let size = tcgetwinsize(descriptor)?;

   Ok(Size {
      columns: size.ws_col,
      rows:    size.ws_row,
   })
}

/// Who started a session and hears how it goes.
pub enum Owner {
   /// This process, which holds its own terminal in raw mode meanwhile.
   Process(Option<RawMode>),
   /// Another `qsh` that shares this one's connection. It hears through its
   /// socket and switches its own terminal.
   Peer(OwnedFd),
}

/// The standard streams a session runs on.
pub struct Streams {
   /// Where the session's input comes from.
   pub input:  File,
   /// Where its output goes.
   pub output: File,
   /// Where its standard error and this program's notices go.
   pub errors: File,
}

/// One session, from the request for it to its exit status.
pub struct Channel {
   /// What to ask the server for, until the session starts.
   open:     Option<Open>,
   /// The streams the session runs on.
   stdio:    Streams,
   /// Who hears how the session goes.
   owner:    Owner,
   /// Ends the thread that reads the input once the session is over. The
   /// input may be a terminal that another program reads next.
   stop:     Arc<Waker>,
   /// The session stream, once the session started.
   relay:    Option<Relay>,
   /// The session's standard error.
   errors:   Option<Relay>,
   /// Standard error whose stream died with its connection, until the
   /// server opens a new one for it.
   orphan:   Option<Relay>,
   /// What the server takes to give the session to a new connection.
   token:    Option<Token>,
   /// The stream that asks for the session back, with the server's answer
   /// so far and the request not yet sent.
   resuming: Option<(StreamId, Deframer, Outbox)>,
   /// How much session output the server last heard that this side has.
   told:     u64,
   /// The terminal size last sent to the server.
   size:     Option<Size>,
   /// Threads still writing to standard output and error.
   writers:  Vec<JoinHandle<()>>,
   /// Exit status of the remote command.
   status:   Option<u32>,
}

impl Drop for Channel {
   fn drop(&mut self) {
      self.stop.wake();
   }
}

impl Channel {
   /// A session that starts once the server accepted the login.
   pub fn new(open: Open, stdio: Streams, owner: Owner) -> Result<Self> {
      Ok(Self {
         open: Some(open),
         stdio,
         owner,
         stop: Arc::new(Waker::new()?),
         relay: None,
         errors: None,
         orphan: None,
         token: None,
         resuming: None,
         told: 0,
         size: None,
         writers: Vec::new(),
         status: None,
      })
   }

   /// Whether the session runs on a terminal.
   pub const fn interactive(&self) -> bool {
      self.size.is_some()
   }

   /// Whether the session's stream was opened.
   pub const fn started(&self) -> bool {
      self.relay.is_some()
   }

   /// Whether a new connection could take the session over.
   pub const fn resumable(&self) -> bool {
      self.token.is_some() && self.relay.is_some()
   }

   /// Whether the session waits on `stream` for the server to hand it back.
   pub fn resuming(&self, stream: StreamId) -> bool {
      self
         .resuming
         .as_ref()
         .is_some_and(|&(asked, ..)| asked == stream)
   }

   /// Notes what the server takes to give the session to a new connection.
   pub const fn keep(&mut self, token: Token) {
      self.token = Some(token);
   }

   /// Notes the exit status of the remote command.
   pub const fn exit(&mut self, status: u32) {
      self.status = Some(status);
   }

   /// Whether this process started the session for itself.
   pub const fn local(&self) -> bool {
      matches!(self.owner, Owner::Process(_))
   }

   /// The stream the session runs on right now.
   pub fn stream(&self) -> Option<StreamId> {
      self
         .resuming
         .as_ref()
         .map(|&(stream, ..)| stream)
         .or_else(|| self.relay.as_ref().map(Relay::stream))
   }

   /// Writes a line about the session where its user reads it.
   pub fn notice(&mut self, text: &str) {
      let _ = write!(self.stdio.errors, "qsh: {text}\r\n");
   }

   /// Switches the owner's terminal to raw mode or back, for a session on a
   /// terminal. Out of raw mode, Ctrl-C reaches the owner while it has no
   /// server to send it to.
   fn raw(&mut self, enabled: bool) -> Result<()> {
      if !self.interactive() {
         return Ok(());
      }

      match self.owner {
         Owner::Process(ref mut raw) => {
            *raw = enabled.then(RawMode::enable).transpose()?;
         },
         Owner::Peer(ref socket) => {
            let notice = if enabled {
               Notice::Resumed
            } else {
               Notice::Lost
            };

            notice.send(socket);
         },
      }

      Ok(())
   }

   /// Opens the session stream once the server accepted the login.
   pub fn start(
      &mut self,
      label: u32,
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<()> {
      let Some(mut open) = self.open.take() else {
         return Ok(());
      };

      open.session = label;
      self.size = open.terminal.as_ref().map(|terminal| terminal.size);

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;

      if self.interactive() {
         connection.send_stream(stream).set_priority(1)?;
         self.raw(true)?;
      }

      let input = reader_until(
         self.stdio.input.try_clone()?,
         Arc::clone(&self.stop),
         Arc::clone(waker),
      );
      let (output, handle) = writer(self.stdio.output.try_clone()?, Arc::clone(waker));

      let mut relay = Relay::new(stream, Some(input), Some(output), Vec::new(), false);
      relay.prefix(Message::Open(open).encode());

      // A terminal may lose input typed during an outage. Anything else
      // must continue without a gap, so its input stays until the server
      // confirms it.
      relay.remember(if self.interactive() {
         Tail::default()
      } else {
         Tail::exact()
      });

      self.writers.push(handle);
      self.relay = Some(relay);
      Ok(())
   }

   /// Tells the user that the connection died.
   pub fn suspend(&mut self) {
      let _ = self.raw(false);
      let _ = write!(
         self.stdio.errors,
         "\r\nqsh: connection lost, reconnecting. Ctrl-C gives up.\r\n"
      );
   }

   /// Forgets the streams of a dead connection.
   pub fn detach(&mut self) {
      self.resuming = None;
      self.orphan = self.errors.take().or_else(|| self.orphan.take());
   }

   /// Asks the server for the session on a new stream.
   pub fn rejoin(&mut self, label: u32, connection: &mut Connection) -> Result<()> {
      let token = self.token.context("no session to resume")?;
      let relay = self.relay.as_ref().context("no session to resume")?;

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;

      if self.interactive() {
         connection.send_stream(stream).set_priority(1)?;
      }

      let mut outbox = Outbox::default();
      outbox.push(&Message::Resume {
         token,
         session: label,
         received: relay.taken(),
         errors: self.orphan.as_ref().map_or(0, Relay::taken),
      });

      self.resuming = Some((stream, Deframer::default(), outbox));
      Ok(())
   }

   /// Reads the server's answer to [`Channel::rejoin`] and continues the
   /// session on the new stream.
   pub fn resumed(&mut self, connection: &mut Connection) -> Result<()> {
      let Some((stream, ref mut deframer, _)) = self.resuming else {
         return Ok(());
      };

      let (chunks, finished) = drain(connection, stream)?;

      for bytes in chunks {
         deframer.push(&bytes);
      }

      let (received, skipped) = match deframer.pop()? {
         Some(Message::Resumed { received, skipped }) => (received, skipped),
         Some(Message::Gone) => bail!("the session ended while the connection was down"),
         Some(_) => bail!("unexpected answer to a resume request"),
         None if finished => bail!("the server gave no answer to a resume request"),
         None => return Ok(()),
      };

      let rest = self
         .resuming
         .take()
         .map_or_else(Vec::new, |(_, answer, _)| answer.into_rest());

      let relay = self.relay.as_mut().context("no session to resume")?;
      let lost = skipped + relay.lacks(received);

      if self.size.is_none() && lost > 0 {
         bail!("the session cannot continue, {lost} bytes of it are gone");
      }

      relay.skip(skipped);
      relay.resume(connection, stream, Vec::new(), received, (rest, finished));

      self.raw(true)?;

      if skipped == 0 {
         self.notice("reconnected");
      } else {
         self.notice(&format!(
            "reconnected, {skipped} bytes of output were not kept"
         ));
      }

      Ok(())
   }

   /// Joins the server's stream for the session's standard error, of which
   /// `rest` already arrived.
   pub fn errors(
      &mut self,
      stream: StreamId,
      (rest, finished): (Vec<u8>, bool),
      connection: &mut Connection,
      waker: &Arc<Waker>,
   ) -> Result<()> {
      if let Some(mut errors) = self.orphan.take() {
         errors.resume(connection, stream, Vec::new(), 0, (rest, finished));
         self.errors = Some(errors);
         return Ok(());
      }

      if self.errors.is_some() {
         bail!("server opened a second stderr stream");
      }

      let (output, handle) = writer(self.stdio.errors.try_clone()?, Arc::clone(waker));

      self.writers.push(handle);
      self.errors = Some(Relay::new(stream, None, Some(output), rest, finished));
      Ok(())
   }

   /// Forgets kept input within the first `taken` bytes, which the server
   /// has.
   pub fn release(&mut self, taken: u64) {
      if let Some(ref mut relay) = self.relay {
         relay.release(taken);
      }
   }

   /// Moves data, and queues what the server should hear about the session
   /// in `outbox`. That is a changed terminal size, and how much output
   /// arrived once enough is new, so that the server can forget it.
   pub fn pump(
      &mut self,
      label: u32,
      connection: &mut Connection,
      outbox: &mut Outbox,
   ) -> Result<()> {
      if let Some((stream, _, ref mut request)) = self.resuming {
         request.flush(connection, stream)?;
         return Ok(());
      }

      let Some(ref mut relay) = self.relay else {
         return Ok(());
      };

      relay.pump(connection)?;

      if let Some(ref mut errors) = self.errors {
         errors.pump(connection)?;
      }

      let taken = relay.taken();
      let errors = self
         .errors
         .as_ref()
         .or(self.orphan.as_ref())
         .map_or(0, Relay::taken);

      if taken + errors >= self.told + CONFIRM_STEP {
         self.told = taken + errors;
         outbox.push(&Message::Taken {
            session: label,
            taken,
            errors,
         });
      }

      // No handler reports a changed window, so a resize is noticed by
      // polling the terminal size.
      if let Some(last) = self.size
         && let Ok(size) = window(&self.stdio.input)
         && size != last
      {
         outbox.push(&Message::Resize {
            session: label,
            size,
         });
         self.size = Some(size);
      }

      Ok(())
   }

   /// Ends the session without a status from the server and says why.
   pub fn fail(&mut self, reason: &str) {
      self.notice(reason);
      self.status = Some(255);
      self.relay = None;
      self.errors = None;
      self.orphan = None;
      self.resuming = None;
   }

   /// The exit status, once the session is over and all of its output is
   /// written.
   pub fn finished(&self) -> Option<u32> {
      let flushed = self.relay.as_ref().is_none_or(Relay::received_all)
         && self.orphan.is_none()
         && self.errors.as_ref().is_none_or(Relay::received_all)
         && self.writers.iter().all(JoinHandle::is_finished);

      self.status.filter(|_| flushed)
   }

   /// Lets go of the session's streams and tells the owner the status. The
   /// server hears of it apart from this, and then ends its side.
   pub fn close(mut self, status: u32, connection: &mut Connection) {
      if let Some(stream) = self.stream() {
         let _ = connection.send_stream(stream).finish();
         let _ = connection.recv_stream(stream).stop(VarInt::from_u32(0));
      }

      if let Some(ref errors) = self.errors {
         let _ = connection
            .recv_stream(errors.stream())
            .stop(VarInt::from_u32(0));
      }

      let _ = self.raw(false);

      if let Owner::Peer(ref socket) = self.owner {
         Notice::Exit(status).send(socket);
      }
   }
}
