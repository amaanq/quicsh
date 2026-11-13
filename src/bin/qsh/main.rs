mod forward;
/// Command line options.
mod options;

use std::{
   collections::HashMap,
   env,
   fs::{
      self,
      File,
      OpenOptions,
   },
   io::{
      self,
      Read as _,
      Write as _,
   },
   mem,
   net::ToSocketAddrs as _,
   os::{
      fd::{
         AsFd,
         OwnedFd,
      },
      unix::{
         fs::OpenOptionsExt as _,
         net::UnixStream,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   process::{
      self,
      Command,
      Stdio,
   },
   sync::{
      Arc,
      mpsc::{
         Receiver,
         Sender,
         TryRecvError,
         channel,
      },
   },
   thread::{
      self,
      JoinHandle,
   },
   time::{
      Duration,
      Instant,
   },
};

use bytes::Bytes;
use knell::signals::{
   SignalPipe,
   shutdown_requested,
};
use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   bail,
};
use pound::Parse as _;
use quicsh::{
   agent::Agent,
   auth::{
      NAMESPACE,
      Request,
      armored,
      challenge,
      exporter,
      message,
   },
   control::{
      DETACH_LIMIT,
      Deframer,
      Message,
      Open,
      Outbox,
      Size,
      Terminal,
      Token,
   },
   forward::Forwards,
   key::PublicKey,
   known_hosts::{
      Trust,
      check,
      entry,
   },
   pipe::{
      Waker,
      reader,
      reopen,
      writer,
   },
   relay::Relay,
   tls,
   transport::{
      App,
      INTERACTIVE_WINDOW,
      Transport,
      drain,
   },
};
use quinn_proto::{
   Connection,
   ConnectionError,
   ConnectionHandle,
   Dir,
   Event,
   StreamEvent,
   StreamId,
   VarInt,
};
use rustix::termios::{
   OptionalActions,
   Termios,
   isatty,
   tcgetattr,
   tcgetwinsize,
   tcsetattr,
};

use crate::{
   forward::{
      Inbound,
      Local,
      Remote,
   },
   options::{
      Login,
      Options,
   },
};

/// How often the loop checks the authentication thread.
const WORKER_POLL: Duration = Duration::from_millis(20);
/// How often the loop checks the terminal size.
const RESIZE_POLL: Duration = Duration::from_millis(250);
/// How long one attempt to reach the server again may take.
const ATTEMPT: Duration = Duration::from_secs(5);
/// Pause between attempts while no network reaches the server.
const REDIAL: Duration = Duration::from_secs(1);
/// TLS server name, unused because the host key is checked instead.
const SERVER_NAME: &str = "quicsh";
/// The number this client gives its one session.
const SESSION: u32 = 1;

/// The user's home directory.
fn home() -> Result<PathBuf> {
   Ok(PathBuf::from(
      env::var_os("HOME").context("HOME is not set")?,
   ))
}

/// Stops unless the user's known hosts vouch for `key`, asking on first
/// contact.
fn trust_host(login: &Login, key: &PublicKey) -> Result<()> {
   let ssh = home()?.join(".ssh");
   let own = ssh.join("known_hosts_quicsh");

   let mut known = String::new();

   for path in [ssh.join("known_hosts"), own.clone()] {
      match fs::read_to_string(&path) {
         Ok(text) => {
            known.push_str(&text);
            known.push('\n');
         },
         Err(error) if error.kind() == io::ErrorKind::NotFound => {},
         Err(error) => {
            return Err(error)
               .with_context(|| format!("reading {}", path.display()))
               .erase();
         },
      }
   }

   let fingerprint = key.fingerprint();

   match check(&known, &login.host, login.port, key) {
      Trust::Known => return Ok(()),
      Trust::Changed => {
         bail!(
            "host key for [{}]:{} changed to {fingerprint}. Someone may be intercepting the \
             connection. Remove the old entry from {} if the change is expected.",
            login.host,
            login.port,
            own.display()
         )
      },
      Trust::Revoked => bail!("host key {fingerprint} is marked revoked"),
      Trust::Unknown => {},
   }

   eprint!(
      "The authenticity of host '[{}]:{}' can't be established.\nED25519 key fingerprint is \
       {fingerprint}.\nAre you sure you want to continue connecting (yes/no)? ",
      login.host, login.port
   );

   let mut answer = String::new();
   io::stdin().read_line(&mut answer)?;

   if answer.trim() != "yes" {
      bail!("host key not accepted");
   }

   let mut file = OpenOptions::new()
      .append(true)
      .create(true)
      .mode(0o600)
      .open(&own)
      .with_context(|| format!("opening {}", own.display()))?;

   file.write_all(entry(&login.host, login.port, key).as_bytes())?;
   Ok(())
}

/// A signed login, or `None` once every agent key has been tried.
type Attempt = Result<Option<Request>>;

/// Checks the host, then yields one signed login per usable agent key, each
/// time the main loop asks for the next.
fn authenticate(
   login: &Login,
   host_key: &PublicKey,
   secret: &[u8; 32],
   attempts: &Sender<Attempt>,
   next: &Receiver<()>,
) -> Result<()> {
   trust_host(login, host_key)?;

   // The main loop takes one login and asks for the next when the server
   // refuses it.
   let offer = |request| attempts.send(Ok(Some(request))).is_ok() && next.recv().is_ok();
   let mut offered = false;

   if env::var_os("SSH_AUTH_SOCK").is_some() {
      let mut agent = Agent::connect()?;
      let data = challenge(secret, &login.user);

      for identity in agent.identities()? {
         if login
            .identity
            .as_ref()
            .is_some_and(|wanted| *wanted != identity.key)
         {
            continue;
         }

         let request = Request {
            user:      login.user.clone(),
            signature: agent
               .sign(&identity.key, &data)
               .with_context(|| format!("signing with {}", identity.comment))?,
            key:       identity.key,
         };

         offered = true;

         if !offer(request) {
            return Ok(());
         }
      }
   }

   if !offered {
      let files = if let Some(ref file) = login.key_file {
         vec![file.clone()]
      } else {
         let ssh = home()?.join(".ssh");

         ["id_ed25519", "id_ed25519_sk"]
            .map(|name| ssh.join(name))
            .into_iter()
            .filter(|file| file.exists())
            .collect()
      };

      if files.is_empty() {
         bail!("no key to log in with, start ssh-agent or name a key file with -i");
      }

      for file in files {
         let (key, signature) = sign_with_file(&file, &message(secret, &login.user))?;

         let request = Request {
            user: login.user.clone(),
            key,
            signature,
         };

         if !offer(request) {
            return Ok(());
         }
      }
   }

   let _ = attempts.send(Ok(None));
   Ok(())
}

/// Signs a login with `ssh-keygen`, which reads the key file and asks for its
/// passphrase, PIN or touch on the terminal.
fn sign_with_file(file: &Path, message: &[u8]) -> Result<(PublicKey, Vec<u8>)> {
   let mut child = Command::new("ssh-keygen")
      .args(["-Y", "sign", "-q", "-n", NAMESPACE, "-f"])
      .arg(file)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .spawn()
      .context("starting ssh-keygen")?;

   child
      .stdin
      .take()
      .context("ssh-keygen has no stdin")?
      .write_all(message)?;

   let output = child.wait_with_output()?;

   if !output.status.success() {
      bail!("ssh-keygen could not sign with {}", file.display());
   }

   Ok(armored(&String::from_utf8_lossy(&output.stdout))?)
}

/// Puts the local terminal in raw mode and restores it when dropped.
struct RawMode(Termios);

impl RawMode {
   /// Switches the terminal to raw mode and remembers the old settings.
   fn enable() -> Result<Self> {
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

/// The current size of the local terminal.
fn window() -> Result<Size> {
   let size = tcgetwinsize(io::stdin())?;

   Ok(Size {
      columns: size.ws_col,
      rows:    size.ws_row,
   })
}

/// What the session runs.
struct Shell {
   /// The remote command, or `None` for a login shell.
   command:  Option<String>,
   /// Run the command on a terminal, as `ssh -t` does.
   terminal: bool,
}

/// Event loop state for one connection to a server.
struct Client {
   /// The connection in use. `None` asks `main` to dial again.
   current:  Option<ConnectionHandle>,
   /// Who to log in as.
   login:    Login,
   /// What the server takes to give the session to a new connection.
   token:    Option<Token>,
   /// When the connection died, until the session is resumed.
   lost:     Option<Instant>,
   /// When the current attempt to reach the server again began, until its
   /// handshake finishes.
   dialed:   Option<Instant>,
   /// The stream that asks for the session back, with the server's answer
   /// so far and the request not yet sent.
   resuming: Option<(StreamId, Deframer, Outbox)>,
   /// The session to start after login.
   shell:    Option<Shell>,
   /// Whether to forward the local SSH agent.
   agent:    bool,
   /// The `-R` forwards, indexed by listener number.
   remotes:  Vec<Remote>,
   /// Connections the local listeners accepted.
   inbound:  Receiver<Inbound>,
   /// Streams the server opened, until their first frame arrived.
   opening:  HashMap<StreamId, Deframer>,
   /// Every forwarded connection in progress.
   forwards: Forwards,
   /// Whether the server accepted the login.
   accepted: bool,
   /// Wakes the loop from I/O threads.
   waker:    Arc<Waker>,
   /// The control stream, once the first login is sent.
   control:  Option<StreamId>,
   /// Reassembles control messages from the server.
   deframer: Deframer,
   /// Control messages waiting for send window.
   outbox:   Outbox,
   /// Signed logins from the authentication thread.
   attempts: Option<Receiver<Attempt>>,
   /// Asks the authentication thread for the next key.
   next:     Option<Sender<()>>,
   /// The session stream.
   session:  Option<Relay>,
   /// The server's stderr stream, until its four byte session header arrived.
   heading:  Option<(StreamId, Vec<u8>)>,
   /// The session's standard error.
   errors:   Option<Relay>,
   /// Threads still writing to standard output and error.
   writers:  Vec<JoinHandle<()>>,
   /// Restores the terminal when dropped.
   raw:      Option<RawMode>,
   /// The terminal size last sent to the server.
   size:     Option<Size>,
   /// Exit status of the remote command.
   status:   Option<u32>,
   /// Whether the connection was closed.
   done:     bool,
}

/// A second handle to a standard stream for an I/O thread to own.
fn standard(descriptor: impl AsFd) -> Result<File> {
   Ok(File::from(descriptor.as_fd().try_clone_to_owned()?))
}

impl Client {
   /// Opens the session stream once the server accepted the login.
   fn start(&mut self, shell: Shell, connection: &mut Connection) -> Result<()> {
      let interactive = (shell.command.is_none() || shell.terminal) && isatty(io::stdin());

      let terminal = if interactive {
         let size = window()?;
         self.size = Some(size);

         Some(Terminal {
            name: env::var("TERM").unwrap_or_else(|_| "xterm".to_owned()),
            size,
         })
      } else {
         None
      };

      let open = Open {
         session: SESSION,
         terminal,
         command: shell.command,
         agent: self.agent,
      };

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;

      if interactive {
         connection.send_stream(stream).set_priority(1)?;
         self.raw = Some(RawMode::enable()?);
      }

      let input = reader(standard(io::stdin())?, Arc::clone(&self.waker));
      let (output, handle) = writer(standard(io::stdout())?, Arc::clone(&self.waker));

      let mut session = Relay::new(stream, Some(input), Some(output), Vec::new(), false);
      session.prefix(Message::Open(open).encode());

      if interactive {
         session.remember();
      }

      self.writers.push(handle);
      self.session = Some(session);
      Ok(())
   }

   /// Whether a new connection could take over the session. Only a terminal
   /// session can, since the server keeps no other kind.
   const fn resumable(&self) -> bool {
      self.token.is_some() && self.size.is_some() && self.session.is_some() && self.status.is_none()
   }

   /// Gives up the dead connection. The terminal leaves raw mode so that
   /// Ctrl-C reaches this process while it has no server to send it to.
   fn suspend(&mut self, now: Instant) {
      self.current = None;

      if self.lost.is_none() {
         self.raw = None;
         self.lost = Some(now);
         eprintln!("\r\nqsh: connection lost, reconnecting. Ctrl-C gives up.");
      }
   }

   /// Forgets everything that belonged to the dead connection.
   fn reset(&mut self, now: Instant) {
      self.dialed = Some(now);
      self.accepted = false;
      self.control = None;
      self.deframer = Deframer::default();
      self.outbox = Outbox::default();
      self.attempts = None;
      self.next = None;
      self.resuming = None;
      self.opening.clear();
      self.forwards = Forwards::default();
      self.heading = None;
      self.errors = None;
   }

   /// Asks the server for the session on a new stream.
   fn rejoin(&mut self, connection: &mut Connection) -> Result<()> {
      let token = self.token.context("no session to resume")?;
      let session = self.session.as_ref().context("no session to resume")?;

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;
      connection.send_stream(stream).set_priority(1)?;

      let mut outbox = Outbox::default();
      outbox.push(&Message::Resume {
         token,
         session: SESSION,
         received: session.taken(),
      });

      self.resuming = Some((stream, Deframer::default(), outbox));
      Ok(())
   }

   /// Reads the server's answer to [`Client::rejoin`] and continues the
   /// session on the new stream.
   fn resumed(&mut self, connection: &mut Connection) -> Result<()> {
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

      let session = self.session.as_mut().context("no session to resume")?;
      session.skip(skipped);
      session.resume(connection, stream, Vec::new(), received, (rest, finished));

      self.lost = None;
      self.raw = Some(RawMode::enable()?);

      if skipped == 0 {
         eprint!("qsh: reconnected\r\n");
      } else {
         eprint!("qsh: reconnected, {skipped} bytes of output were not kept\r\n");
      }

      Ok(())
   }

   /// Reads the stderr stream's header, then relays the rest to stderr.
   fn heading(&mut self, connection: &mut Connection) -> Result<()> {
      let Some((ref mut stream, ref mut header)) = self.heading else {
         return Ok(());
      };

      let (received, finished) = drain(connection, *stream)?;

      for bytes in received {
         header.extend_from_slice(&bytes);
      }

      let Some((_session, rest)) = header.split_first_chunk::<4>() else {
         return Ok(());
      };

      let (output, handle) = writer(standard(io::stderr())?, Arc::clone(&self.waker));

      self.writers.push(handle);
      self.errors = Some(Relay::new(
         *stream,
         None,
         Some(output),
         rest.to_vec(),
         finished,
      ));
      self.heading = None;
      Ok(())
   }

   /// Asks the server for the `-R` listeners.
   fn listen(&mut self) {
      for (listener, remote) in (0..).zip(&self.remotes) {
         self.outbox.push(&Message::Listen {
            listener,
            port: remote.port,
         });
      }
   }

   /// Reads the first frame of a stream the server opened and joins the
   /// stream to what the frame asks for. A bad stream is dropped alone.
   fn opened(&mut self, connection: &mut Connection, stream: StreamId) -> Result<()> {
      let Some(deframer) = self.opening.get_mut(&stream) else {
         return Ok(());
      };

      let (popped, finished) = match drain(connection, stream) {
         Ok((chunks, finished)) => {
            for bytes in chunks {
               deframer.push(&bytes);
            }

            (deframer.pop(), finished)
         },
         Err(error) => (Err(error), true),
      };

      let message = match popped {
         Ok(Some(found)) => found,
         Ok(None) if !finished => return Ok(()),
         Ok(None) | Err(_) => {
            self.opening.remove(&stream);
            Relay::abort(connection, stream);
            return Ok(());
         },
      };

      let rest = self
         .opening
         .remove(&stream)
         .map_or_else(Vec::new, Deframer::into_rest);

      let agent = || {
         let path = env::var_os("SSH_AUTH_SOCK")?;
         Some(OwnedFd::from(UnixStream::connect(path).ok()?))
      };

      match message {
         Message::Forwarded { listener } => {
            let target = usize::try_from(listener)
               .ok()
               .and_then(|index| self.remotes.get(index));

            if let Some(remote) = target {
               self.forwards.dial(
                  stream,
                  (remote.host.clone(), remote.target),
                  (rest, finished),
                  &self.waker,
               );
               return Ok(());
            }
         },
         Message::Agent if self.agent => {
            if let Some(socket) = agent() {
               self
                  .forwards
                  .attach(stream, socket, (rest, finished), &self.waker)?;
               return Ok(());
            }
         },
         _ => {},
      }

      Relay::abort(connection, stream);
      Ok(())
   }

   /// Opens a stream for each connection the local listeners accepted.
   fn connect(&mut self, connection: &mut Connection) -> Result<()> {
      while self.accepted
         && let Ok(inbound) = self.inbound.try_recv()
      {
         // Without stream credit the local connection is closed.
         let Some(stream) = connection.streams().open(Dir::Bi) else {
            continue;
         };

         let connect = Message::Connect {
            host: inbound.host,
            port: inbound.port,
         };

         self
            .forwards
            .open(stream, &connect, inbound.socket, &self.waker)?;
      }

      Ok(())
   }

   /// Handles what arrived on the control stream.
   fn control(&mut self, connection: &mut Connection, id: StreamId) -> Result<()> {
      for bytes in drain(connection, id)?.0 {
         self.deframer.push(&bytes);
      }

      while let Some(message) = self.deframer.pop()? {
         match message {
            Message::Accepted { token } => {
               self.attempts = None;
               self.next = None;
               self.accepted = true;
               self.listen();

               if self.session.is_some() {
                  self.rejoin(connection)?;
               } else {
                  self.token = Some(token);

                  if let Some(shell) = self.shell.take() {
                     self.start(shell, connection)?;
                  }
               }
            },
            Message::Rejected => {
               if let Some(ref next) = self.next {
                  let _ = next.send(());
               }
            },
            Message::Exit { status, .. } => self.status = Some(status),
            Message::Listening { listener, port } => {
               let chosen = usize::try_from(listener)
                  .ok()
                  .and_then(|index| self.remotes.get(index))
                  .is_some_and(|remote| remote.port == 0);

               if chosen {
                  eprintln!("Allocated port {port} for remote forward\r");
               }
            },
            Message::Refused { listener } => {
               let port = usize::try_from(listener)
                  .ok()
                  .and_then(|index| self.remotes.get(index))
                  .map_or(0, |remote| remote.port);
               eprintln!("Warning: remote port forwarding failed for listen port {port}\r");
            },
            _ => bail!("unexpected control message from the server"),
         }
      }

      Ok(())
   }

   /// Sends the next signed login when the authentication thread has one.
   fn login(&mut self, connection: &mut Connection) -> Result<()> {
      let Some(ref attempts) = self.attempts else {
         return Ok(());
      };

      match attempts.try_recv() {
         Ok(Ok(Some(request))) => {
            if self.control.is_none() {
               let control = connection
                  .streams()
                  .open(Dir::Bi)
                  .context("no stream credit")?;
               self.control = Some(control);
            }

            self.outbox.push(&Message::Request(request));
            Ok(())
         },
         Ok(Ok(None)) => bail!("permission denied, the server accepted none of the offered keys"),
         Ok(Err(error)) => Err(error),
         Err(TryRecvError::Empty) => Ok(()),
         Err(TryRecvError::Disconnected) => bail!("authentication worker stopped"),
      }
   }
}

impl App for Client {
   type Error = misstep::Report;

   fn event(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      event: Event,
   ) -> Result<()> {
      if Some(handle) != self.current {
         return Ok(());
      }

      match event {
         Event::Connected => {
            self.dialed = None;

            let login = self.login.clone();
            let host_key = tls::peer_key(connection)?;
            let secret = exporter(connection)?;

            let (attempt_tx, attempt_rx) = channel();
            let (next_tx, next_rx) = channel();
            self.attempts = Some(attempt_rx);
            self.next = Some(next_tx);

            // The host prompt and a FIDO touch can block for a long time, and
            // the loop must keep sending keep-alives meanwhile.
            thread::spawn(move || {
               if let Err(error) = authenticate(&login, &host_key, &secret, &attempt_tx, &next_rx) {
                  let _ = attempt_tx.send(Err(error));
               }
            });
         },
         Event::Stream(StreamEvent::Readable { id })
            if self
               .resuming
               .as_ref()
               .is_some_and(|&(stream, ..)| stream == id) =>
         {
            self.resumed(connection)?;
         },
         Event::Stream(StreamEvent::Readable { id }) if Some(id) == self.control => {
            self.control(connection, id)?;
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
            while let Some(stream) = connection.streams().accept(Dir::Uni) {
               if self.heading.is_some() || self.errors.is_some() {
                  bail!("server opened a second stderr stream");
               }

               self.heading = Some((stream, Vec::new()));
               self.heading(connection)?;
            }
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
            while let Some(stream) = connection.streams().accept(Dir::Bi) {
               self.opening.insert(stream, Deframer::default());
               self.opened(connection, stream)?;
            }
         },
         Event::Stream(StreamEvent::Readable { id }) if self.opening.contains_key(&id) => {
            self.opened(connection, id)?;
         },
         Event::Stream(StreamEvent::Readable { .. }) => self.heading(connection)?,
         Event::ConnectionLost { reason } => {
            let silent = matches!(reason, ConnectionError::TimedOut | ConnectionError::Reset);

            if !silent || !self.resumable() {
               bail!("connection lost: {reason}");
            }

            self.suspend(now);
         },
         _ => {},
      }

      Ok(())
   }

   fn tick(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      if Some(handle) != self.current {
         return Ok(None);
      }

      // A handshake retransmits ever more slowly, so a new attempt reaches a
      // server that just became reachable sooner than a long one does.
      let limit = self
         .dialed
         .filter(|_| self.lost.is_some())
         .map(|at| at + ATTEMPT);

      if limit.is_some_and(|at| now >= at) {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.suspend(now);
         return Ok(None);
      }

      self.login(connection)?;
      self.connect(connection)?;
      self.forwards.pump(connection, &self.waker)?;

      if let Some((stream, _, ref mut request)) = self.resuming {
         request.flush(connection, stream)?;
      } else if self.accepted {
         for relay in self.session.iter_mut().chain(&mut self.errors) {
            relay.pump(connection)?;
         }
      }

      if let Some(last) = self.size {
         let size = window()?;

         if size != last {
            let resize = Message::Resize {
               session: SESSION,
               size,
            };
            self.outbox.push(&resize);
            self.size = Some(size);
         }
      }

      if let Some(control) = self.control {
         self.outbox.flush(connection, control)?;
      }

      let flushed = self.session.as_ref().is_some_and(Relay::received_all)
         && self.heading.is_none()
         && self.errors.as_ref().is_none_or(Relay::received_all);

      if (shutdown_requested() || self.status.is_some() && flushed) && !self.done {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.done = true;
      }

      // No handler reports a changed window, so a resize is noticed by
      // polling the terminal size.
      Ok([
         limit,
         self.attempts.is_some().then_some(now + WORKER_POLL),
         self.size.is_some().then_some(now + RESIZE_POLL),
      ]
      .into_iter()
      .flatten()
      .min())
   }

   fn done(&self) -> bool {
      self.done || self.current.is_none()
   }

   fn waker(&self) -> Option<&Waker> {
      Some(&self.waker)
   }
}

fn main() -> Result<()> {
   let options = Options::parse();
   let login = options.login()?;

   let address = (login.host.as_str(), login.port)
      .to_socket_addrs()
      .with_context(|| format!("resolving {}", login.host))?
      .next()
      .context("host resolved to no address")?;

   let waker = Arc::new(Waker::new()?);

   let signals = SignalPipe::install()?;
   let mut signalled = reopen(signals.read_fd())?;
   let interrupted = Arc::clone(&waker);

   thread::spawn(move || {
      let _ = signalled.read(&mut [0; 1]);
      interrupted.wake();
   });

   let (accepted, inbound) = channel();

   for local in options
      .local
      .into_iter()
      .map(Local::from)
      .chain(options.dynamic.into_iter().map(Local::from))
   {
      local.listen(&accepted, &waker)?;
   }

   let mut transport = Transport::new(options.congestion)?;

   let dial = |endpoint: &mut Transport| -> Result<ConnectionHandle> {
      let handle = endpoint.connect(
         Instant::now(),
         address,
         SERVER_NAME,
         tls::client()?,
         INTERACTIVE_WINDOW,
      )?;

      Ok(handle)
   };

   let mut client = Client {
      current: Some(dial(&mut transport)?),
      login,
      token: None,
      lost: None,
      dialed: None,
      resuming: None,
      shell: (!options.forward).then_some(Shell {
         command:  (!options.command.is_empty()).then(|| options.command.join(" ")),
         terminal: options.terminal,
      }),
      agent: options.agent,
      remotes: options.remote,
      inbound,
      opening: HashMap::new(),
      forwards: Forwards::default(),
      accepted: false,
      waker,
      control: None,
      deframer: Deframer::default(),
      outbox: Outbox::default(),
      attempts: None,
      next: None,
      session: None,
      heading: None,
      errors: None,
      writers: Vec::new(),
      raw: None,
      size: None,
      status: None,
      done: false,
   };

   loop {
      transport.run(&mut client)?;

      let Some(since) = client.lost.filter(|_| !client.done) else {
         break;
      };

      client.current = loop {
         if shutdown_requested() || since.elapsed() >= DETACH_LIMIT {
            bail!("connection lost");
         }

         client.reset(Instant::now());

         // Dialing fails while no network reaches the server.
         if let Ok(handle) = dial(&mut transport) {
            break Some(handle);
         }

         thread::sleep(REDIAL);
      };
   }

   let status = client.status.unwrap_or(255);
   let writers = mem::take(&mut client.writers);
   drop(client);

   for handle in writers {
      let _ = handle.join();
   }

   process::exit(i32::try_from(status).unwrap_or(255))
}
