use std::{
   env,
   fs::{
      self,
      File,
      OpenOptions,
   },
   io::{
      self,
      Write as _,
   },
   net::ToSocketAddrs as _,
   os::{
      fd::AsFd,
      unix::fs::OpenOptionsExt as _,
   },
   path::PathBuf,
   process,
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
use eyre::{
   OptionExt as _,
   Result,
   WrapErr as _,
   bail,
};
use lexopt::{
   Arg,
   Parser,
   ValueExt as _,
};
use quinn_proto::{
   Connection,
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
use ssh_quic::{
   DEFAULT_PORT,
   agent::Agent,
   auth::{
      Request,
      challenge,
      exporter,
   },
   control::{
      Deframer,
      Message,
      Open,
      Size,
      Terminal,
   },
   key::PublicKey,
   known_hosts::{
      Trust,
      check,
      entry,
   },
   pipe::{
      Waker,
      reader,
      writer,
   },
   relay::Relay,
   tls,
   transport::{
      App,
      INTERACTIVE_WINDOW,
      Transport,
      Tuning,
      drain,
   },
};

const WORKER_POLL: Duration = Duration::from_millis(20);
const RESIZE_POLL: Duration = Duration::from_millis(250);
const SERVER_NAME: &str = "ssh-quic";
const SESSION: u32 = 1;
const USAGE: &str =
   "usage: ssh-quic [-t] [-p PORT] [-l USER] [-i PUBLIC_KEY_FILE] [USER@]HOST [COMMAND...]";

struct Login {
   user:     String,
   host:     String,
   port:     u16,
   identity: Option<PublicKey>,
}

struct Options {
   login:    Login,
   command:  Option<String>,
   /// Run the command on a terminal, as `ssh -t` does.
   terminal: bool,
}

impl Options {
   fn parse() -> Result<Self> {
      let mut port = DEFAULT_PORT;
      let mut identity = None;
      let mut target = None;
      let mut command = None;
      let mut terminal = false;
      let mut login_name = None;
      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Short('p') => port = parser.value()?.parse()?,
            Arg::Short('t') => terminal = true,
            Arg::Short('l') => login_name = Some(parser.value()?.string()?),
            Arg::Short('i') => {
               let path: PathBuf = parser.value()?.into();
               let text = fs::read_to_string(&path)
                  .wrap_err_with(|| format!("reading public key {}", path.display()))?;
               identity = Some(text.parse()?);
            },
            Arg::Value(value) => {
               target = Some(value.string()?);

               // Everything after the host is the remote command, flags
               // included.
               let words = parser
                  .raw_args()?
                  .map(lexopt::ValueExt::string)
                  .collect::<Result<Vec<_>, _>>()?;
               command = (!words.is_empty()).then(|| words.join(" "));
            },
            Arg::Long("help") => {
               println!("{USAGE}");
               process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      let target = target.ok_or_eyre(USAGE)?;

      let (named, host) = match target.split_once('@') {
         Some((named, host)) => (Some(named.to_owned()), host.to_owned()),
         None => (None, target),
      };

      let user = match named.or(login_name) {
         Some(user) => user,
         None => env::var("USER").wrap_err("USER is not set, pass USER@HOST")?,
      };

      Ok(Self {
         login: Login {
            user,
            host,
            port,
            identity,
         },
         command,
         terminal,
      })
   }
}

fn home() -> Result<PathBuf> {
   Ok(PathBuf::from(
      env::var_os("HOME").ok_or_eyre("HOME is not set")?,
   ))
}

/// Stops unless the user's known hosts vouch for `key`, asking on first
/// contact.
fn trust_host(login: &Login, key: &PublicKey) -> Result<()> {
   let ssh = home()?.join(".ssh");
   let own = ssh.join("known_hosts_quic");

   let mut known = String::new();

   for path in [ssh.join("known_hosts"), own.clone()] {
      match fs::read_to_string(&path) {
         Ok(text) => {
            known.push_str(&text);
            known.push('\n');
         },
         Err(error) if error.kind() == io::ErrorKind::NotFound => {},
         Err(error) => return Err(error).wrap_err_with(|| format!("reading {}", path.display())),
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
      .wrap_err_with(|| format!("opening {}", own.display()))?;

   file.write_all(entry(&login.host, login.port, key).as_bytes())?;
   Ok(())
}

/// A signed login frame, or `None` once every agent key has been tried.
type Attempt = Result<Option<Vec<u8>>>;

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
            .wrap_err_with(|| format!("signing with {}", identity.comment))?,
         key:       identity.key,
      };

      let frame = Message::Request(request).encode();

      if attempts.send(Ok(Some(frame))).is_err() || next.recv().is_err() {
         return Ok(());
      }
   }

   let _ = attempts.send(Ok(None));
   Ok(())
}

/// Puts the local terminal in raw mode and restores it when dropped.
struct RawMode(Termios);

impl RawMode {
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

fn window() -> Result<Size> {
   let size = tcgetwinsize(io::stdin())?;

   Ok(Size {
      columns: size.ws_col,
      rows:    size.ws_row,
   })
}

struct Client {
   login:    Option<Login>,
   command:  Option<String>,
   terminal: bool,
   waker:    Arc<Waker>,
   control:  Option<StreamId>,
   deframer: Deframer,
   attempts: Option<Receiver<Attempt>>,
   next:     Option<Sender<()>>,
   session:  Option<Relay>,
   /// The server's stderr stream, until its four byte session header arrived.
   heading:  Option<(StreamId, Vec<u8>)>,
   errors:   Option<Relay>,
   writers:  Vec<JoinHandle<()>>,
   raw:      Option<RawMode>,
   size:     Option<Size>,
   status:   Option<u32>,
   done:     bool,
}

/// A second handle to a standard stream for an I/O thread to own.
fn standard(descriptor: impl AsFd) -> Result<File> {
   Ok(File::from(descriptor.as_fd().try_clone_to_owned()?))
}

impl Client {
   /// Opens the session stream once the server accepted the login.
   fn start(&mut self, connection: &mut Connection) -> Result<()> {
      let interactive = (self.command.is_none() || self.terminal) && isatty(io::stdin());

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
         command: self.command.take(),
      };

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .ok_or_eyre("no stream credit")?;
      connection
         .send_stream(stream)
         .write(&Message::Open(open).encode())?;

      if interactive {
         connection.send_stream(stream).set_priority(1)?;
         self.raw = Some(RawMode::enable()?);
      }

      let input = reader(standard(io::stdin())?, Arc::clone(&self.waker));
      let (output, handle) = writer(standard(io::stdout())?, Arc::clone(&self.waker));

      self.writers.push(handle);
      self.session = Some(Relay::new(
         stream,
         Some(input),
         Some(output),
         Vec::new(),
         false,
      ));
      Ok(())
   }

   /// Reads the stderr stream's header, then relays the rest to stderr.
   fn heading(&mut self, connection: &mut Connection) -> Result<()> {
      let Some((stream, header)) = &mut self.heading else {
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

   fn login(&mut self, connection: &mut Connection) -> Result<()> {
      let Some(attempts) = &self.attempts else {
         return Ok(());
      };

      match attempts.try_recv() {
         Ok(Ok(Some(frame))) => {
            let control = if let Some(control) = self.control {
               control
            } else {
               let id = connection
                  .streams()
                  .open(Dir::Bi)
                  .ok_or_eyre("no stream credit")?;
               self.control = Some(id);
               id
            };

            connection.send_stream(control).write(&frame)?;
            Ok(())
         },
         Ok(Ok(None)) => bail!("permission denied, the server accepted none of the agent's keys"),
         Ok(Err(error)) => Err(error),
         Err(TryRecvError::Empty) => Ok(()),
         Err(TryRecvError::Disconnected) => bail!("authentication worker stopped"),
      }
   }
}

impl App for Client {
   type Error = eyre::Report;

   fn event(
      &mut self,
      _now: Instant,
      _handle: ConnectionHandle,
      connection: &mut Connection,
      event: Event,
   ) -> Result<()> {
      match event {
         Event::Connected => {
            let login = self.login.take().ok_or_eyre("connected twice")?;
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
         Event::Stream(StreamEvent::Readable { id }) if Some(id) == self.control => {
            for bytes in drain(connection, id)?.0 {
               self.deframer.push(&bytes);
            }

            while let Some(message) = self.deframer.pop()? {
               match message {
                  Message::Accepted => {
                     self.attempts = None;
                     self.next = None;
                     self.start(connection)?;
                  },
                  Message::Rejected => {
                     if let Some(next) = &self.next {
                        let _ = next.send(());
                     }
                  },
                  Message::Exit { status, .. } => self.status = Some(status),
                  _ => bail!("unexpected control message from the server"),
               }
            }
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
         Event::Stream(StreamEvent::Readable { .. }) => self.heading(connection)?,
         Event::ConnectionLost { reason } => bail!("connection lost: {reason}"),
         _ => {},
      }

      Ok(())
   }

   fn tick(
      &mut self,
      now: Instant,
      _handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      self.waker.clear();
      self.login(connection)?;

      for relay in self.session.iter_mut().chain(&mut self.errors) {
         relay.pump(connection)?;
      }

      if let (Some(control), Some(last)) = (self.control, self.size) {
         let size = window()?;

         if size != last {
            let resize = Message::Resize {
               session: SESSION,
               size,
            };
            connection.send_stream(control).write(&resize.encode())?;
            self.size = Some(size);
         }
      }

      let flushed = self.session.as_ref().is_some_and(Relay::received_all)
         && self.heading.is_none()
         && self.errors.as_ref().is_none_or(Relay::received_all);

      if self.status.is_some() && flushed && !self.done {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.done = true;
      }

      // The loop has no signal handling yet, so a resize is noticed by
      // polling the terminal size.
      Ok([
         self.attempts.is_some().then_some(now + WORKER_POLL),
         self.size.is_some().then_some(now + RESIZE_POLL),
      ]
      .into_iter()
      .flatten()
      .min())
   }

   fn done(&self) -> bool {
      self.done
   }

   fn waker(&self) -> Option<&Waker> {
      Some(&self.waker)
   }
}

fn main() -> Result<()> {
   let options = Options::parse()?;

   let address = (options.login.host.as_str(), options.login.port)
      .to_socket_addrs()
      .wrap_err_with(|| format!("resolving {}", options.login.host))?
      .next()
      .ok_or_eyre("host resolved to no address")?;

   let mut transport = Transport::new(Tuning::default())?;
   transport.connect(
      Instant::now(),
      address,
      SERVER_NAME,
      tls::client()?,
      INTERACTIVE_WINDOW,
   )?;

   let mut client = Client {
      login:    Some(options.login),
      command:  options.command,
      terminal: options.terminal,
      waker:    Arc::new(Waker::new()?),
      control:  None,
      deframer: Deframer::default(),
      attempts: None,
      next:     None,
      session:  None,
      heading:  None,
      errors:   None,
      writers:  Vec::new(),
      raw:      None,
      size:     None,
      status:   None,
      done:     false,
   };

   transport.run(&mut client)?;

   let status = client.status.unwrap_or(255);
   let writers = std::mem::take(&mut client.writers);
   drop(client);

   for handle in writers {
      let _ = handle.join();
   }

   process::exit(i32::try_from(status).unwrap_or(255))
}
