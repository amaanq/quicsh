use std::{
   env,
   fs::{
      self,
      OpenOptions,
   },
   io::{
      self,
      Write as _,
   },
   net::ToSocketAddrs as _,
   os::unix::fs::OpenOptionsExt as _,
   path::PathBuf,
   sync::mpsc::{
      Receiver,
      Sender,
      TryRecvError,
      channel,
   },
   thread,
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
use ssh_quic::{
   DEFAULT_PORT,
   agent::Agent,
   auth::{
      Deframer,
      Message,
      Request,
      challenge,
      exporter,
   },
   key::PublicKey,
   known_hosts::{
      Trust,
      check,
      entry,
   },
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
const SERVER_NAME: &str = "ssh-quic";

struct Options {
   user:     String,
   host:     String,
   port:     u16,
   identity: Option<PublicKey>,
}

impl Options {
   fn parse() -> Result<Self> {
      let mut port = DEFAULT_PORT;
      let mut identity = None;
      let mut target = None;
      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Short('p') => port = parser.value()?.parse()?,
            Arg::Short('i') => {
               let path: PathBuf = parser.value()?.into();
               let text = fs::read_to_string(&path)
                  .wrap_err_with(|| format!("reading public key {}", path.display()))?;
               identity = Some(text.parse()?);
            },
            Arg::Value(value) if target.is_none() => target = Some(value.string()?),
            Arg::Long("help") => {
               println!("usage: ssh-quic [-p PORT] [-i PUBLIC_KEY_FILE] [USER@]HOST");
               std::process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      let target = target.ok_or_eyre("missing host, see --help")?;

      let (user, host) = match target.split_once('@') {
         Some((user, host)) => (user.to_owned(), host.to_owned()),
         None => {
            (
               env::var("USER").wrap_err("USER is not set, pass USER@HOST")?,
               target,
            )
         },
      };

      Ok(Self {
         user,
         host,
         port,
         identity,
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
fn trust_host(options: &Options, key: &PublicKey) -> Result<()> {
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

   match check(&known, &options.host, options.port, key) {
      Trust::Known => return Ok(()),
      Trust::Changed => {
         bail!(
            "host key for [{}]:{} changed to {fingerprint}. Someone may be intercepting the \
             connection. Remove the old entry from {} if the change is expected.",
            options.host,
            options.port,
            own.display()
         )
      },
      Trust::Revoked => bail!("host key {fingerprint} is marked revoked"),
      Trust::Unknown => {},
   }

   eprint!(
      "The authenticity of host '[{}]:{}' can't be established.\nED25519 key fingerprint is \
       {fingerprint}.\nAre you sure you want to continue connecting (yes/no)? ",
      options.host, options.port
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

   file.write_all(entry(&options.host, options.port, key).as_bytes())?;
   Ok(())
}

/// Checks the host, then yields one signed login per usable agent key, each
/// time the main loop asks for the next.
fn authenticate(
   options: &Options,
   host_key: &PublicKey,
   secret: &[u8; 32],
   attempts: &Sender<Attempt>,
   next: &Receiver<()>,
) -> Result<()> {
   trust_host(options, host_key)?;

   let mut agent = Agent::connect()?;
   let data = challenge(secret, &options.user);

   for identity in agent.identities()? {
      if options
         .identity
         .as_ref()
         .is_some_and(|wanted| *wanted != identity.key)
      {
         continue;
      }

      let request = Request {
         user:      options.user.clone(),
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

/// A signed login frame, or `None` once every agent key has been tried.
type Attempt = Result<Option<Vec<u8>>>;

struct Client {
   options:  Option<Options>,
   target:   String,
   control:  Option<StreamId>,
   deframer: Deframer,
   attempts: Option<Receiver<Attempt>>,
   next:     Option<Sender<()>>,
   done:     bool,
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
            let options = self.options.take().ok_or_eyre("connected twice")?;
            let host_key = tls::peer_key(connection)?;
            let secret = exporter(connection)?;

            let (attempt_tx, attempt_rx) = channel();
            let (next_tx, next_rx) = channel();
            self.attempts = Some(attempt_rx);
            self.next = Some(next_tx);

            // The host prompt and a FIDO touch can block for a long time, and
            // the loop must keep sending keep-alives meanwhile.
            thread::spawn(move || {
               if let Err(error) = authenticate(&options, &host_key, &secret, &attempt_tx, &next_rx)
               {
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
                     println!("authenticated to {}", self.target);
                     self.done = true;
                  },
                  Message::Rejected => {
                     if let Some(next) = &self.next {
                        let _ = next.send(());
                     }
                  },
                  Message::Request(_) => bail!("server sent a login request"),
               }
            }
         },
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
      if self.done {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         return Ok(None);
      }

      let Some(attempts) = &self.attempts else {
         return Ok(None);
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
         },
         Ok(Ok(None)) => bail!("permission denied, the server accepted none of the agent's keys"),
         Ok(Err(error)) => return Err(error),
         Err(TryRecvError::Empty) => {},
         Err(TryRecvError::Disconnected) => bail!("authentication worker stopped"),
      }

      Ok(Some(now + WORKER_POLL))
   }

   fn done(&self) -> bool {
      self.done
   }
}

fn main() -> Result<()> {
   let options = Options::parse()?;
   let target = format!("{}@{}", options.user, options.host);

   let address = (options.host.as_str(), options.port)
      .to_socket_addrs()
      .wrap_err_with(|| format!("resolving {}", options.host))?
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
      options: Some(options),
      target,
      control: None,
      deframer: Deframer::default(),
      attempts: None,
      next: None,
      done: false,
   };

   transport.run(&mut client)
}
