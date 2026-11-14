/// One session and its standard streams.
mod channel;
mod forward;
/// The socket that shares a connection.
mod mux;
/// Command line options.
mod options;

use std::{
   collections::{
      BTreeMap,
      HashMap,
   },
   env,
   fs::{
      self,
      DirBuilder,
      File,
      OpenOptions,
   },
   io::{
      self,
      Read as _,
      Write as _,
   },
   iter,
   net::{
      Ipv4Addr,
      SocketAddr,
      ToSocketAddrs as _,
   },
   os::{
      fd::{
         AsFd,
         OwnedFd,
      },
      unix::{
         fs::{
            DirBuilderExt as _,
            OpenOptionsExt as _,
         },
         net::UnixStream,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   process::{
      self,
      Child,
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
   thread,
   time::{
      Duration,
      Instant,
      SystemTime,
      UNIX_EPOCH,
   },
};

use bytes::Bytes;
use knell::signals::{
   SignalPipe,
   shutdown_requested,
};
use misstep::{
   OptionExt as _,
   Report,
   Result,
   ResultExt as _,
   bail,
   ensure,
   report,
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
   certificate::{
      Certificate,
      Kind,
   },
   control::{
      DETACH_LIMIT,
      Deframer,
      Message,
      Open,
      Outbox,
      Program,
      Terminal,
   },
   forward::{
      Forwards,
      datagrams,
   },
   key::PublicKey,
   known_hosts::{
      Trust,
      authorities,
      check,
      entry,
   },
   pipe::{
      Waker,
      reopen,
   },
   relay::{
      Relay,
      following,
   },
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
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use rustix::{
   net::{
      AddressFamily,
      RecvFlags,
      SendFlags,
      SocketFlags,
      SocketType,
      recv,
      send,
      socketpair,
   },
   process::{
      Signal,
      set_parent_process_death_signal,
      setsid,
   },
   stdio::{
      dup2_stderr,
      dup2_stdin,
      dup2_stdout,
   },
   termios::isatty,
};

use crate::{
   channel::{
      Channel,
      Owner,
      Streams,
      window,
   },
   forward::{
      Destination,
      Entry,
      Inbound,
      Local,
      Remote,
   },
   mux::Arrival,
   options::{
      Control,
      Login,
      Options,
      Strict,
      beside,
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
/// How long a client that shares its connection waits for the first run
/// to ask for a session.
const FIRST_SESSION: Duration = Duration::from_secs(30);

/// The user's home directory.
fn home() -> Result<PathBuf> {
   Ok(PathBuf::from(
      env::var_os("HOME").context("HOME is not set")?,
   ))
}

/// The known hosts files in one text, and the path of the one this program
/// writes.
fn known_hosts(login: &Login) -> Result<(String, PathBuf)> {
   let own = home()?.join(".ssh/known_hosts_quicsh");
   let mut known = String::new();

   for path in login.known.iter().chain([&own]) {
      match fs::read_to_string(path) {
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

   Ok((known, own))
}

/// Stops unless the user's known hosts vouch for `key`, asking on first
/// contact.
fn trust_host(login: &Login, key: &PublicKey) -> Result<()> {
   let (known, own) = known_hosts(login)?;
   let fingerprint = key.fingerprint();
   let named = login.alias.as_deref().unwrap_or(&login.host);

   match check(&known, named, login.port, key) {
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

   match login.strict {
      Strict::Refuse => {
         bail!(
            "no known hosts file lists [{named}]:{}, and StrictHostKeyChecking forbids asking",
            login.port
         )
      },
      Strict::AcceptNew => {
         eprintln!(
            "Warning: Permanently added '[{named}]:{}' ({fingerprint}) to the list of known hosts.",
            login.port
         );
      },
      Strict::Ask => {
         eprint!(
            "The authenticity of host '[{named}]:{}' can't be established.\nHost key fingerprint \
             is {fingerprint}.\nAre you sure you want to continue connecting (yes/no)? ",
            login.port
         );

         let mut answer = String::new();
         io::stdin().read_line(&mut answer)?;

         if answer.trim() != "yes" {
            bail!("host key not accepted");
         }
      },
   }

   let ssh = own.parent().unwrap_or(&own);

   DirBuilder::new()
      .recursive(true)
      .mode(0o700)
      .create(ssh)
      .with_context(|| format!("creating {}", ssh.display()))?;

   let mut file = OpenOptions::new()
      .append(true)
      .create(true)
      .mode(0o600)
      .open(&own)
      .with_context(|| format!("opening {}", own.display()))?;

   file.write_all(entry(named, login.port, key).as_bytes())?;
   Ok(())
}

/// A signed login, or `None` once every agent key has been tried.
type Attempt = Result<Option<Request>>;

/// Checks a host that no certificate authority vouched for, then yields one
/// signed login per usable agent key, each time the main loop asks for the
/// next.
fn authenticate(
   login: &Login,
   host: Option<&PublicKey>,
   secret: &[u8; 32],
   attempts: &Sender<Attempt>,
   next: &Receiver<()>,
) -> Result<()> {
   if let Some(host_key) = host {
      trust_host(login, host_key)?;
   }

   // The main loop takes one login and asks for the next when the server
   // refuses it.
   let offer = |request| attempts.send(Ok(Some(request))).is_ok() && next.recv().is_ok();
   let mut tried = Vec::new();

   let certified = |key: &PublicKey| {
      login
         .certificates
         .iter()
         .find(|certificate| certificate.key() == key)
         .cloned()
   };

   if let Some(ref socket) = login.agent {
      let mut agent = Agent::connect(socket)?;
      let data = challenge(secret, &login.user);

      // An agent lists a key with a certificate twice, and the entry with
      // the certificate logs in wherever the bare one does.
      let mut identities = agent.identities()?;
      identities.sort_by_key(|identity| identity.certificate.is_none());

      for identity in identities {
         let wanted =
            login.keys.is_empty() || login.keys.iter().any(|named| named.public == identity.key);

         if !wanted || tried.contains(&identity.key) {
            continue;
         }

         tried.push(identity.key.clone());

         let request = Request {
            user:        login.user.clone(),
            signature:   agent
               .sign(&identity, &data)
               .with_context(|| format!("signing with {}", identity.comment))?,
            certificate: identity
               .certificate
               .or_else(|| certified(&identity.key))
               .map(Box::new),
            key:         identity.key,
         };

         if !offer(request) {
            return Ok(());
         }
      }
   }

   let files = if login.keys.is_empty() && tried.is_empty() {
      let ssh = home()?.join(".ssh");

      [
         "id_ed25519",
         "id_ed25519_sk",
         "id_ecdsa",
         "id_ecdsa_sk",
         "id_rsa",
      ]
      .map(|name| ssh.join(name))
      .into_iter()
      .filter(|file| file.exists())
      .collect()
   } else {
      login
         .keys
         .iter()
         .filter(|named| !tried.contains(&named.public))
         .map(|named| named.file.clone())
         .collect::<Vec<PathBuf>>()
   };

   if files.is_empty() && tried.is_empty() {
      bail!("no key to log in with, start ssh-agent or name a key file with -i");
   }

   for file in files {
      let (key, signature) = sign_with_file(&file, &message(secret, &login.user))?;

      let request = Request {
         user: login.user.clone(),
         certificate: certified(&key).or_else(|| beside(&file)).map(Box::new),
         key,
         signature,
      };

      if !offer(request) {
         return Ok(());
      }
   }

   let _ = attempts.send(Ok(None));
   Ok(())
}

/// Signs a login with `ssh-keygen`, which reads the key file and asks for its
/// passphrase, PIN or touch on the terminal.
fn sign_with_file(file: &Path, message: &[u8]) -> Result<(PublicKey, Vec<u8>)> {
   let mut random = [0; 8];
   SystemRandom::new()
      .fill(&mut random)
      .map_err(|_| report!("system random source failed"))?;

   let directory = env::temp_dir().join(format!("quicsh-{:016x}", u64::from_be_bytes(random)));
   let input = directory.join("login");

   DirBuilder::new()
      .mode(0o700)
      .create(&directory)
      .with_context(|| format!("creating {}", directory.display()))?;

   // ssh-keygen asks for a FIDO PIN on the terminal only when its standard
   // input is one. So the message goes in a file, the signature comes back
   // in a second file beside it, and standard input is the terminal even
   // when this process reads a pipe.
   let signed = fs::write(&input, message)
      .map_err(Report::from)
      .and_then(|()| {
         let status = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-q", "-n", NAMESPACE, "-f"])
            .arg(file)
            .arg(&input)
            .stdin(File::open("/dev/tty").map_or_else(|_| Stdio::null(), Stdio::from))
            .status()
            .context("starting ssh-keygen")?;

         if !status.success() {
            bail!("ssh-keygen could not sign with {}", file.display());
         }

         Ok(fs::read_to_string(directory.join("login.sig"))?)
      });

   let _ = fs::remove_dir_all(&directory);
   Ok(armored(&signed?)?)
}

/// The UDP relay that `-W` asks for.
struct Hop {
   /// Host the server sends the datagrams to.
   host:  String,
   /// Port on that host.
   port:  u16,
   /// The socket pair whose other end the relay's user holds. It stays the
   /// same across connections, so that user never sees one of them end.
   link:  OwnedFd,
   /// Whether the user was told that the relay is open.
   ready: bool,
}

/// What a client needs to share its connection with later runs.
struct Master {
   /// What the later runs ask for.
   arrivals: Receiver<Arrival>,
   /// The session of each run that asked for one.
   peers:    HashMap<u64, u32>,
   /// How long to stay without a session, forever for `None`.
   persist:  Option<Duration>,
   /// Since when there is no session.
   empty:    Option<Instant>,
   /// Whether there ever was a session.
   served:   bool,
   /// Whether a run asked this one to exit.
   stopped:  bool,
   /// Tells the run that started this one that the server accepted the
   /// login.
   ready:    Option<File>,
}

impl Master {
   /// Listens on the socket that `control` names.
   fn listen(control: &Control, waker: &Arc<Waker>) -> Result<Self> {
      Ok(Self {
         arrivals: mux::accept(mux::listen(&control.path)?, waker),
         peers:    HashMap::new(),
         persist:  control.persist,
         empty:    None,
         served:   false,
         stopped:  false,
         ready:    Some(standard(io::stdout())?),
      })
   }

   /// When to exit for want of sessions. `busy` says that there is one now.
   fn deadline(&mut self, now: Instant, busy: bool) -> Option<Instant> {
      if busy {
         self.served = true;
         self.empty = None;
         return None;
      }

      let since = *self.empty.get_or_insert(now);

      if self.stopped {
         return Some(since);
      }

      // The run that started this one has yet to ask for its session.
      let floor = if self.served {
         Duration::ZERO
      } else {
         FIRST_SESSION
      };

      Some(since + self.persist?.max(floor))
   }
}

/// Event loop state for one connection to a server.
struct Client {
   /// The connection in use. `None` asks `main` to dial again.
   current:  Option<ConnectionHandle>,
   /// Who to log in as.
   login:    Login,
   /// When the connection died, until the session is resumed.
   lost:     Option<Instant>,
   /// When the current attempt to reach the server began, until its
   /// handshake finishes.
   dialed:   Option<Instant>,
   /// How many more addresses the host has to try if this attempt fails.
   spares:   usize,
   /// Every session, by the number the server knows it under.
   channels: BTreeMap<u32, Channel>,
   /// The session that moves its data first on the next turn.
   turn:     u32,
   /// The last session number handed out.
   issued:   u32,
   /// The socket that later runs share this connection through.
   master:   Option<Master>,
   /// Whether to forward the local SSH agent.
   agent:    bool,
   /// The `-R` forwards, indexed by listener number.
   remotes:  Vec<Remote>,
   /// What `-W` relays UDP to and from.
   relay:    Option<Hop>,
   /// The socket pair that reaches the server through a jump host.
   link:     Option<OwnedFd>,
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
   /// The host key and the authorities that may vouch for it, while the
   /// server is asked for its certificate.
   vouching: Option<(PublicKey, Vec<PublicKey>)>,
   /// Signed logins from the authentication thread.
   attempts: Option<Receiver<Attempt>>,
   /// Asks the authentication thread for the next key.
   next:     Option<Sender<()>>,
   /// Stderr streams of the server, until their four byte session header
   /// arrived.
   headings: HashMap<StreamId, Vec<u8>>,
   /// Exit status of the session this process started for itself.
   status:   Option<u32>,
   /// Whether the connection was closed.
   done:     bool,
}

/// A second handle to a standard stream for an I/O thread to own.
fn standard(descriptor: impl AsFd) -> Result<File> {
   Ok(File::from(descriptor.as_fd().try_clone_to_owned()?))
}

impl Client {
   /// Whether a new connection could take over. A session can, since the
   /// server keeps it. So can a UDP relay, a client that only forwards
   /// ports and one that shares its connection, which have no state on the
   /// server worth keeping.
   fn resumable(&self) -> bool {
      let connected = self.accepted || self.lost.is_some();

      self.relay.is_some()
         || (self.channels.is_empty() || self.master.is_some()) && connected
         || self.channels.values().any(Channel::resumable)
   }

   /// Gives up the dead connection. A terminal leaves raw mode so that
   /// Ctrl-C reaches this process while it has no server to send it to.
   fn suspend(&mut self, now: Instant) {
      self.current = None;

      if self.lost.is_some() {
         return;
      }

      self.lost = Some(now);

      for channel in self.channels.values_mut() {
         channel.suspend();
      }

      // The qsh that runs through a relay reports the outage itself.
      if self.channels.is_empty() && self.relay.is_none() {
         eprintln!("qsh: connection lost, reconnecting. Ctrl-C gives up.");
      }
   }

   /// Forgets everything that belonged to the dead connection.
   fn reset(&mut self, now: Instant) {
      self.dialed = Some(now);
      self.accepted = false;
      self.control = None;
      self.deframer = Deframer::default();
      self.outbox = Outbox::default();
      self.vouching = None;
      self.attempts = None;
      self.next = None;
      self.opening.clear();
      self.forwards = Forwards::default();
      self.headings.clear();

      for channel in self.channels.values_mut() {
         channel.detach();
      }
   }

   /// Reads the header of a stderr stream, then hands the stream to the
   /// session the header names.
   fn heading(&mut self, connection: &mut Connection, stream: StreamId) -> Result<()> {
      let Some(header) = self.headings.get_mut(&stream) else {
         return Ok(());
      };

      let (received, finished) = drain(connection, stream)?;

      for bytes in received {
         header.extend_from_slice(&bytes);
      }

      let Some((&label, rest)) = header.split_first_chunk::<4>() else {
         return Ok(());
      };

      let pending = (rest.to_vec(), finished);
      self.headings.remove(&stream);

      let Some(channel) = self.channels.get_mut(&u32::from_be_bytes(label)) else {
         let _ = connection.recv_stream(stream).stop(VarInt::from_u32(0));
         return Ok(());
      };

      channel.errors(stream, pending, connection, &self.waker)
   }

   /// Takes what later runs ask of a client that shares its connection.
   fn arrive(&mut self, connection: &mut Connection) -> Result<()> {
      let Some(ref mut master) = self.master else {
         return Ok(());
      };

      while let Ok(arrival) = master.arrivals.try_recv() {
         match arrival {
            Arrival::Open {
               peer,
               open,
               stdio,
               socket,
            } => {
               self.issued += 1;
               self.agent |= open.agent;

               let mut channel = Channel::new(open, stdio, Owner::Peer(socket), self.login.escape)?;

               if self.accepted {
                  channel.start(self.issued, connection, &self.waker)?;
               }

               master.peers.insert(peer, self.issued);
               self.channels.insert(self.issued, channel);
            },
            Arrival::Closed { peer } => {
               let gone = master
                  .peers
                  .remove(&peer)
                  .and_then(|label| Some((label, self.channels.remove(&label)?)));

               if let Some((session, channel)) = gone {
                  self.outbox.push(&Message::Close { session });
                  channel.close(255, connection);
               }
            },
            Arrival::Stop => master.stopped = true,
         }
      }

      Ok(())
   }

   /// Ends every session that is over and whose output is written, and
   /// tells the server, which keeps a session until then.
   fn settle(&mut self, connection: &mut Connection) {
      if !self.headings.is_empty() {
         return;
      }

      let over = self
         .channels
         .iter()
         .filter_map(|(&label, channel)| Some((label, channel.finished()?)))
         .collect::<Vec<(u32, u32)>>();

      for (session, status) in over {
         let Some(channel) = self.channels.remove(&session) else {
            continue;
         };

         if channel.local() {
            self.status = Some(status);
         }

         self.outbox.push(&Message::Close { session });
         channel.close(status, connection);
      }
   }

   /// Opens the UDP relay that `-W` asked for. The first time, one byte
   /// tells the relay's user that it may start.
   fn associate(&mut self, connection: &mut Connection) -> Result<()> {
      let Some(ref mut hop) = self.relay else {
         return Ok(());
      };

      let stream = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;

      let opening = Message::Associate {
         host: hop.host.clone(),
         port: hop.port,
      };

      let socket = datagrams(hop.link.try_clone()?)?;
      self.forwards.open(stream, &opening, socket, &self.waker)?;
      self.lost = None;

      if !hop.ready {
         send(&hop.link, &[0], SendFlags::NOSIGNAL)?;
         hop.ready = true;
      }

      Ok(())
   }

   /// Asks the server for the `-R` listeners.
   fn listen(&mut self) {
      for (listener, remote) in (0..).zip(&self.remotes) {
         self.outbox.push(&match remote.listen {
            Entry::Port(port) => Message::Listen { listener, port },
            Entry::Path(ref path) => {
               Message::Bind {
                  listener,
                  path: path.clone(),
               }
            },
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
         let path = self.login.agent.as_ref()?;
         Some(OwnedFd::from(UnixStream::connect(path).ok()?))
      };

      match message {
         Message::Forwarded { listener } => {
            let target = usize::try_from(listener)
               .ok()
               .and_then(|index| self.remotes.get(index));

            if let Some(remote) = target {
               match remote.target {
                  Destination::Tcp { ref host, port } => {
                     self.forwards.dial(
                        stream,
                        (host.clone(), port),
                        (rest, finished),
                        &self.waker,
                     );
                     return Ok(());
                  },
                  Destination::Unix(ref path) => {
                     if let Ok(socket) = UnixStream::connect(path) {
                        self.forwards.attach(
                           stream,
                           socket.into(),
                           (rest, finished),
                           &self.waker,
                        )?;
                        return Ok(());
                     }
                  },
               }
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

         let connect = match inbound.destination {
            Destination::Tcp { host, port } => Message::Connect { host, port },
            Destination::Unix(path) => Message::Reach { path },
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
            Message::Accepted => {
               self.attempts = None;
               self.next = None;
               self.accepted = true;
               self.listen();

               let back = self.lost.take().is_some();

               if back && self.channels.is_empty() && self.relay.is_none() {
                  eprintln!("qsh: reconnected");
               }

               self.associate(connection)?;

               for (&label, channel) in &mut self.channels {
                  if channel.resumable() {
                     channel.rejoin(label, connection)?;
                  } else if channel.started() {
                     channel.fail("the session ended with its connection");
                  } else {
                     channel.start(label, connection, &self.waker)?;
                  }
               }

               let ready = self.master.as_mut().and_then(|master| master.ready.take());

               if let Some(mut starter) = ready {
                  detach()?;
                  let _ = starter.write_all(&[0]);
               }
            },
            Message::Resumable { session, token } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.keep(token);
               }
            },
            Message::Rejected => {
               if let Some(ref next) = self.next {
                  let _ = next.send(());
               }
            },
            Message::Exit { session, status } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.exit(status);
               }
            },
            Message::Taken { session, taken, .. } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.release(taken);
               }
            },
            Message::HostCertificate(blob) => self.vouched(connection, &blob)?,
            Message::Failed { session, reason } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.fail(&format!("the server did not start the session: {reason}"));
               }
            },
            Message::Listening { listener, port } => {
               let chosen = usize::try_from(listener)
                  .ok()
                  .and_then(|index| self.remotes.get(index))
                  .is_some_and(|remote| remote.listen == Entry::Port(0));

               if chosen {
                  eprintln!("Allocated port {port} for remote forward\r");
               }
            },
            Message::Refused { listener } => {
               let wanted = usize::try_from(listener)
                  .ok()
                  .and_then(|index| self.remotes.get(index));

               if let Some(remote) = wanted {
                  match remote.listen {
                     Entry::Path(ref path) => {
                        eprintln!("Warning: remote forwarding failed for listen path {path}\r");
                     },
                     Entry::Port(port) => {
                        eprintln!(
                           "Warning: remote port forwarding failed for listen port {port}\r"
                        );
                     },
                  }
               }
            },
            _ => bail!("unexpected control message from the server"),
         }
      }

      Ok(())
   }

   /// Starts the login on a new connection. A host that the known hosts do
   /// not list is first asked for its certificate, when they name a
   /// certificate authority for it.
   fn connected(&mut self, connection: &mut Connection) -> Result<()> {
      let host_key = tls::peer_key(connection)?;
      let named = self.login.alias.as_deref().unwrap_or(&self.login.host);
      let (known, _) = known_hosts(&self.login)?;

      let listed = matches!(
         check(&known, named, self.login.port, &host_key),
         Trust::Known | Trust::Revoked
      );
      let trusted = authorities(&known, named, self.login.port);

      if listed || trusted.is_empty() {
         return self.authenticate(connection, Some(host_key));
      }

      let control = connection
         .streams()
         .open(Dir::Bi)
         .context("no stream credit")?;

      self.control = Some(control);
      self.outbox.push(&Message::Certify);
      self.vouching = Some((host_key, trusted));
      Ok(())
   }

   /// Goes on with the login once the server sent its certificate, which
   /// stands in for a known hosts entry when an authority the user trusts
   /// signed it for this host's name and key.
   fn vouched(&mut self, connection: &Connection, blob: &[u8]) -> Result<()> {
      let Some((host_key, trusted)) = self.vouching.take() else {
         bail!("unexpected host certificate");
      };

      let named = self.login.alias.as_deref().unwrap_or(&self.login.host);
      let now = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .map_or(u64::MAX, |since| since.as_secs());

      let vouches = Certificate::from_blob(blob).is_ok_and(|certificate| {
         *certificate.key() == host_key
            && trusted.contains(certificate.authority())
            && certificate.admits(Kind::Host, iter::once(named), now)
      });

      self.authenticate(connection, (!vouches).then_some(host_key))
   }

   /// Starts the thread that checks `host`, when there is a key left to
   /// check, and signs the logins.
   fn authenticate(&mut self, connection: &Connection, host: Option<PublicKey>) -> Result<()> {
      let login = self.login.clone();
      let secret = exporter(connection)?;

      let (attempt_tx, attempt_rx) = channel();
      let (next_tx, next_rx) = channel();
      self.attempts = Some(attempt_rx);
      self.next = Some(next_tx);

      // The host prompt and a FIDO touch can block for a long time, and
      // the loop must keep sending keep-alives meanwhile.
      thread::spawn(move || {
         if let Err(error) = authenticate(&login, host.as_ref(), &secret, &attempt_tx, &next_rx) {
            let _ = attempt_tx.send(Err(error));
         }
      });

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
            self.connected(connection)?;
         },
         Event::Stream(StreamEvent::Readable { id }) if Some(id) == self.control => {
            self.control(connection, id)?;
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
            while let Some(stream) = connection.streams().accept(Dir::Uni) {
               self.headings.insert(stream, Vec::new());
               self.heading(connection, stream)?;
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
         Event::Stream(StreamEvent::Readable { id }) => {
            let resuming = self
               .channels
               .values_mut()
               .find(|channel| channel.resuming(id));

            match resuming {
               Some(channel) => {
                  if let Err(error) = channel.resumed(connection) {
                     channel.fail(&format!("{error}"));
                  }
               },
               None => self.heading(connection, id)?,
            }
         },
         Event::ConnectionLost { .. } if self.dialed.is_some() && self.spares > 0 => {
            self.current = None;
         },
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
      // server that just became reachable sooner than a long one does. The
      // first attempts are cut short only while another address is left, or
      // by `ConnectTimeout`.
      let again = (self.lost.is_some() || self.spares > 0).then_some(ATTEMPT);
      let first = self.login.timeout.filter(|_| self.lost.is_none());
      let limit = self
         .dialed
         .and_then(|at| Some(at + again.into_iter().chain(first).min()?));

      if limit.is_some_and(|at| now >= at) {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.current = None;
         return Ok(None);
      }

      self.arrive(connection)?;
      self.login(connection)?;
      self.connect(connection)?;
      self.forwards.pump(connection, &self.waker)?;

      if self.accepted {
         // The first session to write can fill the send window, so a
         // transfer that always went first would starve a shell beside it.
         for late in [false, true] {
            for (&label, channel) in &mut self.channels {
               if (label < self.turn) != late {
                  continue;
               }

               if let Err(error) = channel.pump(label, connection, &mut self.outbox) {
                  channel.fail(&format!("{error}"));
               }
            }
         }

         self.turn = following(&self.channels, self.turn);

         self.settle(connection);
      }

      if let Some(control) = self.control {
         self.outbox.flush(connection, control)?;
      }

      let busy = !self.channels.is_empty();
      let expiry = self
         .master
         .as_mut()
         .and_then(|master| master.deadline(now, busy));

      let over = if self.master.is_some() {
         expiry.is_some_and(|at| now >= at)
      } else {
         self.status.is_some()
      };

      if (shutdown_requested() || over) && !self.done {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.done = true;
      }

      let resizing = self.channels.values().any(Channel::interactive);

      Ok([
         limit,
         expiry,
         self.attempts.is_some().then_some(now + WORKER_POLL),
         resizing.then_some(now + RESIZE_POLL),
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

/// Runs `client` on the first of `addresses` that answers, and dials that
/// address again for as long as a lost session can be resumed.
fn drive(transport: &mut Transport, client: &mut Client, addresses: &[SocketAddr]) -> Result<()> {
   let dial = |endpoint: &mut Transport, address, link: Option<&OwnedFd>| {
      let handle = endpoint.connect(
         Instant::now(),
         address,
         SERVER_NAME,
         tls::client()?,
         INTERACTIVE_WINDOW,
         link.map(OwnedFd::try_clone).transpose()?,
      )?;

      Ok::<ConnectionHandle, Report>(handle)
   };

   let mut reached = None;

   for (index, &address) in addresses.iter().enumerate() {
      client.reset(Instant::now());
      client.spares = addresses.len() - index - 1;

      client.current = match dial(transport, address, client.link.as_ref()) {
         Ok(handle) => Some(handle),
         Err(_) if client.spares > 0 => continue,
         Err(error) => return Err(error),
      };

      transport.run(client)?;

      // The handshake finished, or the user gave up before it did.
      if client.dialed.is_none() || client.done {
         reached = Some(address);
         break;
      }
   }

   let address =
      reached.with_context(|| format!("no address of {} answered", client.login.host))?;
   client.spares = 0;

   while let Some(since) = client.lost.filter(|_| !client.done) {
      client.current = loop {
         if shutdown_requested() || since.elapsed() >= DETACH_LIMIT {
            bail!("connection lost");
         }

         client.reset(Instant::now());

         // Dialing fails while no network reaches the server.
         if let Ok(handle) = dial(transport, address, client.link.as_ref()) {
            break Some(handle);
         }

         thread::sleep(REDIAL);
      };

      transport.run(client)?;
   }

   Ok(())
}

/// Splits `HOST:PORT`, where brackets may enclose an IPv6 address. A text
/// with no port at its end is all host.
fn endpoint(text: &str) -> (&str, Option<u16>) {
   let split = text.rsplit_once(':').and_then(|(host, port)| {
      let whole = !host.contains(':') || host.ends_with(']');
      whole.then_some((host, port.parse().ok()?))
   });

   let (host, port) = split.map_or((text, None), |(host, port)| (host, Some(port)));
   (host.trim_matches(['[', ']']), port)
}

/// Starts a second `qsh` that relays UDP to the server through the last of
/// `hops`. Returns it with the socket pair that reaches the server, one
/// message for each datagram.
fn jump(hops: &str, login: &Login) -> Result<(Child, OwnedFd)> {
   let (earlier, last) = hops
      .rsplit_once(',')
      .map_or((None, hops), |(earlier, last)| (Some(earlier), last));

   let (user, address) = last
      .split_once('@')
      .map_or((None, last), |(user, address)| (Some(user), address));
   let (host, port) = endpoint(address);

   let mut command = Command::new(env::current_exe()?);
   command
      .arg("-N")
      .arg("-W")
      .arg(format!("{}:{}", login.host, login.port));

   if let Some(hosts) = earlier {
      command.arg("-J").arg(hosts);
   }

   if let Some(name) = user {
      command.arg("-l").arg(name);
   }

   if let Some(number) = port {
      command.arg("-p").arg(number.to_string());
   }

   let (link, remote) = socketpair(
      AddressFamily::UNIX,
      SocketType::SEQPACKET,
      SocketFlags::CLOEXEC,
      None,
   )?;

   // Standard input stays free for the question about an unknown host key.
   let child = command
      .arg("--")
      .arg(host)
      .stdout(remote)
      .spawn()
      .context("starting qsh for the jump host")?;

   // The copy of the other side lives in `command`, and the end of the
   // helper shows only once it is closed.
   drop(command);

   let opened = recv(&link, &mut [0; 1], RecvFlags::empty()).is_ok_and(|(count, _)| count == 1);
   ensure!(opened, "no connection through {host}");

   Ok((child, link))
}

/// What the options ask the server to run, on a terminal when this
/// process has one and the options want it.
fn request(options: &Options, login: &Login) -> Result<Open> {
   let program = match (options.command.is_empty(), options.subsystem) {
      (true, _) => Program::Shell,
      (false, false) => Program::Command(options.command.join(" ")),
      (false, true) => Program::Subsystem(options.command.join(" ")),
   };

   let interactive = (matches!(program, Program::Shell) || options.terminal) && isatty(io::stdin());

   // A `TERM` from `SetEnv` names the terminal, as it does in OpenSSH.
   let (terminals, environment) = login
      .environment
      .iter()
      .cloned()
      .partition::<Vec<(String, String)>, _>(|pair| pair.0 == "TERM");
   let named = terminals.last().map(|pair| &pair.1);

   let terminal = if interactive {
      Some(Terminal {
         name: named
            .cloned()
            .or_else(|| env::var("TERM").ok())
            .unwrap_or_else(|| "xterm".to_owned()),
         size: window(&standard(io::stdin())?)?,
      })
   } else {
      None
   };

   Ok(Open {
      session: 0,
      terminal,
      program,
      agent: options.agent,
      environment,
   })
}

/// Leaves the terminal that started this process, which then goes on in
/// the background.
fn detach() -> Result<()> {
   let null = OpenOptions::new()
      .read(true)
      .write(true)
      .open("/dev/null")?;

   setsid()?;
   dup2_stdin(&null)?;
   dup2_stdout(&null)?;
   dup2_stderr(&null)?;

   Ok(())
}

/// Connects to the `qsh` that shares its connection, and starts one when
/// none runs and the configuration says so. `None` means that this run
/// makes a connection of its own.
fn shared(control: &Control, options: &Options) -> Result<Option<OwnedFd>> {
   if let Ok(socket) = mux::connect(&control.path) {
      return Ok(Some(socket));
   }

   if !control.create {
      return Ok(None);
   }

   let mut command = Command::new(env::current_exe()?);
   command
      .arg("--master")
      .arg("--congestion")
      .arg(options.congestion.to_string());

   for line in &options.option {
      command.arg("-o").arg(line);
   }

   if let Some(port) = options.port {
      command.arg("-p").arg(port.to_string());
   }

   for (flag, value) in [
      ("-l", options.login.as_deref()),
      ("-J", options.jump.as_deref()),
      ("-S", options.control.as_deref()),
   ] {
      if let Some(text) = value {
         command.arg(flag).arg(text);
      }
   }

   if let Some(ref file) = options.identity {
      command.arg("-i").arg(file);
   }

   // The new process asks for a key's PIN or about an unknown host on this
   // terminal, and writes one byte to the pipe once the server let it in.
   let (mut ready, report) = io::pipe()?;

   let mut holder = command
      .arg("--")
      .arg(&options.target)
      .stdout(report)
      .spawn()
      .context("starting qsh for the shared connection")?;

   drop(command);

   if ready.read(&mut [0; 1]).is_ok_and(|count| count == 1) {
      return Ok(Some(mux::connect(&control.path)?));
   }

   // Another run may have started one at the same moment.
   let _ = holder.wait();

   match mux::connect(&control.path) {
      Ok(socket) => Ok(Some(socket)),
      Err(_) => bail!("the shared connection did not start"),
   }
}

/// Runs what the options ask for through the `qsh` behind `socket` and
/// returns its exit status.
fn share(socket: &OwnedFd, options: &Options, login: &Login) -> Result<u32> {
   let signals = SignalPipe::install()?;
   let signalled = reopen(signals.read_fd())?;

   let open = request(options, login)?;
   let interactive = open.terminal.is_some();

   mux::open(socket, open)?;
   mux::wait(socket, &signalled, interactive)
}

/// Handles a run that needs no connection of its own and returns its exit
/// status. That is a question or an order for the `qsh` that shares its
/// connection, or a session through that `qsh`.
fn divert(login: &Login, options: &Options, plain: bool) -> Result<Option<u32>> {
   let Some(ref control) = login.control else {
      ensure!(
         options.order.is_none() && !options.master,
         "no ControlPath names the socket of a shared connection"
      );

      return Ok(None);
   };

   match options.order.as_deref() {
      Some("check") => println!("Master running (pid={})", mux::check(&control.path)?),
      Some("exit" | "stop") => {
         mux::stop(&control.path)?;
         println!("Exit request sent.");
      },
      Some(other) => bail!("-O takes check, exit or stop, not {other}"),
      None => {
         let socket = if plain {
            shared(control, options)?
         } else {
            None
         };

         return socket
            .map(|holder| share(&holder, options, login))
            .transpose();
      },
   }

   Ok(Some(0))
}

/// The session this process runs for itself, when it runs one.
fn first(options: &Options, login: &Login, relaying: bool) -> Result<BTreeMap<u32, Channel>> {
   let mut channels = BTreeMap::new();

   if !options.forward && !options.master && !relaying {
      let stdio = Streams {
         input:  standard(io::stdin())?,
         output: standard(io::stdout())?,
         errors: standard(io::stderr())?,
      };

      channels.insert(
         1,
         Channel::new(
            request(options, login)?,
            stdio,
            Owner::Process(None),
            login.escape,
         )?,
      );
   }

   Ok(channels)
}

/// Every address of the host a login names.
fn resolve(login: &Login) -> Result<Vec<SocketAddr>> {
   let found = (login.host.as_str(), login.port)
      .to_socket_addrs()
      .with_context(|| format!("resolving {}", login.host))?
      .collect();

   Ok(found)
}

fn main() -> Result<()> {
   let mut options = Options::parse();

   // Forwards from the configuration belong to the process that holds a
   // shared connection, so only the command line counts here.
   let plain = options.local.is_empty()
      && options.remote.is_empty()
      && options.dynamic.is_empty()
      && options.relay.is_none()
      && !options.forward
      && !options.master;

   let login = options.login()?;

   if let Some(status) = divert(&login, &options, plain)? {
      process::exit(i32::try_from(status).unwrap_or(255));
   }

   let relay = match options.relay.as_deref().map(endpoint) {
      Some((host, Some(port))) => {
         // The process that asked for the relay is the only user of it.
         set_parent_process_death_signal(Some(Signal::TERM))?;

         Some(Hop {
            host: host.to_owned(),
            port,
            link: io::stdout().as_fd().try_clone_to_owned()?,
            ready: false,
         })
      },
      Some((_, None)) => bail!("-W takes HOST:PORT"),
      None => None,
   };

   // A connection through a jump host has no address of its own to dial.
   // The one below only names the peer, and the jump host looks the real
   // one up.
   let (addresses, link, _helper) = if let Some(ref hops) = login.jump {
      let (child, link) = jump(hops, &login)?;
      let named = SocketAddr::from((Ipv4Addr::LOCALHOST, login.port));

      (vec![named], Some(link), Some(child))
   } else {
      (resolve(&login)?, None, None)
   };

   let waker = Arc::new(Waker::new()?);

   let master = match login.control {
      Some(ref control) if options.master => Some(Master::listen(control, &waker)?),
      Some(_) | None => None,
   };

   let channels = first(&options, &login, relay.is_some())?;

   let signals = SignalPipe::install()?;
   let mut signalled = reopen(signals.read_fd())?;
   let interrupted = Arc::clone(&waker);

   thread::spawn(move || {
      let _ = signalled.read(&mut [0; 1]);
      interrupted.wake();
   });

   let (accepted, inbound) = channel();
   let mut sockets = Vec::new();

   for local in options
      .local
      .into_iter()
      .map(Local::from)
      .chain(options.dynamic.into_iter().map(Local::from))
   {
      sockets.extend(local.listen(&accepted, &waker)?);
   }

   let mut transport = Transport::new(options.congestion)?;

   let mut client = Client {
      current: None,
      login,
      lost: None,
      turn: 0,
      dialed: None,
      spares: 0,
      channels,
      issued: 1,
      master,
      agent: options.agent,
      remotes: options.remote,
      relay,
      link,
      inbound,
      opening: HashMap::new(),
      forwards: Forwards::default(),
      accepted: false,
      waker,
      control: None,
      deframer: Deframer::default(),
      outbox: Outbox::default(),
      vouching: None,
      attempts: None,
      next: None,
      headings: HashMap::new(),
      status: None,
      done: false,
   };

   let ended = drive(&mut transport, &mut client, &addresses);

   let status = match client.master {
      Some(_) => {
         if let Some(ref control) = client.login.control {
            let _ = fs::remove_file(&control.path);
         }

         0
      },
      None => client.status.unwrap_or(255),
   };

   drop((client, sockets));
   ended?;

   process::exit(i32::try_from(status).unwrap_or(255))
}
