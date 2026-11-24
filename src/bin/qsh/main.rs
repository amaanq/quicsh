/// One session and its standard streams.
mod channel;
mod forward;
/// The socket that shares a connection.
mod mux;
/// Command line options.
mod options;
mod predict;
mod proxy;

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
      BufRead as _,
      BufReader,
      Read as _,
      Write as _,
   },
   iter,
   mem,
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
      Asks,
      DETACH_LIMIT,
      Deframer,
      Handle,
      Message,
      Open,
      Outbox,
      Program,
      Terminal,
      Token,
   },
   forward::{
      Bound,
      Forwards,
      Jump,
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
      socket_pair,
   },
   relay::{
      Relay,
      following,
   },
   tls,
   transport::{
      App,
      INTERACTIVE_WINDOW,
      PROTOCOL_ERROR,
      RESTARTING,
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
#[cfg(target_os = "linux")]
use rustix::process::{
   Signal,
   set_parent_process_death_signal,
};
use rustix::{
   net::{
      AddressFamily,
      RecvFlags,
      SocketType,
      recv,
   },
   process::setsid,
   stdio::{
      dup2_stderr,
      dup2_stdin,
      dup2_stdout,
   },
   termios::{
      OptionalActions,
      isatty,
      tcgetattr,
      tcsetattr,
   },
};
use zeroize::Zeroizing;

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
      Family,
      Login,
      Options,
      Strict,
      beside,
   },
};

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
            "no known hosts file lists [{named}]:{}, and StrictHostKeyChecking or BatchMode \
             forbids asking",
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

         // Standard input may be a pipe with the session's data in it.
         let mut answer = String::new();

         match File::open("/dev/tty") {
            Ok(terminal) => BufReader::new(terminal).read_line(&mut answer)?,
            Err(_) => io::stdin().read_line(&mut answer)?,
         };

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

/// What the authentication thread wants sent to the server.
enum Offer {
   /// A signed login.
   Key(Request),
   /// A login by answering what the server asks.
   Converse,
   /// What was typed at one of the server's questions.
   Answer(String),
   /// What the server sent after an earlier login by password.
   Ticket(Zeroizing<Vec<u8>>),
}

/// What the server made of an [`Offer`].
enum Heard {
   /// The login did not pass.
   Rejected,
   /// Something to show, and to answer unless it asks nothing.
   Prompt(Asks, String),
}

/// The next thing to send, or `None` once nothing is left to try.
type Attempt = Result<Option<Offer>>;

/// Most times a login by password is tried.
const PASSWORD_ROUNDS: usize = 3;

/// Shows a question on the terminal and reads a line there, which stays
/// off the screen when `hidden`. Without a terminal, or when
/// `SSH_ASKPASS_REQUIRE` is `force`, the program in `SSH_ASKPASS` gets the
/// question, as it does from `ssh`.
fn ask(question: &str, hidden: bool) -> Result<String> {
   let forced = env::var_os("SSH_ASKPASS_REQUIRE").is_some_and(|rule| rule == "force");

   let opened = (!forced)
      .then(|| {
         OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
      })
      .flatten();

   let Some(mut terminal) = opened else {
      let program = env::var_os("SSH_ASKPASS")
         .context("the server asks for a password, and there is no terminal to type it on")?;

      let output = Command::new(&program)
         .arg(question)
         .stdin(Stdio::null())
         .stderr(Stdio::inherit())
         .output()
         .with_context(|| format!("running {}", Path::new(&program).display()))?;

      ensure!(
         output.status.success(),
         "the SSH_ASKPASS program gave no answer"
      );

      let answer = String::from_utf8(output.stdout)
         .map_err(|_| report!("the SSH_ASKPASS program's answer is not text"))?;

      return Ok(answer.trim_end_matches(['\r', '\n']).to_owned());
   };

   terminal.write_all(question.as_bytes())?;

   // The terminal's own line editing would leave the echo off when a
   // signal ends this program at the prompt.
   let saved = tcgetattr(&terminal)?;
   let mut raw = saved.clone();
   raw.make_raw();
   tcsetattr(&terminal, OptionalActions::Flush, &raw)?;

   let answer = typed(&mut terminal, hidden);
   tcsetattr(&terminal, OptionalActions::Now, &saved)?;
   terminal.write_all(b"\r\n")?;

   answer
}

/// Reads a line a key at a time from a raw terminal, and shows it unless
/// `hidden`.
fn typed(terminal: &mut File, hidden: bool) -> Result<String> {
   const INTERRUPT: u8 = 3;
   const END: u8 = 4;
   const BACKSPACE: u8 = 8;
   const KILL: u8 = 21;
   const DELETE: u8 = 127;

   let mut line = Vec::new();
   let mut key = [0];

   loop {
      ensure!(terminal.read(&mut key)? == 1, "the terminal closed");

      match key[0] {
         b'\r' | b'\n' => break,
         INTERRUPT | END => bail!("interrupted"),
         erase @ (BACKSPACE | DELETE | KILL) => {
            while let Some(last) = line.pop() {
               // The bytes after the first of a character start with 10.
               if last & 0xC0 == 0x80 {
                  continue;
               }

               if !hidden {
                  terminal.write_all(b"\x08 \x08")?;
               }

               if erase != KILL {
                  break;
               }
            }
         },
         byte => {
            line.push(byte);

            if !hidden {
               terminal.write_all(&key)?;
            }
         },
      }
   }

   String::from_utf8(line).map_err(|_| report!("what was typed is not text"))
}

/// Logs in by answering what the server asks, which is a password in most
/// cases. `false` means the server asked nothing, so it takes no passwords.
fn converse(
   login: &Login,
   attempts: &Sender<Attempt>,
   next: &Receiver<Heard>,
   waker: &Waker,
) -> Result<bool> {
   let send = |offer| {
      let sent = attempts.send(Ok(Some(offer))).is_ok();
      waker.wake();
      sent
   };

   for round in 1..=PASSWORD_ROUNDS {
      if !send(Offer::Converse) {
         return Ok(true);
      }

      let mut asked = false;

      loop {
         let (asks, text) = match next.recv() {
            Ok(Heard::Prompt(asks, text)) => (asks, text),
            Ok(Heard::Rejected) => break,
            Err(_) => return Ok(true),
         };

         if asks == Asks::Nothing {
            eprintln!("{text}\r");
            continue;
         }

         let question = format!("({}@{}) {text}", login.user, login.host);
         asked = true;

         if !send(Offer::Answer(ask(&question, asks == Asks::Hidden)?)) {
            return Ok(true);
         }
      }

      if !asked {
         return Ok(false);
      }

      if round < PASSWORD_ROUNDS {
         eprintln!("Permission denied, please try again.\r");
      }
   }

   bail!("permission denied")
}

/// Checks a host that no certificate authority vouched for, then yields one
/// signed login per usable agent key, each time the main loop asks for the
/// next.
fn authenticate(
   login: &Login,
   host: Option<&PublicKey>,
   secret: &[u8; 32],
   attempts: &Sender<Attempt>,
   next: &Receiver<Heard>,
   waker: &Waker,
) -> Result<()> {
   if let Some(host_key) = host {
      trust_host(login, host_key)?;
   }

   // The main loop takes one login and asks for the next when the server
   // refuses it. It sleeps until a packet arrives unless it is woken.
   let offer = |offered| {
      let sent = attempts.send(Ok(Some(offered))).is_ok();
      waker.wake();

      sent && matches!(next.recv(), Ok(Heard::Rejected))
   };

   let ticket = login.ticket.lock().ok().and_then(|mut kept| kept.take());

   // A ticket exists only after a login by password, so no key logs in
   // here, and a session reads the terminal that a password would be
   // typed on.
   if let Some(kept) = ticket {
      if !offer(Offer::Ticket(kept)) {
         return Ok(());
      }

      bail!("the server no longer takes this login's ticket, log in again with the password");
   }

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

         if !offer(Offer::Key(request)) {
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

   let keyless = files.is_empty() && tried.is_empty();

   for file in files {
      let signed = sign_with_file(&file, &message(secret, &login.user), login.batch);

      // A key that would have to ask is passed over when nothing may be
      // asked.
      let (key, signature) = match signed {
         Ok(pair) => pair,
         Err(_) if login.batch => continue,
         Err(error) => return Err(error),
      };

      let request = Request {
         user: login.user.clone(),
         certificate: certified(&key).or_else(|| beside(&file)).map(Box::new),
         key,
         signature,
      };

      if !offer(Offer::Key(request)) {
         return Ok(());
      }
   }

   if login.passwords && !login.batch && converse(login, attempts, next, waker)? {
      return Ok(());
   }

   if keyless {
      bail!("no key to log in with, start ssh-agent or name a key file with -i");
   }

   let _ = attempts.send(Ok(None));
   Ok(())
}

/// Signs a login with `ssh-keygen`, which reads the key file and asks for its
/// passphrase, PIN or touch on the terminal. With `batch` it asks a program
/// that never answers, and so fails where it would have asked.
fn sign_with_file(file: &Path, message: &[u8], batch: bool) -> Result<(PublicKey, Vec<u8>)> {
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
         let mut command = Command::new("ssh-keygen");
         command
            .args(["-Y", "sign", "-q", "-n", NAMESPACE, "-f"])
            .arg(file)
            .arg(&input);

         if batch {
            command
               .env("SSH_ASKPASS_REQUIRE", "force")
               .env("SSH_ASKPASS", "false")
               .stdin(Stdio::null())
               .stderr(Stdio::null());
         } else {
            command.stdin(File::open("/dev/tty").map_or_else(|_| Stdio::null(), Stdio::from));
         }

         let status = command.status().context("starting ssh-keygen")?;

         if !status.success() {
            bail!("ssh-keygen could not sign with {}", file.display());
         }

         Ok(fs::read_to_string(directory.join("login.sig"))?)
      });

   let _ = fs::remove_dir_all(&directory);
   Ok(armored(&signed?)?)
}

/// How long a process waits at its end for the one that relays for it.
const HELPER_EXIT: Duration = Duration::from_secs(2);
/// How often it looks whether that one is gone.
const HELPER_POLL: Duration = Duration::from_millis(2);

/// The UDP relay that `-W` asks for.
struct Hop {
   /// Host the server sends the datagrams to.
   host:  String,
   /// Port on that host.
   port:  u16,
   /// The socket pair whose other end the relay's user holds. It stays the
   /// same across connections, so that user never sees one of them end.
   link:  Jump,
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
   fn listen(control: &Control, waker: &Arc<Waker>, forwards: &Sender<Inbound>) -> Result<Self> {
      Ok(Self {
         arrivals: mux::accept(mux::listen(&control.path)?, waker, forwards),
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
   /// What to ask the server about the account's sessions, once.
   ask:      Option<Message>,
   /// The socket that later runs share this connection through.
   master:   Option<Master>,
   /// The run that waits for the login before it leaves this one in the
   /// background.
   starter:  Option<File>,
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
   /// Tells the authentication thread what the server said.
   next:     Option<Sender<Heard>>,
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
      self.forwards.detach();
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

               let mut channel = Channel::new(
                  open,
                  stdio,
                  Owner::Peer(socket),
                  (self.login.escape, self.login.predict),
               )?;

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
            Arrival::End => {
               master.stopped = true;
               master.peers.clear();

               for (session, mut channel) in mem::take(&mut self.channels) {
                  channel.notice("the shared connection was told to exit");
                  self.outbox.push(&Message::Close { session });
                  channel.close(255, connection);
               }
            },
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

      let socket = hop.link.lend()?;
      self
         .forwards
         .open((stream, None), &opening, socket, &self.waker)?;
      self.lost = None;

      if !hop.ready {
         hop.link.start()?;
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
         Message::Forwarded { listener, kept } => {
            let target = usize::try_from(listener)
               .ok()
               .and_then(|index| self.remotes.get(index));

            if let Some(remote) = target {
               match remote.target {
                  Destination::Tcp { ref host, port } => {
                     self.forwards.dial(
                        (stream, kept),
                        (host.clone(), port),
                        (rest, finished),
                        &self.waker,
                     );
                     return Ok(());
                  },
                  Destination::Unix(ref path) => {
                     if let Ok(socket) = UnixStream::connect(path) {
                        self.forwards.attach(
                           (stream, Some(kept)),
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
                  .attach((stream, None), socket, (rest, finished), &self.waker)?;
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

         self.issued += 1;

         let mut kept = Handle {
            label: self.issued,
            token: Token::default(),
         };

         SystemRandom::new()
            .fill(&mut kept.token)
            .map_err(|_| report!("system random source failed"))?;

         let connect = match inbound.destination {
            Destination::Tcp { host, port } => Message::Connect { host, port, kept },
            Destination::Unix(path) => Message::Reach { path, kept },
         };

         self
            .forwards
            .open((stream, Some(kept)), &connect, inbound.socket, &self.waker)?;
      }

      Ok(())
   }

   /// Handles the server's answer about the account's sessions, or its
   /// word that a session did not start. A question about sessions goes
   /// out under the number 0, which no session has.
   fn heard(&mut self, message: Message) {
      match message {
         Message::Listing(names) => {
            for name in names {
               println!("{name}");
            }

            self.status = Some(0);
         },
         Message::Failed { session: 0, reason } => {
            eprintln!("qsh: {reason}");
            self.status = Some(1);
         },
         Message::Failed { session, reason } => {
            if let Some(channel) = self.channels.get_mut(&session) {
               if channel.started() {
                  channel.fail(&reason);
               } else {
                  channel.fail(&format!("the server did not start the session: {reason}"));
               }
            }
         },
         _ => {},
      }
   }

   /// Tells the authentication thread what the server made of its offer.
   fn told(&self, heard: Heard) {
      if let Some(ref next) = self.next {
         let _ = next.send(heard);
      }
   }

   /// Keeps what logs this account in again without its password.
   fn keep(&self, ticket: Vec<u8>) {
      if let Ok(mut kept) = self.login.ticket.lock() {
         *kept = Some(Zeroizing::new(ticket));
      }
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
               self.forwards.rejoin(connection);

               if let Some(ref question) = self.ask.take() {
                  self.outbox.push(question);
               }

               for (&label, channel) in &mut self.channels {
                  if channel.resumable() {
                     channel.rejoin(label, connection)?;
                  } else if channel.started() {
                     if back {
                        channel.fail("the session ended with its connection");
                     }
                  } else {
                     channel.start(label, connection, &self.waker)?;
                  }
               }

               release(self.starter.take())?;

               let ready = self.master.as_mut().and_then(|master| master.ready.take());

               if let Some(mut starter) = ready {
                  detach()?;
                  let _ = starter.write_all(&[0]);
               }
            },
            Message::Resumable {
               session,
               token,
               name,
               taken,
               skipped,
            } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.keep(token, &name, (taken, skipped));
               }
            },
            heard @ (Message::Listing(_) | Message::Failed { .. }) => self.heard(heard),
            Message::Rejected => self.told(Heard::Rejected),
            Message::Prompt { asks, text } => self.told(Heard::Prompt(asks, text)),
            Message::Ticket(ticket) => self.keep(ticket),
            Message::Exit { session, status } => {
               if let Some(channel) = self.channels.get_mut(&session) {
                  channel.exit(status);
               }
            },
            Message::Taken { session, taken, .. } => {
               match self.channels.get_mut(&session) {
                  Some(channel) => channel.release(taken),
                  None => self.forwards.release(session, taken),
               }
            },
            Message::HostCertificate(blob) => self.vouched(connection, &blob)?,
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

               ensure!(!self.login.exacting, "the server refused a forward");
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
      let waker = Arc::clone(&self.waker);

      thread::spawn(move || {
         let ended = authenticate(
            &login,
            host.as_ref(),
            &secret,
            &attempt_tx,
            &next_rx,
            &waker,
         );

         if let Err(error) = ended {
            let _ = attempt_tx.send(Err(error));
         }

         waker.wake();
      });

      Ok(())
   }

   /// Sends the next signed login when the authentication thread has one.
   fn login(&mut self, connection: &mut Connection) -> Result<()> {
      let Some(ref attempts) = self.attempts else {
         return Ok(());
      };

      match attempts.try_recv() {
         Ok(Ok(Some(offer))) => {
            if self.control.is_none() {
               let control = connection
                  .streams()
                  .open(Dir::Bi)
                  .context("no stream credit")?;
               self.control = Some(control);
            }

            self.outbox.push(&match offer {
               Offer::Key(request) => Message::Request(request),
               Offer::Converse => {
                  Message::Converse {
                     user: self.login.user.clone(),
                  }
               },
               Offer::Answer(text) => Message::Answer(text),
               Offer::Ticket(ticket) => {
                  Message::Redeem {
                     user:   self.login.user.clone(),
                     ticket: ticket.to_vec(),
                  }
               },
            });

            if let Some(control) = self.control {
               self.outbox.flush(connection, control)?;
            }

            // The server reads these streams once it accepted a login, which
            // saves the round trip of waiting for its answer.
            if self.lost.is_none() {
               for (&label, channel) in &mut self.channels {
                  if channel.piped() {
                     channel.start(label, connection, &self.waker)?;
                     channel.lead(connection);
                  }
               }
            }

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
         Event::ConnectionLost {
            reason: ConnectionError::ApplicationClosed(ref close),
         } if close.error_code == PROTOCOL_ERROR => {
            bail!(
               "the server gave up on this connection and its log says why, qshd may be another \
                version than this qsh"
            );
         },
         Event::ConnectionLost { reason } => {
            let silent = match reason {
               ConnectionError::TimedOut | ConnectionError::Reset => true,
               ConnectionError::ApplicationClosed(ref close) => close.error_code == RESTARTING,
               _ => false,
            };

            if !silent || !self.resumable() {
               bail!("connection lost: {reason}");
            }

            // A connection that timed out last heard its server a timeout
            // and a keep-alive interval ago.
            let heard = matches!(reason, ConnectionError::TimedOut)
               .then(|| now.checked_sub(self.login.silence() * 5 / 4))
               .flatten();

            self.suspend(heard.unwrap_or(now));
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

      let lead = self.forwards.leads();

      if lead {
         self.forwards.pump(connection, &self.waker)?;
      }

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

      if !lead {
         self.forwards.pump(connection, &self.waker)?;
      }

      self.forwards.report(&mut self.outbox);

      if let Some(control) = self.control {
         self.outbox.flush(connection, control)?;
      }

      let busy = !self.channels.is_empty();
      let expiry = self
         .master
         .as_mut()
         .and_then(|master| master.deadline(now, busy));

      // A relay ends once its user is gone and the server sent on all
      // that the user left for it.
      let relayed = self.relay.as_ref().is_some_and(|hop| hop.ready)
         && self.lost.is_none()
         && self.forwards.is_empty();

      let over = if self.master.is_some() {
         expiry.is_some_and(|at| now >= at)
      } else {
         self.status.is_some() || relayed
      };

      if (shutdown_requested() || over) && !self.done {
         connection.close(now, VarInt::from_u32(0), Bytes::new());
         self.done = true;
      }

      let resizing = self.channels.values().any(Channel::interactive);

      Ok([limit, expiry, resizing.then_some(now + RESIZE_POLL)]
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
fn serve(transport: &mut Transport, client: &mut Client, addresses: &[SocketAddr]) -> Result<()> {
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
         let patience = client.login.give_up.unwrap_or(DETACH_LIMIT);

         if shutdown_requested() || since.elapsed() >= patience {
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

/// Runs `client` as [`serve`] does, and closes its connection when that
/// ends with an error. A server keeps the sessions of a client that ends
/// without a close.
fn drive(transport: &mut Transport, client: &mut Client, addresses: &[SocketAddr]) -> Result<()> {
   let ended = serve(transport, client, addresses);

   if ended.is_err() {
      transport.close(VarInt::from_u32(0));
   }

   ended
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
      .arg(format!("[{}]:{}", login.host, login.port));

   if let Some(hosts) = earlier {
      command.arg("-J").arg(hosts);
   }

   if let Some(name) = user {
      command.arg("-l").arg(name);
   }

   if let Some(number) = port {
      command.arg("-p").arg(number.to_string());
   }

   command.args(login.family.flag());

   let (link, remote) = socket_pair(AddressFamily::UNIX, SocketType::STREAM)?;

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

/// Waits for a helper that [`jump`] started to pass on the last packets
/// of this process, which closed its end. The helper would end with this
/// process and lose them.
fn outlast(helper: Option<Child>) {
   let Some(mut child) = helper else {
      return;
   };

   let limit = Instant::now() + HELPER_EXIT;

   while Instant::now() < limit && matches!(child.try_wait(), Ok(None)) {
      thread::sleep(HELPER_POLL);
   }
}

/// What the options ask the server to run, on a terminal when this
/// process has one and the options want it.
fn request(options: &Options, login: &Login) -> Result<Open> {
   let program = match (options.command.is_empty(), options.subsystem) {
      (true, _) => Program::Shell,
      (false, false) => Program::Command(options.command.join(" ")),
      (false, true) => Program::Subsystem(options.command.join(" ")),
   };

   let wanted = (matches!(program, Program::Shell) || options.terminal) && !options.piped;
   let interactive = wanted && isatty(io::stdin());

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

   ensure!(
      options.attach.is_none() || terminal.is_some(),
      "--attach needs a terminal"
   );

   Ok(Open {
      session: 0,
      terminal,
      program,
      agent: options.agent,
      environment,
      name: options.attach.clone(),
      patience: login.give_up,
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

/// Starts this run again as a process that outlives it, and returns the
/// status to exit with once the server let that process in or it gave up.
/// Its standard input is the pipe that reports the login, since it reads
/// no input and prompts on the terminal itself.
fn background() -> Result<i32> {
   let (mut ready, report) = io::pipe()?;

   let mut command = Command::new(env::current_exe()?);
   let mut child = command
      .arg("--detached")
      .args(env::args_os().skip(1))
      .stdin(report)
      .spawn()
      .context("starting qsh for the background")?;

   drop(command);

   if ready.read(&mut [0; 1]).is_ok_and(|count| count == 1) {
      return Ok(0);
   }

   Ok(child.wait()?.code().unwrap_or(255))
}

/// Takes the pipe to the run that waits in [`background`] and leaves the
/// session without input, for `-f` and `-n`.
fn silence(options: &Options) -> Result<Option<File>> {
   let starter = options
      .detached
      .then(|| standard(io::stdin()))
      .transpose()?;

   if options.null || options.detached {
      dup2_stdin(File::open("/dev/null")?)?;
   }

   Ok(starter)
}

/// Tells the run that waits in [`background`] that it may exit.
fn release(starter: Option<File>) -> Result<()> {
   if let Some(mut waiting) = starter {
      setsid()?;
      let _ = waiting.write_all(&[0]);
   }

   Ok(())
}

/// Connects to the `qsh` that shares its connection, and starts one when
/// none runs and the configuration says so. `None` means that this run
/// makes a connection of its own.
fn shared(control: &Control, options: &Options, family: Family) -> Result<Option<OwnedFd>> {
   if let Ok(socket) = mux::connect(&control.path) {
      return Ok(Some(socket));
   }

   if !control.create {
      return Ok(None);
   }

   let mut command = Command::new(env::current_exe()?);
   command
      .arg("--master")
      .args(family.flag())
      .arg("--congestion")
      .arg(options.congestion.to_string())
      .arg("--predict")
      .arg(options.predict.to_string());

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
fn share(socket: &OwnedFd, options: &Options, login: &Login, starter: Option<File>) -> Result<u32> {
   let signals = SignalPipe::install()?;
   let signalled = reopen(signals.read_fd())?;

   if options.forward {
      release(starter)?;
      return mux::wait(socket, &signalled, false);
   }

   let open = request(options, login)?;
   let interactive = open.terminal.is_some();

   mux::open(socket, open)?;
   release(starter)?;
   mux::wait(socket, &signalled, interactive)
}

/// Listens for `locals` and hands each connection to the `qsh` that shares
/// its connection. The listeners last as long as what this returns and
/// this process.
fn lend(control: &Control, locals: Vec<Local>) -> Result<Vec<Bound>> {
   let (accepted, inbound) = channel();
   let waker = Arc::new(Waker::new()?);
   let mut sockets = Vec::new();

   for local in locals {
      sockets.extend(local.listen(&accepted, &waker)?);
   }

   let path = control.path.clone();

   thread::spawn(move || {
      for connection in inbound {
         let _ = mux::forward(&path, &connection);
      }
   });

   Ok(sockets)
}

/// Handles a run that needs no connection of its own and returns its exit
/// status. That is a question or an order for the `qsh` that shares its
/// connection, or a session through that `qsh`.
fn divert(
   login: &Login,
   options: &Options,
   plain: bool,
   lent: &mut Vec<Local>,
   starter: &mut Option<File>,
) -> Result<Option<u32>> {
   let Some(ref control) = login.control else {
      ensure!(
         options.order.is_none() && !options.master,
         "no ControlPath names the socket of a shared connection"
      );

      return Ok(None);
   };

   match options.order.as_deref() {
      Some("check") => println!("Master running (pid={})", mux::check(&control.path)?),
      Some(order @ ("exit" | "stop")) => {
         mux::stop(&control.path, order == "exit")?;
         println!(
            "{}",
            if order == "exit" {
               "Exit request sent."
            } else {
               "Stop request sent."
            }
         );
      },
      Some(other) => bail!("-O takes check, exit or stop, not {other}"),
      None => {
         // A run that only forwards starts no holder for its listeners,
         // since it holds the connection as well as one would.
         let socket = if plain || !lent.is_empty() && !options.forward {
            shared(control, options, login.family)?
         } else if lent.is_empty() {
            None
         } else {
            mux::connect(&control.path).ok()
         };

         let Some(holder) = socket else {
            return Ok(None);
         };

         let _listeners = lend(control, mem::take(lent))?;

         return share(&holder, options, login, starter.take()).map(Some);
      },
   }

   Ok(Some(0))
}

/// The addresses to dial, with the socket pair and the helper when another
/// program carries the datagrams to the server.
fn route(login: &Login) -> Result<(Vec<SocketAddr>, Option<OwnedFd>, Option<Child>)> {
   let (child, link) = match (login.proxy.as_deref(), login.jump.as_deref()) {
      (Some(line), _) => proxy::start(line)?,
      (None, Some(hops)) => jump(hops, login)?,
      (None, None) => return Ok((resolve(login)?, None, None)),
   };

   // A connection through a jump host has no address of its own to dial.
   // The one below only names the peer, and the jump host looks the real
   // one up.
   let named = SocketAddr::from((Ipv4Addr::LOCALHOST, login.port));

   Ok((vec![named], Some(link), Some(child)))
}

/// The socket that later runs share this connection through, when this
/// run is the one to hold it.
fn hosting(
   options: &Options,
   login: &Login,
   (waker, forwards): (&Arc<Waker>, &Sender<Inbound>),
   relaying: bool,
) -> Result<Option<Master>> {
   let Some(ref control) = login.control else {
      return Ok(None);
   };

   if options.master {
      return Master::listen(control, waker, forwards).map(Some);
   }

   let wanted = options.forward && control.create && !relaying;

   if !wanted || mux::connect(&control.path).is_ok() {
      return Ok(None);
   }

   // A run that only forwards has no session whose end ControlPersist
   // could count from, and no other run waits to hear of its login.
   match Master::listen(control, waker, forwards) {
      Ok(master) => {
         Ok(Some(Master {
            persist: None,
            ready: None,
            ..master
         }))
      },
      Err(error) => {
         eprintln!("qsh: not sharing this connection, {error:#}");
         Ok(None)
      },
   }
}

/// The session this process runs for itself, when it runs one.
fn first(options: &Options, login: &Login, relaying: bool) -> Result<BTreeMap<u32, Channel>> {
   let mut channels = BTreeMap::new();

   if !options.forward && !options.master && !relaying && options.ask().is_none() {
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
            (login.escape, login.predict),
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
      .filter(|address| login.family.admits(address))
      .collect::<Vec<SocketAddr>>();

   ensure!(
      !found.is_empty(),
      "{} has no address of the family asked for",
      login.host
   );

   Ok(found)
}

fn main() -> Result<()> {
   let mut options = Options::parse();

   let plain = options.plain();
   let mut lent = options.lend();
   let login = options.login()?;

   if options.stdio {
      return proxy::serve(&resolve(&login)?);
   }

   if options.background && !options.detached {
      process::exit(background()?);
   }

   let mut starter = silence(&options)?;

   if let Some(status) = divert(&login, &options, plain, &mut lent, &mut starter)? {
      process::exit(i32::try_from(status).unwrap_or(255));
   }

   let relay = match options.relay.as_deref().map(endpoint) {
      Some((host, Some(port))) => {
         // The process that asked for the relay is the only user of it.
         // macOS has no death signal, and there the helper ends once a
         // read or write on its link fails.
         #[cfg(target_os = "linux")]
         set_parent_process_death_signal(Some(Signal::TERM))?;

         Some(Hop {
            host: host.to_owned(),
            port,
            link: Jump::new(io::stdout().as_fd().try_clone_to_owned()?)?,
            ready: false,
         })
      },
      Some((_, None)) => bail!("-W takes HOST:PORT"),
      None => None,
   };

   let (addresses, link, helper) = route(&login)?;

   let waker = Arc::new(Waker::new()?);

   let (accepted, inbound) = channel();
   let master = hosting(&options, &login, (&waker, &accepted), relay.is_some())?;

   let channels = first(&options, &login, relay.is_some())?;
   let ask = options.ask();

   let signals = SignalPipe::install()?;
   let mut signalled = reopen(signals.read_fd())?;
   let interrupted = Arc::clone(&waker);

   thread::spawn(move || {
      let _ = signalled.read(&mut [0; 1]);
      interrupted.wake();
   });

   let mut sockets = Vec::new();

   for local in lent.into_iter().chain(
      options
         .local
         .into_iter()
         .map(Local::from)
         .chain(options.dynamic.into_iter().map(Local::from)),
   ) {
      sockets.extend(local.listen(&accepted, &waker)?);
   }

   let mut transport = Transport::new(options.congestion, login.silence())?;

   let mut client = Client {
      current: None,
      login,
      lost: None,
      turn: 0,
      dialed: None,
      spares: 0,
      channels,
      issued: 1,
      ask,
      master,
      starter,
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

   drop((client, sockets, transport));

   outlast(helper);
   ended?;

   process::exit(i32::try_from(status).unwrap_or(255))
}
