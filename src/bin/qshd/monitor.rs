//! The privileged process. It holds the host key, decides logins and starts
//! sessions, and it never parses anything a client sent directly.

use std::{
   collections::HashMap,
   env,
   fs::{
      self,
      DirBuilder,
      OpenOptions,
   },
   io::{
      self,
      Write as _,
   },
   net::SocketAddr,
   os::{
      fd::OwnedFd,
      unix::{
         fs::{
            DirBuilderExt as _,
            FileTypeExt as _,
            OpenOptionsExt as _,
            chown,
         },
         process::CommandExt as _,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   process::{
      Command,
      Stdio,
   },
   sync::{
      Arc,
      Mutex,
   },
   thread,
};

use knell::{
   signals::SignalPipe,
   socket::bind_unix,
};
use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   bail,
   ensure,
   report,
};
use quicsh::{
   auth::{
      self,
      Account,
   },
   control::{
      Open,
      Terminal,
      Token,
   },
   key::private_from_openssh,
   pipe::reopen,
   tls,
   transport::{
      Congestion,
      udp_socket,
   },
};
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use rustix::{
   net::{
      AddressFamily,
      SocketAddrUnix,
      SocketFlags,
      SocketType,
      bind,
      connect,
      listen,
      socket_with,
      socketpair,
   },
   process::{
      Pid,
      Signal,
      geteuid,
      kill_process_group,
   },
};
use rustls::{
   SignatureScheme,
   sign::SigningKey,
};

use crate::{
   child::exit_code,
   privsep::{
      Ended,
      Reply,
      Request,
      serve,
   },
};

/// File in the holders directory with the keys a restarted server shares
/// with the old one. It sits on a runtime directory, so a reboot replaces it.
const RESTART_SECRET: &str = "restart-secret";
/// Bytes in the restart secret.
const RESTART_SECRET_LEN: usize = 64;

/// What a TLS 1.3 server signs in `CertificateVerify` (RFC 8446 section
/// 4.4.3), up to the transcript hash.
const TRANSCRIPT_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\0";
/// Spaces that precede the context string in what the server signs.
const TRANSCRIPT_PADDING: usize = 64;
/// Longest transcript hash any TLS 1.3 cipher suite produces.
const MAX_TRANSCRIPT_HASH: usize = 64;

/// How the server was asked to run.
pub struct Settings {
   /// Address and UDP port to listen on.
   pub listen:          SocketAddr,
   /// Path of the host private key.
   pub host_key:        PathBuf,
   /// File that replaces every account's own `authorized_keys`.
   pub authorized_keys: Option<PathBuf>,
   /// The account the network process runs as when the monitor is root.
   pub user:            String,
   /// Congestion controller the network process uses.
   pub congestion:      Congestion,
}

/// The directory and socket that reach a client's SSH agent. Dropping it
/// removes both.
struct AgentDirectory {
   /// The directory only the account can enter.
   directory: PathBuf,
   /// The socket inside it.
   socket:    PathBuf,
}

impl Drop for AgentDirectory {
   fn drop(&mut self) {
      let _ = fs::remove_file(&self.socket);
      let _ = fs::remove_dir(&self.directory);
   }
}

/// One successful login.
struct Grant {
   /// Who logged in.
   account: Account,
   /// The agent socket, once a session asked for one.
   agent:   Option<AgentDirectory>,
}

/// State of the privileged process.
struct Monitor {
   /// The host key.
   key:             Arc<dyn SigningKey>,
   /// Address the server listens on.
   listen:          SocketAddr,
   /// The listening socket, until the network process takes it.
   listener:        Option<OwnedFd>,
   /// File that replaces every account's own `authorized_keys`.
   authorized_keys: Option<PathBuf>,
   /// Logins the network process may start sessions for.
   grants:          HashMap<u64, Grant>,
   /// The process group of every session on pipes that has not exited.
   sessions:        Arc<Mutex<HashMap<u64, Pid>>>,
   /// Directory of the sockets that reach session holders.
   holders:         PathBuf,
   /// The last grant or session number handed out.
   issued:          u64,
}

impl Monitor {
   /// The next unused grant or session number.
   const fn issue(&mut self) -> u64 {
      self.issued += 1;
      self.issued
   }

   /// Signs only what a TLS 1.3 server signs, so the network process cannot
   /// get the host key's signature on anything else.
   fn sign(&self, message: &[u8]) -> Result<Reply> {
      let transcript = message
         .split_at_checked(TRANSCRIPT_PADDING)
         .filter(|&(padding, _)| padding.iter().all(|&byte| byte == b' '))
         .and_then(|(_, rest)| rest.strip_prefix(TRANSCRIPT_CONTEXT));

      ensure!(
         transcript.is_some_and(|hash| hash.len() <= MAX_TRANSCRIPT_HASH),
         "refusing to sign something that is not a handshake transcript"
      );

      let signer = self
         .key
         .choose_scheme(&[SignatureScheme::ED25519])
         .context("host key is not ed25519")?;

      Ok(Reply::Signature(signer.sign(message)?))
   }

   /// Checks a login against its signature and the authorized keys.
   fn login(&mut self, login: &auth::Request, exporter: &[u8; 32]) -> Result<Reply> {
      if login.verify(exporter).is_err() {
         return Ok(Reply::Denied);
      }

      let Some(account) = Account::lookup(&login.user)? else {
         return Ok(Reply::Denied);
      };

      // An unprivileged monitor cannot switch users, so it serves only its
      // own.
      let monitor = geteuid();

      if !monitor.is_root() && monitor.as_raw() != account.uid {
         return Ok(Reply::Denied);
      }

      if !account.authorizes(&login.key, self.authorized_keys.as_deref())? {
         return Ok(Reply::Denied);
      }

      let grant = self.issue();
      self.grants.insert(grant, Grant {
         account,
         agent: None,
      });

      Ok(Reply::Granted { grant })
   }

   /// Makes the agent socket in a new directory that only the account can
   /// enter.
   fn agent(&mut self, id: u64) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get_mut(&id).context("unknown grant")?;
      ensure!(grant.agent.is_none(), "agent socket already exists");

      let mut random = [0; 8];
      SystemRandom::new()
         .fill(&mut random)
         .map_err(|_| report!("system random source failed"))?;

      let directory = env::temp_dir().join(format!("quicsh-{:016x}", u64::from_be_bytes(random)));
      let socket = directory.join("agent.sock");

      DirBuilder::new()
         .mode(0o700)
         .create(&directory)
         .with_context(|| format!("creating {}", directory.display()))?;

      let created = grant.agent.insert(AgentDirectory { directory, socket });
      let listener = bind_unix(&created.socket, 0o600)?;

      if geteuid().is_root() {
         for owned in [&created.directory, &created.socket] {
            chown(owned, Some(grant.account.uid), Some(grant.account.gid))?;
         }
      }

      Ok((Reply::Done, vec![listener.into()]))
   }

   /// Where the socket of the holder for `token` and `uid` lives. The uid in
   /// the name keeps one account from taking another's session.
   fn holder_path(&self, uid: u32, token: Token) -> PathBuf {
      let name = token
         .iter()
         .fold(format!("{uid}-"), |name, byte| format!("{name}{byte:02x}"));

      self.holders.join(name)
   }

   /// Connects to the holder that listens at `path`.
   fn holder(path: &Path) -> io::Result<OwnedFd> {
      let link = socket_with(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      connect(&link, &SocketAddrUnix::new(path)?)?;
      Ok(link)
   }

   /// Starts a holder process with a terminal session for the grant's
   /// account. The holder listens on a socket made here, since it gives up
   /// root and could not make one in a directory only root can enter.
   fn hold(&self, id: u64, open: &Open, terminal: &Terminal) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&id).context("unknown grant")?;

      let mut token = Token::default();
      SystemRandom::new()
         .fill(&mut token)
         .map_err(|_| report!("system random source failed"))?;

      let path = self.holder_path(grant.account.uid, token);

      let listener = socket_with(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      bind(&listener, &SocketAddrUnix::new(&path)?)
         .with_context(|| format!("binding {}", path.display()))?;
      listen(&listener, 4)?;

      let mut command = Command::new(env::current_exe()?);
      command
         .arg("hold")
         .arg(&grant.account.name)
         .arg("--term")
         .arg(&terminal.name)
         .arg("--columns")
         .arg(terminal.size.columns.to_string())
         .arg("--rows")
         .arg(terminal.size.rows.to_string());

      if open.agent {
         command.arg("--agent");
      }

      if let Some(ref text) = open.command {
         command.arg("--command").arg(text);
      }

      let mut child = command
         .stdin(listener)
         .spawn()
         .context("starting the session holder")?;

      // The holder outlives this process on purpose. While both run, it is
      // reaped here.
      thread::spawn(move || {
         let _ = child.wait();
         let _ = fs::remove_file(path);
      });

      let link = Self::holder(&self.holder_path(grant.account.uid, token))?;
      Ok((Reply::Held { token }, vec![link]))
   }

   /// Reads the restart secret, making one when this boot has none yet.
   fn secret(&self) -> Result<Vec<u8>> {
      let path = self.holders.join(RESTART_SECRET);

      if let Ok(secret) = fs::read(&path)
         && secret.len() == RESTART_SECRET_LEN
      {
         return Ok(secret);
      }

      let mut secret = vec![0; RESTART_SECRET_LEN];
      SystemRandom::new()
         .fill(&mut secret)
         .map_err(|_| report!("system random source failed"))?;

      let _ = fs::remove_file(&path);

      OpenOptions::new()
         .write(true)
         .create_new(true)
         .mode(0o600)
         .open(&path)
         .and_then(|mut file| file.write_all(&secret))
         .with_context(|| format!("writing {}", path.display()))?;

      Ok(secret)
   }

   /// Connects a login to a running session of its account.
   fn attach(&self, id: u64, token: Token) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&id).context("unknown grant")?;
      let path = self.holder_path(grant.account.uid, token);

      Ok(Self::holder(&path).map_or_else(
         |_| {
            // No holder listens there any more.
            let _ = fs::remove_file(&path);
            (Reply::Denied, Vec::new())
         },
         |link| (Reply::Held { token }, vec![link]),
      ))
   }

   /// Starts a session on pipes for the grant's account.
   fn spawn(&mut self, id: u64, open: &Open) -> Result<(Reply, Vec<OwnedFd>)> {
      if let Some(ref terminal) = open.terminal {
         return self.hold(id, open, terminal);
      }

      let grant = self.grants.get(&id).context("unknown grant")?;

      let mut command = Command::new(env::current_exe()?);
      command.arg("session").arg(&grant.account.name);

      if let Some(agent) = grant.agent.as_ref().filter(|_| open.agent) {
         command.arg("--agent-socket").arg(&agent.socket);
      }

      if let Some(ref text) = open.command {
         command.arg("--command").arg(text);
      }

      command
         .stdin(Stdio::piped())
         .stdout(Stdio::piped())
         .stderr(Stdio::piped());

      let mut child = command.spawn().context("starting the session process")?;
      let input = child.stdin.take().context("child has no stdin")?;
      let output = child.stdout.take().context("child has no stdout")?;
      let errors = child.stderr.take().context("child has no stderr")?;

      let (exit, mut report) = io::pipe()?;

      let session = self.issue();
      let sessions = Arc::clone(&self.sessions);

      sessions
         .lock()
         .map_err(|_| report!("a session thread died"))?
         .insert(session, Pid::from_child(&child));

      thread::spawn(move || {
         let code = child.wait().map_or(255, exit_code);

         if let Ok(mut running) = sessions.lock() {
            running.remove(&session);
         }

         let _ = report.write_all(&code.to_be_bytes());
      });

      let descriptors = vec![input.into(), output.into(), errors.into(), exit.into()];
      Ok((Reply::Spawned { session }, descriptors))
   }

   /// Hangs up one session, or every session for `None`.
   fn hangup(&self, session: Option<u64>) {
      let Ok(sessions) = self.sessions.lock() else {
         return;
      };

      // Each session process leads its own process group, so this reaches
      // the command and its foreground children.
      for (_, &group) in sessions
         .iter()
         .filter(|&(&id, _)| session.is_none_or(|wanted| wanted == id))
      {
         let _ = kill_process_group(group, Signal::HUP);
      }
   }

   /// Answers one request from the network process.
   fn handle(&mut self, request: Request) -> Result<(Reply, Vec<OwnedFd>)> {
      let plain = |reply| Ok((reply, Vec::new()));

      match request {
         Request::Hello => {
            let listener = self.listener.take().context("socket already handed over")?;
            let key = self
               .key
               .public_key()
               .context("host key has no public half")?;

            let reply = Reply::Hello {
               key:    key.to_vec(),
               listen: self.listen,
               secret: self.secret()?,
            };

            Ok((reply, vec![listener]))
         },
         Request::Sign(message) => plain(self.sign(&message)?),
         Request::Socket { local, remote } => {
            ensure!(
               local.port() == self.listen.port(),
               "socket on a port the server does not listen on"
            );

            Ok((Reply::Done, vec![udp_socket(local, Some(remote))?]))
         },
         Request::Login { login, exporter } => plain(self.login(&login, &exporter)?),
         Request::Agent { grant } => self.agent(grant),
         Request::Spawn { grant, open } => self.spawn(grant, &open),
         Request::Hangup { session } => {
            self.hangup(Some(session));
            plain(Reply::Done)
         },
         Request::Logout { grant } => {
            self.grants.remove(&grant);
            plain(Reply::Done)
         },
         Request::Attach { grant, token } => self.attach(grant, token),
      }
   }
}

/// Makes the directory for holder sockets, which only this user can enter,
/// and removes the sockets that no holder listens on any more.
fn holders() -> Result<PathBuf> {
   let directory = if geteuid().is_root() {
      PathBuf::from("/run/qshd")
   } else {
      env::var_os("XDG_RUNTIME_DIR")
         .map_or_else(env::temp_dir, PathBuf::from)
         .join(format!("qshd-{}", geteuid().as_raw()))
   };

   DirBuilder::new()
      .recursive(true)
      .mode(0o700)
      .create(&directory)
      .with_context(|| format!("creating {}", directory.display()))?;

   for entry in fs::read_dir(&directory)?.filter_map(io::Result::ok) {
      let socket = entry.file_type().is_ok_and(|kind| kind.is_socket());

      if socket && Monitor::holder(&entry.path()).is_err() {
         let _ = fs::remove_file(entry.path());
      }
   }

   Ok(directory)
}

/// Starts the network process and serves it until it exits.
pub fn run(settings: Settings) -> Result<()> {
   let key_text = fs::read_to_string(&settings.host_key)
      .with_context(|| format!("reading host key {}", settings.host_key.display()))?;

   let listener = udp_socket(settings.listen, None)
      .with_context(|| format!("listening on {}", settings.listen))?;

   let (channel, remote) = socketpair(
      AddressFamily::UNIX,
      SocketType::SEQPACKET,
      SocketFlags::CLOEXEC,
      None,
   )?;

   let mut network = Command::new(env::current_exe()?);
   network
      .arg("--congestion")
      .arg(settings.congestion.to_string())
      .arg("network")
      .stdin(remote)
      .env_clear();

   if geteuid().is_root() {
      let Some(account) = Account::lookup(&settings.user)? else {
         bail!(
            "no account {} to run the network process as, name one with --user",
            settings.user
         );
      };

      network.uid(account.uid).gid(account.gid);
   }

   let mut child = network.spawn().context("starting the network process")?;

   // The monitor must hold no copy of the network process's end, or it
   // would never see that process exit.
   drop(network);

   let signals = SignalPipe::install()?;
   let signal = reopen(signals.read_fd())?;

   let mut monitor = Monitor {
      key:             tls::signing_key(&private_from_openssh(&key_text)?)?,
      listen:          settings.listen,
      listener:        Some(listener),
      authorized_keys: settings.authorized_keys,
      grants:          HashMap::new(),
      sessions:        Arc::new(Mutex::new(HashMap::new())),
      holders:         holders()?,
      issued:          0,
   };

   println!("listening on udp {}", settings.listen);
   let ended = serve(&channel, &signal, |request| monitor.handle(request));

   monitor.hangup(None);

   if matches!(ended, Ok(Ended::Signal)) {
      child.kill()?;
      child.wait()?;
      return Ok(());
   }

   let status = child.wait()?;

   ended?;
   bail!("the network process stopped with {status}")
}
