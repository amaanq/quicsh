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
   net::{
      IpAddr,
      SocketAddr,
   },
   os::{
      fd::OwnedFd,
      unix::{
         fs::{
            DirBuilderExt as _,
            FileTypeExt as _,
            OpenOptionsExt as _,
         },
         process::CommandExt as _,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   process::Command,
   sync::Arc,
   thread,
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use knell::signals::SignalPipe;
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
      Attempt,
      Permit,
   },
   control::{
      Open,
      Program,
      Token,
   },
   key::private_from_openssh,
   known_hosts::glob,
   pipe::reopen,
   tls::{
      self,
      HOST_SCHEMES,
   },
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
   process::geteuid,
};
use rustls::sign::SigningKey;

use crate::{
   child::SESSION_ENVIRONMENT,
   privsep::{
      Ended,
      Reply,
      Request,
      serve,
   },
};

/// Where distributions install OpenSSH's `sftp-server`.
const SFTP_SERVERS: [&str; 4] = [
   "/usr/lib/openssh/sftp-server",
   "/usr/libexec/openssh/sftp-server",
   "/usr/lib/ssh/sftp-server",
   "/usr/libexec/sftp-server",
];

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
   /// Program behind the `sftp` subsystem.
   pub sftp_server:     Option<PathBuf>,
   /// Patterns for the environment variables a client may set.
   pub accept_env:      Vec<String>,
   /// The account the network process runs as when the monitor is root.
   pub user:            String,
   /// Congestion controller the network process uses.
   pub congestion:      Congestion,
}

/// One successful login.
struct Grant {
   /// Who logged in.
   account: Account,
   /// What the key that logged in may do.
   permit:  Permit,
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
   /// Program behind the `sftp` subsystem.
   sftp_server:     Option<PathBuf>,
   /// Patterns for the environment variables a client may set.
   accept_env:      Vec<String>,
   /// Logins the network process may start sessions for.
   grants:          HashMap<u64, Grant>,
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
         .choose_scheme(&HOST_SCHEMES)
         .context("host key is of no usable type")?;

      Ok(Reply::Signature(signer.sign(message)?))
   }

   /// Checks a login against its signature and the authorized keys.
   fn login(
      &mut self,
      login: &auth::Request,
      exporter: &[u8; 32],
      remote: IpAddr,
   ) -> Result<Reply> {
      let Ok(presence) = login.verify(exporter) else {
         return Ok(Reply::Denied);
      };

      let Some(account) = Account::lookup(&login.user)? else {
         return Ok(Reply::Denied);
      };

      // An unprivileged monitor cannot switch users, so it serves only its
      // own.
      let monitor = geteuid();

      if !monitor.is_root() && monitor.as_raw() != account.uid {
         return Ok(Reply::Denied);
      }

      let keys_file = self.authorized_keys.as_deref();

      // A clock that cannot be read makes every `expiry-time` count as past.
      let attempt = Attempt {
         remote,
         presence,
         now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |since| since.as_secs()),
         certificate: login.certificate.as_deref(),
      };

      let Some(permit) = account.authorizes(&login.key, keys_file, &attempt)? else {
         return Ok(Reply::Denied);
      };

      // The network process opens and accepts forwards on ports. The ones
      // on Unix sockets are checked here.
      let reply = Reply::Granted {
         grant:      self.issue(),
         forwarding: permit.forwarding.clone(),
      };

      if let Reply::Granted { grant, .. } = reply {
         self.grants.insert(grant, Grant { account, permit });
      }

      Ok(reply)
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

   /// Tells a session or holder process what to run. A command that the
   /// key's line forces replaces the client's, which the session finds in
   /// `SSH_ORIGINAL_COMMAND`.
   fn program(&self, grant: &Grant, open: &Open, command: &mut Command) -> Result<()> {
      let asked = self.command(&open.program)?;

      if let Some(ref forced) = grant.permit.command {
         command.arg("--command").arg(forced);

         if let Some(text) = asked {
            command.arg("--original-command").arg(text);
         }
      } else if let Some(text) = asked {
         command.arg("--command").arg(text);
      }

      Ok(())
   }

   /// The command line the client asked for, or `None` for the shell alone.
   fn command(&self, program: &Program) -> Result<Option<String>> {
      Ok(match *program {
         Program::Shell => None,
         Program::Command(ref line) => Some(line.clone()),
         Program::Subsystem(ref name) => {
            ensure!(name == "sftp", "no subsystem named {name}");

            let server = self
               .sftp_server
               .as_deref()
               .or_else(|| {
                  SFTP_SERVERS
                     .iter()
                     .map(Path::new)
                     .find(|path| path.exists())
               })
               .context("no sftp-server found, name one with --sftp-server")?;

            Some(
               server
                  .to_str()
                  .context("sftp-server path is not UTF-8")?
                  .to_owned(),
            )
         },
      })
   }

   /// Starts a holder process with a session for the grant's account. The
   /// holder listens on a socket made here, since it gives up root and could
   /// not make one in a directory only root can enter.
   fn spawn(&self, id: u64, open: &Open) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&id).context("unknown grant")?;
      ensure!(
         open.terminal.is_none() || grant.permit.terminal,
         "this key may not open a terminal"
      );

      sweep(&self.holders);

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
      command.arg("hold").arg(&grant.account.name);

      if let Some(ref terminal) = open.terminal {
         command
            .arg("--term")
            .arg(&terminal.name)
            .arg("--columns")
            .arg(terminal.size.columns.to_string())
            .arg("--rows")
            .arg(terminal.size.rows.to_string());
      }

      if open.agent && grant.permit.agent {
         command.arg("--agent");
      }

      self.program(grant, open, &mut command)?;

      for pair in &open.environment {
         let (name, value) = (&pair.0, &pair.1);

         let wellformed = name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && !name.starts_with(|first: char| first.is_ascii_digit())
            && !name.is_empty()
            && !value.contains('\0');

         let accepted = self
            .accept_env
            .iter()
            .any(|pattern| glob(pattern.as_bytes(), name.as_bytes()));

         if wellformed && accepted {
            command.env(format!("{SESSION_ENVIRONMENT}{name}"), value);
         }
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

   /// Starts a process that opens a Unix socket as the grant's account, and
   /// answers with the socket pair it passes the socket on.
   fn reach(&self, id: u64, path: &str, listening: bool) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&id).context("unknown grant")?;
      let forwarding = &grant.permit.forwarding;

      let permitted = if listening {
         forwarding.permits_bind()
      } else {
         forwarding.permits_reach()
      };

      ensure!(permitted, "this key may not forward that socket");

      let (near, far) = socketpair(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      let mut command = Command::new(env::current_exe()?);
      command
         .arg("reach")
         .arg(&grant.account.name)
         .arg(format!("--path={path}"));

      if listening {
         command.arg("--listen");
      }

      let mut child = command
         .stdin(far)
         .spawn()
         .context("starting the socket process")?;

      thread::spawn(move || {
         let _ = child.wait();
      });

      Ok((Reply::Done, vec![near]))
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
         Request::Login {
            login,
            exporter,
            remote,
         } => plain(self.login(&login, &exporter, remote.ip().to_canonical())?),
         Request::Spawn { grant, open } => self.spawn(grant, &open),
         Request::Logout { grant } => {
            self.grants.remove(&grant);
            plain(Reply::Done)
         },
         Request::Attach { grant, token } => self.attach(grant, token),
         Request::Reach {
            grant,
            path,
            listen,
         } => self.reach(grant, &path, listen),
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

   sweep(&directory);

   Ok(directory)
}

/// Removes the sockets of holders that are gone. A holder started by an
/// earlier monitor has nobody waiting for it, and connecting to find out
/// whether it lives would take a running session from its client, so the
/// kernel's list of bound sockets decides.
fn sweep(directory: &Path) {
   let (Ok(bound), Ok(entries)) = (
      fs::read_to_string("/proc/net/unix"),
      fs::read_dir(directory),
   ) else {
      return;
   };

   for entry in entries.filter_map(io::Result::ok) {
      let path = entry.path();
      let socket = entry.file_type().is_ok_and(|kind| kind.is_socket());
      let live = path
         .to_str()
         .is_none_or(|name| bound.lines().any(|line| line.ends_with(name)));

      if socket && !live {
         let _ = fs::remove_file(path);
      }
   }
}

/// Starts the network process and serves it until it exits.
pub fn run(settings: Settings) -> Result<()> {
   let key_text = fs::read_to_string(&settings.host_key)
      .with_context(|| format!("reading host key {}", settings.host_key.display()))?;
   let key = tls::signing_key(&private_from_openssh(&key_text)?)
      .with_context(|| format!("loading host key {}", settings.host_key.display()))?;

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
      key,
      listen: settings.listen,
      listener: Some(listener),
      authorized_keys: settings.authorized_keys,
      sftp_server: settings.sftp_server,
      accept_env: settings.accept_env,
      grants: HashMap::new(),
      holders: holders()?,
      issued: 0,
   };

   println!("listening on udp {}", settings.listen);
   let ended = serve(&channel, &signal, |request| monitor.handle(request));

   if matches!(ended, Ok(Ended::Signal)) {
      child.kill()?;
      child.wait()?;
      return Ok(());
   }

   let status = child.wait()?;

   ended?;
   bail!("the network process stopped with {status}")
}
