//! The privileged process. It holds the host key, decides logins and starts
//! sessions, and it never parses anything a client sent directly.

use std::{
   collections::HashMap,
   env,
   fs::{
      self,
      DirBuilder,
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
            chown,
            fchown,
         },
         net::UnixListener,
         process::{
            CommandExt as _,
            ExitStatusExt as _,
         },
      },
   },
   path::PathBuf,
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

use eyre::{
   OptionExt as _,
   Result,
   WrapErr as _,
   bail,
   ensure,
   eyre,
};
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use rustix::{
   net::{
      AddressFamily,
      SocketFlags,
      SocketType,
      socketpair,
   },
   process::{
      Pid,
      Signal,
      geteuid,
      kill_process_group,
   },
   pty::{
      OpenptFlags,
      grantpt,
      ioctl_tiocgptpeer,
      openpt,
      unlockpt,
   },
   termios::tcsetwinsize,
};
use rustls::{
   SignatureScheme,
   sign::SigningKey,
};
use ssh_quic::{
   auth::{
      self,
      Account,
   },
   control::Open,
   key::private_from_openssh,
   tls,
   transport::udp_socket,
};

use crate::{
   privsep::{
      Reply,
      Request,
      serve,
   },
   session::winsize,
};

/// What a TLS 1.3 server signs in `CertificateVerify` (RFC 8446 section
/// 4.4.3), up to the transcript hash.
const TRANSCRIPT_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\0";
const TRANSCRIPT_PADDING: usize = 64;
const MAX_TRANSCRIPT_HASH: usize = 64;

pub struct Settings {
   pub listen:          SocketAddr,
   pub host_key:        PathBuf,
   pub authorized_keys: Option<PathBuf>,
   /// The account the network process runs as when the monitor is root.
   pub user:            String,
}

/// The directory and socket that reach a client's SSH agent. Dropping it
/// removes both.
struct AgentDirectory {
   directory: PathBuf,
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
   account: Account,
   agent:   Option<AgentDirectory>,
}

struct Monitor {
   key:             Arc<dyn SigningKey>,
   listen:          SocketAddr,
   listener:        Option<OwnedFd>,
   authorized_keys: Option<PathBuf>,
   grants:          HashMap<u64, Grant>,
   /// The process group of every session that has not exited.
   sessions:        Arc<Mutex<HashMap<u64, Pid>>>,
   issued:          u64,
}

impl Monitor {
   const fn issue(&mut self) -> u64 {
      self.issued += 1;
      self.issued
   }

   /// Signs only what a TLS 1.3 server signs, so the network process cannot
   /// get the host key's signature on anything else.
   fn sign(&self, message: &[u8]) -> Result<Reply> {
      let transcript = message
         .split_at_checked(TRANSCRIPT_PADDING)
         .filter(|(padding, _)| padding.iter().all(|&byte| byte == b' '))
         .and_then(|(_, rest)| rest.strip_prefix(TRANSCRIPT_CONTEXT));

      ensure!(
         transcript.is_some_and(|hash| hash.len() <= MAX_TRANSCRIPT_HASH),
         "refusing to sign something that is not a handshake transcript"
      );

      let signer = self
         .key
         .choose_scheme(&[SignatureScheme::ED25519])
         .ok_or_eyre("host key is not ed25519")?;

      Ok(Reply::Signature(signer.sign(message)?))
   }

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
   fn agent(&mut self, grant: u64) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get_mut(&grant).ok_or_eyre("unknown grant")?;
      ensure!(grant.agent.is_none(), "agent socket already exists");

      let mut random = [0; 8];
      SystemRandom::new()
         .fill(&mut random)
         .map_err(|_| eyre!("system random source failed"))?;

      let directory = env::temp_dir().join(format!("ssh-quic-{:016x}", u64::from_ne_bytes(random)));
      let socket = directory.join("agent.sock");

      DirBuilder::new()
         .mode(0o700)
         .create(&directory)
         .wrap_err_with(|| format!("creating {}", directory.display()))?;

      let created = grant.agent.insert(AgentDirectory { directory, socket });
      let listener = UnixListener::bind(&created.socket)?;

      if geteuid().is_root() {
         for owned in [&created.directory, &created.socket] {
            chown(owned, Some(grant.account.uid), Some(grant.account.gid))?;
         }
      }

      Ok((Reply::Done, vec![listener.into()]))
   }

   /// Starts a session for the grant's account. The account is made owner
   /// of the terminal device, because programs such as tmux open it by path.
   fn spawn(&mut self, grant: u64, open: &Open) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&grant).ok_or_eyre("unknown grant")?;

      let mut command = Command::new(env::current_exe()?);
      command.arg("--session").arg(&grant.account.name);

      if let Some(agent) = grant.agent.as_ref().filter(|_| open.agent) {
         command.arg("--agent-socket").arg(&agent.socket);
      }

      if let Some(text) = &open.command {
         command.arg("--command").arg(text);
      }

      let (mut child, mut descriptors) = if let Some(terminal) = &open.terminal {
         let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
         let master = openpt(flags).wrap_err("opening a terminal")?;
         grantpt(&master)?;
         unlockpt(&master)?;
         tcsetwinsize(&master, winsize(terminal.size))?;

         let slave = ioctl_tiocgptpeer(&master, flags)?;

         if geteuid().is_root() {
            fchown(&slave, Some(grant.account.uid), None)?;
         }

         command
            .arg("--term")
            .arg(&terminal.name)
            .stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave);

         let child = command.spawn().wrap_err("starting the session process")?;
         (child, vec![master])
      } else {
         command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

         let mut child = command.spawn().wrap_err("starting the session process")?;
         let input = child.stdin.take().ok_or_eyre("child has no stdin")?;
         let output = child.stdout.take().ok_or_eyre("child has no stdout")?;
         let errors = child.stderr.take().ok_or_eyre("child has no stderr")?;

         (child, vec![input.into(), output.into(), errors.into()])
      };

      // The monitor's copies of the terminal's child side live in `command`,
      // and the terminal reports end of output only once they are closed.
      drop(command);

      let (status, mut report) = io::pipe()?;
      descriptors.push(status.into());

      let session = self.issue();
      let sessions = Arc::clone(&self.sessions);

      sessions
         .lock()
         .map_err(|_| eyre!("a session thread died"))?
         .insert(session, Pid::from_child(&child));

      thread::spawn(move || {
         let code = child.wait().map_or(255, |status| {
            status
               .code()
               .or_else(|| status.signal().map(|signal| 128 + signal))
               .and_then(|code| u32::try_from(code).ok())
               .unwrap_or(255)
         });

         if let Ok(mut sessions) = sessions.lock() {
            sessions.remove(&session);
         }

         let _ = report.write_all(&code.to_be_bytes());
      });

      Ok((Reply::Spawned { session }, descriptors))
   }

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

   fn handle(&mut self, request: Request) -> Result<(Reply, Vec<OwnedFd>)> {
      let plain = |reply| Ok((reply, Vec::new()));

      match request {
         Request::Hello => {
            let listener = self
               .listener
               .take()
               .ok_or_eyre("socket already handed over")?;
            let key = self
               .key
               .public_key()
               .ok_or_eyre("host key has no public half")?;

            let reply = Reply::Hello {
               key:    key.to_vec(),
               listen: self.listen,
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
      }
   }
}

/// Starts the network process and serves it until it exits.
pub fn run(settings: Settings) -> Result<()> {
   let key_text = fs::read_to_string(&settings.host_key)
      .wrap_err_with(|| format!("reading host key {}", settings.host_key.display()))?;

   let listener = udp_socket(settings.listen, None)
      .wrap_err_with(|| format!("listening on {}", settings.listen))?;

   let (channel, remote) = socketpair(
      AddressFamily::UNIX,
      SocketType::SEQPACKET,
      SocketFlags::CLOEXEC,
      None,
   )?;

   let mut network = Command::new(env::current_exe()?);
   network.arg("--network").stdin(remote).env_clear();

   if geteuid().is_root() {
      let Some(account) = Account::lookup(&settings.user)? else {
         bail!(
            "no account {} to run the network process as, name one with --user",
            settings.user
         );
      };

      network.uid(account.uid).gid(account.gid);
   }

   let mut child = network.spawn().wrap_err("starting the network process")?;

   // The monitor must hold no copy of the network process's end, or it
   // would never see that process exit.
   drop(network);

   let mut monitor = Monitor {
      key:             tls::signing_key(&private_from_openssh(&key_text)?)?,
      listen:          settings.listen,
      listener:        Some(listener),
      authorized_keys: settings.authorized_keys,
      grants:          HashMap::new(),
      sessions:        Arc::new(Mutex::new(HashMap::new())),
      issued:          0,
   };

   println!("listening on udp {}", settings.listen);
   let served = serve(&channel, |request| monitor.handle(request));

   monitor.hangup(None);
   let status = child.wait()?;

   served?;
   bail!("the network process stopped with {status}")
}
