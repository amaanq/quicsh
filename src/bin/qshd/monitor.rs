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
   mem,
   net::{
      IpAddr,
      SocketAddr,
   },
   os::{
      fd::{
         AsFd as _,
         BorrowedFd,
         OwnedFd,
      },
      unix::{
         fs::{
            DirBuilderExt as _,
            FileTypeExt as _,
            OpenOptionsExt as _,
            symlink,
         },
         process::CommandExt as _,
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
   },
   sync::Arc,
   thread,
   time::{
      Duration,
      Instant,
      SystemTime,
      UNIX_EPOCH,
   },
};

use knell::signals::{
   SignalPipe,
   shutdown_requested,
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
      Attempt,
      Permit,
   },
   certificate::Certificate,
   control::{
      DETACH_LIMIT,
      Open,
      Program,
      Token,
      nameable,
   },
   key::{
      PublicKey,
      private_from_openssh,
   },
   known_hosts::glob,
   pipe::{
      receive_message,
      reopen,
      send_message,
   },
   tls::{
      self,
      HOST_SCHEMES,
   },
   transport::{
      Congestion,
      udp_socket,
   },
};
use ring::{
   hmac,
   rand::{
      SecureRandom as _,
      SystemRandom,
   },
};
use rustix::{
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   net::{
      AddressFamily,
      SocketAddrUnix,
      SocketFlags,
      SocketType,
      accept,
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
      kill_process,
   },
   time::Timespec,
};
use rustls::sign::SigningKey;

use crate::{
   child::SESSION_ENVIRONMENT,
   privsep::{
      Ended,
      Reply,
      Request,
      finish,
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

/// Most logins PAM decides at a time.
const MAX_CONVERSATIONS: usize = 64;
/// How long a PAM process may take to exit once it is done asking.
const CONCLUDE_LIMIT: Duration = Duration::from_secs(2);

/// Most terminal sessions one account has at a time.
const MAX_KEPT: usize = 64;

/// File in the holders directory with the keys a restarted server shares
/// with the old one. It sits on a runtime directory, so a reboot replaces it.
const RESTART_SECRET: &str = "restart-secret";
/// File in the holders directory with the key that signs login tickets.
/// The network process gets the restart secret and never this one.
const TICKET_SECRET: &str = "ticket-secret";
/// How long a ticket logs its account in, which is as long as a session
/// waits for its client.
const TICKET_LIFE: Duration = DETACH_LIMIT;
/// How long after its password was typed a login still gets tickets and
/// its tickets still log in. Renewing a ticket does not move that time.
const TICKET_SPAN: Duration = Duration::from_hours(24);
/// Bytes in the signature that ends a ticket.
const TICKET_TAG: usize = 32;
/// Socket in the holders directory of the process that keeps forwarded
/// connections for the next server.
const KEPT: &str = "forwards";
/// Most messages a keeper takes.
const KEPT_MESSAGES: usize = 1 << 16;
/// Most bytes a keeper takes.
const KEPT_BYTES: usize = 256 << 20;
/// Most bytes in one message to a keeper.
const KEPT_MESSAGE: usize = 1 << 16;
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
   pub listen:           SocketAddr,
   /// Path of the host private key.
   pub host_key:         PathBuf,
   /// Path of the host certificate.
   pub host_certificate: Option<PathBuf>,
   /// Files that replace every account's own `authorized_keys`.
   pub authorized_keys:  Vec<PathBuf>,
   /// File of the authorities whose certificates let an account in.
   pub authorities:      Option<PathBuf>,
   /// The PAM service that checks passwords.
   pub pam:              Option<String>,
   /// Program behind the `sftp` subsystem.
   pub sftp_server:      Option<PathBuf>,
   /// Patterns for the environment variables a client may set.
   pub accept_env:       Vec<String>,
   /// The account the network process runs as when the monitor is root.
   pub user:             String,
   /// Congestion controller the network process uses.
   pub congestion:       Congestion,
}

/// One successful login.
struct Grant {
   /// Who logged in.
   account: Account,
   /// What the key that logged in may do.
   permit:  Permit,
   /// When the password behind the login was typed, in seconds since
   /// 1970. A login by key has none and gets no tickets.
   typed:   Option<u64>,
}

/// State of the privileged process.
struct Monitor {
   /// The host key.
   key:             Arc<dyn SigningKey>,
   /// The host certificate, empty without one.
   certificate:     Vec<u8>,
   /// Address the server listens on.
   listen:          SocketAddr,
   /// The listening socket, until the network process takes it.
   listener:        Option<OwnedFd>,
   /// Files that replace every account's own `authorized_keys`.
   authorized_keys: Vec<PathBuf>,
   /// File of the authorities whose certificates let an account in.
   authorities:     Option<PathBuf>,
   /// The PAM service that checks passwords, and `None` when only keys log
   /// in.
   pam:             Option<String>,
   /// The processes that ask PAM about a login, each with the name it asks
   /// about.
   conversations:   HashMap<u64, (Child, String)>,
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
   /// The user and group the network process runs as, when this process
   /// is root.
   unprivileged:    Option<(u32, u32)>,
   /// Whether a keeper of forwarded connections was started.
   kept:            bool,
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

      let attempt = Attempt {
         remote,
         presence,
         now: clock(),
         certificate: login.certificate.as_deref(),
      };

      let listed = account.authorizes(&login.key, &self.authorized_keys, &attempt)?;

      let trusted = match self.authorities {
         Some(ref authorities) if listed.is_none() => {
            account.certified(&login.key, authorities, &attempt)?
         },
         Some(_) | None => listed,
      };

      let Some(permit) = trusted else {
         return Ok(Reply::Denied);
      };

      Ok(self.grant(account, permit, None))
   }

   /// Records a login that passed.
   fn grant(&mut self, account: Account, permit: Permit, typed: Option<u64>) -> Reply {
      // The network process opens and accepts forwards on ports. The ones
      // on Unix sockets are checked here.
      let reply = Reply::Granted {
         grant:      self.issue(),
         forwarding: permit.forwarding.clone(),
      };

      if let Reply::Granted { grant, .. } = reply {
         self.grants.insert(grant, Grant {
            account,
            permit,
            typed,
         });
      }

      reply
   }

   /// Starts a process that asks PAM whether `user` logs in, and answers
   /// with the socket it asks on.
   fn converse(&mut self, user: String, remote: IpAddr) -> Result<(Reply, Vec<OwnedFd>)> {
      let Some(ref service) = self.pam else {
         return Ok((Reply::Denied, Vec::new()));
      };

      if self.conversations.len() >= MAX_CONVERSATIONS {
         return Ok((Reply::Denied, Vec::new()));
      }

      let (near, far) = socketpair(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      // PAM modules run in that process, so none of their code is ever
      // part of this one.
      let child = Command::new(env::current_exe()?)
         .arg("ask")
         .arg(service)
         .arg(format!("--user={user}"))
         .arg(format!("--remote={remote}"))
         .stdin(far)
         .env_clear()
         .spawn()
         .context("starting the PAM process")?;

      let conversation = self.issue();
      self.conversations.insert(conversation, (child, user));

      Ok((Reply::Asking(conversation), vec![near]))
   }

   /// Ends a PAM process. A login that it allowed and that is still
   /// `wanted` passes for every account but root.
   fn conclude(&mut self, conversation: u64, wanted: bool) -> Result<Reply> {
      let Some((mut child, user)) = self.conversations.remove(&conversation) else {
         return Ok(Reply::Denied);
      };

      let limit = Instant::now() + CONCLUDE_LIMIT;

      let allowed = loop {
         match child.try_wait()? {
            Some(status) => break status.success(),
            None if wanted && Instant::now() < limit => thread::sleep(Duration::from_millis(2)),
            None => {
               let _ = child.kill();
               thread::spawn(move || child.wait());
               break false;
            },
         }
      };

      if !(allowed && wanted) {
         return Ok(Reply::Denied);
      }

      self.admit(&user, clock())
   }

   /// Logs in an account that a password or a ticket vouched for, unless
   /// it is root. The password was typed at `typed`.
   fn admit(&mut self, user: &str, typed: u64) -> Result<Reply> {
      let Some(account) = Account::lookup(user)? else {
         return Ok(Reply::Denied);
      };

      let monitor = geteuid();

      if account.uid == 0 || (!monitor.is_root() && monitor.as_raw() != account.uid) {
         return Ok(Reply::Denied);
      }

      Ok(self.grant(account, Permit::whole(), Some(typed)))
   }

   /// A ticket for the account of a login that gets them. It holds when it
   /// ends, when the password was typed, the account's name and a
   /// signature over the three.
   fn ticket(&self, grant: u64) -> Result<Reply> {
      let held = self.grants.get(&grant).context("unknown grant")?;
      let typed = held.typed.context("a login by key gets no ticket")?;
      let last = typed.saturating_add(TICKET_SPAN.as_secs());
      ensure!(clock() < last, "the password was typed too long ago");

      let ends = clock().saturating_add(TICKET_LIFE.as_secs()).min(last);
      let mut ticket = ends.to_be_bytes().to_vec();
      ticket.extend_from_slice(&typed.to_be_bytes());
      ticket.extend_from_slice(held.account.name.as_bytes());

      let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret(TICKET_SECRET)?);
      let tag = hmac::sign(&key, &ticket);
      ticket.extend_from_slice(tag.as_ref());

      Ok(Reply::Ticket(ticket))
   }

   /// Logs in the account that a ticket of this server names, while the
   /// ticket holds.
   fn redeem(&mut self, user: &str, ticket: &[u8]) -> Result<Reply> {
      let parts = ticket
         .len()
         .checked_sub(TICKET_TAG)
         .and_then(|length| ticket.split_at_checked(length))
         .and_then(|(body, tag)| Some((body.split_first_chunk::<16>()?, body, tag)));

      let Some(((times, named), body, tag)) = parts else {
         return Ok(Reply::Denied);
      };

      let (ends, typed) = times.split_at(8);
      let seconds = |bytes: &[u8]| bytes.try_into().map_or(0, u64::from_be_bytes);
      let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret(TICKET_SECRET)?);

      let holds = hmac::verify(&key, body, tag).is_ok()
         && named == user.as_bytes()
         && seconds(ends) > clock();

      if !holds {
         return Ok(Reply::Denied);
      }

      self.admit(user, seconds(typed))
   }

   /// Where the socket of the holder for `token` and `uid` lives. The uid in
   /// the name keeps one account from taking another's session.
   fn holder_path(&self, uid: u32, token: Token) -> PathBuf {
      let name = token
         .iter()
         .fold(format!("{uid}-"), |name, byte| format!("{name}{byte:02x}"));

      self.holders.join(name)
   }

   /// Where the name of an account's terminal session lives, a link to the
   /// socket of its holder.
   fn named_path(&self, uid: u32, name: &str) -> PathBuf {
      self.holders.join(format!("{uid}-n-{name}"))
   }

   /// The token and the holder of the terminal session that `uid` has under
   /// `name`. A name whose session is over is forgotten.
   fn find(&self, uid: u32, name: &str) -> Option<(Token, OwnedFd)> {
      let link = self.named_path(uid, name);
      let target = nameable(name)
         .then(|| fs::read_link(&link).ok())
         .flatten()?;

      let mut token = Token::default();
      let digits = target.to_str()?.strip_prefix(&format!("{uid}-"))?;
      let wellformed = digits.len() == token.len() * 2 && digits.is_ascii();

      for (byte, pair) in token.iter_mut().zip(digits.as_bytes().chunks(2)) {
         *byte = u8::from_str_radix(str::from_utf8(pair).ok()?, 16).ok()?;
      }

      let holder = wellformed
         .then(|| Self::holder(&self.holder_path(uid, token)).ok())
         .flatten();

      if holder.is_none() {
         let _ = fs::remove_file(link);
      }

      Some((token, holder?))
   }

   /// The names of the terminal sessions `uid` has.
   fn names(&self, uid: u32) -> Vec<String> {
      sweep(&self.holders);

      let prefix = format!("{uid}-n-");

      let mut names = fs::read_dir(&self.holders)
         .into_iter()
         .flatten()
         .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
         .filter_map(|file| Some(file.strip_prefix(&prefix)?.to_owned()))
         .collect::<Vec<String>>();

      names.sort_by_key(|name| (name.parse::<u64>().unwrap_or(u64::MAX), name.clone()));
      names
   }

   /// The name for a new terminal session of `uid`, which is `wanted` or
   /// else the lowest number no session has.
   fn name(&self, uid: u32, wanted: Option<&str>) -> Result<String> {
      let taken = self.names(uid);
      ensure!(
         taken.len() < MAX_KEPT,
         "the account has {MAX_KEPT} terminal sessions, end one first"
      );

      let free = (1..=MAX_KEPT)
         .map(|number| number.to_string())
         .find(|name| !taken.contains(name));

      match wanted {
         Some(name) if nameable(name) => Ok(name.to_owned()),
         Some(_) => bail!("a session name is 1 to 64 letters, digits, dots, dashes or underscores"),
         None => free.context("no session name is free"),
      }
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

   /// Tells a holder where its client is, in sshd's `SSH_CLIENT` and
   /// `SSH_CONNECTION`.
   fn origin(&self, command: &mut Command, remote: SocketAddr, local: Option<IpAddr>) {
      let (client, port) = (remote.ip().to_canonical(), self.listen.port());
      let server = local.unwrap_or_else(|| self.listen.ip()).to_canonical();

      command
         .env(
            format!("{SESSION_ENVIRONMENT}SSH_CLIENT"),
            format!("{client} {} {port}", remote.port()),
         )
         .env(
            format!("{SESSION_ENVIRONMENT}SSH_CONNECTION"),
            format!("{client} {} {server} {port}", remote.port()),
         );
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
   fn spawn(
      &self,
      id: u64,
      open: &Open,
      remote: SocketAddr,
      local: Option<IpAddr>,
   ) -> Result<(Reply, Vec<OwnedFd>)> {
      let grant = self.grants.get(&id).context("unknown grant")?;
      ensure!(
         open.terminal.is_none() || grant.permit.terminal,
         "this key may not open a terminal"
      );

      sweep(&self.holders);

      let uid = grant.account.uid;

      let label = match (&open.terminal, open.name.as_deref()) {
         (&None, None) => None,
         (&None, Some(_)) => bail!("only a terminal session has a name"),
         (&Some(_), wanted) => {
            if let Some((token, link)) = wanted.and_then(|asked| self.find(uid, asked)) {
               let reply = Reply::Held {
                  token,
                  name: wanted.unwrap_or_default().to_owned(),
                  old: true,
               };

               return Ok((reply, vec![link]));
            }

            Some(self.name(uid, wanted)?)
         },
      };

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

      if let Some(limit) = open.patience {
         command.arg("--patience").arg(limit.as_secs().to_string());
      }

      self.program(grant, open, &mut command)?;

      if let Some(ref chosen) = label {
         command.env(format!("{SESSION_ENVIRONMENT}QSH_SESSION"), chosen);
      }

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

      // After the client's own, as sshd sets them, so SetEnv cannot forge
      // where a session came from.
      self.origin(&mut command, remote, local);

      let mut child = command
         .stdin(listener)
         .spawn()
         .context("starting the session holder")?;

      let alias = label.as_deref().map(|chosen| self.named_path(uid, chosen));

      if let (Some(link), Some(socket)) = (alias.as_ref(), path.file_name()) {
         symlink(socket, link).with_context(|| format!("naming {}", link.display()))?;
      }

      // The holder outlives this process on purpose. While both run, it is
      // reaped here.
      thread::spawn(move || {
         let _ = child.wait();
         let _ = fs::remove_file(path);
         let _ = alias.map(fs::remove_file);
      });

      let link = Self::holder(&self.holder_path(uid, token))?;

      let reply = Reply::Held {
         token,
         name: label.unwrap_or_default(),
         old: false,
      };

      Ok((reply, vec![link]))
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

   /// Reads one of the secrets that outlast a restart, making it when this
   /// boot has none yet.
   fn secret(&self, name: &str) -> Result<Vec<u8>> {
      let path = self.holders.join(name);
      let whole = || {
         fs::read(&path)
            .ok()
            .filter(|secret| secret.len() == RESTART_SECRET_LEN)
      };

      if let Some(secret) = whole() {
         return Ok(secret);
      }

      let mut secret = vec![0; RESTART_SECRET_LEN];
      SystemRandom::new()
         .fill(&mut secret)
         .map_err(|_| report!("system random source failed"))?;

      let draft = self.holders.join(format!("{name}.{}", process::id()));

      OpenOptions::new()
         .write(true)
         .create_new(true)
         .mode(0o600)
         .open(&draft)
         .and_then(|mut file| file.write_all(&secret))
         .with_context(|| format!("writing {}", draft.display()))?;

      // A link appears whole or not at all, so a server that starts at the
      // same moment either reads this secret or wins with its own.
      let chosen = match (fs::hard_link(&draft, &path), whole()) {
         (Ok(()), _) | (Err(_), None) => {
            fs::rename(&draft, &path).with_context(|| format!("writing {}", path.display()))?;
            secret
         },
         (Err(_), Some(other)) => other,
      };

      let _ = fs::remove_file(&draft);
      Ok(chosen)
   }

   /// Starts a process that keeps what the network process hands it until
   /// the next server asks for it, and answers with the link to it.
   fn keeper(&mut self) -> Result<(Reply, Vec<OwnedFd>)> {
      // A network process that a client took over gets one keeper, at the
      // end, and that keeper has no more rights than it has itself.
      ensure!(
         shutdown_requested() && !mem::replace(&mut self.kept, true),
         "the server is not stopping"
      );

      let path = self.holders.join(KEPT);
      let _ = fs::remove_file(&path);

      let listener = socket_with(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      bind(&listener, &SocketAddrUnix::new(&path)?)
         .with_context(|| format!("binding {}", path.display()))?;
      listen(&listener, 1)?;

      let (link, remote) = socketpair(
         AddressFamily::UNIX,
         SocketType::SEQPACKET,
         SocketFlags::CLOEXEC,
         None,
      )?;

      let mut command = Command::new(env::current_exe()?);
      command
         .arg("keep")
         .stdin(remote)
         .stdout(listener)
         .env_clear()
         .process_group(0);

      if let Some((uid, gid)) = self.unprivileged {
         command.uid(uid).gid(gid);
      }

      let mut child = command.spawn().context("starting the keeper of forwards")?;

      // The keeper outlives this process on purpose.
      thread::spawn(move || child.wait());

      Ok((Reply::Done, vec![link]))
   }

   /// Connects to the process an earlier server left its forwarded
   /// connections with.
   fn kept(&self) -> (Reply, Vec<OwnedFd>) {
      let path = self.holders.join(KEPT);
      let link = Self::holder(&path);
      let _ = fs::remove_file(&path);

      link.map_or_else(
         |_| (Reply::Denied, Vec::new()),
         |keeper| (Reply::Done, vec![keeper]),
      )
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
         |link| {
            let reply = Reply::Held {
               token,
               name: String::new(),
               old: true,
            };

            (reply, vec![link])
         },
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
               key:         key.to_vec(),
               listen:      self.listen,
               secret:      self.secret(RESTART_SECRET)?,
               certificate: self.certificate.clone(),
            };

            Ok((reply, vec![listener]))
         },
         Request::Sign(message) => plain(self.sign(&message)?),
         Request::Keep => self.keeper(),
         Request::Converse { user, remote } => self.converse(user, remote.ip().to_canonical()),
         Request::Conclude {
            conversation,
            wanted,
         } => plain(self.conclude(conversation, wanted)?),
         Request::Redeem { user, ticket } => plain(self.redeem(&user, &ticket)?),
         Request::Ticket { grant } => plain(self.ticket(grant)?),
         Request::Kept => Ok(self.kept()),
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
         Request::Spawn {
            grant,
            open,
            remote,
            local,
         } => self.spawn(grant, &open, remote, local),
         Request::Logout { grant } => {
            self.grants.remove(&grant);
            plain(Reply::Done)
         },
         Request::Attach { grant, token } => self.attach(grant, token),
         Request::Names { grant } => {
            let uid = self
               .grants
               .get(&grant)
               .context("unknown grant")?
               .account
               .uid;
            plain(Reply::Named(self.names(uid)))
         },
         Request::Find { grant, name } => {
            let uid = self
               .grants
               .get(&grant)
               .context("unknown grant")?
               .account
               .uid;

            Ok(match self.find(uid, &name) {
               Some((token, link)) => {
                  let reply = Reply::Held {
                     token,
                     name,
                     old: true,
                  };

                  (reply, vec![link])
               },
               None => (Reply::Denied, Vec::new()),
            })
         },
         Request::Reach {
            grant,
            path,
            listen,
         } => self.reach(grant, &path, listen),
      }
   }
}

/// Seconds since 1970. A clock that cannot be read makes every ticket and
/// every `expiry-time` count as past.
fn clock() -> u64 {
   SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(u64::MAX, |since| since.as_secs())
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

   let mut names = Vec::new();

   for entry in entries.filter_map(io::Result::ok) {
      let path = entry.path();
      let socket = entry.file_type().is_ok_and(|kind| kind.is_socket());
      let live = path
         .to_str()
         .is_none_or(|name| bound.lines().any(|line| line.ends_with(name)));

      if socket && !live {
         let _ = fs::remove_file(path);
      } else if !socket {
         names.push(path);
      }
   }

   // A session's name is a link to its holder's socket.
   for name in names {
      if name.is_symlink() && !name.exists() {
         let _ = fs::remove_file(name);
      }
   }
}

/// Takes what a network process that stops hands over on standard input,
/// and gives it to the first process that connects to the socket on
/// standard output. Nobody else can connect, since only the server's user
/// can enter the socket's directory.
pub fn keep() -> Result<()> {
   let link = io::stdin().as_fd().try_clone_to_owned()?;
   let listener = io::stdout().as_fd().try_clone_to_owned()?;

   let mut kept = Vec::new();
   let mut size = 0;

   while let Some(message) = receive_message(&link, KEPT_MESSAGE)? {
      size += message.0.len();
      ensure!(
         kept.len() < KEPT_MESSAGES && size <= KEPT_BYTES,
         "more forwarded connections than one process keeps"
      );

      kept.push(message);
   }

   let wait = Timespec {
      tv_sec:  i64::try_from(DETACH_LIMIT.as_secs()).unwrap_or(i64::MAX),
      tv_nsec: 0,
   };

   if kept.is_empty() || poll(&mut [PollFd::new(&listener, PollFlags::IN)], Some(&wait))? == 0 {
      return Ok(());
   }

   let taker = accept(&listener)?;

   for message in &kept {
      let borrowed = message
         .1
         .iter()
         .map(OwnedFd::as_fd)
         .collect::<Vec<BorrowedFd>>();

      send_message(&taker, &message.0, &borrowed)?;
   }

   Ok(())
}

/// Starts the network process and serves it until it exits.
pub fn run(settings: Settings) -> Result<()> {
   let key_text = fs::read_to_string(&settings.host_key)
      .with_context(|| format!("reading host key {}", settings.host_key.display()))?;
   let key = tls::signing_key(&private_from_openssh(&key_text)?)
      .with_context(|| format!("loading host key {}", settings.host_key.display()))?;

   let certificate = match settings.host_certificate {
      Some(ref path) => {
         let about = fs::read_to_string(path)
            .with_context(|| format!("reading host certificate {}", path.display()))?
            .parse::<Certificate>()
            .with_context(|| format!("loading host certificate {}", path.display()))?;

         let public = key.public_key().context("host key has no public half")?;
         ensure!(
            *about.key() == PublicKey::from_spki(&public)?,
            "the host certificate {} is about another key",
            path.display()
         );

         about.to_blob().to_vec()
      },
      None => Vec::new(),
   };

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

   let unprivileged = if geteuid().is_root() {
      let Some(account) = Account::lookup(&settings.user)? else {
         bail!(
            "no account {} to run the network process as, name one with --user",
            settings.user
         );
      };

      network.uid(account.uid).gid(account.gid);
      Some((account.uid, account.gid))
   } else {
      None
   };

   let mut child = network.spawn().context("starting the network process")?;

   // The monitor must hold no copy of the network process's end, or it
   // would never see that process exit.
   drop(network);

   let signals = SignalPipe::install()?;
   let signal = reopen(signals.read_fd())?;

   let mut monitor = Monitor {
      key,
      certificate,
      listen: settings.listen,
      listener: Some(listener),
      authorized_keys: settings.authorized_keys,
      authorities: settings.authorities,
      pam: settings.pam,
      conversations: HashMap::new(),
      sftp_server: settings.sftp_server,
      accept_env: settings.accept_env,
      grants: HashMap::new(),
      holders: holders()?,
      issued: 0,
      unprivileged,
      kept: false,
   };

   println!("listening on udp {}", settings.listen);
   let ended = serve(&channel, &signal, |request| monitor.handle(request));

   // The network process hands its forwarded connections to a keeper
   // before it exits.
   if matches!(ended, Ok(Ended::Signal)) {
      if let Some(process) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
         let _ = kill_process(process, Signal::TERM);
      }

      let _ = finish(&channel, |request| monitor.handle(request));
      child.kill()?;
      child.wait()?;
      return Ok(());
   }

   let status = child.wait()?;

   ended?;
   bail!("the network process stopped with {status}")
}
