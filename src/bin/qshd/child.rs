//! The process the server starts for each session, as the user it runs as.
//!
//! Taking a controlling terminal and switching user must happen in the
//! process that becomes the shell. The server therefore starts its own binary
//! in this mode, which does both and then replaces itself with the shell.

use std::{
   convert::Infallible,
   env,
   io,
   os::{
      fd::AsFd as _,
      unix::process::{
         CommandExt as _,
         ExitStatusExt as _,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   process::{
      Command,
      ExitStatus,
   },
   time::Duration,
};

use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   bail,
};
use quicsh::{
   auth::Account,
   forward::Bound,
   pipe::send_message,
};
use rustix::{
   net::{
      AddressFamily,
      RecvFlags,
      SocketAddrUnix,
      SocketFlags,
      SocketType,
      connect,
      recv,
      socket_with,
      sockopt::{
         Timeout,
         set_socket_timeout,
      },
   },
   process::{
      Gid,
      Signal,
      Uid,
      geteuid,
      ioctl_tiocsctty,
      set_parent_process_death_signal,
      setsid,
   },
   thread::{
      set_thread_gid,
      set_thread_groups,
      set_thread_uid,
   },
};

/// `PATH` for sessions when the server has none.
const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Gives up root for `account`. An unprivileged server can only be the
/// account already.
pub fn become_account(account: &Account) -> Result<()> {
   if geteuid().is_root() {
      let groups = account
         .groups()?
         .into_iter()
         .map(Gid::from_raw)
         .collect::<Vec<Gid>>();

      // Groups and gid go first, because dropping the uid removes the
      // right to change them.
      set_thread_groups(&groups).context("setting groups")?;
      set_thread_gid(Gid::from_raw(account.gid)).context("setting gid")?;
      set_thread_uid(Uid::from_raw(account.uid)).context("setting uid")?;
   } else if geteuid().as_raw() != account.uid {
      bail!(
         "an unprivileged server cannot run sessions for {}",
         account.name
      );
   }

   Ok(())
}

/// The status a shell would report for a process that ended this way.
pub fn exit_code(status: ExitStatus) -> u32 {
   status
      .code()
      .or_else(|| status.signal().map(|signal| 128 + signal))
      .and_then(|code| u32::try_from(code).ok())
      .unwrap_or(255)
}

/// How long a connection to a forwarded Unix socket may take. Without a
/// limit, a socket that never accepts would hold a process for good.
const REACH_TIMEOUT: Duration = Duration::from_secs(10);

/// A Unix socket to forward, which only the account can open.
pub struct Reach {
   /// Account that reaches the socket.
   pub user:   String,
   /// Where the socket is, from the account's home when relative.
   pub path:   PathBuf,
   /// Whether to listen there.
   pub listen: bool,
}

impl Reach {
   /// Becomes the account, opens the socket and passes it to the network
   /// process on standard input. A listener's file is removed once the
   /// network process closes its side.
   pub fn run(&self) -> Result<()> {
      let account = Account::lookup(&self.user)?.context("account vanished after login")?;
      let link = io::stdin().as_fd().try_clone_to_owned()?;

      become_account(&account)?;

      if self.path.is_relative() {
         env::set_current_dir(&account.home)
            .with_context(|| format!("entering {}", account.home.display()))?;
      }

      if self.listen {
         let (bound, listener) = Bound::listen(&self.path)
            .with_context(|| format!("listening on {}", self.path.display()))?;

         send_message(&link, &[0], &[listener.as_fd()])?;
         drop(listener);

         let _ = recv(&link, &mut [0_u8; 1], RecvFlags::empty());
         drop(bound);
      } else {
         let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
         )?;

         set_socket_timeout(&socket, Timeout::Send, Some(REACH_TIMEOUT))?;
         connect(&socket, &SocketAddrUnix::new(&self.path)?)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
         set_socket_timeout(&socket, Timeout::Send, None)?;

         send_message(&link, &[0], &[socket.as_fd()])?;
      }

      Ok(())
   }
}

/// What one session process runs.
pub struct Launch {
   /// Account the session runs as.
   pub user:     String,
   /// The client's `TERM`, present when standard input is a terminal to adopt.
   pub terminal: Option<String>,
   /// The command, or `None` for a login shell.
   pub command:  Option<String>,
   /// What the client asked for when the key forces another command.
   pub original: Option<String>,
   /// Where the session finds the client's forwarded SSH agent.
   pub agent:    Option<PathBuf>,
}

impl Launch {
   /// Becomes the account and replaces this process with its shell.
   pub fn run(&self) -> Result<Infallible> {
      let account = Account::lookup(&self.user)?.context("account vanished after login")?;

      setsid().context("starting a session")?;

      if self.terminal.is_some() {
         ioctl_tiocsctty(io::stdin()).context("taking the controlling terminal")?;
      }

      become_account(&account)?;

      // The kernel clears this setting when the uid changes, so it comes
      // after the switch. A monitor that dies can hang nothing up itself.
      set_parent_process_death_signal(Some(Signal::HUP))?;

      let mut shell = Command::new(&account.shell);

      shell
         .env_clear()
         .env("HOME", &account.home)
         .env("USER", &account.name)
         .env("LOGNAME", &account.name)
         .env("SHELL", &account.shell)
         .env(
            "PATH",
            env::var_os("PATH").unwrap_or_else(|| FALLBACK_PATH.into()),
         )
         .current_dir(if account.home.is_dir() {
            &account.home
         } else {
            Path::new("/")
         });

      if let Some(ref terminal) = self.terminal {
         shell.env("TERM", terminal);
      }

      if let Some(ref agent) = self.agent {
         shell.env("SSH_AUTH_SOCK", agent);
      }

      if let Some(ref original) = self.original {
         shell.env("SSH_ORIGINAL_COMMAND", original);
      }

      if let Some(ref command) = self.command {
         shell.arg("-c").arg(command);
      } else {
         let name = account
            .shell
            .file_name()
            .unwrap_or(account.shell.as_os_str());
         shell.arg0(format!("-{}", name.to_string_lossy()));
      }

      Err(shell.exec())
         .with_context(|| format!("running {}", account.shell.display()))
         .erase()
   }
}
