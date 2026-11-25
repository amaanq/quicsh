//! The process the server starts for each session, as the user it runs as.
//!
//! Taking a controlling terminal and switching user must happen in the
//! process that becomes the shell. The server therefore starts its own binary
//! in this mode, which does both and then replaces itself with the shell.

#[cfg(not(target_os = "linux"))] use std::thread;
use std::{
   convert::Infallible,
   env,
   ffi::OsStr,
   io,
   os::{
      fd::AsFd as _,
      unix::{
         ffi::OsStrExt as _,
         process::{
            CommandExt as _,
            ExitStatusExt as _,
         },
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
   report,
};
use quicsh::{
   auth::Account,
   control::{
      Asks,
      MAX_DIALOGUE,
      Message,
   },
   forward::Bound,
   pipe::{
      receive_framed,
      send_framed,
      socket,
   },
};
#[cfg(target_os = "macos")] use quicsh_pam::become_user;
use quicsh_pam::{
   Style,
   login,
   permitted,
};
#[cfg(not(target_os = "linux"))]
use rustix::process::{
   getpid,
   getppid,
   kill_process,
};
use rustix::{
   net::{
      AddressFamily,
      RecvFlags,
      SocketAddrUnix,
      SocketType,
      connect,
      recv,
      sockopt::{
         Timeout,
         set_socket_timeout,
      },
   },
   process::{
      Signal,
      geteuid,
      ioctl_tiocsctty,
      setsid,
   },
   termios::ttyname,
};
#[cfg(target_os = "linux")]
use rustix::{
   process::{
      Gid,
      Uid,
      set_parent_process_death_signal,
   },
   thread::{
      set_thread_gid,
      set_thread_groups,
      set_thread_uid,
   },
};

/// Lets PAM decide whether `user` logs in from `remote`. Each question
/// leaves on standard input as a [`Message::Prompt`] and its answer arrives
/// there. With `account`, PAM is asked only whether the account may be
/// used. The monitor reads the decision from the exit status.
pub fn ask(service: &str, user: &str, remote: &str, account: bool) -> Result<()> {
   end_with_parent(Signal::TERM)?;

   if account {
      return permitted(service, user, remote)
         .map_err(|refusal| report!("no login for {user:?} from {remote}: {refusal}"));
   }

   let link = io::stdin().as_fd().try_clone_to_owned()?;

   let decided = login(service, user, remote, |style, text| {
      let prompt = Message::Prompt {
         asks: match style {
            Style::Hidden => Asks::Hidden,
            Style::Shown => Asks::Shown,
            Style::Failure | Style::Notice => Asks::Nothing,
         },
         text: text
            .get(..text.floor_char_boundary(MAX_DIALOGUE))
            .unwrap_or_default()
            .to_owned(),
      };

      send_framed(&link, &prompt.encode(), &[]).ok()?;

      if !style.asks() {
         return Some(String::new());
      }

      let (answer, _) = receive_framed(&link, MAX_DIALOGUE).ok()??;
      String::from_utf8(answer).ok()
   });

   decided.map_err(|refusal| report!("no login for {user:?} from {remote}: {refusal}"))
}

/// Starts the name of each variable in a holder's environment that the
/// session gets under the rest of the name. They travel there because a
/// command line is open for every account to read. The session sets them
/// before its own, so a client cannot replace `HOME` or `PATH`.
pub const SESSION_ENVIRONMENT: &str = "QSHD_SESSION_";

/// `PATH` for sessions when the server has none.
const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Sends `signal` to this process once its parent exits.
#[cfg(target_os = "linux")]
pub fn end_with_parent(signal: Signal) -> Result<()> {
   set_parent_process_death_signal(Some(signal))?;
   Ok(())
}

/// Sends `signal` to this process once its parent exits by polling `getppid`.
#[cfg(not(target_os = "linux"))]
#[expect(clippy::unnecessary_wraps, reason = "the Linux version can fail")]
pub fn end_with_parent(signal: Signal) -> Result<()> {
   let parent = getppid();

   thread::spawn(move || {
      while getppid() == parent {
         thread::sleep(PARENT_CHECK);
      }

      let _ = kill_process(getpid(), signal);
   });

   Ok(())
}

/// Polling interval for parent-exit detection on non-Linux targets.
#[cfg(not(target_os = "linux"))]
const PARENT_CHECK: Duration = Duration::from_millis(250);

/// Gives up root for `account`. An unprivileged server can only be the
/// account already.
pub fn become_account(account: &Account) -> Result<()> {
   if geteuid().is_root() {
      switch(account)?;
   } else if geteuid().as_raw() != account.uid {
      bail!(
         "an unprivileged server cannot run sessions for {}",
         account.name
      );
   }

   Ok(())
}

/// Switches the current thread's credentials to `account`.
#[cfg(target_os = "linux")]
fn switch(account: &Account) -> Result<()> {
   let groups = account
      .groups()?
      .into_iter()
      .map(Gid::from_raw)
      .collect::<Vec<Gid>>();

   // Groups and gid go first, because dropping the uid removes the right to
   // change them.
   set_thread_groups(&groups).context("setting groups")?;
   set_thread_gid(Gid::from_raw(account.gid)).context("setting gid")?;
   set_thread_uid(Uid::from_raw(account.uid)).context("setting uid")?;
   Ok(())
}

/// Switches this process to `account`.
#[cfg(target_os = "macos")]
fn switch(account: &Account) -> Result<()> {
   become_user(&account.name, account.uid, account.gid)
      .with_context(|| format!("becoming {}", account.name))?;
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

         send_framed(&link, &[0], &[listener.as_fd()])?;
         drop(listener);

         let _ = recv(&link, &mut [0_u8; 1], RecvFlags::empty());
         drop(bound);
      } else {
         let socket = socket(AddressFamily::UNIX, SocketType::STREAM)?;

         set_socket_timeout(&socket, Timeout::Send, Some(REACH_TIMEOUT))?;
         connect(&socket, &SocketAddrUnix::new(&self.path)?)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
         set_socket_timeout(&socket, Timeout::Send, None)?;

         send_framed(&link, &[0], &[socket.as_fd()])?;
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
      #[cfg(target_os = "linux")]
      set_parent_process_death_signal(Some(Signal::HUP))?;

      let mut shell = Command::new(&account.shell);

      shell.env_clear();

      for (name, value) in env::vars_os() {
         if let Some(wanted) = name
            .to_str()
            .and_then(|text| text.strip_prefix(SESSION_ENVIRONMENT))
         {
            shell.env(wanted, value);
         }
      }

      shell
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
         shell.env(
            "SSH_TTY",
            OsStr::from_bytes(ttyname(io::stdin(), Vec::new())?.as_bytes()),
         );
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
