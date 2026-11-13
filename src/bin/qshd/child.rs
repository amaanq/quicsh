//! The process the server starts for each session, as the user it runs as.
//!
//! Taking a controlling terminal and switching user must happen in the
//! process that becomes the shell. The server therefore starts its own binary
//! in this mode, which does both and then replaces itself with the shell.

use std::{
   convert::Infallible,
   env,
   io,
   os::unix::process::CommandExt as _,
   path::{
      Path,
      PathBuf,
   },
   process::Command,
};

use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   bail,
};
use quicsh::auth::Account;
use rustix::{
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

/// What one session process runs.
pub struct Launch {
   /// Account the session runs as.
   pub user:     String,
   /// The client's `TERM`, present when standard input is a terminal to adopt.
   pub terminal: Option<String>,
   /// The command, or `None` for a login shell.
   pub command:  Option<String>,
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

      if geteuid().is_root() {
         let groups: Vec<Gid> = account.groups()?.into_iter().map(Gid::from_raw).collect();

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
