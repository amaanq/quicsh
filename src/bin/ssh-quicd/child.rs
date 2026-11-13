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

use eyre::{
   OptionExt as _,
   Result,
   WrapErr as _,
   bail,
};
use rustix::{
   process::{
      Gid,
      Uid,
      geteuid,
      ioctl_tiocsctty,
      setsid,
   },
   thread::{
      set_thread_gid,
      set_thread_groups,
      set_thread_uid,
   },
};
use ssh_quic::auth::Account;

const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

pub struct Launch {
   pub user:     String,
   /// The client's `TERM`, present when standard input is a terminal to adopt.
   pub terminal: Option<String>,
   pub command:  Option<String>,
   /// Where the session finds the client's forwarded SSH agent.
   pub agent:    Option<PathBuf>,
}

impl Launch {
   pub fn run(&self) -> Result<Infallible> {
      let account = Account::lookup(&self.user)?.ok_or_eyre("account vanished after login")?;

      setsid().wrap_err("starting a session")?;

      if self.terminal.is_some() {
         ioctl_tiocsctty(io::stdin()).wrap_err("taking the controlling terminal")?;
      }

      if geteuid().is_root() {
         let groups: Vec<Gid> = account.groups()?.into_iter().map(Gid::from_raw).collect();

         // Groups and gid go first, because dropping the uid removes the
         // right to change them.
         set_thread_groups(&groups).wrap_err("setting groups")?;
         set_thread_gid(Gid::from_raw(account.gid)).wrap_err("setting gid")?;
         set_thread_uid(Uid::from_raw(account.uid)).wrap_err("setting uid")?;
      } else if geteuid().as_raw() != account.uid {
         bail!(
            "an unprivileged server cannot run sessions for {}",
            account.name
         );
      }

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

      if let Some(terminal) = &self.terminal {
         shell.env("TERM", terminal);
      }

      if let Some(agent) = &self.agent {
         shell.env("SSH_AUTH_SOCK", agent);
      }

      if let Some(command) = &self.command {
         shell.arg("-c").arg(command);
      } else {
         let name = account
            .shell
            .file_name()
            .unwrap_or(account.shell.as_os_str());
         shell.arg0(format!("-{}", name.to_string_lossy()));
      }

      Err(shell.exec()).wrap_err_with(|| format!("running {}", account.shell.display()))
   }
}
