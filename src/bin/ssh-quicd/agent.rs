use std::{
   env,
   fs::{
      self,
      DirBuilder,
   },
   os::{
      fd::OwnedFd,
      unix::fs::{
         DirBuilderExt as _,
         chown,
      },
   },
   path::{
      Path,
      PathBuf,
   },
   sync::Arc,
};

use eyre::{
   Result,
   WrapErr as _,
   eyre,
};
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use rustix::process::geteuid;
use ssh_quic::{
   auth::Account,
   forward::Acceptor,
   pipe::Waker,
};

/// The Unix socket a session's programs use to reach the client's SSH agent.
/// Dropping it removes the socket and its directory.
pub struct AgentSocket {
   acceptor:  Acceptor,
   directory: PathBuf,
   path:      PathBuf,
}

impl AgentSocket {
   /// Creates the socket in a new directory that only `account` can enter.
   pub fn create(account: &Account, waker: &Arc<Waker>) -> Result<Self> {
      let mut random = [0; 8];
      SystemRandom::new()
         .fill(&mut random)
         .map_err(|_| eyre!("system random source failed"))?;

      let directory = env::temp_dir().join(format!("ssh-quic-{:016x}", u64::from_ne_bytes(random)));
      let path = directory.join("agent.sock");

      DirBuilder::new()
         .mode(0o700)
         .create(&directory)
         .wrap_err_with(|| format!("creating {}", directory.display()))?;

      let acceptor = Acceptor::unix(&path, waker)?;

      if geteuid().is_root() {
         for owned in [&directory, &path] {
            chown(owned, Some(account.uid), Some(account.gid))?;
         }
      }

      Ok(Self {
         acceptor,
         directory,
         path,
      })
   }

   pub fn path(&self) -> &Path {
      &self.path
   }

   pub fn poll(&self) -> Option<OwnedFd> {
      self.acceptor.poll()
   }
}

impl Drop for AgentSocket {
   fn drop(&mut self) {
      let _ = fs::remove_file(&self.path);
      let _ = fs::remove_dir(&self.directory);
   }
}
