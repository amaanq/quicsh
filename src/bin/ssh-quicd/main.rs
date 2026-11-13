mod child;
mod monitor;
mod network;
mod privsep;
mod session;

use std::{
   net::{
      Ipv4Addr,
      SocketAddr,
   },
   path::PathBuf,
   process,
};

use eyre::Result;
use lexopt::{
   Arg,
   Parser,
   ValueExt as _,
};
use ssh_quic::DEFAULT_PORT;

use crate::{
   child::Launch,
   monitor::Settings,
};

const USAGE: &str =
   "usage: ssh-quicd [--listen ADDR:PORT] [--host-key FILE] [--authorized-keys FILE] [--user NAME]";

enum Mode {
   Serve(Settings),
   /// Set by the monitor when it starts the unprivileged network process.
   Network,
   /// Set by the monitor when it starts itself for one session.
   Session(Launch),
}

impl Mode {
   fn parse() -> Result<Self> {
      let mut listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT));
      let mut host_key = PathBuf::from("/etc/ssh/ssh_host_ed25519_key");
      let mut authorized_keys = None;
      let mut user = "sshd".to_owned();
      let mut network = false;
      let mut session = None;
      let mut terminal = None;
      let mut command = None;
      let mut agent = None;

      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Long("listen") => listen = parser.value()?.parse()?,
            Arg::Long("host-key") => host_key = parser.value()?.into(),
            Arg::Long("authorized-keys") => authorized_keys = Some(parser.value()?.into()),
            Arg::Long("user") => user = parser.value()?.string()?,
            Arg::Long("network") => network = true,
            Arg::Long("session") => session = Some(parser.value()?.string()?),
            Arg::Long("term") => terminal = Some(parser.value()?.string()?),
            Arg::Long("command") => command = Some(parser.value()?.string()?),
            Arg::Long("agent-socket") => agent = Some(parser.value()?.into()),
            Arg::Long("help") => {
               println!("{USAGE}");
               process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      if let Some(user) = session {
         return Ok(Self::Session(Launch {
            user,
            terminal,
            command,
            agent,
         }));
      }

      if network {
         return Ok(Self::Network);
      }

      Ok(Self::Serve(Settings {
         listen,
         host_key,
         authorized_keys,
         user,
      }))
   }
}

fn main() -> Result<()> {
   match Mode::parse()? {
      Mode::Serve(settings) => monitor::run(settings),
      Mode::Network => network::run(),
      Mode::Session(launch) => match launch.run()? {},
   }
}
