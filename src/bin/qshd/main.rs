mod child;
mod monitor;
mod network;
/// Command line options.
mod options;
mod privsep;
/// The network process's side of a session.
mod session;

use std::net::Ipv6Addr;

use misstep::Result;
use pound::Parse as _;
use quicsh::DEFAULT_PORT;

use crate::{
   child::Launch,
   monitor::Settings,
   options::{
      Options,
      Stage,
   },
};

fn main() -> Result<()> {
   let options = Options::parse();

   match options.stage {
      None => {
         monitor::run(Settings {
            listen:          options
               .listen
               .unwrap_or_else(|| (Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into()),
            host_key:        options.host_key,
            authorized_keys: options.authorized_keys,
            user:            options.user,
         })
      },
      Some(Stage::Network) => network::run(),
      Some(Stage::Session {
         user,
         term,
         command,
         agent_socket,
      }) => {
         let launch = Launch {
            user,
            terminal: term,
            command,
            agent: agent_socket,
         };

         match launch.run()? {}
      },
   }
}
