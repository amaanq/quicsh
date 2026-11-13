mod child;
/// The process that owns one terminal session.
mod hold;
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
use quicsh::{
   DEFAULT_PORT,
   control::Size,
};

use crate::{
   child::Launch,
   hold::Hold,
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
            sftp_server:     options.sftp_server,
            user:            options.user,
            congestion:      options.congestion,
         })
      },
      Some(Stage::Network) => network::run(options.congestion),
      Some(Stage::Hold {
         user,
         term,
         columns,
         rows,
         command,
         agent,
         original_command,
      }) => {
         let hold = Hold {
            user,
            terminal: term,
            command,
            original: original_command,
            agent,
            size: Size { columns, rows },
         };

         hold.run()
      },
      Some(Stage::Session {
         user,
         term,
         command,
         agent_socket,
         original_command,
      }) => {
         let launch = Launch {
            user,
            terminal: term,
            command,
            original: original_command,
            agent: agent_socket,
         };

         match launch.run()? {}
      },
   }
}
