mod child;
/// The process that owns one session.
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
   control::{
      Size,
      Terminal,
   },
};

use crate::{
   child::{
      Launch,
      Reach,
   },
   hold::Hold,
   monitor::Settings,
   options::{
      Options,
      Stage,
   },
};

/// The variables a client may set when no `--accept-env` says otherwise,
/// which are the ones most distributions let through `sshd`, and the one
/// that tells programs how many colors the terminal shows.
const ACCEPTED_ENVIRONMENT: [&str; 3] = ["LANG", "LC_*", "COLORTERM"];

fn main() -> Result<()> {
   let options = Options::parse();

   match options.stage {
      None => {
         monitor::run(Settings {
            listen:           options
               .listen
               .unwrap_or_else(|| (Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into()),
            host_key:         options.host_key,
            host_certificate: options.host_certificate,
            authorized_keys:  options.authorized_keys,
            sftp_server:      options.sftp_server,
            accept_env:       if options.accept_env.is_empty() {
               ACCEPTED_ENVIRONMENT.map(str::to_owned).to_vec()
            } else {
               options.accept_env
            },
            user:             options.user,
            congestion:       options.congestion,
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
            terminal: term.map(|name| {
               Terminal {
                  name,
                  size: Size { columns, rows },
               }
            }),
            command,
            original: original_command,
            agent,
         };

         hold.run()
      },
      Some(Stage::Reach { user, path, listen }) => Reach { user, path, listen }.run(),
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
