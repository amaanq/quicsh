#[cfg(target_os = "linux")] mod child;
/// The process that owns one session.
#[cfg(target_os = "linux")]
mod hold;
#[cfg(target_os = "linux")] mod mirror;
#[cfg(target_os = "linux")] mod monitor;
#[cfg(target_os = "linux")] mod network;
/// Command line options.
#[cfg(target_os = "linux")]
mod options;
#[cfg(target_os = "linux")] mod privsep;
/// The network process's side of a session.
#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
use std::{
   net::Ipv6Addr,
   time::Duration,
};

#[cfg(target_os = "linux")]
use misstep::{
   Result,
   ensure,
};
#[cfg(target_os = "linux")] use pound::Parse as _;
#[cfg(target_os = "linux")]
use quicsh::{
   DEFAULT_PORT,
   control::{
      DETACH_LIMIT,
      Size,
      Terminal,
   },
};

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
const ACCEPTED_ENVIRONMENT: [&str; 3] = ["LANG", "LC_*", "COLORTERM"];

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
   let options = Options::parse();

   match options.stage {
      None => {
         for pattern in &options.authorized_keys {
            let rest = pattern
               .to_string_lossy()
               .replace("%%", "")
               .replace("%u", "")
               .replace("%h", "");

            ensure!(
               !rest.contains('%'),
               "--authorized-keys {} has a % that is not %u, %h or %%",
               pattern.display()
            );
         }

         ensure!(
            !options.passwords || options.pam.is_some(),
            "--passwords needs the PAM service that checks them, name it with --pam"
         );

         monitor::run(Settings {
            listen:           options
               .listen
               .unwrap_or_else(|| (Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into()),
            host_key:         options.host_key,
            host_certificate: options.host_certificate,
            authorized_keys:  options.authorized_keys,
            authorities:      options.authorities,
            pam:              options.pam,
            passwords:        options.passwords,
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
      Some(Stage::Keep) => monitor::keep(),
      Some(Stage::Ask {
         service,
         user,
         remote,
         account,
      }) => child::ask(&service, &user, &remote, account),
      Some(Stage::Hold {
         user,
         term,
         columns,
         rows,
         command,
         agent,
         original_command,
         patience,
         pam,
      }) => {
         let hold = Hold {
            user,
            pam,
            terminal: term.map(|name| {
               Terminal {
                  name,
                  size: Size { columns, rows },
               }
            }),
            command,
            original: original_command,
            agent,
            patience: patience.map_or(DETACH_LIMIT, |seconds| {
               Duration::from_secs(seconds).min(DETACH_LIMIT)
            }),
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

/// The server needs Linux for its holders, privilege split and PAM sessions.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
   eprintln!("qshd: the server runs on Linux only");
   std::process::ExitCode::FAILURE
}
