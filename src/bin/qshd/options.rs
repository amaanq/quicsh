#![expect(
   unused_imports,
   reason = "pound 0.6.1's derive imports `ViaFromStr` for every field and uses it only for \
             fields that parse through `FromStr`"
)]

use std::{
   net::SocketAddr,
   path::PathBuf,
};

/// SSH over QUIC server.
#[derive(pound::Parse)]
#[pound(name = "qshd", version = env!("CARGO_PKG_VERSION"))]
pub struct Options {
   /// Address and UDP port to listen on. An IPv6 address also serves IPv4,
   /// and the default is [::]:22.
   #[pound(long, value_name = "ADDR:PORT")]
   pub listen:          Option<SocketAddr>,
   /// The ed25519 host key in OpenSSH format.
   #[pound(long, value_name = "FILE", default = "/etc/ssh/ssh_host_ed25519_key")]
   pub host_key:        PathBuf,
   /// Check every login against FILE instead of each account's own key file.
   #[pound(long, value_name = "FILE")]
   pub authorized_keys: Option<PathBuf>,
   /// The account the network process runs as when the server is root.
   #[pound(long, value_name = "NAME", default = "sshd")]
   pub user:            String,

   /// The internal process to run, absent when started by an operator.
   #[pound(subcommand)]
   pub stage: Option<Stage>,
}

/// The processes the monitor starts from its own binary.
#[derive(pound::Parse)]
pub enum Stage {
   /// The unprivileged network process.
   #[pound(hidden)]
   Network,
   /// One session, run as its account.
   #[pound(hidden)]
   Session {
      /// Account the session runs as.
      user:         String,
      /// The client's `TERM`.
      #[pound(long)]
      term:         Option<String>,
      /// The command, absent for a login shell.
      #[pound(long, allow_hyphen_values)]
      command:      Option<String>,
      /// Socket that reaches the client's SSH agent.
      #[pound(long)]
      agent_socket: Option<PathBuf>,
   },
}
