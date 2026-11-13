#![expect(
   unused_imports,
   reason = "pound 0.6.1's derive imports `ViaFromStr` for every field and uses it only for \
             fields that parse through `FromStr`"
)]

use std::{
   env,
   fs,
   path::PathBuf,
};

use misstep::{
   Result,
   ResultExt as _,
};
use quicsh::{
   DEFAULT_PORT,
   key::PublicKey,
   transport::Congestion,
};

use crate::forward::{
   Fixed,
   Remote,
   Socks,
};

/// Where to connect and who to log in as.
#[derive(Clone)]
pub struct Login {
   /// Account name on the server.
   pub user:     String,
   /// Host name or address of the server.
   pub host:     String,
   /// The server's UDP port.
   pub port:     u16,
   /// The only key to offer, when one was named.
   pub identity: Option<PublicKey>,
   /// The private key file that goes with it.
   pub key_file: Option<PathBuf>,
}

/// SSH over QUIC client.
#[derive(pound::Parse)]
#[pound(name = "qsh", version = env!("CARGO_PKG_VERSION"))]
pub struct Options {
   /// Forward the local SSH agent to the session.
   #[pound(short = 'A')]
   pub agent:      bool,
   /// Start no session and only forward ports.
   #[pound(short = 'N')]
   pub forward:    bool,
   /// Run COMMAND on a terminal.
   #[pound(short = 't')]
   pub terminal:   bool,
   /// The server's UDP port, 22 when not given.
   #[pound(short = 'p', value_name = "PORT")]
   pub port:       Option<u16>,
   /// The account to log in to, the local user name when not given.
   #[pound(short = 'l', value_name = "USER")]
   pub login:      Option<String>,
   /// Log in with the key in FILE, which may name either half. The agent
   /// signs when it holds the key, and ssh-keygen does otherwise.
   #[pound(short = 'i', value_name = "FILE")]
   pub identity:   Option<PathBuf>,
   /// Listen locally and connect each connection to HOST:HOSTPORT from the
   /// server.
   #[pound(short = 'L', value_name = "[BIND:]PORT:HOST:HOSTPORT")]
   pub local:      Vec<Fixed>,
   /// Listen on the server's loopback and connect each connection to
   /// HOST:HOSTPORT from here.
   #[pound(short = 'R', value_name = "PORT:HOST:HOSTPORT")]
   pub remote:     Vec<Remote>,
   /// Listen locally as a SOCKS5 proxy that connects from the server.
   #[pound(short = 'D', value_name = "[BIND:]PORT")]
   pub dynamic:    Vec<Socks>,
   /// Congestion controller for what this side sends, bbr or cubic. Cubic is
   /// faster on a clean local network and collapses on a lossy one.
   #[pound(long, value_name = "NAME", default = "bbr")]
   pub congestion: Congestion,

   /// The server, with an optional account name.
   #[pound(value_name = "[USER@]HOST")]
   pub target:  String,
   /// Runs in place of the login shell. Flags after HOST belong to it.
   #[pound(trailing, value_name = "COMMAND")]
   pub command: Vec<String>,
}

impl Options {
   /// Resolves the account, host, port and identity the options name.
   pub fn login(&self) -> Result<Login> {
      let (identity, key_file) = match self.identity {
         Some(ref path) => {
            let (public, private) = if path.extension().is_some_and(|extension| extension == "pub")
            {
               (path.clone(), path.with_extension(""))
            } else {
               let mut name = path.clone().into_os_string();
               name.push(".pub");
               (PathBuf::from(name), path.clone())
            };

            let text = fs::read_to_string(&public)
               .with_context(|| format!("reading public key {}", public.display()))?;
            (Some(text.parse()?), Some(private))
         },
         None => (None, None),
      };

      let (named, host) = match self.target.split_once('@') {
         Some((named, host)) => (Some(named), host),
         None => (None, self.target.as_str()),
      };

      let user = match named.or(self.login.as_deref()) {
         Some(user) => user.to_owned(),
         None => env::var("USER").context("USER is not set, pass USER@HOST")?,
      };

      Ok(Login {
         user,
         host: host.to_owned(),
         port: self.port.unwrap_or(DEFAULT_PORT),
         identity,
         key_file,
      })
   }
}
