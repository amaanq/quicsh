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
use ssh_quic::{
   DEFAULT_PORT,
   key::PublicKey,
};

use crate::forward::{
   Fixed,
   Remote,
   Socks,
};

pub struct Login {
   pub user:     String,
   pub host:     String,
   pub port:     u16,
   pub identity: Option<PublicKey>,
}

/// SSH over QUIC client.
#[derive(pound::Parse)]
#[pound(name = "ssh-quic", version = env!("CARGO_PKG_VERSION"))]
pub struct Options {
   /// Forward the local SSH agent to the session.
   #[pound(short = 'A')]
   pub agent:    bool,
   /// Start no session and only forward ports.
   #[pound(short = 'N')]
   pub forward:  bool,
   /// Run COMMAND on a terminal.
   #[pound(short = 't')]
   pub terminal: bool,
   /// The server's UDP port, 22 when not given.
   #[pound(short = 'p', value_name = "PORT")]
   port:         Option<u16>,
   /// The account to log in to, the local user name when not given.
   #[pound(short = 'l', value_name = "USER")]
   login:        Option<String>,
   /// Offer only the agent key whose public half is in FILE.
   #[pound(short = 'i', value_name = "FILE")]
   identity:     Option<PathBuf>,
   /// Listen locally and connect each connection to HOST:HOSTPORT from the
   /// server.
   #[pound(short = 'L', value_name = "[BIND:]PORT:HOST:HOSTPORT")]
   pub local:    Vec<Fixed>,
   /// Listen on the server's loopback and connect each connection to
   /// HOST:HOSTPORT from here.
   #[pound(short = 'R', value_name = "PORT:HOST:HOSTPORT")]
   pub remote:   Vec<Remote>,
   /// Listen locally as a SOCKS5 proxy that connects from the server.
   #[pound(short = 'D', value_name = "[BIND:]PORT")]
   pub dynamic:  Vec<Socks>,

   #[pound(value_name = "[USER@]HOST")]
   target:      String,
   /// Runs in place of the login shell. Flags after HOST belong to it.
   #[pound(trailing, value_name = "COMMAND")]
   pub command: Vec<String>,
}

impl Options {
   pub fn login(&self) -> Result<Login> {
      let identity = match &self.identity {
         Some(path) => {
            let text = fs::read_to_string(path)
               .with_context(|| format!("reading public key {}", path.display()))?;
            Some(text.parse()?)
         },
         None => None,
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
      })
   }
}
