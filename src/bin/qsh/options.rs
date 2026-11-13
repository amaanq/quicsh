#![expect(
   unused_imports,
   reason = "pound 0.6.1's derive imports `ViaFromStr` for every field and uses it only for \
             fields that parse through `FromStr`"
)]

use std::{
   env,
   fs,
   path::{
      Path,
      PathBuf,
   },
};

use misstep::{
   Result,
   ResultExt as _,
};
use quicsh::{
   DEFAULT_PORT,
   config::Host,
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
   pub user: String,
   /// Host name or address of the server.
   pub host: String,
   /// The server's UDP port.
   pub port: u16,
   /// The only keys to offer, when any were named.
   pub keys: Vec<Identity>,
   /// The hosts to connect through, the nearest first.
   pub jump: Option<String>,
}

/// A key to log in with.
#[derive(Clone)]
pub struct Identity {
   /// The public half.
   pub public: PublicKey,
   /// The private key file, for when no agent holds the key.
   pub file:   PathBuf,
}

impl Identity {
   /// Reads the public half that sits beside a key file. `path` may name
   /// either half.
   fn load(path: &Path) -> Result<Self> {
      let (public, file) = if path.extension().is_some_and(|extension| extension == "pub") {
         (path.to_owned(), path.with_extension(""))
      } else {
         let mut name = path.to_owned().into_os_string();
         name.push(".pub");
         (PathBuf::from(name), path.to_owned())
      };

      let text = fs::read_to_string(&public)
         .with_context(|| format!("reading public key {}", public.display()))?;

      Ok(Self {
         public: text.parse()?,
         file,
      })
   }
}

/// SSH over QUIC client.
#[derive(pound::Parse)]
#[pound(name = "qsh", version = env!("CARGO_PKG_VERSION"))]
#[expect(
   clippy::struct_excessive_bools,
   reason = "each flag is an independent switch on the command line"
)]
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
   /// Ask for the subsystem COMMAND names, as sftp and scp do.
   #[pound(short = 's')]
   pub subsystem:  bool,
   /// Accepted for scp and ignored, since nothing forwards X11.
   #[pound(short = 'x')]
   pub no_x11:     bool,
   /// Accepted for scp and sftp and ignored.
   #[pound(short = 'q')]
   pub quiet:      bool,
   /// Accepted for scp and sftp and ignored.
   #[pound(short = 'v')]
   pub verbose:    bool,
   /// Accepted for scp and sftp and ignored, since nothing compresses.
   #[pound(short = 'C')]
   pub compress:   bool,
   /// An OpenSSH option, as sftp and scp pass them. Port sets the UDP port
   /// and the rest are ignored.
   #[pound(short = 'o', value_name = "OPTION")]
   pub option:     Vec<String>,
   /// The server's UDP port. Without it, the OpenSSH client configuration
   /// may name one, and 22 is the default.
   #[pound(short = 'p', value_name = "PORT")]
   pub port:       Option<u16>,
   /// The account to log in to, the local user name when not given.
   #[pound(short = 'l', value_name = "USER")]
   pub login:      Option<String>,
   /// Log in with the key in FILE, which may name either half. The agent
   /// signs when it holds the key, and ssh-keygen does otherwise. Without
   /// it, the OpenSSH client configuration picks the key.
   #[pound(short = 'i', value_name = "FILE")]
   pub identity:   Option<PathBuf>,
   /// Connect through the qshd on each of these hosts in turn. The OpenSSH
   /// client configuration may name them too.
   #[pound(short = 'J', value_name = "[USER@]HOST[:PORT][,...]")]
   pub jump:       Option<String>,
   /// Relay UDP between a local port, which is printed, and HOST:PORT as the
   /// server reaches it. This is what -J runs on the jump host.
   #[pound(short = 'W', value_name = "HOST:PORT")]
   pub relay:      Option<String>,
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

   /// The server, with an optional account name. The OpenSSH client
   /// configuration may give HOST a real name and an account.
   #[pound(value_name = "[USER@]HOST")]
   pub target:  String,
   /// Runs in place of the login shell. Flags after HOST belong to it.
   #[pound(trailing, value_name = "COMMAND")]
   pub command: Vec<String>,
}

impl Options {
   /// Resolves the account, host, port and identity the options name.
   pub fn login(&self) -> Result<Login> {
      let (named, alias) = match self.target.split_once('@') {
         Some((named, alias)) => (Some(named), alias),
         None => (None, self.target.as_str()),
      };

      let mut host = Host::default();

      if let Some(home) = env::var_os("HOME") {
         host.read(&Path::new(&home).join(".ssh/config"), alias);
      }

      host.read(Path::new("/etc/ssh/ssh_config"), alias);

      let chosen = self.option.iter().find_map(|option| {
         let (name, value) = option.split_once(['=', ' '])?;
         name.eq_ignore_ascii_case("port").then_some(value.trim())
      });

      let port = match (self.port, chosen.or(host.port.as_deref())) {
         (Some(port), _) => port,
         (None, Some(text)) => {
            text
               .parse::<u16>()
               .with_context(|| format!("bad port {text} for {alias}"))?
         },
         (None, None) => DEFAULT_PORT,
      };

      // A key named on the command line must be usable. A configured one is
      // skipped when it is of a type this program cannot use.
      let keys = match self.identity {
         Some(ref path) => vec![Identity::load(path)?],
         None => {
            host
               .identity_files
               .iter()
               .filter_map(|file| Identity::load(file).ok())
               .collect()
         },
      };

      let user = match named.or(self.login.as_deref()) {
         Some(user) => user.to_owned(),
         None => {
            match host.user {
               Some(user) => user,
               None => env::var("USER").context("USER is not set, pass USER@HOST")?,
            }
         },
      };

      Ok(Login {
         user,
         host: host.hostname.unwrap_or_else(|| alias.to_owned()),
         port,
         keys,
         jump: self
            .jump
            .clone()
            .or(host.jump)
            .filter(|jump| !jump.eq_ignore_ascii_case("none")),
      })
   }
}
