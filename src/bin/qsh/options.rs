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
   config::{
      Host,
      expand,
   },
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
   pub user:   String,
   /// Host name or address of the server.
   pub host:   String,
   /// The server's UDP port.
   pub port:   u16,
   /// The only keys to offer, when any were named.
   pub keys:   Vec<Identity>,
   /// The hosts to connect through, the nearest first.
   pub jump:   Option<String>,
   /// Socket of the SSH agent, when there is one to use.
   pub agent:  Option<PathBuf>,
   /// What to do about a host key nobody vouched for yet.
   pub strict: Strict,
   /// The name to look the host key up under, in place of the host's.
   pub alias:  Option<String>,
}

/// What to do about a host key that no known hosts file lists.
#[derive(Clone, Copy)]
pub enum Strict {
   /// Ask the user.
   Ask,
   /// Trust it and remember it.
   AcceptNew,
   /// Refuse it.
   Refuse,
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
   /// A line of the OpenSSH client configuration, which wins over the files.
   /// Port sets the UDP port here, as sftp and scp expect.
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

/// The agent socket that `IdentityAgent` names, which is the one in
/// `SSH_AUTH_SOCK` when the keyword is absent.
fn socket(named: Option<&str>) -> Option<PathBuf> {
   match named {
      Some(text) if text.eq_ignore_ascii_case("none") => None,
      Some("SSH_AUTH_SOCK") | None => env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
      Some(text) => {
         text.strip_prefix('$').map_or_else(
            || Some(expand(text)),
            |variable| env::var_os(variable).map(PathBuf::from),
         )
      },
   }
}

impl Options {
   /// Takes the forwards, the command, the terminal and the agent switch from
   /// the OpenSSH client configuration where the command line left them open.
   fn adopt(&mut self, host: &Host) -> Result<()> {
      let yes = |value: &Option<String>| {
         value.as_deref().is_some_and(|text| {
            text.eq_ignore_ascii_case("yes") || text.eq_ignore_ascii_case("true")
         })
      };

      self.agent |= yes(&host.forward_agent);
      self.terminal |= host.terminal.as_deref().is_some_and(|text| {
         text.eq_ignore_ascii_case("yes") || text.eq_ignore_ascii_case("force")
      });

      // A relay for another qsh must not claim the ports a host's forwards
      // name, and neither must scp or sftp, which say so with this option.
      if self.relay.is_none() && !yes(&host.clear) {
         let joined = |spec: &String| spec.split_whitespace().collect::<Vec<&str>>().join(":");

         for spec in &host.locals {
            self.local.push(joined(spec).parse()?);
         }

         for spec in &host.remotes {
            self.remote.push(joined(spec).parse()?);
         }

         for spec in &host.dynamics {
            self.dynamic.push(spec.parse()?);
         }
      }

      let command = host
         .command
         .as_deref()
         .filter(|text| !text.eq_ignore_ascii_case("none"));

      if let Some(text) = command
         && self.command.is_empty()
         && !self.forward
         && self.relay.is_none()
      {
         self.command.push(text.to_owned());
      }

      Ok(())
   }

   /// Resolves the account, host, port and identity the options name, and
   /// fills the open options from the OpenSSH client configuration.
   pub fn login(&mut self) -> Result<Login> {
      let (named, alias) = match self.target.split_once('@') {
         Some((named, alias)) => (Some(named), alias),
         None => (None, self.target.as_str()),
      };

      let mut host = Host::default();
      host.options(&self.option, alias);

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
            match host.user.take() {
               Some(user) => user,
               None => env::var("USER").context("USER is not set, pass USER@HOST")?,
            }
         },
      };

      let name = host.hostname.take().unwrap_or_else(|| alias.to_owned());
      self.adopt(&host)?;

      // OpenSSH's `no` also accepts a key that changed, which is not on
      // offer here.
      let strict = match host
         .strict
         .as_deref()
         .map(str::to_ascii_lowercase)
         .as_deref()
      {
         Some("yes") => Strict::Refuse,
         Some("accept-new" | "no" | "off") => Strict::AcceptNew,
         Some(_) | None => Strict::Ask,
      };

      Ok(Login {
         user,
         host: name,
         port,
         keys,
         jump: self
            .jump
            .clone()
            .or(host.jump)
            .filter(|jump| !jump.eq_ignore_ascii_case("none")),
         agent: socket(host.agent.as_deref()),
         strict,
         alias: host.alias,
      })
   }
}
