#![expect(
   unused_imports,
   reason = "pound 0.6.1's derive imports `ViaFromStr` for every field and uses it only for \
             fields that parse through `FromStr`"
)]

use std::{
   env,
   fmt::Write as _,
   fs,
   path::{
      Path,
      PathBuf,
   },
   time::Duration,
};

use misstep::{
   Result,
   ResultExt as _,
   bail,
};
use quicsh::{
   DEFAULT_PORT,
   certificate::Certificate,
   config::{
      Host,
      Target,
      expand,
   },
   key::PublicKey,
   known_hosts::glob,
   transport::Congestion,
};
use ring::digest::{
   SHA256,
   digest,
};
use rustix::process::getuid;

use crate::forward::{
   Fixed,
   Remote,
   Socks,
};

/// Where to connect and who to log in as.
#[derive(Clone)]
pub struct Login {
   /// Account name on the server.
   pub user:         String,
   /// Host name or address of the server.
   pub host:         String,
   /// The server's UDP port.
   pub port:         u16,
   /// The only keys to offer, when any were named.
   pub keys:         Vec<Identity>,
   /// The hosts to connect through, the nearest first.
   pub jump:         Option<String>,
   /// Socket of the SSH agent, when there is one to use.
   pub agent:        Option<PathBuf>,
   /// What to do about a host key nobody vouched for yet.
   pub strict:       Strict,
   /// The name to look the host key up under, in place of the host's.
   pub alias:        Option<String>,
   /// The connection to share, when the configuration names a socket.
   pub control:      Option<Control>,
   /// Variables for the session's environment, from `SendEnv` and `SetEnv`.
   pub environment:  Vec<(String, String)>,
   /// The character that starts an order to this program at the start of
   /// a line, when there is one.
   pub escape:       Option<u8>,
   /// How long the first connection may take per address, from
   /// `ConnectTimeout`.
   pub timeout:      Option<Duration>,
   /// Certificates for the keys to log in with, from `CertificateFile` and
   /// from beside the named key files.
   pub certificates: Vec<Certificate>,
}

/// How a connection is shared with other runs of this program.
#[derive(Clone)]
pub struct Control {
   /// The socket of the `qsh` that holds the connection.
   pub path:    PathBuf,
   /// Whether to start that `qsh` when none listens.
   pub create:  bool,
   /// How long it stays without a session, forever for `None`.
   pub persist: Option<Duration>,
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

/// The certificate in the file that `ssh-keygen -s` writes beside the key
/// file at `path`, when there is one this program can read.
pub fn beside(path: &Path) -> Option<Certificate> {
   let mut name = path.to_owned().into_os_string();
   name.push("-cert.pub");

   fs::read_to_string(name).ok()?.parse().ok()
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
   /// The character that starts an escape sequence at the start of a line,
   /// which may be written as ^X. none turns the sequences off.
   #[pound(short = 'e', value_name = "CHAR")]
   pub escape:     Option<String>,
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
   /// Share one connection through the socket at PATH, as `ControlPath` does.
   /// The name gets .qsh at its end, and none turns sharing off.
   #[pound(short = 'S', value_name = "PATH")]
   pub control:    Option<String>,
   /// Ask the qsh that shares its connection to check or to exit.
   #[pound(short = 'O', value_name = "COMMAND")]
   pub order:      Option<String>,
   /// Hold the connection for other runs and start no session.
   #[pound(long, hidden)]
   pub master:     bool,
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

/// The escape character that `EscapeChar` or `-e` names, which is `~` when
/// neither does.
fn escape(named: Option<&str>) -> Result<Option<u8>> {
   Ok(match named.map(str::as_bytes) {
      None => Some(b'~'),
      Some(text) if text.eq_ignore_ascii_case(b"none") => None,
      Some(&[b'^', letter]) if letter.is_ascii() => Some(letter.to_ascii_uppercase() ^ 0x40),
      Some(&[symbol]) if symbol.is_ascii() => Some(symbol),
      Some(_) => bail!("the escape character is one character, ^X or none"),
   })
}

/// The variables that `SendEnv` takes from this process and the ones that
/// `SetEnv` spells out, which win.
fn environment(host: &Host) -> Result<Vec<(String, String)>> {
   let mut found = env::vars_os()
      .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
      .filter(|pair| {
         host
            .send_env
            .iter()
            .any(|pattern| glob(pattern.as_bytes(), pair.0.as_bytes()))
      })
      .collect::<Vec<(String, String)>>();

   for word in &host.set_env {
      let Some((name, value)) = word.split_once('=') else {
         bail!("SetEnv takes NAME=VALUE, got {word}");
      };

      found.retain(|sent| sent.0 != name);
      found.push((name.to_owned(), value.to_owned()));
   }

   Ok(found)
}

/// How long `ControlPersist` keeps a connection without a session, forever
/// for `None`.
fn persist(text: Option<&str>) -> Result<Option<Duration>> {
   let lowered = text.map(str::to_ascii_lowercase);

   let spans = match lowered.as_deref() {
      None | Some("no" | "false") => return Ok(Some(Duration::ZERO)),
      Some("yes" | "true" | "0") => return Ok(None),
      Some(spans) => spans,
   };

   let mut seconds = 0_u64;
   let mut digits = String::new();

   for symbol in spans.chars().chain(['s']) {
      if symbol.is_ascii_digit() {
         digits.push(symbol);
         continue;
      }

      let unit = match symbol {
         's' => 1,
         'm' => 60,
         'h' => 3600,
         'd' => 86400,
         'w' => 604_800,
         _ => bail!("bad ControlPersist time {spans}"),
      };

      if !digits.is_empty() {
         let count = digits
            .parse::<u64>()
            .with_context(|| format!("bad ControlPersist time {spans}"))?;

         seconds = seconds.saturating_add(count.saturating_mul(unit));
         digits.clear();
      }
   }

   Ok(Some(Duration::from_secs(seconds)))
}

/// Fills in the `%` tokens of a `ControlPath`. The result ends in `.qsh`, so
/// that it never names a socket that `ssh` made from the same line.
fn socket_path(template: &str, user: &str, host: &str, alias: &str, port: u16) -> Result<PathBuf> {
   let mut path = String::new();
   let mut rest = template.chars();

   while let Some(symbol) = rest.next() {
      if symbol != '%' {
         path.push(symbol);
         continue;
      }

      match rest.next() {
         Some('h') => path.push_str(host),
         Some('n') => path.push_str(alias),
         Some('p') => path.push_str(&port.to_string()),
         Some('r') => path.push_str(user),
         Some('u') => path.push_str(&env::var("USER").unwrap_or_default()),
         Some('i') => path.push_str(&getuid().as_raw().to_string()),
         Some('C') => {
            let hash = digest(&SHA256, format!("{host}\0{port}\0{user}").as_bytes());

            for byte in hash.as_ref().iter().take(20) {
               let _ = write!(path, "{byte:02x}");
            }
         },
         Some('%') => path.push('%'),
         Some(other) => bail!("ControlPath token %{other} is not supported"),
         None => bail!("ControlPath ends in a lone %"),
      }
   }

   path.push_str(".qsh");
   Ok(expand(&path))
}

impl Options {
   /// The connection to share, when `-S` or the configuration names a
   /// socket for it.
   fn control(&self, host: &Host, user: &str, name: &str, port: u16) -> Result<Option<Control>> {
      let template = self
         .control
         .as_deref()
         .or(host.control_path.as_deref())
         .filter(|path| !path.eq_ignore_ascii_case("none"));

      let Some(path) = template else {
         return Ok(None);
      };

      let alias = self
         .target
         .rsplit_once('@')
         .map_or(self.target.as_str(), |(_, alias)| alias);

      let create = host.control_master.as_deref().is_some_and(|mode| {
         ["yes", "auto", "ask", "autoask"]
            .iter()
            .any(|known| mode.eq_ignore_ascii_case(known))
      });

      Ok(Some(Control {
         path:    socket_path(path, user, name, alias, port)?,
         create:  create || self.master,
         persist: persist(host.control_persist.as_deref())?,
      }))
   }

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
      let local = env::var("USER").unwrap_or_default();

      let target = Target {
         host:  alias,
         user:  named.or(self.login.as_deref()),
         local: &local,
      };

      host.options(&self.option, target);

      if let Some(home) = env::var_os("HOME") {
         host.read(&Path::new(&home).join(".ssh/config"), target);
      }

      host.read(Path::new("/etc/ssh/ssh_config"), target);

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

      let certificates = host
         .certificates
         .iter()
         .filter_map(|file| fs::read_to_string(file).ok()?.parse().ok())
         .chain(keys.iter().filter_map(|identity| beside(&identity.file)))
         .collect();

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

      let control = self.control(&host, &user, &name, port)?;

      Ok(Login {
         control,
         certificates,
         environment: environment(&host)?,
         escape: escape(self.escape.as_deref().or(host.escape.as_deref()))?,
         timeout: match host.connect_timeout.as_deref() {
            None | Some("none" | "0") => None,
            Some(seconds) => {
               let count = seconds
                  .parse::<u64>()
                  .context("ConnectTimeout takes a number of seconds")?;

               Some(Duration::from_secs(count))
            },
         },
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
