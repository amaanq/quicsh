//! User authentication on the control stream.
//!
//! - The client signs a challenge derived from the TLS exporter, so a signature
//!   is valid for one connection to one server key only.
//! - The challenge uses the `SSHSIG` framing of `ssh-keygen -Y sign` under its
//!   own namespace. A signature made here cannot pass as an SSH login
//!   signature, and the reverse holds too.
//! - Plain and FIDO-backed keys take the same path, since both sign through the
//!   agent.

use std::{
   fs,
   io,
   iter,
   net::IpAddr,
   os::unix::fs::MetadataExt as _,
   path::{
      Path,
      PathBuf,
   },
   process::{
      Command,
      Stdio,
   },
};

use quinn_proto::Connection;
use ring::digest::{
   SHA512,
   digest,
};

use crate::{
   error::Error,
   key::{
      PublicKey,
      decode,
   },
   wire::{
      Reader,
      put_string,
   },
};

/// TLS exporter label that binds a login to one connection.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-quicsh-auth";
/// `SSHSIG` namespace that keeps these signatures out of other protocols.
pub const NAMESPACE: &str = "quicsh-auth";

/// The secret both sides derive from this connection's TLS handshake.
///
/// # Errors
///
/// Fails when the handshake has not produced keys yet.
pub fn exporter(connection: &Connection) -> Result<[u8; 32], Error> {
   let mut secret = [0; 32];

   connection
      .crypto_session()
      .export_keying_material(&mut secret, EXPORTER_LABEL, &[])
      .map_err(|_| Error::Exporter)?;

   Ok(secret)
}

/// What `ssh-keygen -Y sign` takes on standard input to produce the signature
/// over [`challenge`], since it hashes and frames its input the same way.
#[must_use]
pub fn message(exporter: &[u8; 32], user: &str) -> Vec<u8> {
   let mut message = Vec::new();
   put_string(&mut message, exporter);
   put_string(&mut message, user.as_bytes());
   message
}

/// Reads the armored output of `ssh-keygen -Y sign` and returns the signing
/// key with the signature blob.
///
/// # Errors
///
/// Fails when the text is malformed or was made for another namespace or
/// hash.
pub fn armored(text: &str) -> Result<(PublicKey, Vec<u8>), Error> {
   let body = text
      .lines()
      .map(str::trim)
      .filter(|line| !line.starts_with("-----"))
      .collect::<String>();

   let bytes = decode(&body)?;
   let mut reader = Reader::new(bytes.strip_prefix(b"SSHSIG").ok_or(Error::Signature)?);

   let version = reader.u32()?;
   let key = PublicKey::from_blob(reader.string()?)?;
   let namespace = reader.string()?;
   let _reserved = reader.string()?;
   let hash = reader.string()?;
   let signature = reader.string()?.to_vec();

   if version != 1 || namespace != NAMESPACE.as_bytes() || hash != b"sha512" || !reader.is_empty() {
      return Err(Error::Signature);
   }

   Ok((key, signature))
}

/// The bytes a key signs to log `user` in on the connection behind `exporter`.
#[must_use]
pub fn challenge(exporter: &[u8; 32], user: &str) -> Vec<u8> {
   let message = message(exporter, user);

   let mut signed = b"SSHSIG".to_vec();
   put_string(&mut signed, NAMESPACE.as_bytes());
   put_string(&mut signed, b"");
   put_string(&mut signed, b"sha512");
   put_string(&mut signed, digest(&SHA512, &message).as_ref());
   signed
}

pub struct Request {
   pub user:      String,
   pub key:       PublicKey,
   pub signature: Vec<u8>,
}

impl Request {
   /// # Errors
   ///
   /// Fails when the signature does not cover this connection and user.
   pub fn verify(&self, exporter: &[u8; 32]) -> Result<(), Error> {
      self
         .key
         .verify(&challenge(exporter, &self.user), &self.signature)
   }
}

/// A user of this machine.
pub struct Account {
   pub name:  String,
   pub uid:   u32,
   pub gid:   u32,
   pub home:  PathBuf,
   pub shell: PathBuf,
}

impl Account {
   /// Finds `name` in `/etc/passwd`, then in the other sources `getent`
   /// knows.
   ///
   /// # Errors
   ///
   /// Fails when `/etc/passwd` cannot be read.
   pub fn lookup(name: &str) -> Result<Option<Self>, Error> {
      let passwd = fs::read_to_string("/etc/passwd").map_err(Error::Passwd)?;

      Ok(Self::listed(&passwd, name).or_else(|| Self::listed(&getent("passwd", name)?, name)))
   }

   /// The entry for `name` among `passwd` lines. `getent` also answers a
   /// user ID with the entry it belongs to, so the name must match.
   fn listed(passwd: &str, name: &str) -> Option<Self> {
      passwd.lines().find_map(|line| {
         let fields = line.split(':').collect::<Vec<&str>>();
         let [user, _password, uid, gid, _gecos, home, shell] = *fields.as_slice() else {
            return None;
         };

         (user == name).then_some(())?;

         Some(Self {
            name:  name.to_owned(),
            uid:   uid.parse().ok()?,
            gid:   gid.parse().ok()?,
            home:  PathBuf::from(home),
            shell: PathBuf::from(shell),
         })
      })
   }

   /// The primary group followed by every group that lists this account as
   /// a member, in `/etc/group` or in the other sources `getent` knows.
   ///
   /// # Errors
   ///
   /// Fails when `/etc/group` cannot be read.
   pub fn groups(&self) -> Result<Vec<u32>, Error> {
      let group = fs::read_to_string("/etc/group").map_err(Error::Passwd)?;

      let supplementary = group.lines().filter_map(|line| {
         let fields = line.split(':').collect::<Vec<&str>>();
         let [_name, _password, gid, members] = *fields.as_slice() else {
            return None;
         };

         members
            .split(',')
            .any(|member| member == self.name)
            .then(|| gid.parse().ok())?
      });

      let mut groups = iter::once(self.gid)
         .chain(supplementary)
         .collect::<Vec<u32>>();

      let known = getent("initgroups", &self.name).unwrap_or_default();

      for gid in known
         .split_ascii_whitespace()
         .skip(1)
         .filter_map(|field| field.parse().ok())
      {
         if !groups.contains(&gid) {
            groups.push(gid);
         }
      }

      Ok(groups)
   }

   /// Whether `key` may log in to this account.
   ///
   /// The default file is `~/.ssh/authorized_keys`, and it is ignored unless
   /// only the account or root can write it and its parent directories.
   /// `keys_file` names a file the server operator vouches for instead.
   ///
   /// The answer is what the first line that lists `key` and applies to a
   /// client at `remote` permits. A line with an option this server cannot
   /// enforce is skipped, because honoring the key without the restriction
   /// would grant more than the line allows.
   ///
   /// # Errors
   ///
   /// Fails when the file exists but cannot be read.
   pub fn authorizes(
      &self,
      key: &PublicKey,
      keys_file: Option<&Path>,
      remote: IpAddr,
   ) -> Result<Option<Permit>, Error> {
      let default = self.home.join(".ssh/authorized_keys");

      let guarded = [self.home.as_path(), &self.home.join(".ssh"), &default];

      if keys_file.is_none() && !guarded.iter().all(|path| self.controls(path)) {
         return Ok(None);
      }

      let path = keys_file.unwrap_or(&default);

      let text = match fs::read_to_string(path) {
         Ok(text) => text,
         Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
         Err(error) => return Err(Error::AuthorizedKeys(error)),
      };

      Ok(text
         .lines()
         .filter_map(entry)
         .filter(|found| found.1 == *key)
         .find_map(|(options, _)| Permit::parse(options, remote)))
   }

   /// Whether only the account or root can write `path`.
   fn controls(&self, path: &Path) -> bool {
      fs::metadata(path).is_ok_and(|metadata| {
         (metadata.uid() == self.uid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0
      })
   }
}

/// What `getent` prints for `key` in `database`, which covers LDAP,
/// `systemd-homed` and whatever else the name service switch lists. `None`
/// means it found nothing or is not installed. A name that could pass for
/// an option is never handed over.
fn getent(database: &str, key: &str) -> Option<String> {
   let plain = !key.is_empty()
      && !key.starts_with('-')
      && key
         .chars()
         .all(|letter| letter.is_ascii_alphanumeric() || "._@-".contains(letter));

   let output = plain
      .then(|| {
         Command::new("getent")
            .args([database, "--", key])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
      })
      .flatten()?;

   output
      .status
      .success()
      .then(|| String::from_utf8(output.stdout).ok())?
}

/// What a key may do, from the options on its `authorized_keys` line.
#[derive(Debug, PartialEq, Eq)]
pub struct Permit {
   /// Runs in place of whatever the client asks for.
   pub command:    Option<String>,
   /// Whether a session may have a terminal.
   pub terminal:   bool,
   /// Whether a session may reach the client's SSH agent.
   pub agent:      bool,
   /// Whether the client may forward ports.
   pub forwarding: bool,
}

impl Permit {
   /// Reads the options of one line for a client at `remote`. `None` means
   /// the line does not apply, which covers an option this server cannot
   /// enforce.
   fn parse(options: &str, remote: IpAddr) -> Option<Self> {
      let mut permit = Self {
         command:    None,
         terminal:   true,
         agent:      true,
         forwarding: true,
      };

      for option in split(options, ',').filter(|option| !option.is_empty()) {
         let (name, value) = match option.split_once('=') {
            Some((name, quoted)) => (name, Some(unquote(quoted)?)),
            None => (option, None),
         };

         match (name.to_ascii_lowercase().as_str(), value) {
            ("restrict", None) => {
               permit.terminal = false;
               permit.agent = false;
               permit.forwarding = false;
            },
            ("pty", None) => permit.terminal = true,
            ("no-pty", None) => permit.terminal = false,
            ("agent-forwarding", None) => permit.agent = true,
            ("no-agent-forwarding", None) => permit.agent = false,
            ("port-forwarding", None) => permit.forwarding = true,
            ("no-port-forwarding", None) => permit.forwarding = false,
            ("x11-forwarding" | "no-x11-forwarding" | "user-rc" | "no-user-rc", None) => {},
            ("command", Some(line)) => permit.command = Some(line),
            ("from", Some(list)) if admits(&list, remote) => {},
            _ => return None,
         }
      }

      Some(permit)
   }
}

/// The index of each `separator` in `text` that no double quotes enclose.
fn unquoted(text: &str, separator: impl Fn(char) -> bool) -> impl Iterator<Item = usize> {
   let mut quoted = false;
   let mut escaped = false;

   text.char_indices().filter_map(move |(at, letter)| {
      if letter == '"' && !escaped {
         quoted = !quoted;
      }

      escaped = letter == '\\' && !escaped;
      (!quoted && separator(letter)).then_some(at)
   })
}

/// Splits `text` at each `separator` that no double quotes enclose.
fn split(text: &str, separator: char) -> impl Iterator<Item = &str> {
   let mut start = 0;

   unquoted(text, move |letter| letter == separator)
      .chain(iter::once(text.len()))
      .filter_map(move |end| {
         let part = text.get(start..end);
         start = end + separator.len_utf8();
         part
      })
}

/// The text between double quotes, with `\"` standing for a quote.
fn unquote(value: &str) -> Option<String> {
   let inner = value.strip_prefix('"')?.strip_suffix('"')?;
   Some(inner.replace("\\\"", "\""))
}

/// The options and the key of one `authorized_keys` line.
fn entry(line: &str) -> Option<(&str, PublicKey)> {
   let trimmed = line.trim();

   if let Ok(key) = trimmed.parse() {
      return Some(("", key));
   }

   let (options, rest) =
      trimmed.split_at_checked(unquoted(trimmed, char::is_whitespace).next()?)?;
   Some((options, rest.parse().ok()?))
}

/// Whether a `from=` pattern list lets a client at `remote` in. A pattern is
/// a network in CIDR form or an address with `*` and `?` wildcards, and `!`
/// in front of one keeps its matches out. Host names never match, since
/// nothing here looks a name up.
fn admits(list: &str, remote: IpAddr) -> bool {
   let address = remote.to_string();
   let mut admitted = false;

   for listed in list.split(',') {
      let (negated, pattern) = listed
         .strip_prefix('!')
         .map_or((false, listed), |rest| (true, rest));

      let matched =
         within(pattern, remote).unwrap_or_else(|| glob(pattern.as_bytes(), address.as_bytes()));

      if matched && negated {
         return false;
      }

      admitted |= matched;
   }

   admitted
}

/// Whether `remote` is in the network `pattern` names, or `None` when
/// `pattern` is not in CIDR form.
fn within(pattern: &str, remote: IpAddr) -> Option<bool> {
   let (address, length) = pattern.split_once('/')?;
   let network = address.parse::<IpAddr>().ok()?;
   let bits = length.parse::<u32>().ok()?;

   let shared = |left: u128, right: u128, width: u32| {
      bits <= width && (bits == 0 || (left ^ right) >> (width - bits) == 0)
   };

   Some(match (network, remote) {
      (IpAddr::V4(left), IpAddr::V4(right)) => {
         shared(left.to_bits().into(), right.to_bits().into(), 32)
      },
      (IpAddr::V6(left), IpAddr::V6(right)) => shared(left.to_bits(), right.to_bits(), 128),
      (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
   })
}

/// Whether `text` matches `pattern`, where `*` stands for any run of bytes
/// and `?` for one.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
   match (pattern.split_first(), text.split_first()) {
      (None, None) => true,
      (Some((&b'*', rest)), following) => {
         glob(rest, text) || following.is_some_and(|(_, tail)| glob(pattern, tail))
      },
      (Some((&b'?', rest)), Some((_, tail))) => glob(rest, tail),
      (Some((want, rest)), Some((have, tail))) => want == have && glob(rest, tail),
      (None, Some(_)) | (Some(_), None) => false,
   }
}

#[cfg(test)]
mod tests {
   use std::{
      env,
      fs,
      net::IpAddr,
      path::PathBuf,
      process,
   };

   use ring::signature::{
      Ed25519KeyPair,
      KeyPair as _,
   };

   use crate::{
      auth::{
         Account,
         Permit,
         Request,
         challenge,
      },
      key::PublicKey,
      wire::put_string,
   };

   /// A login signature is good for one user on one connection.
   #[test]
   fn signature_binds_user_and_connection() {
      let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();

      let mut signature = Vec::new();
      put_string(&mut signature, b"ssh-ed25519");
      put_string(
         &mut signature,
         pair.sign(&challenge(&[3; 32], "alice")).as_ref(),
      );

      let mut request = Request {
         user: "alice".to_owned(),
         key: PublicKey::Ed25519(pair.public_key().as_ref().try_into().unwrap()),
         signature,
      };

      assert!(request.verify(&[3; 32]).is_ok(), "same connection and user");
      assert!(request.verify(&[4; 32]).is_err(), "another connection");

      request.user = "root".to_owned();

      assert!(request.verify(&[3; 32]).is_err(), "another user");
   }

   /// The options on an `authorized_keys` line limit the key, and a line
   /// with an option that cannot be enforced does not log in.
   #[test]
   fn options_limit_a_key() {
      let plain = PublicKey::Ed25519([1; 32]);
      let forced = PublicKey::Ed25519([2; 32]);
      let unknown = PublicKey::Ed25519([3; 32]);

      let path = env::temp_dir().join(format!("quicsh-authorized-keys-{}", process::id()));
      fs::write(
         &path,
         format!(
            "# keys\nfrom=\"10.0.0.0/8,!10.9.*\",restrict,command=\"echo \\\"a, b\\\"\" {forced} \
             backup\ntunnel=\"1\" {unknown}\n{plain} laptop\n"
         ),
      )
      .unwrap();

      let account = Account {
         name:  "alice".to_owned(),
         uid:   1000,
         gid:   1000,
         home:  PathBuf::from("/nonexistent"),
         shell: PathBuf::from("/bin/sh"),
      };

      let inside = IpAddr::from([10, 1, 2, 3]);
      let check = |key, remote| account.authorizes(key, Some(&path), remote).unwrap();

      let listed = check(&plain, inside);
      let limited = check(&forced, inside);
      let negated = check(&forced, IpAddr::from([10, 9, 2, 3]));
      let outside = check(&forced, IpAddr::from([192, 168, 1, 1]));
      let skipped = check(&unknown, inside);
      fs::remove_file(&path).unwrap();

      assert!(listed.is_some_and(|permit| permit.terminal), "plain line");
      assert_eq!(
         limited,
         Some(Permit {
            command:    Some("echo \"a, b\"".to_owned()),
            terminal:   false,
            agent:      false,
            forwarding: false,
         }),
         "restricted line"
      );
      assert_eq!(negated, None, "negated pattern");
      assert_eq!(outside, None, "address outside the network");
      assert_eq!(skipped, None, "option that is not enforced");
   }
}
