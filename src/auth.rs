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
   os::unix::fs::MetadataExt as _,
   path::{
      Path,
      PathBuf,
   },
};

use quinn_proto::Connection;
use ring::digest::{
   SHA512,
   digest,
};

use crate::{
   error::Error,
   key::PublicKey,
   wire::{
      Reader,
      put_string,
   },
};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-ssh-quic-auth";
const NAMESPACE: &[u8] = b"ssh-quic-auth";
const MAX_FRAME: usize = 8 << 10;
const MAX_USER: usize = 64;
const REQUEST: u8 = 1;
const ACCEPTED: u8 = 2;
const REJECTED: u8 = 3;

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

/// The bytes a key signs to log `user` in on the connection behind `exporter`.
#[must_use]
pub fn challenge(exporter: &[u8; 32], user: &str) -> Vec<u8> {
   let mut message = Vec::new();
   put_string(&mut message, exporter);
   put_string(&mut message, user.as_bytes());

   let mut signed = b"SSHSIG".to_vec();
   put_string(&mut signed, NAMESPACE);
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

pub enum Message {
   Request(Request),
   Accepted,
   Rejected,
}

impl Message {
   /// The length-prefixed frame to write to the control stream.
   #[must_use]
   pub fn encode(&self) -> Vec<u8> {
      let mut payload = Vec::new();

      match self {
         Self::Request(request) => {
            payload.push(REQUEST);
            put_string(&mut payload, request.user.as_bytes());
            put_string(&mut payload, &request.key.to_blob());
            put_string(&mut payload, &request.signature);
         },
         Self::Accepted => payload.push(ACCEPTED),
         Self::Rejected => payload.push(REJECTED),
      }

      let mut frame = Vec::with_capacity(payload.len() + 4);
      put_string(&mut frame, &payload);
      frame
   }

   fn decode(payload: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(payload);

      let message = match reader.byte()? {
         REQUEST => {
            let user = str::from_utf8(reader.string()?).map_err(|_| Error::Frame)?;

            if user.is_empty() || user.len() > MAX_USER {
               return Err(Error::Frame);
            }

            Self::Request(Request {
               user:      user.to_owned(),
               key:       PublicKey::from_blob(reader.string()?)?,
               signature: reader.string()?.to_vec(),
            })
         },
         ACCEPTED => Self::Accepted,
         REJECTED => Self::Rejected,
         _ => return Err(Error::Frame),
      };

      if reader.is_empty() {
         Ok(message)
      } else {
         Err(Error::Frame)
      }
   }
}

/// Reassembles control stream bytes into messages.
#[derive(Default)]
pub struct Deframer(Vec<u8>);

impl Deframer {
   pub fn push(&mut self, bytes: &[u8]) {
      self.0.extend_from_slice(bytes);
   }

   /// # Errors
   ///
   /// Fails on a frame over the size limit or with unknown content.
   pub fn pop(&mut self) -> Result<Option<Message>, Error> {
      let Some((prefix, rest)) = self.0.split_first_chunk::<4>() else {
         return Ok(None);
      };

      let length = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| Error::Frame)?;

      if length > MAX_FRAME {
         return Err(Error::Frame);
      }

      let Some(payload) = rest.get(..length) else {
         return Ok(None);
      };

      let message = Message::decode(payload)?;
      self.0.drain(..length + 4);
      Ok(Some(message))
   }
}

/// A local user from `/etc/passwd`. Users that exist only in NSS sources such
/// as LDAP are not found.
pub struct Account {
   pub name:  String,
   pub uid:   u32,
   pub gid:   u32,
   pub home:  PathBuf,
   pub shell: PathBuf,
}

impl Account {
   /// # Errors
   ///
   /// Fails when `/etc/passwd` cannot be read.
   pub fn lookup(name: &str) -> Result<Option<Self>, Error> {
      let passwd = fs::read_to_string("/etc/passwd").map_err(Error::Passwd)?;

      Ok(passwd.lines().find_map(|line| {
         let fields: Vec<&str> = line.split(':').collect();
         let [user, _password, uid, gid, _gecos, home, shell] = fields.as_slice() else {
            return None;
         };

         (*user == name).then_some(())?;

         Some(Self {
            name:  name.to_owned(),
            uid:   uid.parse().ok()?,
            gid:   gid.parse().ok()?,
            home:  PathBuf::from(home),
            shell: PathBuf::from(shell),
         })
      }))
   }

   /// Whether `key` may log in to this account.
   ///
   /// The default file is `~/.ssh/authorized_keys`, and it is ignored unless
   /// only the account or root can write it and its parent directories.
   /// `keys_file` names a file the server operator vouches for instead.
   ///
   /// Lines with options such as `command=` or `from=` are skipped, because
   /// honoring the key without the restriction would grant more than the line
   /// allows.
   ///
   /// # Errors
   ///
   /// Fails when the file exists but cannot be read.
   pub fn authorizes(&self, key: &PublicKey, keys_file: Option<&Path>) -> Result<bool, Error> {
      let default = self.home.join(".ssh/authorized_keys");

      let guarded = [self.home.as_path(), &self.home.join(".ssh"), &default];

      if keys_file.is_none() && !guarded.iter().all(|path| self.controls(path)) {
         return Ok(false);
      }

      let path = keys_file.unwrap_or(&default);

      let text = match fs::read_to_string(path) {
         Ok(text) => text,
         Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
         Err(error) => return Err(Error::AuthorizedKeys(error)),
      };

      Ok(text
         .lines()
         .filter_map(|line| line.parse::<PublicKey>().ok())
         .any(|listed| listed == *key))
   }

   fn controls(&self, path: &Path) -> bool {
      fs::metadata(path).is_ok_and(|metadata| {
         (metadata.uid() == self.uid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0
      })
   }
}
