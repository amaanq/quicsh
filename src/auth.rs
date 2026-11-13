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
   wire::put_string,
};

/// TLS exporter label that binds a login to one connection.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-quicsh-auth";
/// `SSHSIG` namespace that keeps these signatures out of other protocols.
const NAMESPACE: &[u8] = b"quicsh-auth";

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
      }))
   }

   /// The primary group followed by every group in `/etc/group` that lists
   /// this account as a member.
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

      Ok(iter::once(self.gid).chain(supplementary).collect())
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

   /// Whether only the account or root can write `path`.
   fn controls(&self, path: &Path) -> bool {
      fs::metadata(path).is_ok_and(|metadata| {
         (metadata.uid() == self.uid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0
      })
   }
}

#[cfg(test)]
mod tests {
   use std::{
      env,
      fs,
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

   /// A key behind `authorized_keys` options does not log in, since the
   /// options would not be enforced.
   #[test]
   fn restricted_key_is_skipped() {
      let plain = PublicKey::Ed25519([1; 32]);
      let restricted = PublicKey::Ed25519([2; 32]);

      let path = env::temp_dir().join(format!("quicsh-authorized-keys-{}", process::id()));
      fs::write(
         &path,
         format!("# keys\ncommand=\"date\" {restricted}\n{plain} laptop\n"),
      )
      .unwrap();

      let account = Account {
         name:  "alice".to_owned(),
         uid:   1000,
         gid:   1000,
         home:  PathBuf::from("/nonexistent"),
         shell: PathBuf::from("/bin/sh"),
      };

      let listed = account.authorizes(&plain, Some(&path));
      let skipped = account.authorizes(&restricted, Some(&path));
      fs::remove_file(&path).unwrap();

      assert!(listed.unwrap(), "plain line");
      assert!(!skipped.unwrap(), "line with options");
   }
}
