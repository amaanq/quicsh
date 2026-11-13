//! OpenSSH certificates (PROTOCOL.certkeys). One is a public key and what a
//! certificate authority says about it, under the authority's signature.

use std::str::FromStr;

use crate::{
   error::Error,
   key::{
      PublicKey,
      decode,
   },
   known_hosts::glob,
   wire::Reader,
};

/// Ends the name of every certificate type, after the name of the key type.
const SUFFIX: &[u8] = b"-cert-v01@openssh.com";

/// What a certificate's key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
   /// Logging in to an account.
   User,
   /// Naming a server.
   Host,
}

/// A certificate whose signature was checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
   /// The certificate as it was read.
   blob:       Vec<u8>,
   /// The key it is about.
   key:        PublicKey,
   /// What the key is for.
   kind:       Kind,
   /// The accounts or host names the key stands for.
   principals: Vec<String>,
   /// When it starts to count, in seconds since 1970.
   after:      u64,
   /// When it stops counting.
   before:     u64,
   /// Limits that whoever accepts the certificate must enforce, each with
   /// its value.
   critical:   Vec<(String, Vec<u8>)>,
   /// What the certificate allows beyond the bare login.
   extensions: Vec<String>,
   /// The key that signed it.
   authority:  PublicKey,
}

/// Reads a number of eight bytes.
fn number(reader: &mut Reader<'_>) -> Result<u64, Error> {
   Ok((u64::from(reader.u32()?) << 32) | u64::from(reader.u32()?))
}

/// Reads a field that holds one name after another, each with a value
/// when `valued`.
fn listed(field: &[u8], valued: bool) -> Result<Vec<(String, Vec<u8>)>, Error> {
   let mut reader = Reader::new(field);
   let mut found = Vec::new();

   while !reader.is_empty() {
      let name = str::from_utf8(reader.string()?).map_err(|_| Error::Frame)?;

      // A value is a string inside the field's own string, and a name that
      // takes none has an empty field.
      let value = match valued.then(|| reader.string()).transpose()? {
         Some(wrapped) if !wrapped.is_empty() => Reader::new(wrapped).string()?.to_vec(),
         Some(_) | None => Vec::new(),
      };

      found.push((name.to_owned(), value));
   }

   Ok(found)
}

impl Certificate {
   /// Reads a certificate and checks the authority's signature on it.
   ///
   /// # Errors
   ///
   /// Fails when the blob is malformed, of an unsupported type or not
   /// signed by the key it names.
   pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(blob);

      let name = reader
         .string()?
         .strip_suffix(SUFFIX)
         .ok_or(Error::KeyType)?;
      let _nonce = reader.string()?;
      let key = PublicKey::read(name, &mut reader)?;
      let _serial = number(&mut reader)?;

      let kind = match reader.u32()? {
         1 => Kind::User,
         2 => Kind::Host,
         _ => return Err(Error::KeyType),
      };

      let _id = reader.string()?;
      let principals = listed(reader.string()?, false)?;
      let after = number(&mut reader)?;
      let before = number(&mut reader)?;
      let critical = listed(reader.string()?, true)?;
      let extensions = listed(reader.string()?, true)?;
      let _reserved = reader.string()?;
      let authority = PublicKey::from_blob(reader.string()?)?;
      let signature = reader.string()?;

      if !reader.is_empty() {
         return Err(Error::Truncated);
      }

      // The signature covers everything in front of its own length.
      let signed = blob
         .len()
         .checked_sub(signature.len() + 4)
         .and_then(|end| blob.get(..end))
         .ok_or(Error::Truncated)?;

      authority.verify(signed, signature)?;

      Ok(Self {
         blob: blob.to_vec(),
         key,
         kind,
         principals: principals.into_iter().map(|pair| pair.0).collect(),
         after,
         before,
         critical,
         extensions: extensions.into_iter().map(|pair| pair.0).collect(),
         authority,
      })
   }

   /// The certificate as it travels.
   #[must_use]
   pub fn to_blob(&self) -> &[u8] {
      &self.blob
   }

   /// The key the certificate is about.
   #[must_use]
   pub const fn key(&self) -> &PublicKey {
      &self.key
   }

   /// The key that signed the certificate.
   #[must_use]
   pub const fn authority(&self) -> &PublicKey {
      &self.authority
   }

   /// Whether the certificate vouches at `now` for a key of `kind` that goes
   /// by one of `names`. A host's principal may hold `*` and `?`. A
   /// certificate without principals vouches for nobody, where OpenSSH takes
   /// some of those for everybody.
   pub fn admits<'name, Names>(&self, kind: Kind, mut names: Names, now: u64) -> bool
   where
      Names: Iterator<Item = &'name str>,
   {
      let covers = |name: &str| {
         self.principals.iter().any(|principal| {
            match kind {
               Kind::User => principal == name,
               Kind::Host => glob(principal.as_bytes(), name.as_bytes()),
            }
         })
      };

      self.kind == kind && self.after <= now && now < self.before && names.any(covers)
   }

   /// The limits that whoever accepts the certificate must enforce, each
   /// with its value.
   pub fn critical(&self) -> impl Iterator<Item = (&str, &[u8])> {
      self
         .critical
         .iter()
         .map(|pair| (pair.0.as_str(), pair.1.as_slice()))
   }

   /// Whether the certificate has the extension `name`.
   #[must_use]
   pub fn extends(&self, name: &str) -> bool {
      self.extensions.iter().any(|extension| extension == name)
   }
}

impl FromStr for Certificate {
   type Err = Error;

   /// Parses `<type> <base64> [comment]`, the form in `-cert.pub` files.
   fn from_str(text: &str) -> Result<Self, Error> {
      let blob = text
         .split_ascii_whitespace()
         .nth(1)
         .ok_or(Error::Truncated)?;
      Self::from_blob(&decode(blob)?)
   }
}

#[cfg(test)]
mod tests {
   use std::iter;

   use ring::signature::{
      Ed25519KeyPair,
      KeyPair as _,
   };

   use crate::{
      certificate::{
         Certificate,
         Kind,
      },
      error::Error,
      key::PublicKey,
      wire::put_string,
   };

   /// A user certificate for `alice` that counts from 100 to 200, signed by
   /// the key from `seed`.
   fn signed(seed: u8) -> Vec<u8> {
      let authority = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
      let public = PublicKey::Ed25519(authority.public_key().as_ref().try_into().unwrap());

      let mut principals = Vec::new();
      put_string(&mut principals, b"alice");

      let mut extensions = Vec::new();
      put_string(&mut extensions, b"permit-pty");
      put_string(&mut extensions, b"");

      let mut blob = Vec::new();
      put_string(&mut blob, b"ssh-ed25519-cert-v01@openssh.com");
      put_string(&mut blob, b"nonce");
      put_string(&mut blob, &[9; 32]);
      blob.extend_from_slice(&7_u64.to_be_bytes());
      blob.extend_from_slice(&1_u32.to_be_bytes());
      put_string(&mut blob, b"id");
      put_string(&mut blob, &principals);
      blob.extend_from_slice(&100_u64.to_be_bytes());
      blob.extend_from_slice(&200_u64.to_be_bytes());
      put_string(&mut blob, b"");
      put_string(&mut blob, &extensions);
      put_string(&mut blob, b"");
      put_string(&mut blob, &public.to_blob());

      let mut signature = Vec::new();
      put_string(&mut signature, b"ssh-ed25519");
      put_string(&mut signature, authority.sign(&blob).as_ref());
      put_string(&mut blob, &signature);

      blob
   }

   /// A certificate counts for its principals inside its time, and one
   /// changed after it was signed is refused.
   #[test]
   fn signature_covers_the_statement() {
      let blob = signed(5);
      let certificate = Certificate::from_blob(&blob).unwrap();
      let admits = |kind, name, now| certificate.admits(kind, iter::once(name), now);

      assert_eq!(
         *certificate.key(),
         PublicKey::Ed25519([9; 32]),
         "the key it is about"
      );
      assert!(admits(Kind::User, "alice", 150), "listed principal in time");
      assert!(!admits(Kind::User, "bob", 150), "another account");
      assert!(!admits(Kind::User, "alice", 200), "at its end");
      assert!(!admits(Kind::Host, "alice", 150), "as a host");
      assert!(certificate.extends("permit-pty"), "extension");

      let position = blob
         .windows(5)
         .position(|window| window == b"alice")
         .unwrap();
      let mut forged = blob;
      forged[position] = b'b';

      assert!(
         matches!(Certificate::from_blob(&forged), Err(Error::Signature)),
         "principal changed after signing"
      );
   }
}
