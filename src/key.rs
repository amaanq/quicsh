//! OpenSSH ed25519 keys, plain and FIDO-backed, in their text, blob and file
//! forms.

use std::{
   fmt::{
      self,
      Display,
      Formatter,
   },
   str::FromStr,
};

use ring::{
   digest::{
      SHA256,
      digest,
   },
   signature::{
      ED25519,
      UnparsedPublicKey,
   },
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use zeroize::Zeroizing;

use crate::{
   error::Error,
   wire::{
      Reader,
      put_string,
   },
};

/// SSH name of a plain ed25519 key.
const ED25519_NAME: &[u8] = b"ssh-ed25519";
/// SSH name of a FIDO-backed ed25519 key.
const SK_ED25519_NAME: &[u8] = b"sk-ssh-ed25519@openssh.com";
/// DER bytes that precede the key in a `SubjectPublicKeyInfo` document.
const SPKI_PREFIX: [u8; 12] = [
   0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// DER bytes that precede the seed in a PKCS#8 document.
const PKCS8_PREFIX: [u8; 16] = [
   0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// First bytes of an OpenSSH private key.
const PRIVATE_MAGIC: &[u8] = b"openssh-key-v1\0";
/// First line of an OpenSSH private key file.
const PRIVATE_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// Last line of an OpenSSH private key file.
const PRIVATE_END: &str = "-----END OPENSSH PRIVATE KEY-----";
/// Authenticator flag set when the user touched the key.
const SK_USER_PRESENT: u8 = 0x01;
/// The base64 alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
   Ed25519([u8; 32]),
   /// A key held by a FIDO authenticator, which signs over `application`.
   SkEd25519 {
      key:         [u8; 32],
      application: Vec<u8>,
   },
}

impl PublicKey {
   /// # Errors
   ///
   /// Fails when the blob is malformed or names an unsupported key type.
   pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(blob);

      let key = match reader.string()? {
         ED25519_NAME => Self::Ed25519(reader.array()?),
         SK_ED25519_NAME => {
            Self::SkEd25519 {
               key:         reader.array()?,
               application: reader.string()?.to_vec(),
            }
         },
         _ => return Err(Error::KeyType),
      };

      if reader.is_empty() {
         Ok(key)
      } else {
         Err(Error::Truncated)
      }
   }

   #[must_use]
   pub fn to_blob(&self) -> Vec<u8> {
      let mut blob = Vec::new();
      put_string(&mut blob, self.name());

      match *self {
         Self::Ed25519(ref key) => put_string(&mut blob, key),
         Self::SkEd25519 {
            ref key,
            ref application,
         } => {
            put_string(&mut blob, key);
            put_string(&mut blob, application);
         },
      }

      blob
   }

   /// Reads the key a TLS peer presented as an RFC 7250 raw public key.
   ///
   /// # Errors
   ///
   /// Fails when the structure is not an ed25519 `SubjectPublicKeyInfo`.
   pub fn from_spki(der: &[u8]) -> Result<Self, Error> {
      let key = der.strip_prefix(&SPKI_PREFIX).ok_or(Error::KeyType)?;
      Ok(Self::Ed25519(key.try_into().map_err(|_| Error::KeyType)?))
   }

   /// The SSH name of the key type.
   const fn name(&self) -> &'static [u8] {
      match *self {
         Self::Ed25519(_) => ED25519_NAME,
         Self::SkEd25519 { .. } => SK_ED25519_NAME,
      }
   }

   /// The `SHA256:` fingerprint that `ssh-keygen -l` prints.
   #[must_use]
   pub fn fingerprint(&self) -> String {
      let encoded = encode(digest(&SHA256, &self.to_blob()).as_ref());
      format!("SHA256:{}", encoded.trim_end_matches('='))
   }

   /// Checks an SSH signature blob over `message`.
   ///
   /// # Errors
   ///
   /// Fails when the blob is malformed, names another key type, lacks the
   /// FIDO user-presence flag, or does not verify.
   pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
      let mut reader = Reader::new(signature);

      if reader.string()? != self.name() {
         return Err(Error::Signature);
      }

      let raw = reader.string()?;

      let (key, signed) = match *self {
         Self::Ed25519(ref key) => (key, message.to_vec()),
         Self::SkEd25519 {
            ref key,
            ref application,
         } => {
            let flags = reader.byte()?;
            let counter = reader.u32()?;

            if flags & SK_USER_PRESENT == 0 {
               return Err(Error::Signature);
            }

            // OpenSSH PROTOCOL.u2f fixes this layout for what the authenticator
            // signs.
            let mut signed = digest(&SHA256, application).as_ref().to_vec();
            signed.push(flags);
            signed.extend_from_slice(&counter.to_be_bytes());
            signed.extend_from_slice(digest(&SHA256, message).as_ref());

            (key, signed)
         },
      };

      if !reader.is_empty() {
         return Err(Error::Signature);
      }

      UnparsedPublicKey::new(&ED25519, key)
         .verify(&signed, raw)
         .map_err(|_| Error::Signature)
   }
}

impl FromStr for PublicKey {
   type Err = Error;

   /// Parses `<type> <base64> [comment]`, the form in `.pub` files,
   /// `authorized_keys` and `known_hosts`.
   fn from_str(text: &str) -> Result<Self, Error> {
      let mut fields = text.split_ascii_whitespace();
      let name = fields.next().ok_or(Error::Truncated)?;
      let key = Self::from_blob(&decode(fields.next().ok_or(Error::Truncated)?)?)?;

      if key.name() == name.as_bytes() {
         Ok(key)
      } else {
         Err(Error::KeyType)
      }
   }
}

impl Display for PublicKey {
   fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      let name = str::from_utf8(self.name()).map_err(|_| fmt::Error)?;
      write!(formatter, "{name} {}", encode(&self.to_blob()))
   }
}

/// Reads an unencrypted OpenSSH ed25519 private key file.
///
/// # Errors
///
/// Fails when the file is malformed, encrypted, or holds another key type.
pub fn private_from_openssh(text: &str) -> Result<PrivatePkcs8KeyDer<'static>, Error> {
   let body = text
      .trim()
      .strip_prefix(PRIVATE_BEGIN)
      .and_then(|rest| rest.strip_suffix(PRIVATE_END))
      .ok_or(Error::PrivateKey)?;

   let file = Zeroizing::new(decode(body)?);
   let mut reader = Reader::new(file.strip_prefix(PRIVATE_MAGIC).ok_or(Error::PrivateKey)?);

   let cipher = reader.string()?;
   let _kdf = reader.string()?;
   let _kdf_options = reader.string()?;

   if cipher != b"none" || reader.u32()? != 1 {
      return Err(Error::PrivateKey);
   }

   let _public = reader.string()?;
   let mut private = Reader::new(reader.string()?);

   if private.u32()? != private.u32()? || private.string()? != ED25519_NAME {
      return Err(Error::PrivateKey);
   }

   let _repeated = private.string()?;
   let pair = Zeroizing::new(private.array::<64>()?);

   let mut pkcs8 = Zeroizing::new(PKCS8_PREFIX.to_vec());
   pkcs8.extend_from_slice(&pair[..32]);

   Ok(PrivatePkcs8KeyDer::from(pkcs8.to_vec()))
}

/// Decodes standard base64, skipping ASCII whitespace.
///
/// # Errors
///
/// Fails on a character outside the alphabet or a bad final group.
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
   let mut out = Vec::with_capacity(text.len() / 4 * 3);
   let mut buffer = 0_u32;
   let mut bits = 0_u32;

   for &character in text.as_bytes() {
      if character == b'=' {
         break;
      }

      if character.is_ascii_whitespace() {
         continue;
      }

      let value = ALPHABET
         .iter()
         .position(|&symbol| symbol == character)
         .ok_or(Error::Base64)?;

      buffer = (buffer << 6) | u32::try_from(value).map_err(|_| Error::Base64)?;
      bits += 6;

      if bits >= 8 {
         bits -= 8;
         out.push(u8::try_from((buffer >> bits) & 0xFF).map_err(|_| Error::Base64)?);
      }
   }

   if bits >= 6 || buffer & ((1 << bits) - 1) != 0 {
      return Err(Error::Base64);
   }

   Ok(out)
}

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
   let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

   for chunk in bytes.chunks(3) {
      let group = [
         chunk[0],
         *chunk.get(1).unwrap_or(&0),
         *chunk.get(2).unwrap_or(&0),
      ];
      let indices = [
         group[0] >> 2,
         ((group[0] & 0x03) << 4) | (group[1] >> 4),
         ((group[1] & 0x0F) << 2) | (group[2] >> 6),
         group[2] & 0x3F,
      ];

      for (position, index) in indices.into_iter().enumerate() {
         if position <= chunk.len() {
            out.push(char::from(ALPHABET[usize::from(index)]));
         } else {
            out.push('=');
         }
      }
   }

   out
}
