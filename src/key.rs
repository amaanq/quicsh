//! OpenSSH public keys in their text and blob forms, and the ed25519 host
//! key file.

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
      ECDSA_P256_SHA256_FIXED,
      ECDSA_P384_SHA384_FIXED,
      ED25519,
      EcdsaVerificationAlgorithm,
      RSA_PKCS1_2048_8192_SHA256,
      RSA_PKCS1_2048_8192_SHA512,
      RsaPublicKeyComponents,
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
/// SSH name of a FIDO-backed ECDSA key.
const SK_ECDSA_NAME: &[u8] = b"sk-ecdsa-sha2-nistp256@openssh.com";
/// SSH name of an RSA key.
const RSA_NAME: &[u8] = b"ssh-rsa";
/// SSH name of an RSA signature over SHA-256.
const RSA_SHA256_NAME: &[u8] = b"rsa-sha2-256";
/// SSH name of an RSA signature over SHA-512.
const RSA_SHA512_NAME: &[u8] = b"rsa-sha2-512";
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
/// Authenticator flag set when the user gave a PIN or a fingerprint.
const SK_USER_VERIFIED: u8 = 0x04;
/// The base64 alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The NIST curve of an ECDSA key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
   P256,
   P384,
}

impl Curve {
   /// The curve an SSH key type name or curve name stands for.
   fn named(name: &[u8]) -> Option<Self> {
      [Self::P256, Self::P384]
         .into_iter()
         .find(|curve| name == curve.key_name() || name == curve.name())
   }

   /// The SSH name of the curve.
   const fn name(self) -> &'static [u8] {
      match self {
         Self::P256 => b"nistp256",
         Self::P384 => b"nistp384",
      }
   }

   /// The SSH name of a key on the curve.
   const fn key_name(self) -> &'static [u8] {
      match self {
         Self::P256 => b"ecdsa-sha2-nistp256",
         Self::P384 => b"ecdsa-sha2-nistp384",
      }
   }

   /// Bytes in one coordinate.
   const fn width(self) -> usize {
      match self {
         Self::P256 => 32,
         Self::P384 => 48,
      }
   }

   /// How ring checks a signature made on the curve.
   fn algorithm(self) -> &'static EcdsaVerificationAlgorithm {
      match self {
         Self::P256 => &ECDSA_P256_SHA256_FIXED,
         Self::P384 => &ECDSA_P384_SHA384_FIXED,
      }
   }
}

/// What a signature says about the person at the key. Only a FIDO
/// authenticator reports this, and other keys count as both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presence {
   /// Someone touched the authenticator.
   pub touched:  bool,
   /// The authenticator checked a PIN or a fingerprint.
   pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
   Ed25519([u8; 32]),
   /// A key held by a FIDO authenticator, which signs over `application`.
   SkEd25519 {
      key:         [u8; 32],
      application: Vec<u8>,
   },
   /// `point` is the uncompressed public point.
   Ecdsa {
      curve: Curve,
      point: Vec<u8>,
   },
   /// A P-256 key held by a FIDO authenticator.
   SkEcdsa {
      point:       Vec<u8>,
      application: Vec<u8>,
   },
   /// Both numbers are big-endian, as the key file has them.
   Rsa {
      exponent: Vec<u8>,
      modulus:  Vec<u8>,
   },
}

impl PublicKey {
   /// # Errors
   ///
   /// Fails when the blob is malformed or names an unsupported key type.
   pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(blob);

      let name = reader.string()?;

      let key = match name {
         ED25519_NAME => Self::Ed25519(reader.array()?),
         SK_ED25519_NAME => {
            Self::SkEd25519 {
               key:         reader.array()?,
               application: reader.string()?.to_vec(),
            }
         },
         SK_ECDSA_NAME => {
            if reader.string()? != Curve::P256.name() {
               return Err(Error::KeyType);
            }

            Self::SkEcdsa {
               point:       reader.string()?.to_vec(),
               application: reader.string()?.to_vec(),
            }
         },
         RSA_NAME => {
            Self::Rsa {
               exponent: reader.string()?.to_vec(),
               modulus:  reader.string()?.to_vec(),
            }
         },
         _ => {
            let curve = Curve::named(name).ok_or(Error::KeyType)?;

            if Curve::named(reader.string()?) != Some(curve) {
               return Err(Error::KeyType);
            }

            Self::Ecdsa {
               curve,
               point: reader.string()?.to_vec(),
            }
         },
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
         Self::Ecdsa { curve, ref point } => {
            put_string(&mut blob, curve.name());
            put_string(&mut blob, point);
         },
         Self::SkEcdsa {
            ref point,
            ref application,
         } => {
            put_string(&mut blob, Curve::P256.name());
            put_string(&mut blob, point);
            put_string(&mut blob, application);
         },
         Self::Rsa {
            ref exponent,
            ref modulus,
         } => {
            put_string(&mut blob, exponent);
            put_string(&mut blob, modulus);
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
         Self::Ecdsa { curve, .. } => curve.key_name(),
         Self::SkEcdsa { .. } => SK_ECDSA_NAME,
         Self::Rsa { .. } => RSA_NAME,
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
   /// Fails when the blob is malformed, names another key type, or does not
   /// verify.
   pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<Presence, Error> {
      let mut reader = Reader::new(signature);
      let algorithm = reader.string()?;
      let raw = reader.string()?;

      let named = match *self {
         Self::Rsa { .. } => algorithm == RSA_SHA512_NAME || algorithm == RSA_SHA256_NAME,
         Self::Ed25519(_) | Self::SkEd25519 { .. } | Self::Ecdsa { .. } | Self::SkEcdsa { .. } => {
            algorithm == self.name()
         },
      };

      if !named {
         return Err(Error::Signature);
      }

      let mut presence = Presence {
         touched:  true,
         verified: true,
      };

      let signed = match *self {
         Self::SkEd25519 {
            ref application, ..
         }
         | Self::SkEcdsa {
            ref application, ..
         } => {
            let flags = reader.byte()?;
            let counter = reader.u32()?;

            presence = Presence {
               touched:  flags & SK_USER_PRESENT != 0,
               verified: flags & SK_USER_VERIFIED != 0,
            };

            // OpenSSH PROTOCOL.u2f fixes this layout for what the authenticator
            // signs.
            let mut framed = digest(&SHA256, application).as_ref().to_vec();
            framed.push(flags);
            framed.extend_from_slice(&counter.to_be_bytes());
            framed.extend_from_slice(digest(&SHA256, message).as_ref());
            framed
         },
         Self::Ed25519(_) | Self::Ecdsa { .. } | Self::Rsa { .. } => message.to_vec(),
      };

      if !reader.is_empty() {
         return Err(Error::Signature);
      }

      let checked = match *self {
         Self::Ed25519(ref key) | Self::SkEd25519 { ref key, .. } => {
            UnparsedPublicKey::new(&ED25519, key).verify(&signed, raw)
         },
         Self::Ecdsa { curve, ref point } => {
            UnparsedPublicKey::new(curve.algorithm(), point)
               .verify(&signed, &fixed(raw, curve.width())?)
         },
         Self::SkEcdsa { ref point, .. } => {
            UnparsedPublicKey::new(Curve::P256.algorithm(), point)
               .verify(&signed, &fixed(raw, Curve::P256.width())?)
         },
         Self::Rsa {
            ref exponent,
            ref modulus,
         } => {
            let parameters = if algorithm == RSA_SHA512_NAME {
               &RSA_PKCS1_2048_8192_SHA512
            } else {
               &RSA_PKCS1_2048_8192_SHA256
            };

            let components = RsaPublicKeyComponents {
               n: unsigned(modulus),
               e: unsigned(exponent),
            };

            // ring wants a signature as long as the modulus, and some signers
            // drop its leading zero bytes.
            let mut padded = vec![0; components.n.len().saturating_sub(raw.len())];
            padded.extend_from_slice(raw);

            components.verify(parameters, &signed, &padded)
         },
      };

      checked.map(|()| presence).map_err(|_| Error::Signature)
   }
}

/// A big-endian number without the zero bytes SSH puts in front of it.
fn unsigned(number: &[u8]) -> &[u8] {
   let zeros = number.iter().take_while(|&&byte| byte == 0).count();
   number.get(zeros..).unwrap_or_default()
}

/// Turns the two numbers of an SSH ECDSA signature into the fixed-width
/// form ring verifies.
fn fixed(raw: &[u8], width: usize) -> Result<Vec<u8>, Error> {
   let mut reader = Reader::new(raw);
   let mut joined = Vec::with_capacity(width * 2);

   for _ in 0..2 {
      let number = unsigned(reader.string()?);
      let padding = width.checked_sub(number.len()).ok_or(Error::Signature)?;

      joined.resize(joined.len() + padding, 0);
      joined.extend_from_slice(number);
   }

   if reader.is_empty() {
      Ok(joined)
   } else {
      Err(Error::Signature)
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

#[cfg(test)]
mod tests {
   use ring::{
      digest::{
         SHA256,
         digest,
      },
      signature::{
         Ed25519KeyPair,
         KeyPair as _,
      },
   };

   use crate::{
      error::Error,
      key::{
         PublicKey,
         SK_ED25519_NAME,
         encode,
      },
      wire::put_string,
   };

   /// A fixed key pair and its public half.
   fn pair() -> (Ed25519KeyPair, [u8; 32]) {
      let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
      let public = pair.public_key().as_ref().try_into().unwrap();

      (pair, public)
   }

   /// Both key types survive the text form, and a wrong type name is refused.
   #[test]
   fn text_form_round_trips() {
      let plain = PublicKey::Ed25519([1; 32]);
      let fido = PublicKey::SkEd25519 {
         key:         [2; 32],
         application: b"ssh:".to_vec(),
      };

      assert_eq!(
         plain.to_string().parse::<PublicKey>().unwrap(),
         plain,
         "plain key"
      );
      assert_eq!(
         format!("{fido} comment").parse::<PublicKey>().unwrap(),
         fido,
         "fido key"
      );

      let mislabeled = format!("ssh-ed25519 {}", encode(&fido.to_blob()));

      assert!(
         matches!(mislabeled.parse::<PublicKey>(), Err(Error::KeyType)),
         "name and blob disagree"
      );
   }

   /// A plain signature covers one message and nothing may follow it.
   #[test]
   fn plain_signature() {
      let (pair, public) = pair();
      let key = PublicKey::Ed25519(public);

      let mut blob = Vec::new();
      put_string(&mut blob, b"ssh-ed25519");
      put_string(&mut blob, pair.sign(b"message").as_ref());

      assert!(key.verify(b"message", &blob).is_ok(), "signed message");
      assert!(key.verify(b"other", &blob).is_err(), "another message");

      blob.push(0);

      assert!(key.verify(b"message", &blob).is_err(), "trailing byte");
   }

   /// A FIDO signature made without a touch is refused.
   #[test]
   fn fido_signature_needs_touch() {
      let (pair, public) = pair();
      let key = PublicKey::SkEd25519 {
         key:         public,
         application: b"ssh:".to_vec(),
      };

      let blob = |flags: u8| {
         let mut signed = digest(&SHA256, b"ssh:").as_ref().to_vec();
         signed.push(flags);
         signed.extend_from_slice(&5_u32.to_be_bytes());
         signed.extend_from_slice(digest(&SHA256, b"message").as_ref());

         let mut blob = Vec::new();
         put_string(&mut blob, SK_ED25519_NAME);
         put_string(&mut blob, pair.sign(&signed).as_ref());
         blob.push(flags);
         blob.extend_from_slice(&5_u32.to_be_bytes());
         blob
      };

      let touched = key.verify(b"message", &blob(1)).unwrap();
      let verified = key.verify(b"message", &blob(4)).unwrap();

      assert!(touched.touched && !touched.verified, "touched");
      assert!(
         !verified.touched && verified.verified,
         "verified without a touch"
      );
   }
}
