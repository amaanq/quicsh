//! The X25519MLKEM768 key exchange for TLS 1.3, from
//! draft-ietf-tls-ecdhe-mlkem.
//!
//! - The client's share is an ML-KEM-768 encapsulation key followed by an
//!   X25519 public key. The server's share is the ML-KEM ciphertext followed by
//!   its X25519 public key.
//! - The secret is the ML-KEM secret followed by the X25519 secret, so a
//!   recorded session stays private unless both are broken.

use ml_kem::{
   DecapsulationKey768,
   EncapsulationKey768,
   MlKem768,
   kem::{
      Decapsulate as _,
      Encapsulate as _,
      Kem as _,
      KeyExport as _,
      TryKeyInit as _,
   },
};
use ring::{
   agreement::{
      EphemeralPrivateKey,
      UnparsedPublicKey,
      X25519,
      agree_ephemeral,
   },
   rand::SystemRandom,
};
use rustls::{
   Error,
   NamedGroup,
   PeerMisbehaved,
   crypto::{
      ActiveKeyExchange,
      CompletedKeyExchange,
      SharedSecret,
      SupportedKxGroup,
   },
};

/// Length of an ML-KEM-768 encapsulation key.
const ENCAPSULATION_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext.
const CIPHERTEXT_LEN: usize = 1088;
/// Length of an X25519 public key.
const X25519_LEN: usize = 32;

/// The only key exchange group this program offers or accepts.
pub static X25519_MLKEM768: &dyn SupportedKxGroup = &Hybrid;

/// What a peer gets for a key share of the wrong shape.
const fn invalid() -> Error {
   Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

/// A new X25519 key and its public half.
fn classical() -> Result<(EphemeralPrivateKey, Vec<u8>), Error> {
   let failed = |_| Error::General("generating an X25519 key failed".into());

   let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).map_err(failed)?;
   let public = private.compute_public_key().map_err(failed)?;

   Ok((private, public.as_ref().to_vec()))
}

/// Appends the X25519 secret shared with `peer` to the ML-KEM secret.
fn combine(
   post_quantum: &[u8],
   private: EphemeralPrivateKey,
   peer: &[u8],
) -> Result<SharedSecret, Error> {
   let public = UnparsedPublicKey::new(&X25519, peer);

   agree_ephemeral(private, &public, |shared| {
      let mut secret = post_quantum.to_vec();
      secret.extend_from_slice(shared);
      SharedSecret::from(secret)
   })
   .map_err(|_| invalid())
}

/// The X25519MLKEM768 group.
#[derive(Debug)]
struct Hybrid;

impl SupportedKxGroup for Hybrid {
   fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
      let (decapsulation, encapsulation) = MlKem768::generate_keypair();
      let (private, public) = classical()?;

      let mut share = encapsulation.to_bytes().to_vec();
      share.extend_from_slice(&public);

      Ok(Box::new(Offer {
         decapsulation,
         private,
         share,
      }))
   }

   fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
      let (key, peer_public) = peer
         .split_at_checked(ENCAPSULATION_KEY_LEN)
         .filter(|&(_, rest)| rest.len() == X25519_LEN)
         .ok_or_else(invalid)?;

      let encapsulation = EncapsulationKey768::new_from_slice(key).map_err(|_| invalid())?;
      let (ciphertext, post_quantum) = encapsulation.encapsulate();
      let (private, public) = classical()?;

      let mut share = ciphertext.to_vec();
      share.extend_from_slice(&public);

      Ok(CompletedKeyExchange {
         group:   NamedGroup::X25519MLKEM768,
         pub_key: share,
         secret:  combine(&post_quantum, private, peer_public)?,
      })
   }

   fn name(&self) -> NamedGroup {
      NamedGroup::X25519MLKEM768
   }
}

/// The client's half of an exchange that waits for the server's share.
struct Offer {
   /// Opens the server's ML-KEM ciphertext.
   decapsulation: DecapsulationKey768,
   /// The X25519 private key.
   private:       EphemeralPrivateKey,
   /// The share sent to the server.
   share:         Vec<u8>,
}

impl ActiveKeyExchange for Offer {
   fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
      let (ciphertext, peer_public) = peer
         .split_at_checked(CIPHERTEXT_LEN)
         .filter(|&(_, rest)| rest.len() == X25519_LEN)
         .ok_or_else(invalid)?;

      let post_quantum = self
         .decapsulation
         .decapsulate_slice(ciphertext)
         .map_err(|_| invalid())?;

      combine(&post_quantum, self.private, peer_public)
   }

   fn pub_key(&self) -> &[u8] {
      &self.share
   }

   fn group(&self) -> NamedGroup {
      NamedGroup::X25519MLKEM768
   }
}

#[cfg(test)]
mod tests {
   use crate::kex::X25519_MLKEM768;

   /// Both sides derive the same 64 byte secret, and a truncated share is
   /// refused.
   #[test]
   fn both_sides_agree() {
      let offer = X25519_MLKEM768.start().unwrap();
      let answer = X25519_MLKEM768.start_and_complete(offer.pub_key()).unwrap();

      assert!(
         X25519_MLKEM768
            .start_and_complete(&offer.pub_key()[1..])
            .is_err(),
         "short client share"
      );

      let secret = offer.complete(&answer.pub_key).unwrap();

      assert_eq!(secret.secret_bytes().len(), 64, "two 32 byte secrets");
      assert_eq!(
         secret.secret_bytes(),
         answer.secret.secret_bytes(),
         "same secret"
      );
   }
}
