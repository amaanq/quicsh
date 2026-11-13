//! Client for the `ssh-agent` protocol (draft-miller-ssh-agent), which holds
//! the user's keys and signs with them.

use std::{
   io::{
      Read as _,
      Write as _,
   },
   os::unix::net::UnixStream,
   path::Path,
};

use crate::{
   certificate::Certificate,
   error::Error,
   key::PublicKey,
   wire::{
      Reader,
      put_string,
   },
};

/// Reply type for a request the agent refused.
const FAILURE: u8 = 5;
/// Request type that lists keys.
const REQUEST_IDENTITIES: u8 = 11;
/// Reply type that carries the key list.
const IDENTITIES_ANSWER: u8 = 12;
/// Request type that asks for a signature.
const SIGN_REQUEST: u8 = 13;
/// Reply type that carries a signature.
const SIGN_RESPONSE: u8 = 14;
/// Sign flag that asks for an RSA signature over SHA-512.
const RSA_SHA2_512: u32 = 4;
/// Largest reply the client accepts from the agent.
const MAX_REPLY: usize = 256 << 10;

pub struct Identity {
   pub key:         PublicKey,
   pub comment:     String,
   /// What a certificate authority says about the key, when the agent
   /// holds the key under its certificate.
   pub certificate: Option<Certificate>,
}

pub struct Agent(UnixStream);

impl Agent {
   /// Connects to the agent that listens at `path`.
   ///
   /// # Errors
   ///
   /// Fails when the socket refuses the connection.
   pub fn connect(path: &Path) -> Result<Self, Error> {
      Ok(Self(UnixStream::connect(path).map_err(Error::Agent)?))
   }

   /// Lists the agent's keys of a supported type, in the agent's order.
   ///
   /// # Errors
   ///
   /// Fails when the agent is unreachable or its reply is malformed.
   pub fn identities(&mut self) -> Result<Vec<Identity>, Error> {
      let reply = self.call(&[REQUEST_IDENTITIES], IDENTITIES_ANSWER)?;
      let mut reader = Reader::new(&reply);
      let mut identities = Vec::new();

      for _ in 0..reader.u32()? {
         let blob = reader.string()?;
         let comment = String::from_utf8_lossy(reader.string()?).into_owned();

         let certificate = Certificate::from_blob(blob).ok();

         let held = certificate.as_ref().map_or_else(
            || PublicKey::from_blob(blob),
            |found| Ok(found.key().clone()),
         );

         if let Ok(key) = held {
            identities.push(Identity {
               key,
               comment,
               certificate,
            });
         }
      }

      Ok(identities)
   }

   /// Returns an SSH signature blob over `data`. A FIDO key blocks here until
   /// the user touches it.
   ///
   /// # Errors
   ///
   /// Fails when the agent is unreachable or declines to sign.
   pub fn sign(&mut self, identity: &Identity, data: &[u8]) -> Result<Vec<u8>, Error> {
      let key = &identity.key;

      // The agent knows a key that came with a certificate by the
      // certificate alone.
      let mut request = vec![SIGN_REQUEST];
      match identity.certificate {
         Some(ref held) => put_string(&mut request, held.to_blob()),
         None => put_string(&mut request, &key.to_blob()),
      }
      put_string(&mut request, data);

      // Without the flag an agent signs RSA over SHA-1, which nothing here
      // accepts.
      let flags = if matches!(*key, PublicKey::Rsa { .. }) {
         RSA_SHA2_512
      } else {
         0
      };
      request.extend_from_slice(&flags.to_be_bytes());

      let reply = self.call(&request, SIGN_RESPONSE)?;
      Ok(Reader::new(&reply).string()?.to_vec())
   }

   /// Sends one request and returns the reply body after checking its type.
   fn call(&mut self, request: &[u8], expected: u8) -> Result<Vec<u8>, Error> {
      let mut message = Vec::with_capacity(request.len() + 4);
      put_string(&mut message, request);
      self.0.write_all(&message).map_err(Error::Agent)?;

      let mut prefix = [0; 4];
      self.0.read_exact(&mut prefix).map_err(Error::Agent)?;

      let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Truncated)?;

      if length == 0 || length > MAX_REPLY {
         return Err(Error::Truncated);
      }

      let mut reply = vec![0; length];
      self.0.read_exact(&mut reply).map_err(Error::Agent)?;

      match reply.remove(0) {
         kind if kind == expected => Ok(reply),
         FAILURE => Err(Error::AgentRefused),
         _ => Err(Error::Truncated),
      }
   }
}
