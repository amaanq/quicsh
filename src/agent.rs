//! Client for the `ssh-agent` protocol (draft-miller-ssh-agent), which holds
//! the user's keys and signs with them.

use std::{
   env,
   io::{
      Read as _,
      Write as _,
   },
   os::unix::net::UnixStream,
};

use crate::{
   error::Error,
   key::PublicKey,
   wire::{
      Reader,
      put_string,
   },
};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const MAX_REPLY: usize = 256 << 10;

pub struct Identity {
   pub key:     PublicKey,
   pub comment: String,
}

pub struct Agent(UnixStream);

impl Agent {
   /// Connects to the agent named by `SSH_AUTH_SOCK`.
   ///
   /// # Errors
   ///
   /// Fails when the variable is unset or the socket refuses the connection.
   pub fn connect() -> Result<Self, Error> {
      let path = env::var_os("SSH_AUTH_SOCK").ok_or(Error::AgentUnavailable)?;
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

         if let Ok(key) = PublicKey::from_blob(blob) {
            identities.push(Identity { key, comment });
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
   pub fn sign(&mut self, key: &PublicKey, data: &[u8]) -> Result<Vec<u8>, Error> {
      let mut request = vec![SIGN_REQUEST];
      put_string(&mut request, &key.to_blob());
      put_string(&mut request, data);
      request.extend_from_slice(&0_u32.to_be_bytes());

      let reply = self.call(&request, SIGN_RESPONSE)?;
      Ok(Reader::new(&reply).string()?.to_vec())
   }

   fn call(&mut self, request: &[u8], expected: u8) -> Result<Vec<u8>, Error> {
      let mut message = Vec::with_capacity(request.len() + 4);
      put_string(&mut message, request);
      self.0.write_all(&message).map_err(Error::Agent)?;

      let mut length = [0; 4];
      self.0.read_exact(&mut length).map_err(Error::Agent)?;

      let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Error::Truncated)?;

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
