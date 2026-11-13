use std::io;

use quinn_proto::{
   ConfigError,
   ConnectError,
   crypto::rustls::NoInitialCipherSuite,
};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
   #[error("socket setup failed")]
   Socket(#[source] io::Error),
   #[error("receiving datagrams failed")]
   Receive(#[source] io::Error),
   #[error("sending datagrams failed")]
   Send(#[source] io::Error),
   #[error("waiting for socket readiness failed")]
   Poll(#[source] io::Error),
   #[error("transport parameter rejected")]
   Config(#[source] ConfigError),
   #[error("connection attempt failed")]
   Connect(#[source] ConnectError),
   #[error("TLS configuration rejected")]
   Tls(#[source] rustls::Error),
   #[error("TLS configuration lacks the QUIC initial cipher suite")]
   InitialCipherSuite(#[source] NoInitialCipherSuite),
   #[error("ed25519 key generation failed")]
   KeyGeneration,
   #[error("signing key exposes no public key")]
   PublicKey,
   #[error("unknown congestion controller {0:?}")]
   Congestion(String),
}
