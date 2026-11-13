use std::io;

use quinn_proto::{
   ConfigError,
   ConnectError,
   ReadError,
   WriteError,
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
   #[error("reading a stream failed")]
   Read(#[source] ReadError),
   #[error("writing a stream failed")]
   Write(#[source] WriteError),
   #[error("data ended early or has the wrong shape")]
   Truncated,
   #[error("invalid base64")]
   Base64,
   #[error("unsupported key type")]
   KeyType,
   #[error("not an unencrypted OpenSSH ed25519 private key")]
   PrivateKey,
   #[error("signature does not verify")]
   Signature,
   #[error("SSH_AUTH_SOCK is not set")]
   AgentUnavailable,
   #[error("talking to the SSH agent failed")]
   Agent(#[source] io::Error),
   #[error("the SSH agent refused the request")]
   AgentRefused,
   #[error("peer presented no ed25519 key")]
   PeerKey,
   #[error("TLS exporter is unavailable")]
   Exporter,
   #[error("control frame is oversized or unknown")]
   Frame,
   #[error("reading the account database failed")]
   Passwd(#[source] io::Error),
   #[error("reading authorized keys failed")]
   AuthorizedKeys(#[source] io::Error),
}
