use std::sync::Arc;

use quinn_proto::{
   Connection,
   crypto::rustls::{
      QuicClientConfig,
      QuicServerConfig,
   },
};
use ring::{
   rand::SystemRandom,
   signature::Ed25519KeyPair,
};
use rustls::{
   CipherSuite,
   ClientConfig,
   DigitallySignedStruct,
   ServerConfig,
   SignatureScheme,
   client::danger::{
      HandshakeSignatureValid,
      ServerCertVerified,
      ServerCertVerifier,
   },
   crypto::{
      CryptoProvider,
      WebPkiSupportedAlgorithms,
      ring::{
         default_provider,
         sign::any_eddsa_type,
      },
      verify_tls13_signature_with_raw_key,
   },
   pki_types::{
      CertificateDer,
      PrivatePkcs8KeyDer,
      ServerName,
      SubjectPublicKeyInfoDer,
      UnixTime,
   },
   server::AlwaysResolvesServerRawPublicKeys,
   sign::CertifiedKey,
   version::TLS13,
};

use crate::{
   error::Error,
   key::PublicKey,
};

const ALPN: &[u8] = b"ssh-quic";

fn provider() -> Arc<CryptoProvider> {
   let mut provider = default_provider();
   provider
      .cipher_suites
      .retain(|suite| suite.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
   Arc::new(provider)
}

/// # Errors
///
/// Fails when the system random source is unavailable.
pub fn generate_key() -> Result<PrivatePkcs8KeyDer<'static>, Error> {
   let pkcs8 =
      Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| Error::KeyGeneration)?;

   Ok(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()))
}

/// Presents `key` as an RFC 7250 raw public key.
///
/// # Errors
///
/// Fails when `key` is not a valid ed25519 PKCS#8 document.
pub fn server(key: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<QuicServerConfig>, Error> {
   let signer = any_eddsa_type(key).map_err(Error::Tls)?;
   let public = signer.public_key().ok_or(Error::PublicKey)?;
   let certified = CertifiedKey::new(vec![CertificateDer::from(public.to_vec())], signer);

   let mut tls = ServerConfig::builder_with_provider(provider())
      .with_protocol_versions(&[&TLS13])
      .map_err(Error::Tls)?
      .with_no_client_auth()
      .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
         certified,
      ))));
   tls.alpn_protocols = vec![ALPN.to_vec()];

   let quic = QuicServerConfig::try_from(tls).map_err(Error::InitialCipherSuite)?;
   Ok(Arc::new(quic))
}

/// The handshake proves the server holds the key it presents and nothing
/// more. The caller must check [`peer_key`] against its known hosts before it
/// sends anything.
///
/// # Errors
///
/// Fails when rustls rejects the protocol configuration.
pub fn client() -> Result<Arc<QuicClientConfig>, Error> {
   let verifier = AcceptAnyKey(provider().signature_verification_algorithms);

   let mut tls = ClientConfig::builder_with_provider(provider())
      .with_protocol_versions(&[&TLS13])
      .map_err(Error::Tls)?
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(verifier))
      .with_no_client_auth();
   tls.alpn_protocols = vec![ALPN.to_vec()];

   let quic = QuicClientConfig::try_from(tls).map_err(Error::InitialCipherSuite)?;
   Ok(Arc::new(quic))
}

/// The key the peer proved possession of during the handshake.
///
/// # Errors
///
/// Fails before the handshake completes or when the peer sent no ed25519 key.
pub fn peer_key(connection: &Connection) -> Result<PublicKey, Error> {
   let chain = connection
      .crypto_session()
      .peer_identity()
      .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
      .ok_or(Error::PeerKey)?;

   PublicKey::from_spki(chain.first().ok_or(Error::PeerKey)?)
}

#[derive(Debug)]
struct AcceptAnyKey(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AcceptAnyKey {
   fn verify_server_cert(
      &self,
      _end_entity: &CertificateDer<'_>,
      _intermediates: &[CertificateDer<'_>],
      _server_name: &ServerName<'_>,
      _ocsp_response: &[u8],
      _now: UnixTime,
   ) -> Result<ServerCertVerified, rustls::Error> {
      Ok(ServerCertVerified::assertion())
   }

   fn verify_tls12_signature(
      &self,
      _message: &[u8],
      _cert: &CertificateDer<'_>,
      _dss: &DigitallySignedStruct,
   ) -> Result<HandshakeSignatureValid, rustls::Error> {
      Err(rustls::Error::General("TLS 1.2 is not offered".into()))
   }

   fn verify_tls13_signature(
      &self,
      message: &[u8],
      cert: &CertificateDer<'_>,
      dss: &DigitallySignedStruct,
   ) -> Result<HandshakeSignatureValid, rustls::Error> {
      let key = SubjectPublicKeyInfoDer::from(cert.as_ref());
      verify_tls13_signature_with_raw_key(message, &key, dss, &self.0)
   }

   fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
      self.0.supported_schemes()
   }

   fn requires_raw_public_keys(&self) -> bool {
      true
   }
}
