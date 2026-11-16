use std::sync::Arc;

use p521::ecdsa::{
   Signature,
   SigningKey as P521SigningKey,
   VerifyingKey,
   signature::{
      Signer as _,
      Verifier as _,
   },
};
use quinn_proto::{
   Connection,
   crypto::rustls::{
      QuicClientConfig,
      QuicServerConfig,
   },
};
use rustls::{
   CertificateError,
   CipherSuite,
   ClientConfig,
   DigitallySignedStruct,
   ServerConfig,
   SignatureAlgorithm,
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
         sign::any_supported_type,
      },
      verify_tls13_signature_with_raw_key,
   },
   pki_types::{
      CertificateDer,
      ServerName,
      SubjectPublicKeyInfoDer,
      UnixTime,
   },
   server::AlwaysResolvesServerRawPublicKeys,
   sign::{
      CertifiedKey,
      Signer,
      SigningKey,
   },
   version::TLS13,
};

use crate::{
   error::Error,
   kex::X25519_MLKEM768,
   key::{
      Curve,
      HostKey,
      PublicKey,
   },
};

/// ALPN protocol name.
const ALPN: &[u8] = b"quicsh";

/// The ring provider limited to one cipher suite and the hybrid key exchange.
fn provider() -> Arc<CryptoProvider> {
   let mut provider = default_provider();
   provider
      .cipher_suites
      .retain(|suite| suite.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
   provider.kx_groups = vec![X25519_MLKEM768];
   Arc::new(provider)
}

/// The signature schemes a host key may use, one per key type.
pub const HOST_SCHEMES: [SignatureScheme; 5] = [
   SignatureScheme::ED25519,
   SignatureScheme::ECDSA_NISTP256_SHA256,
   SignatureScheme::ECDSA_NISTP384_SHA384,
   SignatureScheme::ECDSA_NISTP521_SHA512,
   SignatureScheme::RSA_PSS_SHA256,
];

/// Bytes in one number of a P-521 signature.
const P521_WIDTH: usize = 66;

/// The scheme a host key of this type signs handshakes with.
///
/// # Errors
///
/// Fails for a key type that cannot be a host key.
pub const fn scheme(key: &PublicKey) -> Result<SignatureScheme, Error> {
   match *key {
      PublicKey::Ed25519(_) => Ok(SignatureScheme::ED25519),
      PublicKey::Ecdsa {
         curve: Curve::P256, ..
      } => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
      PublicKey::Ecdsa {
         curve: Curve::P384, ..
      } => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
      PublicKey::Ecdsa {
         curve: Curve::P521, ..
      } => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
      PublicKey::Rsa { .. } => Ok(SignatureScheme::RSA_PSS_SHA256),
      PublicKey::SkEd25519 { .. } | PublicKey::SkEcdsa { .. } => Err(Error::KeyType),
   }
}

/// A P-521 host key. The ring provider has none, so the `p521` crate signs.
#[derive(Debug)]
struct P521Key {
   /// The private half.
   key:    Arc<P521SigningKey>,
   /// The public half as a `SubjectPublicKeyInfo` document.
   public: Vec<u8>,
}

impl SigningKey for P521Key {
   fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
      offered
         .contains(&SignatureScheme::ECDSA_NISTP521_SHA512)
         .then(|| Box::new(P521Signer(Arc::clone(&self.key))) as Box<dyn Signer>)
   }

   fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
      Some(SubjectPublicKeyInfoDer::from(self.public.as_slice()))
   }

   fn algorithm(&self) -> SignatureAlgorithm {
      SignatureAlgorithm::ECDSA
   }
}

/// Signs one handshake with a [`P521Key`].
#[derive(Debug)]
struct P521Signer(Arc<P521SigningKey>);

impl Signer for P521Signer {
   fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
      let signature: Signature = self
         .0
         .try_sign(message)
         .map_err(|_| rustls::Error::General("signing with the host key failed".into()))?;

      let joined = signature.to_bytes();
      let mut body = Vec::with_capacity(P521_WIDTH * 2 + 6);

      // DER wants the shortest form of each number, with a zero in front of
      // one whose top bit is set.
      for number in joined.chunks(P521_WIDTH) {
         let zeros = number.iter().take_while(|&&byte| byte == 0).count();
         let digits = number.get(zeros..).unwrap_or_default();
         let signed = digits.first().is_none_or(|&top| top >= 0x80);

         body.push(0x02);
         body.push(u8::try_from(digits.len() + usize::from(signed)).unwrap_or(u8::MAX));
         body.extend(signed.then_some(0));
         body.extend_from_slice(digits);
      }

      let mut document = vec![0x30];
      document.extend((body.len() >= 0x80).then_some(0x81));
      document.push(u8::try_from(body.len()).unwrap_or(u8::MAX));
      document.extend_from_slice(&body);
      Ok(document)
   }

   fn scheme(&self) -> SignatureScheme {
      SignatureScheme::ECDSA_NISTP521_SHA512
   }
}

/// Checks the DER signature of a TLS 1.3 handshake by the P-521 key in
/// `spki`.
fn verify_p521(message: &[u8], spki: &[u8], der: &[u8]) -> Option<()> {
   let PublicKey::Ecdsa {
      curve: Curve::P521,
      ref point,
   } = PublicKey::from_spki(spki).ok()?
   else {
      return None;
   };

   let (&long, rest) = der.strip_prefix(&[0x30])?.split_first()?;
   let (&length, mut body) = if long == 0x81 {
      rest.split_first()?
   } else {
      (&long, rest)
   };

   if usize::from(length) != body.len() {
      return None;
   }

   let mut joined = Vec::with_capacity(P521_WIDTH * 2);

   for _ in 0..2 {
      let (&size, tail) = body.strip_prefix(&[0x02])?.split_first()?;
      let (number, after) = tail.split_at_checked(size.into())?;
      let zeros = number.iter().take_while(|&&byte| byte == 0).count();
      let digits = number.get(zeros..)?;

      joined.resize(joined.len() + P521_WIDTH.checked_sub(digits.len())?, 0);
      joined.extend_from_slice(digits);
      body = after;
   }

   if !body.is_empty() {
      return None;
   }

   VerifyingKey::from_sec1_bytes(point)
      .ok()?
      .verify(message, &Signature::from_slice(&joined).ok()?)
      .ok()
}

/// # Errors
///
/// Fails when `key` is not a valid private key.
pub fn signing_key(key: &HostKey) -> Result<Arc<dyn SigningKey>, Error> {
   match *key {
      HostKey::Document(ref document) => any_supported_type(document).map_err(Error::Tls),
      HostKey::P521 {
         ref scalar,
         ref point,
      } => {
         let public = PublicKey::Ecdsa {
            curve: Curve::P521,
            point: point.clone(),
         };

         Ok(Arc::new(P521Key {
            key:    Arc::new(P521SigningKey::from_slice(scalar).map_err(|_| Error::PrivateKey)?),
            public: public.to_spki()?,
         }))
      },
   }
}

/// Presents the public half of `signer` as an RFC 7250 raw public key.
///
/// # Errors
///
/// Fails when `signer` cannot name its public key.
pub fn server(signer: Arc<dyn SigningKey>) -> Result<Arc<QuicServerConfig>, Error> {
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
/// Fails before the handshake completes or when the peer sent no key of a
/// usable type.
pub fn peer_key(connection: &Connection) -> Result<PublicKey, Error> {
   let chain = connection
      .crypto_session()
      .peer_identity()
      .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
      .ok_or(Error::PeerKey)?;

   PublicKey::from_spki(chain.first().ok_or(Error::PeerKey)?)
}

/// Accepts any server key whose handshake signature is valid.
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
      if dss.scheme == SignatureScheme::ECDSA_NISTP521_SHA512 {
         return verify_p521(message, cert.as_ref(), dss.signature())
            .map(|()| HandshakeSignatureValid::assertion())
            .ok_or(rustls::Error::InvalidCertificate(
               CertificateError::BadSignature,
            ));
      }

      let key = SubjectPublicKeyInfoDer::from(cert.as_ref());
      verify_tls13_signature_with_raw_key(message, &key, dss, &self.0)
   }

   fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
      let mut schemes = self.0.supported_schemes();
      schemes.push(SignatureScheme::ECDSA_NISTP521_SHA512);
      schemes
   }

   fn requires_raw_public_keys(&self) -> bool {
      true
   }
}
