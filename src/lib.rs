use std::{
    fmt::{Display, Formatter},
    io,
    sync::Arc,
};

use hyper::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use log::warn;
use rsa::{
    pkcs1::{der, der::Reader},
    pkcs1v15,
    pkcs1v15::VerifyingKey,
    signature::Verifier,
    BigUint,
    RsaPublicKey,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier,
        CertificateDer,
        InvalidSignature,
        ServerName,
        SignatureVerificationAlgorithm,
        UnixTime,
    },
    DigitallySignedStruct,
    Error,
    OtherError,
    SignatureScheme,
};
use webpki::{alg_id, EndEntityCert};

#[derive(Clone, Debug)]
struct Verify {
    cert: CertificateDer<'static>,
    verify_server_name: bool,
}

fn der(pem: &[u8]) -> CertificateDer<'static> {
    let mut ca = io::Cursor::new(pem);

    let cert = rustls_pemfile::certs(&mut ca)
        .next()
        .expect("No certs found")
        .expect("Invalid cert");
    cert
}

#[derive(Debug)]
struct CannotVerify;

impl std::error::Error for CannotVerify {}

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[RSA_PKCS1_SHA256],
    mapping: &[(SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256])],
};

#[derive(Debug, Copy, Clone)]
struct RsaPkcs1Sha256Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = decode_spki_spk(public_key)?;

        let signature =
            pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;

        VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier { alg_id::RSA_ENCRYPTION }

    fn signature_alg_id(&self) -> AlgorithmIdentifier { alg_id::RSA_PKCS1_SHA256 }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key
    // material. decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader.decode().map_err(|_| InvalidSignature)?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(ne[0].as_bytes()),
        BigUint::from_bytes_be(ne[1].as_bytes()),
    )
    .map_err(|_| InvalidSignature)
}

static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256Verify;

impl Display for CannotVerify {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cannot verify server identity")
    }
}

impl ServerCertVerifier for Verify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.verify_server_name {
            let cert = EndEntityCert::try_from(end_entity)
                .map_err(|e| Error::Other(OtherError(Arc::new(e))))?;
            cert.verify_is_valid_for_subject_name(server_name)
                .map_err(|e| Error::Other(OtherError(Arc::new(e))))?;
        }

        if end_entity != &self.cert {
            return Err(Error::Other(OtherError(Arc::new(CannotVerify))));
        }

        if now != UnixTime::now() {
            warn!("server has invalid time");
        }

        if !intermediates.is_empty() {
            warn!("intermediates is not empty");
        }

        if !ocsp_response.is_empty() {
            warn!("ocsp_response is not empty");
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &ALGORITHMS)
    }

    // WARNING: this is untested
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Err(Error::PeerIncompatible(
        //     PeerIncompatible::ServerDoesNotSupportTls12Or13,
        // ))
        rustls::crypto::verify_tls13_signature(message, cert, dss, &ALGORITHMS)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PKCS1_SHA256]
    }
}

pub fn make_client<B>(
    pem: &[u8],
    verify_server_name: bool,
) -> Result<Client<HttpsConnector<HttpConnector>, B>, Box<dyn std::error::Error>>
where
    B: Body + Send,
    <B as Body>::Data: Send,
{
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verify {
            cert: der(pem),
            verify_server_name,
        }))
        .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http2()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
}

#[cfg(test)]
mod tests {
    use http_body_util::Full;
    use hyper::{body::Bytes, Request};

    #[tokio::test]
    async fn test() {
        let client = crate::make_client(include_bytes!("../badssl-com.pem"), true)
            .expect("Could not make client");

        let req = Request::builder()
            .uri("https://self-signed.badssl.com/")
            .body(Full::new(Bytes::new()))
            .expect("Error with request");

        let res = client.request(req).await.expect("http error");

        assert!(res.status().is_success());
    }
}
