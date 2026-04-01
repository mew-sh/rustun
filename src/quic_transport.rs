use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// QUIC configuration (compatible with gost's QUICConfig).
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub keep_alive: bool,
    pub keep_alive_period: Duration,
    pub timeout: Duration,
    pub idle_timeout: Duration,
    pub key: Option<Vec<u8>>, // For packet-level AES encryption
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            keep_alive: false,
            keep_alive_period: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            key: None,
        }
    }
}

/// QUIC transporter (client side) using quinn.
pub struct QuicTransporter {
    config: QuicConfig,
}

impl QuicTransporter {
    pub fn new(config: QuicConfig) -> Self {
        Self { config }
    }

    /// Dial a QUIC connection and open a stream.
    pub async fn dial(
        &self,
        addr: &str,
    ) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
        let remote: SocketAddr = addr.parse().map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid address {}: {}", addr, e),
            )) as Box<dyn std::error::Error + Send + Sync>
        })?;

        // Create client config with insecure verification for testing
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("localhost");

        let connection = endpoint.connect(remote, host)?.await?;

        info!("[quic] connected to {}", addr);
        Ok(connection)
    }
}

/// QUIC listener (server side) using quinn.
pub struct QuicListener {
    config: QuicConfig,
    addr: String,
}

impl QuicListener {
    pub fn new(addr: &str, config: QuicConfig) -> Self {
        Self {
            config,
            addr: addr.to_string(),
        }
    }

    /// Start listening for QUIC connections.
    pub async fn listen(
        &self,
    ) -> Result<quinn::Endpoint, Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr: SocketAddr = self.addr.parse()?;

        // Generate self-signed cert for the server
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], priv_key.into())?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));

        let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
        info!("[quic] listening on {}", bind_addr);

        Ok(endpoint)
    }
}

/// Skip server certificate verification (for self-signed certs).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config_default() {
        let config = QuicConfig::default();
        assert!(!config.keep_alive);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert!(config.key.is_none());
    }

    #[test]
    fn test_quic_transporter_creation() {
        let config = QuicConfig {
            keep_alive: true,
            keep_alive_period: Duration::from_secs(30),
            ..Default::default()
        };
        let t = QuicTransporter::new(config);
        assert!(t.config.keep_alive);
    }

    #[test]
    fn test_quic_listener_creation() {
        let l = QuicListener::new("0.0.0.0:4433", QuicConfig::default());
        assert_eq!(l.addr, "0.0.0.0:4433");
    }
}
