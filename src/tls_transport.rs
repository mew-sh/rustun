use native_tls::{Identity, TlsConnector as NativeTlsConnector};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};

/// Generate a self-signed TLS certificate for testing/default use.
pub fn gen_self_signed_cert() -> Result<Identity, Box<dyn std::error::Error>> {
    // For production use, we'd use rcgen or similar
    // This is a placeholder; the actual cert generation would use rcgen
    Err("self-signed cert generation requires rcgen crate".into())
}

/// Create a TLS connector that skips verification (insecure).
pub fn insecure_tls_connector() -> Result<TlsConnector, native_tls::Error> {
    let connector = NativeTlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    Ok(TlsConnector::from(connector))
}

/// Create a default TLS connector.
pub fn default_tls_connector() -> Result<TlsConnector, native_tls::Error> {
    let connector = NativeTlsConnector::new()?;
    Ok(TlsConnector::from(connector))
}

/// Wrap a TCP stream in TLS.
pub async fn tls_connect(
    stream: TcpStream,
    domain: &str,
    insecure: bool,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let connector = if insecure {
        insecure_tls_connector()?
    } else {
        default_tls_connector()?
    };
    let tls_stream = connector.connect(domain, stream).await?;
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insecure_connector() {
        let connector = insecure_tls_connector();
        assert!(connector.is_ok());
    }

    #[test]
    fn test_default_connector() {
        let connector = default_tls_connector();
        assert!(connector.is_ok());
    }
}
