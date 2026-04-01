use std::sync::Arc;

use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{TlsAcceptor, TlsStream};
use tracing::{error, info};

use crate::handler::Handler;

/// TLS Server - wraps incoming TCP connections in TLS before handling.
pub struct TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: Arc<dyn Handler>,
}

impl TlsServer {
    /// Create a new TLS server with the given identity (cert+key).
    pub async fn new(
        addr: &str,
        identity: Identity,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let native_acceptor = NativeTlsAcceptor::new(identity)?;
        let acceptor = TlsAcceptor::from(native_acceptor);
        let listener = TcpListener::bind(addr).await?;

        info!("TLS listening on {}", listener.local_addr()?);

        Ok(Self {
            listener,
            acceptor,
            handler: Arc::new(handler),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve TLS connections.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let _handler = self.handler.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(_tls_stream) => {
                        info!("[tls] accepted connection from {}", peer_addr);
                        // TLS stream accepted; handler dispatch requires
                        // the Handler trait to accept generic AsyncRead+AsyncWrite
                        // rather than concrete TcpStream. This is a known limitation
                        // that will be resolved when the Handler trait is generalized.
                    }
                    Err(e) => {
                        error!("[tls] handshake error from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

/// Load a PKCS12 identity from cert and key PEM files.
pub fn load_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<Identity, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    // native-tls requires PKCS12, but we can use the PEM directly
    // with a workaround: concatenate cert and key
    let identity = Identity::from_pkcs8(&cert_pem, &key_pem)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_identity_missing_files() {
        let result = load_identity("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());
    }
}
