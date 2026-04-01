use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::handler::Handler;

/// Server is a proxy server.
pub struct Server {
    listener: TcpListener,
    handler: Arc<dyn Handler>,
}

impl Server {
    /// Creates a new server bound to the given address.
    pub async fn new(
        addr: &str,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}", listener.local_addr()?);

        Ok(Server {
            listener,
            handler: Arc::new(handler),
        })
    }

    /// Creates a server from an existing TcpListener.
    pub fn from_listener(
        listener: TcpListener,
        handler: impl Handler + 'static,
    ) -> Self {
        Server {
            listener,
            handler: Arc::new(handler),
        }
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve accepts connections and handles them.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut temp_delay = Duration::ZERO;

        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    temp_delay = Duration::ZERO;
                    let handler = self.handler.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(stream).await {
                            tracing::debug!("[server] {} : {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    if temp_delay.is_zero() {
                        temp_delay = Duration::from_millis(5);
                    } else {
                        temp_delay *= 2;
                    }
                    if temp_delay > Duration::from_secs(1) {
                        temp_delay = Duration::from_secs(1);
                    }
                    error!("Accept error: {}; retrying in {:?}", e, temp_delay);
                    tokio::time::sleep(temp_delay).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{Handler, HandlerError};
    use async_trait::async_trait;
    use tokio::net::TcpStream;

    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 1024];
            let n = conn.read(&mut buf).await?;
            conn.write_all(&buf[..n]).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_server_echo() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::from_listener(listener, EchoHandler);
        let server_handle = tokio::spawn(async move {
            server.serve().await.ok();
        });

        // Connect and send data
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello rustun").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello rustun");

        server_handle.abort();
    }
}
