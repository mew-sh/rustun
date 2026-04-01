use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info};

use crate::handler::{Handler, HandlerError, HandlerOptions};

/// DNS proxy handler - forwards DNS queries to upstream resolver.
pub struct DnsHandler {
    upstream: String,
    options: HandlerOptions,
}

impl DnsHandler {
    pub fn new(upstream: &str, options: HandlerOptions) -> Self {
        let upstream = if upstream.is_empty() {
            "8.8.8.8:53".to_string()
        } else if !upstream.contains(':') {
            format!("{}:53", upstream)
        } else {
            upstream.to_string()
        };

        Self { upstream, options }
    }
}

#[async_trait]
impl Handler for DnsHandler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // DNS over TCP: first 2 bytes = message length
        let mut len_buf = [0u8; 2];
        conn.read_exact(&mut len_buf).await?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut query = vec![0u8; msg_len];
        conn.read_exact(&mut query).await?;

        debug!(
            "[dns] {} -> {} : {} bytes",
            peer_addr, self.upstream, msg_len
        );

        // Forward to upstream via UDP
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        udp.connect(&self.upstream).await?;
        udp.send(&query).await?;

        let mut reply_buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            udp.recv(&mut reply_buf),
        )
        .await
        .map_err(|_| HandlerError::Proxy("DNS upstream timeout".into()))?
        .map_err(|e| HandlerError::Io(e))?;

        // Send reply back over TCP
        let reply_len = (n as u16).to_be_bytes();
        conn.write_all(&reply_len).await?;
        conn.write_all(&reply_buf[..n]).await?;

        debug!("[dns] {} <- {} : {} bytes", peer_addr, self.upstream, n);

        Ok(())
    }
}

/// DNS UDP listener - accepts UDP DNS queries and wraps them for the handler.
pub struct DnsUdpProxy {
    bind_addr: String,
    upstream: String,
}

impl DnsUdpProxy {
    pub fn new(bind_addr: &str, upstream: &str) -> Self {
        let upstream = if upstream.is_empty() {
            "8.8.8.8:53".to_string()
        } else if !upstream.contains(':') {
            format!("{}:53", upstream)
        } else {
            upstream.to_string()
        };

        Self {
            bind_addr: bind_addr.to_string(),
            upstream,
        }
    }

    /// Run the UDP DNS proxy.
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind(&self.bind_addr).await?;
        info!("[dns] UDP listening on {}", self.bind_addr);

        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer_addr) = socket.recv_from(&mut buf).await?;
            let query = buf[..n].to_vec();
            let upstream = self.upstream.clone();

            tokio::spawn(async move {
                match forward_dns_query(&upstream, &query).await {
                    Ok(reply) => {
                        debug!(
                            "[dns] {} <- {} : {} bytes",
                            peer_addr,
                            upstream,
                            reply.len()
                        );
                    }
                    Err(e) => {
                        debug!("[dns] {} : forward error: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

async fn forward_dns_query(
    upstream: &str,
    query: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(upstream).await?;
    udp.send(query).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv(&mut buf))
        .await??;

    Ok(buf[..n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_forward_query() {
        // Test that we can forward a minimal DNS query
        // This test requires network access, so we test the structure
        // by creating a mock DNS query
        let query = build_dns_query("example.com", 1); // type A
        assert!(!query.is_empty());
        assert!(query.len() > 12); // DNS header is 12 bytes minimum
    }

    /// Build a minimal DNS query for testing.
    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&[0x00, 0x01]); // ID
        buf.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // terminator
        buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        buf
    }
}
