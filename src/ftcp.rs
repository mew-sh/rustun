use std::time::Duration;

use tracing::info;

/// FakeTCP listen configuration.
#[derive(Clone, Debug)]
pub struct FakeTcpListenConfig {
    pub ttl: Duration,
    pub backlog: usize,
    pub queue_size: usize,
}

impl Default for FakeTcpListenConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            backlog: 128,
            queue_size: 128,
        }
    }
}

/// FakeTCP transporter.
/// FakeTCP disguises UDP traffic as TCP packets using raw sockets.
/// This makes UDP-based protocols (like KCP) appear as TCP traffic
/// to middleboxes and firewalls.
///
/// Full implementation requires raw socket access (e.g., `socket2` crate
/// with CAP_NET_RAW on Linux, or `tcpraw` equivalent).
pub struct FakeTcpTransporter;

impl FakeTcpTransporter {
    pub fn new() -> Self {
        Self
    }

    /// Dial a FakeTCP connection.
    /// In a full implementation, this would:
    /// 1. Create a raw TCP socket
    /// 2. Perform a fake 3-way handshake
    /// 3. Send UDP payloads wrapped in TCP frames
    pub async fn dial(
        &self,
        addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("[ftcp] dialing {}", addr);
        Err("FakeTCP requires raw socket support (platform-specific)".into())
    }
}

/// FakeTCP listener.
/// Accepts FakeTCP connections that disguise UDP traffic as TCP.
pub struct FakeTcpListener {
    addr: String,
    config: FakeTcpListenConfig,
}

impl FakeTcpListener {
    pub fn new(addr: &str, config: FakeTcpListenConfig) -> Self {
        Self {
            addr: addr.to_string(),
            config,
        }
    }

    /// Listen for FakeTCP connections.
    pub async fn listen(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("[ftcp] listening on {}", self.addr);
        Err("FakeTCP requires raw socket support (platform-specific)".into())
    }
}

/// FakeTCP connection wrapper.
/// Wraps a raw packet connection to appear as a TCP stream.
pub struct FakeTcpConn {
    pub local_addr: String,
    pub remote_addr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftcp_config_default() {
        let config = FakeTcpListenConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(60));
        assert_eq!(config.backlog, 128);
        assert_eq!(config.queue_size, 128);
    }

    #[test]
    fn test_ftcp_listener_creation() {
        let listener =
            FakeTcpListener::new("0.0.0.0:8080", FakeTcpListenConfig::default());
        assert_eq!(listener.addr, "0.0.0.0:8080");
    }

    #[test]
    fn test_ftcp_transporter_creation() {
        let _ = FakeTcpTransporter::new();
    }

    #[tokio::test]
    async fn test_ftcp_dial_fails_gracefully() {
        let t = FakeTcpTransporter::new();
        let result = t.dial("127.0.0.1:8080").await;
        assert!(result.is_err()); // Expected: raw sockets not available
    }
}
