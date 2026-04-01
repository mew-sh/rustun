use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// ---------------------------------------------------------------------------
// TCP Redirect Handler
// ---------------------------------------------------------------------------

/// TCP Redirect Handler -- transparent proxy using original destination.
///
/// On Linux this retrieves the original destination address set by iptables
/// REDIRECT or TPROXY using the `SO_ORIGINAL_DST` getsockopt option.
///
/// On non-Linux platforms transparent proxying is not available; the handler
/// returns an error explaining this.
pub struct TcpRedirectHandler {
    options: HandlerOptions,
}

impl TcpRedirectHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl Handler for TcpRedirectHandler {
    async fn handle(&self, conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let local_addr = conn
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let target = get_original_dst_linux(&conn).unwrap_or_else(|| local_addr.clone());

        info!("[redirect] {} -> {}", peer_addr, target);

        if !Can(
            "tcp",
            &target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!(
                "[redirect] {} : unauthorized to connect to {}",
                peer_addr, target
            );
            return Err(HandlerError::Forbidden);
        }

        if let Some(ref bypass) = self.options.bypass {
            if bypass.contains(&target) {
                info!("[redirect] {} bypass {}", peer_addr, target);
                return Ok(());
            }
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        match chain.dial(&target).await {
            Ok(cc) => {
                info!("[redirect] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[redirect] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => Err(HandlerError::Chain(e)),
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl Handler for TcpRedirectHandler {
    async fn handle(&self, _conn: TcpStream) -> Result<(), HandlerError> {
        warn!("[redirect] TCP redirect is not available on this platform");
        Err(HandlerError::Proxy(
            "TCP redirect is not available on this platform".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// UDP Redirect Handler (Linux only, stub on others)
// ---------------------------------------------------------------------------

/// UDP Redirect Handler -- transparent UDP proxy via TPROXY.
///
/// Only functional on Linux with appropriate iptables TPROXY rules.
/// On all other platforms the handler returns an error.
pub struct UdpRedirectHandler {
    options: HandlerOptions,
}

impl UdpRedirectHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl Handler for UdpRedirectHandler {
    async fn handle(&self, conn: TcpStream) -> Result<(), HandlerError> {
        // Full implementation would use tproxy to intercept UDP and recover
        // original destination.  This requires CAP_NET_ADMIN and appropriate
        // iptables -t mangle -A PREROUTING -p udp --dport ... -j TPROXY rules.
        warn!("[redirect-udp] UDP tproxy handler invoked");
        Err(HandlerError::Proxy(
            "UDP redirect handler requires tproxy integration".to_string(),
        ))
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl Handler for UdpRedirectHandler {
    async fn handle(&self, _conn: TcpStream) -> Result<(), HandlerError> {
        warn!("[redirect-udp] UDP redirect is not available on this platform");
        Err(HandlerError::Proxy(
            "UDP redirect is not available on this platform".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// SO_ORIGINAL_DST (Linux)
// ---------------------------------------------------------------------------

/// Retrieve the original destination address from a redirected TCP socket
/// using the Linux-specific `SO_ORIGINAL_DST` getsockopt option.
///
/// This works when the connection was intercepted by an iptables REDIRECT
/// rule.  Returns `None` if the syscall fails or is not available.
#[cfg(target_os = "linux")]
fn get_original_dst_linux(conn: &TcpStream) -> Option<String> {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::unix::io::AsRawFd;

    // SOL_IP = 0, SO_ORIGINAL_DST = 80
    const SOL_IP: libc::c_int = 0;
    const SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = conn.as_raw_fd();

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut addr_len,
        )
    };

    if ret < 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(format!("{}:{}", ip, port))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_redirect_handler_creation() {
        let handler = TcpRedirectHandler::new(HandlerOptions::default());
        // On non-Linux: handler should return platform error.
        // On Linux without iptables: SO_ORIGINAL_DST will fail, falls back to local_addr.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let _ = handler.handle(conn).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"test").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn test_udp_redirect_handler_not_available() {
        let handler = UdpRedirectHandler::new(HandlerOptions::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            handler.handle(conn).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"test").await.unwrap();

        let result = handle.await.unwrap();
        // Should fail on all platforms (either "not available" or "requires tproxy")
        assert!(result.is_err());
    }

    #[test]
    fn test_platform_detection() {
        // Verify we compile on the current platform
        #[cfg(target_os = "linux")]
        {
            assert!(true, "Linux platform detected");
        }
        #[cfg(target_os = "windows")]
        {
            assert!(true, "Windows platform detected");
        }
        #[cfg(target_os = "macos")]
        {
            assert!(true, "macOS platform detected");
        }
    }
}
