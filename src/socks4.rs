use std::net::Ipv4Addr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// SOCKS4 constants
const SOCKS4_VERSION: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;

// SOCKS4 reply codes
const REP_GRANTED: u8 = 0x5A;
const REP_REJECTED: u8 = 0x5B;

/// SOCKS4 connector (client side).
pub struct Socks4Connector;

impl Socks4Connector {
    pub fn new() -> Self {
        Self
    }

    /// Perform SOCKS4 CONNECT through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let (host, port) = parse_address(address)?;
        let ip: Ipv4Addr = host
            .parse()
            .map_err(|_| HandlerError::Proxy("SOCKS4 requires IPv4 address".into()))?;

        let mut req = Vec::with_capacity(9);
        req.push(SOCKS4_VERSION);
        req.push(CMD_CONNECT);
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00); // null-terminated user ID

        conn.write_all(&req).await?;

        let mut resp = [0u8; 8];
        conn.read_exact(&mut resp).await?;

        if resp[1] != REP_GRANTED {
            return Err(HandlerError::Proxy(format!(
                "SOCKS4 connect rejected: code {}",
                resp[1]
            )));
        }

        Ok(conn)
    }
}

/// SOCKS4a connector (client side) - supports domain names.
pub struct Socks4aConnector;

impl Socks4aConnector {
    pub fn new() -> Self {
        Self
    }

    /// Perform SOCKS4a CONNECT through proxy (supports domain names).
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let (host, port) = parse_address(address)?;

        let mut req = Vec::new();
        req.push(SOCKS4_VERSION);
        req.push(CMD_CONNECT);
        req.extend_from_slice(&port.to_be_bytes());

        // For SOCKS4a: use invalid IP 0.0.0.x where x != 0
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            req.extend_from_slice(&ip.octets());
            req.push(0x00); // null-terminated user ID
        } else {
            req.extend_from_slice(&[0, 0, 0, 1]); // 0.0.0.1 = SOCKS4a domain mode
            req.push(0x00); // null-terminated user ID
            req.extend_from_slice(host.as_bytes());
            req.push(0x00); // null-terminated domain
        }

        conn.write_all(&req).await?;

        let mut resp = [0u8; 8];
        conn.read_exact(&mut resp).await?;

        if resp[1] != REP_GRANTED {
            return Err(HandlerError::Proxy(format!(
                "SOCKS4a connect rejected: code {}",
                resp[1]
            )));
        }

        Ok(conn)
    }
}

/// SOCKS4(a) handler (server side).
pub struct Socks4Handler {
    options: HandlerOptions,
}

impl Socks4Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl Handler for Socks4Handler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Read version byte (already peeked by auto handler)
        let mut ver = [0u8; 1];
        conn.read_exact(&mut ver).await?;
        if ver[0] != SOCKS4_VERSION {
            return Err(HandlerError::Proxy(format!(
                "unsupported SOCKS version: {}",
                ver[0]
            )));
        }

        // Read command
        let mut cmd = [0u8; 1];
        conn.read_exact(&mut cmd).await?;

        // Read port
        let mut port_buf = [0u8; 2];
        conn.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read IP
        let mut ip_buf = [0u8; 4];
        conn.read_exact(&mut ip_buf).await?;
        let ip = Ipv4Addr::from(ip_buf);

        // Read user ID (null terminated)
        let mut user_id = Vec::new();
        loop {
            let mut b = [0u8; 1];
            conn.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            user_id.push(b[0]);
        }

        // Check for SOCKS4a: IP is 0.0.0.x where x != 0
        let is_socks4a = ip_buf[0] == 0 && ip_buf[1] == 0 && ip_buf[2] == 0 && ip_buf[3] != 0;
        let host = if is_socks4a {
            // Read domain name (null terminated)
            let mut domain = Vec::new();
            loop {
                let mut b = [0u8; 1];
                conn.read_exact(&mut b).await?;
                if b[0] == 0 {
                    break;
                }
                domain.push(b[0]);
            }
            String::from_utf8_lossy(&domain).to_string()
        } else {
            ip.to_string()
        };

        let target = format!("{}:{}", host, port);
        info!("[socks4] {} -> {}", peer_addr, target);

        match cmd[0] {
            CMD_CONNECT => {
                // Check permissions
                if !Can(
                    "tcp",
                    &target,
                    self.options.whitelist.as_ref(),
                    self.options.blacklist.as_ref(),
                ) {
                    send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                    return Err(HandlerError::Forbidden);
                }

                // Check bypass
                if let Some(ref bypass) = self.options.bypass {
                    if bypass.contains(&target) {
                        send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                        return Ok(());
                    }
                }

                let chain = self
                    .options
                    .chain
                    .as_ref()
                    .cloned()
                    .unwrap_or_default();

                match chain.dial(&target).await {
                    Ok(cc) => {
                        let local = cc
                            .local_addr()
                            .map(|a| a.ip().to_string())
                            .unwrap_or_else(|_| "0.0.0.0".into());
                        let local_port = cc.local_addr().map(|a| a.port()).unwrap_or(0);
                        send_reply(&mut conn, REP_GRANTED, &local, local_port).await?;

                        info!("[socks4] {} <-> {}", peer_addr, target);
                        transport(conn, cc).await.ok();
                        info!("[socks4] {} >-< {}", peer_addr, target);
                    }
                    Err(e) => {
                        debug!("[socks4] {} -> {} : {}", peer_addr, target, e);
                        send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                        return Err(HandlerError::Chain(e));
                    }
                }
            }
            _ => {
                send_reply(&mut conn, REP_REJECTED, "0.0.0.0", 0).await?;
                return Err(HandlerError::Proxy(format!(
                    "unsupported SOCKS4 command: {}",
                    cmd[0]
                )));
            }
        }

        Ok(())
    }
}

async fn send_reply(
    conn: &mut TcpStream,
    code: u8,
    addr: &str,
    port: u16,
) -> Result<(), HandlerError> {
    let ip: Ipv4Addr = addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut reply = vec![0x00, code]; // VN=0, CD=code
    reply.extend_from_slice(&port.to_be_bytes());
    reply.extend_from_slice(&ip.octets());
    conn.write_all(&reply).await?;
    Ok(())
}

fn parse_address(addr: &str) -> Result<(String, u16), HandlerError> {
    let (host, port_str) = addr.rsplit_once(':').ok_or_else(|| {
        HandlerError::Proxy(format!("invalid address: {}", addr))
    })?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| HandlerError::Proxy(format!("invalid port: {}", port_str)))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks4_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks4 ok").await.unwrap();
        });

        // Start SOCKS4 proxy
        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SOCKS4 client
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let ip = match target_addr.ip() {
            std::net::IpAddr::V4(ip4) => ip4,
            _ => panic!("expected IPv4"),
        };
        let port = target_addr.port();

        let mut req = vec![0x04, 0x01]; // VER=4, CMD=CONNECT
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip.octets());
        req.push(0x00); // null user ID
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x5A); // granted

        // Read data from target
        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks4 ok");
    }

    #[tokio::test]
    async fn test_socks4a_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks4a ok").await.unwrap();
        });

        // Start SOCKS4 proxy (supports 4a)
        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SOCKS4a client (with domain name as IP address)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        let port = target_addr.port();
        let _target_host = format!("127.0.0.1:{}", port);

        // Use the Socks4aConnector for simplicity, but manually test the domain path
        let mut req = vec![0x04, 0x01]; // VER=4, CMD=CONNECT
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]); // SOCKS4a indicator
        req.push(0x00); // null user ID
        req.extend_from_slice(b"127.0.0.1");
        req.push(0x00); // null domain terminator
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 8];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x5A); // granted

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks4a ok");
    }

    #[tokio::test]
    async fn test_socks4_connector() {
        // Start SOCKS4 proxy with our handler
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"from target").await.unwrap();
        });

        let handler = Socks4Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Use Socks4Connector
        let connector = Socks4Connector::new();
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector
            .connect(stream, &target_addr.to_string())
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from target");
    }
}
