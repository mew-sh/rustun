use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 connector (client side).
pub struct Socks5Connector {
    pub user: Option<(String, Option<String>)>,
}

impl Socks5Connector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Perform SOCKS5 handshake and CONNECT through proxy.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        // Determine methods
        let methods = if self.user.is_some() {
            vec![METHOD_NO_AUTH, METHOD_USER_PASS]
        } else {
            vec![METHOD_NO_AUTH]
        };

        // Send greeting
        let mut greeting = vec![SOCKS5_VERSION, methods.len() as u8];
        greeting.extend_from_slice(&methods);
        conn.write_all(&greeting).await?;

        // Read server choice
        let mut resp = [0u8; 2];
        conn.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy("invalid SOCKS5 version".into()));
        }

        // Handle auth if required
        if resp[1] == METHOD_USER_PASS {
            if let Some((ref user, ref pass)) = self.user {
                let p = pass.as_deref().unwrap_or("");
                let mut auth = vec![0x01, user.len() as u8];
                auth.extend_from_slice(user.as_bytes());
                auth.push(p.len() as u8);
                auth.extend_from_slice(p.as_bytes());
                conn.write_all(&auth).await?;

                let mut auth_resp = [0u8; 2];
                conn.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    return Err(HandlerError::AuthFailed);
                }
            } else {
                return Err(HandlerError::AuthFailed);
            }
        } else if resp[1] == METHOD_NO_ACCEPTABLE {
            return Err(HandlerError::Proxy("no acceptable method".into()));
        }

        // Send CONNECT request
        let (host, port) = parse_address(address)?;
        let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
        encode_address(&host, port, &mut req);
        conn.write_all(&req).await?;

        // Read reply
        let mut reply = [0u8; 4];
        conn.read_exact(&mut reply).await?;
        if reply[1] != REP_SUCCESS {
            return Err(HandlerError::Proxy(format!(
                "SOCKS5 connect failed: code {}",
                reply[1]
            )));
        }

        // Skip bound address
        skip_address(&mut conn, reply[3]).await?;

        Ok(conn)
    }
}

/// SOCKS5 handler (server side).
pub struct Socks5Handler {
    options: HandlerOptions,
}

impl Socks5Handler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }

    async fn authenticate(
        &self,
        user: &str,
        password: &str,
    ) -> bool {
        if let Some(ref auth) = self.options.authenticator {
            auth.authenticate(user, password)
        } else {
            true
        }
    }
}

#[async_trait]
impl Handler for Socks5Handler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Read greeting
        let mut ver = [0u8; 1];
        conn.read_exact(&mut ver).await?;
        if ver[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy(format!(
                "unsupported SOCKS version: {}",
                ver[0]
            )));
        }

        let mut nmethods = [0u8; 1];
        conn.read_exact(&mut nmethods).await?;
        let mut methods = vec![0u8; nmethods[0] as usize];
        conn.read_exact(&mut methods).await?;

        let requires_auth = self.options.authenticator.is_some();

        if requires_auth {
            if methods.contains(&METHOD_USER_PASS) {
                conn.write_all(&[SOCKS5_VERSION, METHOD_USER_PASS]).await?;

                // Read auth request
                let mut auth_ver = [0u8; 1];
                conn.read_exact(&mut auth_ver).await?;

                let mut ulen = [0u8; 1];
                conn.read_exact(&mut ulen).await?;
                let mut uname = vec![0u8; ulen[0] as usize];
                conn.read_exact(&mut uname).await?;

                let mut plen = [0u8; 1];
                conn.read_exact(&mut plen).await?;
                let mut passwd = vec![0u8; plen[0] as usize];
                conn.read_exact(&mut passwd).await?;

                let user = String::from_utf8_lossy(&uname).to_string();
                let pass = String::from_utf8_lossy(&passwd).to_string();

                if self.authenticate(&user, &pass).await {
                    conn.write_all(&[0x01, 0x00]).await?;
                    debug!("[socks5] {} authenticated as {}", peer_addr, user);
                } else {
                    conn.write_all(&[0x01, 0x01]).await?;
                    warn!(
                        "[socks5] {} authentication failed for {}",
                        peer_addr, user
                    );
                    return Err(HandlerError::AuthFailed);
                }
            } else {
                conn.write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
                    .await?;
                return Err(HandlerError::AuthFailed);
            }
        } else {
            conn.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH]).await?;
        }

        // Read request
        let mut req_header = [0u8; 4];
        conn.read_exact(&mut req_header).await?;

        if req_header[0] != SOCKS5_VERSION {
            return Err(HandlerError::Proxy("invalid version in request".into()));
        }

        let (host, port) = read_address(&mut conn, req_header[3]).await?;
        let target = format!("{}:{}", host, port);

        info!("[socks5] {} -> {}", peer_addr, target);

        match req_header[1] {
            CMD_CONNECT => {
                // Check permissions
                if !Can(
                    "tcp",
                    &target,
                    self.options.whitelist.as_ref(),
                    self.options.blacklist.as_ref(),
                ) {
                    send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
                    return Err(HandlerError::Forbidden);
                }

                // Check bypass
                if let Some(ref bypass) = self.options.bypass {
                    if bypass.contains(&target) {
                        send_reply(&mut conn, REP_NOT_ALLOWED, "0.0.0.0", 0).await?;
                        return Ok(());
                    }
                }

                // Connect through chain
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
                            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                        send_reply(
                            &mut conn,
                            REP_SUCCESS,
                            &local.ip().to_string(),
                            local.port(),
                        )
                        .await?;

                        info!("[socks5] {} <-> {}", peer_addr, target);
                        transport(conn, cc).await.ok();
                        info!("[socks5] {} >-< {}", peer_addr, target);
                    }
                    Err(e) => {
                        debug!("[socks5] {} -> {} : {}", peer_addr, target, e);
                        send_reply(&mut conn, REP_HOST_UNREACHABLE, "0.0.0.0", 0).await?;
                        return Err(HandlerError::Chain(e));
                    }
                }
            }
            CMD_UDP_ASSOCIATE => {
                // UDP associate - simplified: just reply with our address
                let local = conn
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                send_reply(
                    &mut conn,
                    REP_SUCCESS,
                    &local.ip().to_string(),
                    local.port(),
                )
                .await?;
                // Keep connection alive until client disconnects
                let mut buf = [0u8; 1];
                conn.read(&mut buf).await.ok();
            }
            _ => {
                send_reply(&mut conn, REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0).await?;
                return Err(HandlerError::Proxy(format!(
                    "unsupported command: {}",
                    req_header[1]
                )));
            }
        }

        Ok(())
    }
}

async fn send_reply(
    conn: &mut TcpStream,
    rep: u8,
    addr: &str,
    port: u16,
) -> Result<(), HandlerError> {
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00];
    if let Ok(ip) = addr.parse::<Ipv4Addr>() {
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = addr.parse::<Ipv6Addr>() {
        reply.push(ATYP_IPV6);
        reply.extend_from_slice(&ip.octets());
    } else {
        reply.push(ATYP_IPV4);
        reply.extend_from_slice(&[0, 0, 0, 0]);
    }
    reply.extend_from_slice(&port.to_be_bytes());
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

fn encode_address(host: &str, port: u16, buf: &mut Vec<u8>) {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.push(ATYP_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

async fn read_address(
    conn: &mut TcpStream,
    atyp: u8,
) -> Result<(String, u16), HandlerError> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            conn.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            conn.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => return Err(HandlerError::Proxy(format!("unsupported atyp: {}", atyp))),
    };

    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

async fn skip_address(conn: &mut TcpStream, atyp: u8) -> Result<(), HandlerError> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 + 2
            conn.read_exact(&mut buf).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            conn.read_exact(&mut buf).await?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 + 2
            conn.read_exact(&mut buf).await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"hello from socks5 target").await.unwrap();
        });

        // Start SOCKS5 proxy
        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SOCKS5 client
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // CONNECT request
        let ip = target_addr.ip();
        let port = target_addr.port();
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        if let std::net::IpAddr::V4(ip4) = ip {
            req.extend_from_slice(&ip4.octets());
        }
        req.extend_from_slice(&port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // version
        assert_eq!(reply[1], 0x00); // success

        // Skip bound address
        skip_address(&mut client, reply[3]).await.unwrap();

        // Read data from target
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from socks5 target");
    }

    #[tokio::test]
    async fn test_socks5_handler_with_auth() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("user".into(), "pass".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = Socks5Handler::new(HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting with user/pass method
        client
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x05);
        assert_eq!(resp[1], 0x02); // user/pass required

        // Send auth - wrong password
        let auth_req = [0x01, 4, b'u', b's', b'e', b'r', 5, b'w', b'r', b'o', b'n', b'g'];
        client.write_all(&auth_req).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_ne!(auth_resp[1], 0x00); // auth failed
    }

    #[test]
    fn test_parse_address() {
        let (host, port) = parse_address("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_encode_address_ipv4() {
        let mut buf = Vec::new();
        encode_address("127.0.0.1", 80, &mut buf);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[127, 0, 0, 1]);
        assert_eq!(&buf[5..7], &[0, 80]);
    }

    #[test]
    fn test_encode_address_domain() {
        let mut buf = Vec::new();
        encode_address("example.com", 443, &mut buf);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // "example.com" length
        assert_eq!(&buf[2..13], b"example.com");
    }

    #[test]
    fn test_encode_address_ipv6() {
        let mut buf = Vec::new();
        encode_address("::1", 8080, &mut buf);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2); // type + 16 bytes IPv6 + port
    }

    #[test]
    fn test_parse_address_valid() {
        let (h, p) = parse_address("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_address_invalid_no_port() {
        assert!(parse_address("example.com").is_err());
    }

    #[test]
    fn test_parse_address_invalid_port() {
        assert!(parse_address("example.com:notaport").is_err());
    }

    #[tokio::test]
    async fn test_socks5_handler_domain_connect() {
        // Test connecting via domain name (not IP)
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"domain-connect").await.unwrap();
        });

        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        // CONNECT with domain address type
        let host = format!("127.0.0.1");
        let port = target_addr.port();
        let mut req = vec![0x05, 0x01, 0x00, 0x03]; // ver, connect, rsv, domain
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        client.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00); // success

        skip_address(&mut client, reply[3]).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"domain-connect");
    }

    #[tokio::test]
    async fn test_socks5_handler_unsupported_command() {
        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // Send BIND command (0x02) which is not fully supported
        let req = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        client.write_all(&req).await.unwrap();

        let mut reply = [0u8; 4];
        let result = client.read_exact(&mut reply).await;
        if result.is_ok() {
            assert_eq!(reply[1], REP_CMD_NOT_SUPPORTED);
        }
    }

    #[tokio::test]
    async fn test_socks5_handler_with_bypass() {
        use std::sync::Arc;

        let bypass = Arc::new(crate::bypass::Bypass::from_patterns(false, &["blocked.com"]));
        let handler = Socks5Handler::new(HandlerOptions {
            bypass: Some(bypass),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();

        // Greeting
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CONNECT to bypassed domain
        let host = b"blocked.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        req.push(host.len() as u8);
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut reply = [0u8; 4];
        let result = client.read_exact(&mut reply).await;
        if result.is_ok() {
            assert_eq!(reply[1], REP_NOT_ALLOWED);
        }
    }

    #[tokio::test]
    async fn test_socks5_connector_basic() {
        // Start a real SOCKS5 proxy
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"connector-test").await.unwrap();
        });

        let handler = Socks5Handler::new(HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let connector = Socks5Connector::new(None);
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector
            .connect(stream, &target_addr.to_string())
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"connector-test");
    }
}
