use std::net::IpAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::{Node, NodeGroup};
use crate::permissions::Can;
use crate::transport::transport;

// Relay protocol constants
const RELAY_VERSION1: u8 = 0x01;
const RELAY_STATUS_OK: u8 = 0x00;
const RELAY_STATUS_BAD_REQUEST: u8 = 0x01;
const RELAY_STATUS_UNAUTHORIZED: u8 = 0x02;
const RELAY_STATUS_FORBIDDEN: u8 = 0x03;
const RELAY_STATUS_SERVICE_UNAVAILABLE: u8 = 0x04;

const RELAY_FLAG_UDP: u8 = 0x01;

const FEATURE_USER_AUTH: u8 = 0x01;
const FEATURE_ADDR: u8 = 0x02;

const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;
const ADDR_DOMAIN: u8 = 0x03;

/// Relay connector (client side).
pub struct RelayConnector {
    pub user: Option<(String, Option<String>)>,
}

impl RelayConnector {
    pub fn new(user: Option<(String, Option<String>)>) -> Self {
        Self { user }
    }

    /// Connect via relay protocol.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        network: &str,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        let udp = matches!(network, "udp" | "udp4" | "udp6");

        let mut req = Vec::new();
        req.push(RELAY_VERSION1);
        let flags = if udp { RELAY_FLAG_UDP } else { 0 };
        req.push(flags);

        // Add features length placeholder - we'll fill the features inline
        let mut features = Vec::new();

        // User auth feature
        if let Some((ref user, ref pass)) = self.user {
            let p = pass.as_deref().unwrap_or("");
            features.push(FEATURE_USER_AUTH);
            let user_bytes = user.as_bytes();
            let pass_bytes = p.as_bytes();
            let flen = 1 + user_bytes.len() + 1 + pass_bytes.len();
            features.extend_from_slice(&(flen as u16).to_be_bytes());
            features.push(user_bytes.len() as u8);
            features.extend_from_slice(user_bytes);
            features.push(pass_bytes.len() as u8);
            features.extend_from_slice(pass_bytes);
        }

        // Address feature
        if !address.is_empty() {
            if let Some((host, port_str)) = address.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    features.push(FEATURE_ADDR);
                    let mut addr_data = Vec::new();
                    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                        addr_data.push(ADDR_IPV4);
                        addr_data.extend_from_slice(&ip.octets());
                    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                        addr_data.push(ADDR_IPV6);
                        addr_data.extend_from_slice(&ip.octets());
                    } else {
                        addr_data.push(ADDR_DOMAIN);
                        addr_data.push(host.len() as u8);
                        addr_data.extend_from_slice(host.as_bytes());
                    }
                    addr_data.extend_from_slice(&port.to_be_bytes());

                    features.extend_from_slice(&(addr_data.len() as u16).to_be_bytes());
                    features.extend_from_slice(&addr_data);
                }
            }
        }

        // Write number of features
        req.push(features.len() as u8);
        req.extend_from_slice(&features);

        conn.write_all(&req).await?;

        // Read response
        let mut resp = [0u8; 3];
        conn.read_exact(&mut resp).await?;

        if resp[0] != RELAY_VERSION1 {
            return Err(HandlerError::Proxy("relay: bad version".into()));
        }
        if resp[1] != RELAY_STATUS_OK {
            return Err(HandlerError::Proxy(format!("relay: status {}", resp[1])));
        }

        Ok(conn)
    }
}

/// Relay handler (server side).
pub struct RelayHandler {
    raddr: String,
    group: NodeGroup,
    options: HandlerOptions,
}

impl RelayHandler {
    pub fn new(raddr: &str, options: HandlerOptions) -> Self {
        let group = NodeGroup::new(Vec::new());
        let addrs: Vec<&str> = raddr.split(',').filter(|a| !a.is_empty()).collect();
        for (i, addr) in addrs.iter().enumerate() {
            let mut node = Node::default();
            node.id = i + 1;
            node.addr = addr.to_string();
            group.add_node(node);
        }

        Self {
            raddr: raddr.to_string(),
            group,
            options,
        }
    }
}

#[async_trait]
impl Handler for RelayHandler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // Read request header
        let mut header = [0u8; 3];
        conn.read_exact(&mut header).await?;

        if header[0] != RELAY_VERSION1 {
            return Err(HandlerError::Proxy("relay: bad version".into()));
        }

        let udp = (header[1] & RELAY_FLAG_UDP) != 0;
        let features_len = header[2] as usize;

        // Read features
        let mut features_buf = vec![0u8; features_len];
        if features_len > 0 {
            conn.read_exact(&mut features_buf).await?;
        }

        // Parse features
        let mut user = String::new();
        let mut pass = String::new();
        let mut raddr = String::new();
        let mut pos = 0;

        while pos < features_buf.len() {
            let ftype = features_buf[pos];
            pos += 1;
            if pos + 2 > features_buf.len() {
                break;
            }
            let flen = u16::from_be_bytes([features_buf[pos], features_buf[pos + 1]]) as usize;
            pos += 2;
            if pos + flen > features_buf.len() {
                break;
            }
            let fdata = &features_buf[pos..pos + flen];
            pos += flen;

            match ftype {
                FEATURE_USER_AUTH => {
                    if !fdata.is_empty() {
                        let ulen = fdata[0] as usize;
                        if 1 + ulen < fdata.len() {
                            user = String::from_utf8_lossy(&fdata[1..1 + ulen]).to_string();
                            let plen = fdata[1 + ulen] as usize;
                            if 2 + ulen + plen <= fdata.len() {
                                pass = String::from_utf8_lossy(
                                    &fdata[2 + ulen..2 + ulen + plen],
                                )
                                .to_string();
                            }
                        }
                    }
                }
                FEATURE_ADDR => {
                    if !fdata.is_empty() {
                        let (host, port) = parse_relay_addr(fdata);
                        raddr = format!("{}:{}", host, port);
                    }
                }
                _ => {}
            }
        }

        // Authenticate
        if let Some(ref auth) = self.options.authenticator {
            if !auth.authenticate(&user, &pass) {
                send_relay_reply(&mut conn, RELAY_STATUS_UNAUTHORIZED).await?;
                info!(
                    "[relay] {} -> {} : {} unauthorized",
                    peer_addr,
                    conn.local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                    user
                );
                return Err(HandlerError::AuthFailed);
            }
        }

        // Determine target
        if raddr.is_empty() {
            if self.group.nodes().is_empty() {
                send_relay_reply(&mut conn, RELAY_STATUS_BAD_REQUEST).await?;
                return Err(HandlerError::Proxy("relay: no target address".into()));
            }
        }

        let network = if udp { "udp" } else { "tcp" };
        if !Can(
            network,
            &raddr,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            send_relay_reply(&mut conn, RELAY_STATUS_FORBIDDEN).await?;
            return Err(HandlerError::Forbidden);
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        let mut node = Node::default();
        let target = if !self.group.nodes().is_empty() {
            if let Ok(n) = self.group.next() {
                node = n;
                node.addr.clone()
            } else {
                raddr.clone()
            }
        } else {
            raddr.clone()
        };

        info!("[relay] {} -> {}", peer_addr, target);

        match chain.dial(&target).await {
            Ok(cc) => {
                node.reset_dead();
                send_relay_reply(&mut conn, RELAY_STATUS_OK).await?;

                info!("[relay] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[relay] {} >-< {}", peer_addr, target);
            }
            Err(e) => {
                node.mark_dead();
                send_relay_reply(&mut conn, RELAY_STATUS_SERVICE_UNAVAILABLE).await?;
                return Err(HandlerError::Chain(e));
            }
        }

        Ok(())
    }
}

fn parse_relay_addr(data: &[u8]) -> (String, u16) {
    if data.is_empty() {
        return (String::new(), 0);
    }
    let atype = data[0];
    match atype {
        ADDR_IPV4 if data.len() >= 7 => {
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            (ip.to_string(), port)
        }
        ADDR_IPV6 if data.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            (ip.to_string(), port)
        }
        ADDR_DOMAIN if data.len() >= 2 => {
            let dlen = data[1] as usize;
            if data.len() >= 2 + dlen + 2 {
                let domain = String::from_utf8_lossy(&data[2..2 + dlen]).to_string();
                let port = u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]);
                (domain, port)
            } else {
                (String::new(), 0)
            }
        }
        _ => (String::new(), 0),
    }
}

async fn send_relay_reply(conn: &mut TcpStream, status: u8) -> Result<(), HandlerError> {
    let reply = [RELAY_VERSION1, status, 0x00]; // version, status, no features
    conn.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_relay_handler_connect() {
        // Start a mock target server
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"relay ok").await.unwrap();
        });

        // Start relay handler with target
        let handler = RelayHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Use RelayConnector
        let connector = RelayConnector::new(None);
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Connect without specifying address (handler has fixed target)
        let mut conn = connector.connect(stream, "tcp", "").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"relay ok");
    }

    #[test]
    fn test_parse_relay_addr_ipv4() {
        let data = [ADDR_IPV4, 127, 0, 0, 1, 0, 80];
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_relay_addr_domain() {
        let mut data = vec![ADDR_DOMAIN, 11]; // domain length
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_relay_addr_ipv6() {
        let mut data = vec![ADDR_IPV6];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        data.extend_from_slice(&8080u16.to_be_bytes());
        let (host, port) = parse_relay_addr(&data);
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_relay_addr_empty() {
        let (host, port) = parse_relay_addr(&[]);
        assert!(host.is_empty());
        assert_eq!(port, 0);
    }

    #[tokio::test]
    async fn test_relay_handler_auth_failure() {
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let auth = Arc::new(crate::auth::LocalAuthenticator::new(kvs));

        let handler = RelayHandler::new("", HandlerOptions {
            authenticator: Some(auth),
            ..Default::default()
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Send relay request with no auth
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = [RELAY_VERSION1, 0x00, 0x00]; // version, no flags, no features
        client.write_all(&req).await.unwrap();

        let mut resp = [0u8; 3];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], RELAY_VERSION1);
        assert_eq!(resp[1], RELAY_STATUS_UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_relay_connector_with_auth() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"relay-auth-ok").await.unwrap();
        });

        let handler = RelayHandler::new(&target_addr.to_string(), HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        let connector = RelayConnector::new(Some(("user".into(), Some("pass".into()))));
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let mut conn = connector.connect(stream, "tcp", "").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"relay-auth-ok");
    }
}
