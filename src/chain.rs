use std::time::Duration;

use tokio::net::TcpStream;
use tracing::debug;

use crate::hosts::Hosts;
use crate::node::{Node, NodeGroup};

/// Chain is a proxy chain that holds a list of proxy node groups.
#[derive(Clone, Debug)]
pub struct Chain {
    pub retries: usize,
    pub mark: i32,
    pub interface: String,
    node_groups: Vec<NodeGroup>,
    is_route: bool,
}

impl Chain {
    pub fn new(nodes: Vec<Node>) -> Self {
        let node_groups = nodes.into_iter().map(|n| NodeGroup::new(vec![n])).collect();
        Chain {
            retries: 0,
            mark: 0,
            interface: String::new(),
            node_groups,
            is_route: false,
        }
    }

    pub fn empty() -> Self {
        Chain {
            retries: 0,
            mark: 0,
            interface: String::new(),
            node_groups: Vec::new(),
            is_route: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.node_groups.is_empty()
    }

    pub fn nodes(&self) -> Vec<Node> {
        self.node_groups
            .iter()
            .filter_map(|g| g.get_node(0))
            .collect()
    }

    pub fn last_node(&self) -> Node {
        if self.is_empty() {
            return Node::default();
        }
        self.node_groups
            .last()
            .and_then(|g| g.get_node(0))
            .unwrap_or_default()
    }

    pub fn add_node(&mut self, node: Node) {
        self.node_groups.push(NodeGroup::new(vec![node]));
    }

    pub fn add_node_group(&mut self, group: NodeGroup) {
        self.node_groups.push(group);
    }

    /// Dial connects to the target address through the chain.
    pub async fn dial(&self, address: &str) -> Result<TcpStream, ChainError> {
        self.dial_with_options(address, &ChainOptions::default())
            .await
    }

    pub async fn dial_with_options(
        &self,
        address: &str,
        options: &ChainOptions,
    ) -> Result<TcpStream, ChainError> {
        let retries = if self.retries > 0 {
            self.retries
        } else if options.retries > 0 {
            options.retries
        } else {
            1
        };

        let mut last_err = ChainError::EmptyChain;
        for _ in 0..retries {
            match self.dial_once(address, options).await {
                Ok(conn) => return Ok(conn),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn dial_once(
        &self,
        address: &str,
        options: &ChainOptions,
    ) -> Result<TcpStream, ChainError> {
        // Resolve address if needed
        let resolved = self.resolve(address, options.resolver.as_ref(), options.hosts.as_ref());
        let target = if resolved.is_empty() {
            address.to_string()
        } else {
            resolved
        };

        let timeout = if options.timeout > Duration::ZERO {
            options.timeout
        } else {
            Duration::from_secs(crate::DIAL_TIMEOUT)
        };

        if self.is_empty() {
            // Direct connection
            let conn = tokio::time::timeout(timeout, TcpStream::connect(&target))
                .await
                .map_err(|_| ChainError::Timeout)?
                .map_err(ChainError::Io)?;
            return Ok(conn);
        }

        // Connect through proxy chain
        let nodes = self.nodes();
        if nodes.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // Connect to first node
        let first = &nodes[0];
        debug!("[chain] connecting to first node: {}", first.addr);
        let conn = tokio::time::timeout(timeout, TcpStream::connect(&first.addr))
            .await
            .map_err(|_| ChainError::Timeout)?
            .map_err(ChainError::Io)?;

        // For a simple single-hop chain, we need to do CONNECT through the proxy
        // This is handled by the connector in the full implementation
        if nodes.len() == 1 {
            // Use the first node's protocol to CONNECT to the target
            match first.protocol.as_str() {
                "http" => {
                    return http_connect(conn, &target).await;
                }
                "socks5" => {
                    return socks5_connect(conn, &target).await;
                }
                _ => {
                    // For direct/forward connections, just return the conn to the first node
                    return Ok(conn);
                }
            }
        }

        // Multi-hop chain: connect through each node
        let mut current = conn;
        for (i, node) in nodes.iter().enumerate() {
            if i == nodes.len() - 1 {
                // Last node: connect to the actual target
                match node.protocol.as_str() {
                    "http" => {
                        current = http_connect(current, &target).await?;
                    }
                    "socks5" => {
                        current = socks5_connect(current, &target).await?;
                    }
                    _ => {}
                }
            } else {
                // Intermediate node: connect to the next node
                let next = &nodes[i + 1];
                match node.protocol.as_str() {
                    "http" => {
                        current = http_connect(current, &next.addr).await?;
                    }
                    "socks5" => {
                        current = socks5_connect(current, &next.addr).await?;
                    }
                    _ => {}
                }
            }
        }

        Ok(current)
    }

    fn resolve(
        &self,
        addr: &str,
        resolver: Option<&crate::resolver::Resolver>,
        hosts: Option<&Hosts>,
    ) -> String {
        if let Some((host, port)) = addr.rsplit_once(':') {
            // Check hosts table first
            if let Some(hosts) = hosts {
                if let Some(ip) = hosts.lookup(host) {
                    return format!("{}:{}", ip, port);
                }
            }

            // Then try resolver
            if let Some(_resolver) = resolver {
                // DNS resolution would go here
                // For now, return the original address
            }

            addr.to_string()
        } else {
            addr.to_string()
        }
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::empty()
    }
}

/// HTTP CONNECT tunnel through a proxy.
async fn http_connect(mut stream: TcpStream, target: &str) -> Result<TcpStream, ChainError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let req =
        format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target, target, crate::DEFAULT_USER_AGENT
    );

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(ChainError::Io)?;

    // Read response
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.map_err(ChainError::Io)?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains("200") {
        Ok(stream)
    } else {
        Err(ChainError::ProxyError(format!(
            "HTTP CONNECT failed: {}",
            response.lines().next().unwrap_or("unknown")
        )))
    }
}

/// SOCKS5 CONNECT through a proxy.
async fn socks5_connect(mut stream: TcpStream, target: &str) -> Result<TcpStream, ChainError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // SOCKS5 handshake: send greeting
    stream
        .write_all(&[0x05, 0x01, 0x00]) // ver=5, 1 method, no auth
        .await
        .map_err(ChainError::Io)?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.map_err(ChainError::Io)?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err(ChainError::ProxyError("SOCKS5 handshake failed".into()));
    }

    // Parse target
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| ChainError::ProxyError("invalid target address".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ChainError::ProxyError("invalid port".into()))?;

    // Send CONNECT request
    let mut req = vec![0x05, 0x01, 0x00]; // ver, cmd=connect, rsv
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01); // IPv4
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04); // IPv6
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03); // Domain
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await.map_err(ChainError::Io)?;

    // Read response
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await.map_err(ChainError::Io)?;

    if resp[1] != 0x00 {
        return Err(ChainError::ProxyError(format!(
            "SOCKS5 connect failed with code: {}",
            resp[1]
        )));
    }

    // Read the rest of the response based on address type
    match resp[3] {
        0x01 => {
            let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(ChainError::Io)?;
            let mut addr = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        0x04 => {
            let mut addr = [0u8; 18]; // 16 bytes IPv6 + 2 bytes port
            stream.read_exact(&mut addr).await.map_err(ChainError::Io)?;
        }
        _ => {}
    }

    Ok(stream)
}

/// ChainOptions holds options for Chain.
#[derive(Clone, Default)]
pub struct ChainOptions {
    pub retries: usize,
    pub timeout: Duration,
    pub hosts: Option<Hosts>,
    pub resolver: Option<crate::resolver::Resolver>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("empty chain")]
    EmptyChain,
    #[error("connection timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy error: {0}")]
    ProxyError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::Handler; // needed for .handle() method

    #[test]
    fn test_chain_empty() {
        let c = Chain::empty();
        assert!(c.is_empty());
        assert_eq!(c.nodes().len(), 0);
    }

    #[test]
    fn test_chain_new() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("socks5://localhost:1080").unwrap();
        let c = Chain::new(vec![n1, n2]);
        assert!(!c.is_empty());
        assert_eq!(c.nodes().len(), 2);
    }

    #[test]
    fn test_chain_last_node() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("socks5://localhost:1080").unwrap();
        let c = Chain::new(vec![n1, n2]);
        assert_eq!(c.last_node().addr, "localhost:1080");
    }

    #[test]
    fn test_chain_last_node_empty() {
        let c = Chain::empty();
        assert!(c.last_node().addr.is_empty());
    }

    #[test]
    fn test_chain_add_node() {
        let mut c = Chain::empty();
        c.add_node(Node::parse("http://localhost:8080").unwrap());
        assert!(!c.is_empty());
        assert_eq!(c.nodes().len(), 1);
    }

    #[tokio::test]
    async fn test_chain_direct_dial() {
        // Start a simple TCP listener to test direct connection
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let c = Chain::empty();
        let handle = tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
        });

        let conn = c.dial(&addr.to_string()).await;
        assert!(conn.is_ok());
        handle.await.ok();
    }

    #[tokio::test]
    async fn test_chain_direct_dial_timeout() {
        // Connect to a non-routable address to trigger timeout
        let c = Chain::empty();
        let opts = ChainOptions {
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let result = c.dial_with_options("192.0.2.1:12345", &opts).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chain_direct_dial_invalid_address() {
        let c = Chain::empty();
        let result = c.dial("not-a-real-host-that-exists.invalid:9999").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chain_dial_through_http_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a target server
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"chain-target-data").await.unwrap();
        });

        // Start an HTTP proxy
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let handler =
                crate::http_proxy::HttpHandler::new(crate::handler::HandlerOptions::default());
            let (conn, _) = proxy_listener.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Create chain with the HTTP proxy
        let proxy_node = Node::parse(&format!("http://{}", proxy_addr)).unwrap();
        let chain = Chain::new(vec![proxy_node]);

        let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"chain-target-data");
    }

    #[tokio::test]
    async fn test_chain_dial_through_socks5_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a target server
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"socks5-chain-data").await.unwrap();
        });

        // Start a SOCKS5 proxy
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let handler =
                crate::socks5::Socks5Handler::new(crate::handler::HandlerOptions::default());
            let (conn, _) = proxy_listener.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Create chain with the SOCKS5 proxy
        let proxy_node = Node::parse(&format!("socks5://{}", proxy_addr)).unwrap();
        let chain = Chain::new(vec![proxy_node]);

        let mut conn = chain.dial(&target_addr.to_string()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"socks5-chain-data");
    }

    #[tokio::test]
    async fn test_chain_with_retries() {
        // Test that retries work on failure
        let c = Chain::empty();
        let opts = ChainOptions {
            retries: 3,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        // Connect to unreachable address; should fail after 3 retries
        let result = c.dial_with_options("192.0.2.1:12345", &opts).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_clone() {
        let n = Node::parse("http://localhost:8080").unwrap();
        let mut c = Chain::new(vec![n]);
        c.mark = 42;
        c.interface = "eth0".to_string();
        c.retries = 3;

        let c2 = c.clone();
        assert_eq!(c2.mark, 42);
        assert_eq!(c2.interface, "eth0");
        assert_eq!(c2.retries, 3);
        assert_eq!(c2.nodes().len(), 1);
    }

    #[test]
    fn test_chain_resolve_with_hosts() {
        let mut hosts = Hosts::new(vec![]);
        hosts.add_host(crate::hosts::Host::new(
            "10.0.0.1".parse().unwrap(),
            "myhost",
            vec![],
        ));

        let c = Chain::empty();
        let resolved = c.resolve("myhost:80", None, Some(&hosts));
        assert_eq!(resolved, "10.0.0.1:80");
    }

    #[test]
    fn test_chain_resolve_no_hosts() {
        let c = Chain::empty();
        let resolved = c.resolve("example.com:443", None, None);
        assert_eq!(resolved, "example.com:443");
    }

    #[test]
    fn test_chain_add_node_group() {
        let mut c = Chain::empty();
        let group = NodeGroup::new(vec![
            Node::parse("http://a:1").unwrap(),
            Node::parse("http://b:2").unwrap(),
        ]);
        c.add_node_group(group);
        assert_eq!(c.nodes().len(), 1); // first node of group
    }

    #[test]
    fn test_chain_default() {
        let c = Chain::default();
        assert!(c.is_empty());
        assert_eq!(c.retries, 0);
        assert_eq!(c.mark, 0);
    }
}
