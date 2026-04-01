use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bypass::Bypass;

#[derive(Debug, thiserror::Error)]
pub enum ParseNodeError {
    #[error("invalid node: empty string")]
    Empty,
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("invalid node: {0}")]
    Invalid(String),
}

/// A proxy node, mainly used to construct a proxy chain.
#[derive(Clone, Debug)]
pub struct Node {
    pub id: usize,
    pub addr: String,
    pub host: String,
    pub protocol: String,
    pub transport: String,
    pub remote: String,
    pub user: Option<(String, Option<String>)>, // (username, optional password)
    pub values: HashMap<String, String>,
    pub marker: Arc<FailMarker>,
    pub bypass: Option<Arc<Bypass>>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: 0,
            addr: String::new(),
            host: String::new(),
            protocol: String::new(),
            transport: String::new(),
            remote: String::new(),
            user: None,
            values: HashMap::new(),
            marker: Arc::new(FailMarker::new()),
            bypass: None,
        }
    }
}

impl Node {
    /// Parses the node info from a URL string.
    /// The pattern is [scheme://][user:pass@host]:port[/remote][?params]
    /// Scheme can be split by '+': http+tls means protocol=http, transport=tls
    pub fn parse(s: &str) -> Result<Self, ParseNodeError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseNodeError::Empty);
        }

        let s = if !s.contains("://") {
            format!("auto://{}", s)
        } else {
            s.to_string()
        };

        let u = url::Url::parse(&s)?;

        let addr = u
            .host_str()
            .map(|h| {
                if let Some(port) = u.port() {
                    format!("{}:{}", h, port)
                } else {
                    h.to_string()
                }
            })
            .unwrap_or_default();

        let host = addr.clone();
        let remote = u.path().trim_matches('/').to_string();

        let user = if !u.username().is_empty() {
            Some((
                u.username().to_string(),
                u.password().map(|p| p.to_string()),
            ))
        } else {
            None
        };

        let values: HashMap<String, String> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();

        let scheme = u.scheme();
        let schemes: Vec<&str> = scheme.split('+').collect();

        let (protocol, transport) = if schemes.len() == 2 {
            (schemes[0].to_string(), schemes[1].to_string())
        } else {
            (schemes[0].to_string(), schemes[0].to_string())
        };

        let transport = normalize_transport(&transport);
        let protocol = normalize_protocol(&protocol);

        Ok(Node {
            id: 0,
            addr,
            host,
            protocol,
            transport,
            remote,
            user,
            values,
            marker: Arc::new(FailMarker::new()),
            bypass: None,
        })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.values
            .get(key)
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
    }

    pub fn get_int(&self, key: &str) -> i64 {
        self.values
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    pub fn get_duration(&self, key: &str) -> Duration {
        self.values
            .get(key)
            .and_then(|v| {
                // Try parsing as a Go-style duration (e.g., "5s", "100ms")
                parse_duration(v)
            })
            .unwrap_or(Duration::from_secs(0))
    }

    pub fn mark_dead(&self) {
        self.marker.mark();
    }

    pub fn reset_dead(&self) {
        self.marker.reset();
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.protocol.is_empty() && self.transport.is_empty() {
            write!(f, "auto://{}", self.addr)
        } else if self.protocol == self.transport
            || self.transport == "tcp"
            || self.transport.is_empty()
        {
            write!(f, "{}://{}", self.protocol, self.addr)
        } else {
            write!(f, "{}+{}://{}", self.protocol, self.transport, self.addr)
        }
    }
}

fn normalize_transport(t: &str) -> String {
    match t {
        "https" => "tls".to_string(),
        "tls" | "mtls" | "http2" | "h2" | "h2c" | "ws" | "mws" | "wss" | "mwss" | "kcp"
        | "ssh" | "quic" | "ohttp" | "otls" | "obfs4" | "tcp" | "udp" | "rtcp" | "rudp"
        | "tun" | "tap" | "ftcp" | "dns" | "redu" | "redirectu" | "vsock" | "ssu" => {
            if t == "ssu" {
                "udp".to_string()
            } else {
                t.to_string()
            }
        }
        _ => "tcp".to_string(),
    }
}

fn normalize_protocol(p: &str) -> String {
    match p {
        "https" => "http".to_string(),
        "socks" | "socks5" => "socks5".to_string(),
        "ss2" => "ss".to_string(),
        "http" | "http2" | "socks4" | "socks4a" | "ss" | "ssu" | "sni" | "tcp" | "udp"
        | "rtcp" | "rudp" | "direct" | "remote" | "forward" | "red" | "redirect" | "redu"
        | "redirectu" | "tun" | "tap" | "ftcp" | "dns" | "dot" | "doh" | "relay" => {
            p.to_string()
        }
        "auto" => String::new(),
        _ => String::new(),
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    if let Some(s) = s.strip_suffix("ms") {
        return s.parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(s) = s.strip_suffix('s') {
        return s.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(s) = s.strip_suffix('m') {
        return s.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60));
    }
    if let Some(s) = s.strip_suffix('h') {
        return s
            .parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600));
    }
    None
}

/// FailMarker tracks connection failure state for a node.
#[derive(Debug)]
pub struct FailMarker {
    fail_time: AtomicI64,
    fail_count: AtomicU32,
}

impl FailMarker {
    pub fn new() -> Self {
        Self {
            fail_time: AtomicI64::new(0),
            fail_count: AtomicU32::new(0),
        }
    }

    pub fn mark(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.fail_time.store(now, Ordering::Relaxed);
        self.fail_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.fail_time.store(0, Ordering::Relaxed);
        self.fail_count.store(0, Ordering::Relaxed);
    }

    pub fn fail_time(&self) -> i64 {
        self.fail_time.load(Ordering::Relaxed)
    }

    pub fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    pub fn clone_marker(&self) -> FailMarker {
        FailMarker {
            fail_time: AtomicI64::new(self.fail_time.load(Ordering::Relaxed)),
            fail_count: AtomicU32::new(self.fail_count.load(Ordering::Relaxed)),
        }
    }
}

impl Default for FailMarker {
    fn default() -> Self {
        Self::new()
    }
}

/// NodeGroup is a group of nodes, typically used for load balancing.
#[derive(Clone, Debug)]
pub struct NodeGroup {
    pub id: usize,
    nodes: Arc<RwLock<Vec<Node>>>,
    selector: Option<Arc<dyn NodeSelector + Send + Sync>>,
}

use crate::selector::NodeSelector;

impl NodeGroup {
    pub fn new(nodes: Vec<Node>) -> Self {
        Self {
            id: 0,
            nodes: Arc::new(RwLock::new(nodes)),
            selector: None,
        }
    }

    pub fn add_node(&self, node: Node) {
        self.nodes.write().unwrap().push(node);
    }

    pub fn nodes(&self) -> Vec<Node> {
        self.nodes.read().unwrap().clone()
    }

    pub fn get_node(&self, i: usize) -> Option<Node> {
        self.nodes.read().unwrap().get(i).cloned()
    }

    pub fn set_selector(&mut self, selector: Arc<dyn NodeSelector + Send + Sync>) {
        self.selector = Some(selector);
    }

    /// Selects the next node from the group.
    pub fn next(&self) -> Result<Node, crate::selector::SelectError> {
        let nodes = self.nodes.read().unwrap().clone();
        if nodes.is_empty() {
            return Err(crate::selector::SelectError::NoneAvailable);
        }

        if let Some(selector) = &self.selector {
            selector.select(&nodes)
        } else {
            // Default: round-robin
            let selector = crate::selector::DefaultSelector;
            selector.select(&nodes)
        }
    }
}

impl Default for NodeGroup {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_basic() {
        let node = Node::parse("http://localhost:8080").unwrap();
        assert_eq!(node.addr, "localhost:8080");
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tcp");
    }

    #[test]
    fn test_parse_node_auto() {
        let node = Node::parse("localhost:8080").unwrap();
        assert_eq!(node.addr, "localhost:8080");
        assert_eq!(node.protocol, "");
        assert_eq!(node.transport, "tcp");
    }

    #[test]
    fn test_parse_node_with_auth() {
        let node = Node::parse("socks5://user:pass@localhost:1080").unwrap();
        assert_eq!(node.protocol, "socks5");
        assert_eq!(node.transport, "tcp");
        assert_eq!(node.user, Some(("user".into(), Some("pass".into()))));
    }

    #[test]
    fn test_parse_node_with_transport() {
        let node = Node::parse("http+tls://localhost:443").unwrap();
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tls");
    }

    #[test]
    fn test_parse_node_socks() {
        let node = Node::parse("socks://localhost:1080").unwrap();
        assert_eq!(node.protocol, "socks5");
    }

    #[test]
    fn test_parse_node_https() {
        let node = Node::parse("https://localhost:443").unwrap();
        assert_eq!(node.protocol, "http");
        assert_eq!(node.transport, "tls");
    }

    #[test]
    fn test_parse_node_with_remote() {
        let node = Node::parse("tcp://localhost:8080/192.168.1.1:80").unwrap();
        assert_eq!(node.remote, "192.168.1.1:80");
    }

    #[test]
    fn test_parse_node_with_params() {
        let node = Node::parse("http://localhost:8080?timeout=5s&retry=3").unwrap();
        assert_eq!(node.get("timeout"), Some("5s"));
        assert_eq!(node.get("retry"), Some("3"));
        assert_eq!(node.get_int("retry"), 3);
    }

    #[test]
    fn test_parse_node_empty() {
        assert!(Node::parse("").is_err());
    }

    #[test]
    fn test_fail_marker() {
        let m = FailMarker::new();
        assert_eq!(m.fail_count(), 0);
        assert_eq!(m.fail_time(), 0);

        m.mark();
        assert_eq!(m.fail_count(), 1);
        assert!(m.fail_time() > 0);

        m.mark();
        assert_eq!(m.fail_count(), 2);

        m.reset();
        assert_eq!(m.fail_count(), 0);
        assert_eq!(m.fail_time(), 0);
    }

    #[test]
    fn test_node_display() {
        let node = Node::parse("http://localhost:8080").unwrap();
        assert_eq!(format!("{}", node), "http://localhost:8080");
    }

    #[test]
    fn test_parse_duration_fn() {
        assert_eq!(parse_duration("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("5s"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("100ms"), Some(Duration::from_millis(100)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("invalid"), None);
    }

    #[test]
    fn test_node_group() {
        let n1 = Node::parse("http://localhost:8080").unwrap();
        let n2 = Node::parse("http://localhost:8081").unwrap();
        let group = NodeGroup::new(vec![n1.clone()]);
        group.add_node(n2);

        let nodes = group.nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].addr, "localhost:8080");
        assert_eq!(nodes[1].addr, "localhost:8081");
    }
}
