use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::node::Node;

#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("no node available")]
    NoneAvailable,
}

/// NodeSelector picks nodes and marks their status.
pub trait NodeSelector: Send + Sync + std::fmt::Debug {
    fn select(&self, nodes: &[Node]) -> Result<Node, SelectError>;
}

/// Strategy is a selection strategy (random, round-robin, fifo).
pub trait Strategy: Send + Sync + std::fmt::Debug {
    fn apply(&self, nodes: &[Node]) -> Node;
    fn name(&self) -> &str;
}

/// Filter filters nodes during selection.
pub trait Filter: Send + Sync + std::fmt::Debug {
    fn filter(&self, nodes: &[Node]) -> Vec<Node>;
    fn name(&self) -> &str;
}

/// Default selector implementation.
#[derive(Debug)]
pub struct DefaultSelector;

impl NodeSelector for DefaultSelector {
    fn select(&self, nodes: &[Node]) -> Result<Node, SelectError> {
        if nodes.is_empty() {
            return Err(SelectError::NoneAvailable);
        }
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        Ok(nodes[n as usize % nodes.len()].clone())
    }
}

/// Creates a strategy by name.
pub fn new_strategy(name: &str) -> Box<dyn Strategy> {
    match name {
        "random" => Box::new(RandomStrategy::new()),
        "fifo" => Box::new(FifoStrategy),
        _ => Box::new(RoundStrategy::new()),
    }
}

/// Round-robin strategy.
#[derive(Debug)]
pub struct RoundStrategy {
    counter: AtomicU64,
}

impl RoundStrategy {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for RoundStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RoundStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        nodes[n as usize % nodes.len()].clone()
    }

    fn name(&self) -> &str {
        "round"
    }
}

/// Random strategy.
#[derive(Debug)]
pub struct RandomStrategy;

impl RandomStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RandomStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..nodes.len());
        nodes[idx].clone()
    }

    fn name(&self) -> &str {
        "random"
    }
}

/// FIFO strategy - always pick the first available node.
#[derive(Debug)]
pub struct FifoStrategy;

impl Strategy for FifoStrategy {
    fn apply(&self, nodes: &[Node]) -> Node {
        if nodes.is_empty() {
            return Node::default();
        }
        nodes[0].clone()
    }

    fn name(&self) -> &str {
        "fifo"
    }
}

/// Default max fails and fail timeout for FailFilter.
pub const DEFAULT_MAX_FAILS: u32 = 1;
pub const DEFAULT_FAIL_TIMEOUT: Duration = Duration::from_secs(30);

/// FailFilter filters out dead nodes.
#[derive(Debug)]
pub struct FailFilter {
    pub max_fails: u32,
    pub fail_timeout: Duration,
}

impl FailFilter {
    pub fn new(max_fails: u32, fail_timeout: Duration) -> Self {
        Self {
            max_fails: if max_fails == 0 {
                DEFAULT_MAX_FAILS
            } else {
                max_fails
            },
            fail_timeout: if fail_timeout.is_zero() {
                DEFAULT_FAIL_TIMEOUT
            } else {
                fail_timeout
            },
        }
    }
}

impl Default for FailFilter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FAILS, DEFAULT_FAIL_TIMEOUT)
    }
}

impl Filter for FailFilter {
    fn filter(&self, nodes: &[Node]) -> Vec<Node> {
        if nodes.len() <= 1 {
            return nodes.to_vec();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        nodes
            .iter()
            .filter(|n| {
                let count = n.marker.fail_count();
                let time = n.marker.fail_time();
                count < self.max_fails || (now - time) >= self.fail_timeout.as_secs() as i64
            })
            .cloned()
            .collect()
    }

    fn name(&self) -> &str {
        "fail"
    }
}

/// InvalidFilter filters nodes with invalid ports.
#[derive(Debug)]
pub struct InvalidFilter;

impl Filter for InvalidFilter {
    fn filter(&self, nodes: &[Node]) -> Vec<Node> {
        nodes
            .iter()
            .filter(|n| {
                if let Some(idx) = n.addr.rfind(':') {
                    if let Ok(port) = n.addr[idx + 1..].parse::<u16>() {
                        return port > 0;
                    }
                }
                false
            })
            .cloned()
            .collect()
    }

    fn name(&self) -> &str {
        "invalid"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;

    fn make_nodes(addrs: &[&str]) -> Vec<Node> {
        addrs
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mut n = Node::parse(&format!("http://{}", a)).unwrap();
                n.id = i + 1;
                n
            })
            .collect()
    }

    #[test]
    fn test_round_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = RoundStrategy::new();
        let n1 = s.apply(&nodes);
        let n2 = s.apply(&nodes);
        let n3 = s.apply(&nodes);
        let n4 = s.apply(&nodes);

        // Should cycle through nodes
        assert_ne!(n1.addr, n2.addr);
        assert_ne!(n2.addr, n3.addr);
        assert_eq!(n1.addr, n4.addr);
    }

    #[test]
    fn test_random_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = RandomStrategy::new();
        // Just verify it doesn't panic and returns valid nodes
        for _ in 0..10 {
            let n = s.apply(&nodes);
            assert!(!n.addr.is_empty());
        }
    }

    #[test]
    fn test_fifo_strategy() {
        let nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        let s = FifoStrategy;
        assert_eq!(s.apply(&nodes).addr, "a:1");
        assert_eq!(s.apply(&nodes).addr, "a:1");
    }

    #[test]
    fn test_fifo_empty() {
        let s = FifoStrategy;
        let n = s.apply(&[]);
        assert!(n.addr.is_empty());
    }

    #[test]
    fn test_fail_filter() {
        let mut nodes = make_nodes(&["a:1", "b:2", "c:3"]);
        nodes[1].mark_dead(); // mark b as dead

        let f = FailFilter::new(1, Duration::from_secs(30));
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].addr, "a:1");
        assert_eq!(filtered[1].addr, "c:3");
    }

    #[test]
    fn test_fail_filter_timeout_expired() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        // Mark dead with time far in the past
        nodes[0].marker.mark();

        // With very short timeout (1 nanosecond), the failed node should be included again
        // because time since failure > fail_timeout
        let f = FailFilter {
            max_fails: 1,
            fail_timeout: Duration::from_nanos(1),
        };
        // Sleep briefly to ensure time has passed
        std::thread::sleep(Duration::from_millis(1));
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_invalid_filter() {
        let f = InvalidFilter;
        // Create nodes manually to control addr
        let mut valid = Node::default();
        valid.addr = "127.0.0.1:80".to_string();
        valid.id = 1;

        let mut invalid = Node::default();
        invalid.addr = "127.0.0.1".to_string(); // no port
        invalid.id = 2;

        let nodes = vec![valid, invalid];
        let filtered = f.filter(&nodes);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].addr, "127.0.0.1:80");
    }

    #[test]
    fn test_new_strategy() {
        assert_eq!(new_strategy("random").name(), "random");
        assert_eq!(new_strategy("fifo").name(), "fifo");
        assert_eq!(new_strategy("round").name(), "round");
        assert_eq!(new_strategy("unknown").name(), "round");
    }

    #[test]
    fn test_default_selector() {
        let nodes = make_nodes(&["a:1", "b:2"]);
        let sel = DefaultSelector;
        let n = sel.select(&nodes).unwrap();
        assert!(!n.addr.is_empty());
    }

    #[test]
    fn test_default_selector_empty() {
        let sel = DefaultSelector;
        assert!(sel.select(&[]).is_err());
    }
}
