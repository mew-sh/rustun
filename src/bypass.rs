use std::net::IpAddr;
use std::sync::RwLock;

/// Matcher is a generic pattern matcher.
pub trait Matcher: Send + Sync + std::fmt::Debug {
    fn match_value(&self, v: &str) -> bool;
    fn description(&self) -> String;
}

/// Creates a Matcher based on the pattern:
/// - IP address -> IpMatcher
/// - CIDR notation -> CidrMatcher
/// - Otherwise -> DomainMatcher
pub fn new_matcher(pattern: &str) -> Option<Box<dyn Matcher>> {
    if pattern.is_empty() {
        return None;
    }
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return Some(Box::new(IpMatcher { ip }));
    }
    if let Ok(net) = pattern.parse::<ipnet::IpNet>() {
        return Some(Box::new(CidrMatcher { net }));
    }
    Some(Box::new(DomainMatcher::new(pattern)))
}

/// Matches a specific IP address.
#[derive(Debug)]
pub struct IpMatcher {
    pub ip: IpAddr,
}

impl Matcher for IpMatcher {
    fn match_value(&self, v: &str) -> bool {
        if let Ok(ip) = v.parse::<IpAddr>() {
            self.ip == ip
        } else {
            false
        }
    }

    fn description(&self) -> String {
        format!("ip {}", self.ip)
    }
}

/// Matches a CIDR range.
#[derive(Debug)]
pub struct CidrMatcher {
    pub net: ipnet::IpNet,
}

impl Matcher for CidrMatcher {
    fn match_value(&self, v: &str) -> bool {
        if let Ok(ip) = v.parse::<IpAddr>() {
            self.net.contains(&ip)
        } else {
            false
        }
    }

    fn description(&self) -> String {
        format!("cidr {}", self.net)
    }
}

/// Matches domain patterns with wildcard support.
#[derive(Debug)]
pub struct DomainMatcher {
    pattern: String,
    plain: String, // without leading dot/wildcard prefix
}

impl DomainMatcher {
    pub fn new(pattern: &str) -> Self {
        let (pat, plain) = if let Some(stripped) = pattern.strip_prefix('.') {
            (format!("*.{}", stripped), stripped.to_string())
        } else {
            (pattern.to_string(), pattern.to_string())
        };
        Self {
            pattern: pat,
            plain,
        }
    }
}

impl Matcher for DomainMatcher {
    fn match_value(&self, domain: &str) -> bool {
        if domain == self.plain {
            return true;
        }
        glob_match::glob_match(&self.pattern, domain)
    }

    fn description(&self) -> String {
        format!("domain {}", self.plain)
    }
}

/// Bypass is a filter for addresses (IP or domain).
/// It contains a list of matchers.
#[derive(Debug)]
pub struct Bypass {
    matchers: RwLock<Vec<Box<dyn Matcher>>>,
    reversed: RwLock<bool>,
}

impl Bypass {
    pub fn new(reversed: bool, matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self {
            matchers: RwLock::new(matchers),
            reversed: RwLock::new(reversed),
        }
    }

    pub fn from_patterns(reversed: bool, patterns: &[&str]) -> Self {
        let matchers: Vec<Box<dyn Matcher>> =
            patterns.iter().filter_map(|p| new_matcher(p)).collect();
        Self::new(reversed, matchers)
    }

    /// Checks whether the bypass includes the given address.
    pub fn contains(&self, addr: &str) -> bool {
        if addr.is_empty() {
            return false;
        }

        // Strip port if present
        let host = if let Some(idx) = addr.rfind(':') {
            let possible_port = &addr[idx + 1..];
            if possible_port.parse::<u16>().is_ok() {
                // Check if it's actually IPv6 without brackets
                if addr.starts_with('[') || addr.matches(':').count() <= 1 {
                    &addr[..idx]
                } else {
                    addr
                }
            } else {
                addr
            }
        } else {
            addr
        };

        let matchers = self.matchers.read().unwrap();
        if matchers.is_empty() {
            return false;
        }

        let matched = matchers.iter().any(|m| m.match_value(host));
        let reversed = *self.reversed.read().unwrap();

        (!reversed && matched) || (reversed && !matched)
    }

    pub fn add_matchers(&self, new_matchers: Vec<Box<dyn Matcher>>) {
        self.matchers.write().unwrap().extend(new_matchers);
    }

    pub fn reversed(&self) -> bool {
        *self.reversed.read().unwrap()
    }

    /// Reload from a reader (line-based config).
    pub fn reload(&self, reader: impl std::io::Read) -> std::io::Result<()> {
        use std::io::BufRead;
        let buf = std::io::BufReader::new(reader);
        let mut matchers: Vec<Box<dyn Matcher>> = Vec::new();
        let mut reversed = false;

        for line in buf.lines() {
            let line = line?;
            let parts: Vec<&str> = crate::auth::split_line_ref(&line);
            if parts.is_empty() {
                continue;
            }
            match parts[0] {
                "reload" => {} // handled externally
                "reverse" => {
                    if parts.len() > 1 {
                        reversed = parts[1] == "true" || parts[1] == "1";
                    }
                }
                _ => {
                    if let Some(m) = new_matcher(parts[0]) {
                        matchers.push(m);
                    }
                }
            }
        }

        *self.matchers.write().unwrap() = matchers;
        *self.reversed.write().unwrap() = reversed;
        Ok(())
    }
}

impl Default for Bypass {
    fn default() -> Self {
        Self::new(false, Vec::new())
    }
}

// We need to add a public split_line_ref helper to auth module
// For now, we duplicate the logic here

fn _split_line(line: &str) -> Vec<String> {
    let line = if let Some(idx) = line.find('#') {
        &line[..idx]
    } else {
        line
    };
    let line = line.replace('\t', " ");
    line.split_whitespace().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matcher() {
        let m = IpMatcher {
            ip: "192.168.1.1".parse().unwrap(),
        };
        assert!(m.match_value("192.168.1.1"));
        assert!(!m.match_value("192.168.1.2"));
        assert!(!m.match_value("invalid"));
    }

    #[test]
    fn test_cidr_matcher() {
        let m = CidrMatcher {
            net: "192.168.1.0/24".parse().unwrap(),
        };
        assert!(m.match_value("192.168.1.1"));
        assert!(m.match_value("192.168.1.254"));
        assert!(!m.match_value("192.168.2.1"));
    }

    #[test]
    fn test_domain_matcher_exact() {
        let m = DomainMatcher::new("example.com");
        assert!(m.match_value("example.com"));
        assert!(!m.match_value("sub.example.com"));
        assert!(!m.match_value("other.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard() {
        let m = DomainMatcher::new("*.example.com");
        assert!(m.match_value("sub.example.com"));
        assert!(m.match_value("deep.sub.example.com"));
        assert!(!m.match_value("example.com"));
    }

    #[test]
    fn test_domain_matcher_dot_prefix() {
        let m = DomainMatcher::new(".example.com");
        assert!(m.match_value("example.com"));
        assert!(m.match_value("sub.example.com"));
    }

    #[test]
    fn test_new_matcher() {
        assert!(new_matcher("192.168.1.1")
            .unwrap()
            .match_value("192.168.1.1"));
        assert!(new_matcher("192.168.1.0/24")
            .unwrap()
            .match_value("192.168.1.100"));
        assert!(new_matcher("example.com")
            .unwrap()
            .match_value("example.com"));
        assert!(new_matcher("").is_none());
    }

    #[test]
    fn test_bypass_contains() {
        let bp = Bypass::from_patterns(false, &["192.168.1.0/24", "example.com"]);
        assert!(bp.contains("192.168.1.1"));
        assert!(bp.contains("192.168.1.1:8080"));
        assert!(bp.contains("example.com"));
        assert!(bp.contains("example.com:443"));
        assert!(!bp.contains("10.0.0.1"));
        assert!(!bp.contains("other.com"));
        assert!(!bp.contains(""));
    }

    #[test]
    fn test_bypass_reversed() {
        let bp = Bypass::from_patterns(true, &["192.168.1.0/24"]);
        // Reversed: contains returns true for addresses NOT in the list
        assert!(!bp.contains("192.168.1.1"));
        assert!(bp.contains("10.0.0.1"));
    }

    #[test]
    fn test_bypass_empty() {
        let bp = Bypass::new(false, Vec::new());
        assert!(!bp.contains("anything"));
    }
}
