use std::fmt;

/// PortRange specifies a range of ports.
#[derive(Clone, Debug)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s == "*" {
            return Ok(PortRange { min: 0, max: 65535 });
        }

        if let Some((min_str, max_str)) = s.split_once('-') {
            let min: u16 = min_str
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            let max: u16 = max_str
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            let real_min = min.min(max);
            let real_max = min.max(max);
            Ok(PortRange {
                min: real_min,
                max: real_max,
            })
        } else {
            let port: u16 = s
                .parse()
                .map_err(|_| PermissionError::InvalidPort(s.to_string()))?;
            Ok(PortRange {
                min: port,
                max: port,
            })
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }
}

/// PortSet is a set of PortRange.
#[derive(Clone, Debug)]
pub struct PortSet(Vec<PortRange>);

impl PortSet {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Err(PermissionError::EmptyPort);
        }
        let ranges: Result<Vec<PortRange>, _> =
            s.split(',').map(|r| PortRange::parse(r.trim())).collect();
        Ok(PortSet(ranges?))
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }
}

/// StringSet is a set of glob patterns.
#[derive(Clone, Debug)]
pub struct StringSet(Vec<String>);

impl StringSet {
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Err(PermissionError::EmptyString);
        }
        Ok(StringSet(s.split(',').map(|s| s.to_string()).collect()))
    }

    pub fn contains(&self, subj: &str) -> bool {
        self.0.iter().any(|s| glob_match::glob_match(s, subj))
    }
}

/// Permission is a rule for whitelist/blacklist.
#[derive(Clone, Debug)]
pub struct Permission {
    pub actions: StringSet,
    pub hosts: StringSet,
    pub ports: PortSet,
}

/// Permissions is a set of Permission rules.
#[derive(Clone, Debug)]
pub struct Permissions(Vec<Permission>);

impl Permissions {
    /// Parse permissions from a space-separated string.
    /// Format: "action1,action2:host1,host2:port1,port2-port3"
    pub fn parse(s: &str) -> Result<Self, PermissionError> {
        if s.is_empty() {
            return Ok(Permissions(Vec::new()));
        }

        let mut perms = Vec::new();
        for perm_str in s.split_whitespace() {
            let parts: Vec<&str> = perm_str.split(':').collect();
            if parts.len() != 3 {
                return Err(PermissionError::InvalidFormat(perm_str.to_string()));
            }
            let actions = StringSet::parse(parts[0])?;
            let hosts = StringSet::parse(parts[1])?;
            let ports = PortSet::parse(parts[2])?;

            perms.push(Permission {
                actions,
                hosts,
                ports,
            });
        }

        Ok(Permissions(perms))
    }

    pub fn can(&self, action: &str, host: &str, port: u16) -> bool {
        self.0
            .iter()
            .any(|p| p.actions.contains(action) && p.hosts.contains(host) && p.ports.contains(port))
    }
}

/// Tests whether the given action and address is allowed by the whitelist and blacklist.
#[allow(non_snake_case)]
pub fn Can(
    action: &str,
    addr: &str,
    whitelist: Option<&Permissions>,
    blacklist: Option<&Permissions>,
) -> bool {
    let addr = if !addr.contains(':') {
        format!("{}:80", addr)
    } else {
        addr.to_string()
    };

    let (host, port_str) = match addr.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return false,
    };

    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let wl_ok = whitelist.is_none() || whitelist.unwrap().can(action, host, port);
    let bl_ok = blacklist.is_none() || !blacklist.unwrap().can(action, host, port);

    wl_ok && bl_ok
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("empty port")]
    EmptyPort,
    #[error("empty string")]
    EmptyString,
    #[error("invalid permission format: {0}")]
    InvalidFormat(String),
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range_single() {
        let pr = PortRange::parse("80").unwrap();
        assert!(pr.contains(80));
        assert!(!pr.contains(81));
    }

    #[test]
    fn test_port_range_range() {
        let pr = PortRange::parse("80-90").unwrap();
        assert!(pr.contains(80));
        assert!(pr.contains(85));
        assert!(pr.contains(90));
        assert!(!pr.contains(79));
        assert!(!pr.contains(91));
    }

    #[test]
    fn test_port_range_wildcard() {
        let pr = PortRange::parse("*").unwrap();
        assert!(pr.contains(0));
        assert!(pr.contains(80));
        assert!(pr.contains(65535));
    }

    #[test]
    fn test_port_set() {
        let ps = PortSet::parse("80,443,8000-9000").unwrap();
        assert!(ps.contains(80));
        assert!(ps.contains(443));
        assert!(ps.contains(8080));
        assert!(!ps.contains(81));
    }

    #[test]
    fn test_string_set() {
        let ss = StringSet::parse("*.google.com,example.com").unwrap();
        assert!(ss.contains("www.google.com"));
        assert!(ss.contains("example.com"));
        assert!(!ss.contains("example.org"));
    }

    #[test]
    fn test_permissions_parse() {
        let perms = Permissions::parse("tcp,udp:*.google.com,example.com:80,443").unwrap();
        assert!(perms.can("tcp", "www.google.com", 80));
        assert!(perms.can("udp", "example.com", 443));
        assert!(!perms.can("tcp", "evil.com", 80));
        assert!(!perms.can("tcp", "www.google.com", 8080));
    }

    #[test]
    fn test_permissions_empty() {
        let perms = Permissions::parse("").unwrap();
        assert!(!perms.can("tcp", "anything", 80));
    }

    #[test]
    fn test_can_function() {
        let wl = Permissions::parse("tcp:*:80,443").unwrap();
        let bl = Permissions::parse("tcp:evil.com:*").unwrap();

        assert!(Can("tcp", "good.com:80", Some(&wl), Some(&bl)));
        assert!(!Can("tcp", "good.com:8080", Some(&wl), Some(&bl)));
        assert!(!Can("tcp", "evil.com:80", Some(&wl), Some(&bl)));
    }

    #[test]
    fn test_can_no_lists() {
        assert!(Can("tcp", "anything:80", None, None));
    }

    #[test]
    fn test_can_default_port() {
        let wl = Permissions::parse("tcp:*:80").unwrap();
        assert!(Can("tcp", "example.com", Some(&wl), None));
    }
}
