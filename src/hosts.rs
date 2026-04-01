use std::io::{self, BufRead};
use std::net::IpAddr;
use std::sync::RwLock;

/// Host is a static mapping from hostname to IP.
#[derive(Clone, Debug)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: String,
    pub aliases: Vec<String>,
}

impl Host {
    pub fn new(ip: IpAddr, hostname: &str, aliases: Vec<String>) -> Self {
        Self {
            ip,
            hostname: hostname.to_string(),
            aliases,
        }
    }
}

/// Hosts is a static table lookup for hostnames.
#[derive(Debug)]
pub struct Hosts {
    hosts: RwLock<Vec<Host>>,
}

impl Clone for Hosts {
    fn clone(&self) -> Self {
        Self {
            hosts: RwLock::new(self.hosts.read().unwrap().clone()),
        }
    }
}

impl Hosts {
    pub fn new(hosts: Vec<Host>) -> Self {
        Self {
            hosts: RwLock::new(hosts),
        }
    }

    pub fn add_host(&self, host: Host) {
        self.hosts.write().unwrap().push(host);
    }

    /// Lookup searches for the IP address corresponding to the given host.
    pub fn lookup(&self, host: &str) -> Option<IpAddr> {
        if host.is_empty() {
            return None;
        }
        let hosts = self.hosts.read().unwrap();
        for h in hosts.iter() {
            if h.hostname == host {
                return Some(h.ip);
            }
            for alias in &h.aliases {
                if alias == host {
                    return Some(h.ip);
                }
            }
        }
        None
    }

    /// Reload parses config from reader, then reloads the hosts.
    pub fn reload(&self, reader: impl io::Read) -> io::Result<()> {
        let buf = io::BufReader::new(reader);
        let mut hosts = Vec::new();

        for line in buf.lines() {
            let line = line?;
            let parts = split_line(&line);
            if parts.len() < 2 {
                continue;
            }
            match parts[0].as_str() {
                "reload" => {} // handled externally
                _ => {
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        let hostname = parts[1].clone();
                        let aliases = parts[2..].to_vec();
                        hosts.push(Host {
                            ip,
                            hostname,
                            aliases,
                        });
                    }
                }
            }
        }

        *self.hosts.write().unwrap() = hosts;
        Ok(())
    }
}

impl Default for Hosts {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

fn split_line(line: &str) -> Vec<String> {
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
    fn test_hosts_lookup() {
        let hosts = Hosts::new(vec![
            Host::new("127.0.0.1".parse().unwrap(), "localhost", vec![]),
            Host::new(
                "192.168.1.1".parse().unwrap(),
                "router",
                vec!["gateway".into()],
            ),
        ]);

        assert_eq!(
            hosts.lookup("localhost"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("router"), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(
            hosts.lookup("gateway"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(hosts.lookup("unknown"), None);
        assert_eq!(hosts.lookup(""), None);
    }

    #[test]
    fn test_hosts_add() {
        let hosts = Hosts::new(vec![]);
        assert_eq!(hosts.lookup("test"), None);

        hosts.add_host(Host::new("10.0.0.1".parse().unwrap(), "test", vec![]));
        assert_eq!(hosts.lookup("test"), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_hosts_reload() {
        let hosts = Hosts::new(vec![]);
        let data = b"127.0.0.1 localhost\n192.168.1.1 router gateway\n# comment\n";
        hosts.reload(&data[..]).unwrap();

        assert_eq!(
            hosts.lookup("localhost"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            hosts.lookup("gateway"),
            Some("192.168.1.1".parse().unwrap())
        );
    }
}
