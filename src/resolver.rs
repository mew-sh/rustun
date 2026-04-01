use std::net::IpAddr;

/// Simple DNS resolver.
/// In a full implementation this would use the trust-dns or hickory-dns crate.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    pub servers: Vec<String>,
    pub prefer: String, // "ipv4" or "ipv6"
}

impl Resolver {
    pub fn new(servers: Vec<String>) -> Self {
        Self {
            servers,
            prefer: "ipv4".to_string(),
        }
    }

    /// Resolve a hostname to IP addresses using the system resolver.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, std::io::Error> {
        // Use tokio's built-in DNS resolution
        let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", host))
            .await?
            .map(|a| a.ip())
            .collect();

        if self.prefer == "ipv6" {
            let mut v6: Vec<IpAddr> = addrs.iter().filter(|a| a.is_ipv6()).cloned().collect();
            let v4: Vec<IpAddr> = addrs.iter().filter(|a| a.is_ipv4()).cloned().collect();
            v6.extend(v4);
            Ok(v6)
        } else {
            let mut v4: Vec<IpAddr> = addrs.iter().filter(|a| a.is_ipv4()).cloned().collect();
            let v6: Vec<IpAddr> = addrs.iter().filter(|a| a.is_ipv6()).cloned().collect();
            v4.extend(v6);
            Ok(v4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolver_localhost() {
        let r = Resolver::new(vec![]);
        let ips = r.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
        // localhost should resolve to 127.0.0.1 or ::1
        assert!(ips.iter().any(|ip| {
            ip == &IpAddr::from([127, 0, 0, 1]) || ip == &IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
        }));
    }

    #[tokio::test]
    async fn test_resolver_invalid() {
        let r = Resolver::new(vec![]);
        let result = r.resolve("this.host.does.not.exist.invalid").await;
        // Should either fail or return empty
        assert!(result.is_err() || result.unwrap().is_empty());
    }
}
