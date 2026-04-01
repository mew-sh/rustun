use std::collections::HashMap;
use std::io::{self, BufRead};
use std::sync::RwLock;

/// Authenticator is a trait for user authentication.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, user: &str, password: &str) -> bool;
}

/// LocalAuthenticator authenticates using local key-value pairs.
pub struct LocalAuthenticator {
    kvs: RwLock<HashMap<String, String>>,
}

impl LocalAuthenticator {
    pub fn new(kvs: HashMap<String, String>) -> Self {
        Self {
            kvs: RwLock::new(kvs),
        }
    }

    pub fn add(&self, k: String, v: String) {
        self.kvs.write().unwrap().insert(k, v);
    }

    /// Reload parses config from reader, then reloads the authenticator.
    pub fn reload(&self, reader: impl io::Read) -> io::Result<()> {
        let mut kvs = HashMap::new();

        let buf = io::BufReader::new(reader);
        for line in buf.lines() {
            let line = line?;
            let parts = split_line(&line);
            if parts.is_empty() {
                continue;
            }

            match parts[0].as_str() {
                "reload" => {} // reload period - handled externally
                _ => {
                    let k = parts[0].clone();
                    let v = if parts.len() > 1 {
                        parts[1].clone()
                    } else {
                        String::new()
                    };
                    kvs.insert(k, v);
                }
            }
        }

        *self.kvs.write().unwrap() = kvs;
        Ok(())
    }
}

impl Authenticator for LocalAuthenticator {
    fn authenticate(&self, user: &str, password: &str) -> bool {
        let kvs = self.kvs.read().unwrap();
        if kvs.is_empty() {
            return true;
        }
        match kvs.get(user) {
            Some(v) => v.is_empty() || password == v,
            None => false,
        }
    }
}

/// Helper: split a line by whitespace, ignoring comments (#). Returns &str slices.
pub fn split_line_ref(line: &str) -> Vec<&str> {
    let line = if let Some(idx) = line.find('#') {
        &line[..idx]
    } else {
        line
    };
    line.split_whitespace().collect()
}

/// Helper: split a line by whitespace, ignoring comments (#).
fn split_line(line: &str) -> Vec<String> {
    let line = if let Some(idx) = line.find('#') {
        &line[..idx]
    } else {
        line
    };
    let line = line.replace('\t', " ");
    line.split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_authenticator_empty() {
        let au = LocalAuthenticator::new(HashMap::new());
        // Empty authenticator allows everything
        assert!(au.authenticate("any", "any"));
    }

    #[test]
    fn test_local_authenticator_basic() {
        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), "secret".into());
        let au = LocalAuthenticator::new(kvs);

        assert!(au.authenticate("admin", "secret"));
        assert!(!au.authenticate("admin", "wrong"));
        assert!(!au.authenticate("unknown", "secret"));
    }

    #[test]
    fn test_local_authenticator_empty_password() {
        let mut kvs = HashMap::new();
        kvs.insert("admin".into(), String::new());
        let au = LocalAuthenticator::new(kvs);

        // Empty password in the store means any password is accepted
        assert!(au.authenticate("admin", "anything"));
        assert!(au.authenticate("admin", ""));
    }

    #[test]
    fn test_local_authenticator_add() {
        let au = LocalAuthenticator::new(HashMap::new());
        assert!(au.authenticate("user", "pass")); // empty = allow all

        au.add("user".into(), "pass".into());
        assert!(au.authenticate("user", "pass"));
        assert!(!au.authenticate("user", "wrong"));
    }

    #[test]
    fn test_local_authenticator_reload() {
        let au = LocalAuthenticator::new(HashMap::new());
        let data = b"admin secret\nuser pass123\n# comment line\n";
        au.reload(&data[..]).unwrap();

        assert!(au.authenticate("admin", "secret"));
        assert!(au.authenticate("user", "pass123"));
        assert!(!au.authenticate("admin", "wrong"));
        assert!(!au.authenticate("unknown", "any"));
    }

    #[test]
    fn test_split_line() {
        assert_eq!(split_line(""), Vec::<String>::new());
        assert_eq!(split_line("# comment"), Vec::<String>::new());
        assert_eq!(split_line("admin secret"), vec!["admin", "secret"]);
        assert_eq!(
            split_line("admin\tsecret # comment"),
            vec!["admin", "secret"]
        );
    }
}
