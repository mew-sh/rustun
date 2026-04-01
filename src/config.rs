use serde::Deserialize;
use std::fs;

/// Route configuration (matching gost's JSON config exactly).
#[derive(Clone, Debug, Deserialize)]
pub struct RouteConfig {
    #[serde(rename = "ServeNodes", default)]
    pub serve_nodes: Vec<String>,
    #[serde(rename = "ChainNodes", default)]
    pub chain_nodes: Vec<String>,
    #[serde(rename = "Retries", default)]
    pub retries: usize,
    #[serde(rename = "Mark", default)]
    pub mark: i32,
    #[serde(rename = "Interface", default)]
    pub interface: String,
}

/// Top-level configuration (compatible with gost JSON format).
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub default_route: RouteConfig,
    #[serde(rename = "Routes", default)]
    pub routes: Vec<RouteConfig>,
    #[serde(rename = "Debug", default)]
    pub debug: bool,
}

/// Load configuration from a JSON file.
pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut cfg: Config = serde_json::from_str(&content)?;

    // If the default route has nodes, include it
    if !cfg.default_route.serve_nodes.is_empty() {
        cfg.routes.insert(0, cfg.default_route.clone());
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let json = r#"{
            "ServeNodes": [":8080"],
            "ChainNodes": ["http://proxy:8080"],
            "Retries": 3,
            "Mark": 100,
            "Interface": "eth0",
            "Debug": true,
            "Routes": [
                {
                    "ServeNodes": ["socks5://:1080"],
                    "ChainNodes": [],
                    "Retries": 1
                }
            ]
        }"#;

        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.debug);
        assert_eq!(cfg.default_route.serve_nodes, vec![":8080"]);
        assert_eq!(cfg.default_route.chain_nodes, vec!["http://proxy:8080"]);
        assert_eq!(cfg.default_route.retries, 3);
        assert_eq!(cfg.default_route.mark, 100);
        assert_eq!(cfg.default_route.interface, "eth0");
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].serve_nodes, vec!["socks5://:1080"]);
        assert_eq!(cfg.routes[0].mark, 0); // default
    }

    #[test]
    fn test_parse_empty_config() {
        let json = r#"{}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(!cfg.debug);
        assert!(cfg.default_route.serve_nodes.is_empty());
        assert!(cfg.routes.is_empty());
    }

    #[test]
    fn test_parse_config_mark_interface() {
        let json = r#"{
            "ServeNodes": [":8080"],
            "ChainNodes": [],
            "Mark": 42,
            "Interface": "eth0"
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.default_route.mark, 42);
        assert_eq!(cfg.default_route.interface, "eth0");
    }

    #[test]
    fn test_parse_config_multiple_routes() {
        let json = r#"{
            "Routes": [
                {"ServeNodes": ["http://:8080"], "ChainNodes": []},
                {"ServeNodes": ["socks5://:1080"], "ChainNodes": ["http://proxy:3128"]}
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].serve_nodes[0], "http://:8080");
        assert_eq!(cfg.routes[1].chain_nodes[0], "http://proxy:3128");
    }

    #[test]
    fn test_parse_malformed_json() {
        let json = r#"{ broken json"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config("nonexistent_config.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_defaults() {
        let json = r#"{"ServeNodes": [":80"]}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.default_route.retries, 0);
        assert_eq!(cfg.default_route.mark, 0);
        assert_eq!(cfg.default_route.interface, "");
        assert!(!cfg.debug);
    }
}
