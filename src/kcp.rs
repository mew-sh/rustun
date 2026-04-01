use serde::{Deserialize, Serialize};
use tracing::info;

/// KCP protocol configuration (compatible with gost's KCPConfig JSON format).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KcpConfig {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub crypt: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default = "default_sndwnd")]
    pub sndwnd: u32,
    #[serde(default = "default_rcvwnd")]
    pub rcvwnd: u32,
    #[serde(default = "default_datashard")]
    pub datashard: u32,
    #[serde(default = "default_parityshard")]
    pub parityshard: u32,
    #[serde(default)]
    pub dscp: u32,
    #[serde(default)]
    pub nocomp: bool,
    #[serde(default)]
    pub acknodelay: bool,
    #[serde(default)]
    pub nodelay: u32,
    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default)]
    pub resend: u32,
    #[serde(default)]
    pub nc: u32,
    #[serde(default = "default_sockbuf")]
    pub sockbuf: u32,
    #[serde(default)]
    pub smuxbuf: u32,
    #[serde(default)]
    pub streambuf: u32,
    #[serde(default = "default_smuxver")]
    pub smuxver: u32,
    #[serde(default = "default_keepalive")]
    pub keepalive: u32,
    #[serde(default)]
    pub tcp: bool,
}

fn default_mtu() -> u32 { 1350 }
fn default_sndwnd() -> u32 { 1024 }
fn default_rcvwnd() -> u32 { 1024 }
fn default_datashard() -> u32 { 10 }
fn default_parityshard() -> u32 { 3 }
fn default_interval() -> u32 { 50 }
fn default_sockbuf() -> u32 { 4194304 }
fn default_smuxver() -> u32 { 1 }
fn default_keepalive() -> u32 { 10 }

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            key: String::new(),
            crypt: "aes".to_string(),
            mode: "fast".to_string(),
            mtu: default_mtu(),
            sndwnd: default_sndwnd(),
            rcvwnd: default_rcvwnd(),
            datashard: default_datashard(),
            parityshard: default_parityshard(),
            dscp: 0,
            nocomp: false,
            acknodelay: false,
            nodelay: 0,
            interval: default_interval(),
            resend: 0,
            nc: 0,
            sockbuf: default_sockbuf(),
            smuxbuf: 0,
            streambuf: 0,
            smuxver: default_smuxver(),
            keepalive: default_keepalive(),
            tcp: false,
        }
    }
}

impl KcpConfig {
    /// Initialize config with mode presets (matching gost behavior).
    pub fn init(&mut self) {
        match self.mode.as_str() {
            "normal" => {
                self.nodelay = 0;
                self.interval = 40;
                self.resend = 2;
                self.nc = 1;
            }
            "fast" => {
                self.nodelay = 0;
                self.interval = 30;
                self.resend = 2;
                self.nc = 1;
            }
            "fast2" => {
                self.nodelay = 1;
                self.interval = 20;
                self.resend = 2;
                self.nc = 1;
            }
            "fast3" => {
                self.nodelay = 1;
                self.interval = 10;
                self.resend = 2;
                self.nc = 1;
            }
            _ => {}
        }
        if self.smuxver == 0 {
            self.smuxver = 1;
        }
        if self.smuxbuf == 0 {
            self.smuxbuf = self.sockbuf;
        }
        if self.streambuf == 0 {
            self.streambuf = self.sockbuf / 2;
        }
    }

    /// Load KCP config from JSON file.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: KcpConfig = serde_json::from_str(&content)?;
        config.init();
        Ok(config)
    }
}

/// KCP transporter placeholder.
/// Full implementation requires a KCP crate (e.g., tokio-kcp).
pub struct KcpTransporter {
    config: KcpConfig,
}

impl KcpTransporter {
    pub fn new(config: KcpConfig) -> Self {
        Self { config }
    }
}

/// KCP listener placeholder.
pub struct KcpListener {
    config: KcpConfig,
    addr: String,
}

impl KcpListener {
    pub fn new(addr: &str, config: KcpConfig) -> Self {
        Self {
            config,
            addr: addr.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcp_config_default() {
        let config = KcpConfig::default();
        assert_eq!(config.mtu, 1350);
        assert_eq!(config.mode, "fast");
        assert_eq!(config.sndwnd, 1024);
    }

    #[test]
    fn test_kcp_config_init_modes() {
        let mut config = KcpConfig::default();

        config.mode = "normal".to_string();
        config.init();
        assert_eq!(config.nodelay, 0);
        assert_eq!(config.interval, 40);

        config.mode = "fast3".to_string();
        config.init();
        assert_eq!(config.nodelay, 1);
        assert_eq!(config.interval, 10);
    }

    #[test]
    fn test_kcp_config_json_parse() {
        let json = r#"{
            "key": "secret",
            "crypt": "aes",
            "mode": "fast2",
            "mtu": 1400,
            "sndwnd": 2048,
            "rcvwnd": 2048,
            "tcp": true
        }"#;

        let config: KcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.key, "secret");
        assert_eq!(config.crypt, "aes");
        assert_eq!(config.mode, "fast2");
        assert_eq!(config.mtu, 1400);
        assert!(config.tcp);
    }

    #[test]
    fn test_kcp_config_json_roundtrip() {
        let config = KcpConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KcpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mtu, config.mtu);
        assert_eq!(parsed.mode, config.mode);
    }
}
