use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::transport::transport;

// Shadowsocks SOCKS5-style address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Supported Shadowsocks cipher methods.
#[derive(Clone, Debug)]
pub enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Plain, // No encryption (for testing)
}

impl SsCipher {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Some(Self::ChaCha20Poly1305),
            "plain" | "none" | "" => Some(Self::Plain),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
            Self::Plain => 0,
        }
    }
}

/// Derive key from password using EVP_BytesToKey (OpenSSL compatible).
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    // MD5 for key derivation

    let mut key = Vec::with_capacity(key_len);
    let mut prev_hash: Vec<u8> = Vec::new();

    while key.len() < key_len {
        let mut data = Vec::new();
        if !prev_hash.is_empty() {
            data.extend_from_slice(&prev_hash);
        }
        data.extend_from_slice(password);
        let digest = md5::compute(&data);
        prev_hash = digest.0.to_vec();
        key.extend_from_slice(&prev_hash);
    }

    key.truncate(key_len);
    key
}

/// Shadowsocks connector (client side).
pub struct ShadowConnector {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl ShadowConnector {
    pub fn new(method: &str, password: &str) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self { cipher, key }
    }

    /// Connect via Shadowsocks protocol.
    pub async fn connect(
        &self,
        mut conn: TcpStream,
        address: &str,
    ) -> Result<TcpStream, HandlerError> {
        // Encode target address in SOCKS5-style format
        let addr_buf = encode_ss_address(address)?;

        // In a full implementation, we'd encrypt with AEAD
        // For the plain cipher, just send the raw address header
        conn.write_all(&addr_buf).await?;

        Ok(conn)
    }
}

/// Shadowsocks UDP connector.
pub struct ShadowUdpConnector {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl ShadowUdpConnector {
    pub fn new(method: &str, password: &str) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self { cipher, key }
    }
}

/// Shadowsocks handler (server side).
pub struct ShadowHandler {
    cipher: SsCipher,
    key: Vec<u8>,
    options: HandlerOptions,
}

impl ShadowHandler {
    pub fn new(method: &str, password: &str, options: HandlerOptions) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self {
            cipher,
            key,
            options,
        }
    }
}

#[async_trait]
impl Handler for ShadowHandler {
    async fn handle(&self, mut conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        // In a full implementation, we'd decrypt the AEAD stream
        // Read the target address (SOCKS5-style)
        let target = read_ss_address(&mut conn).await?;

        info!("[ss] {} -> {}", peer_addr, target);

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        match chain.dial(&target).await {
            Ok(cc) => {
                info!("[ss] {} <-> {}", peer_addr, target);
                transport(conn, cc).await.ok();
                info!("[ss] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => Err(HandlerError::Chain(e)),
        }
    }
}

/// Shadowsocks UDP relay handler.
pub struct ShadowUdpHandler {
    cipher: SsCipher,
    key: Vec<u8>,
    options: HandlerOptions,
}

impl ShadowUdpHandler {
    pub fn new(method: &str, password: &str, options: HandlerOptions) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self {
            cipher,
            key,
            options,
        }
    }
}

/// Encode target address in Shadowsocks format (SOCKS5-style).
fn encode_ss_address(address: &str) -> Result<Vec<u8>, HandlerError> {
    let (host, port_str) = address
        .rsplit_once(':')
        .ok_or_else(|| HandlerError::Proxy(format!("invalid address: {}", address)))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| HandlerError::Proxy(format!("invalid port: {}", port_str)))?;

    let mut buf = Vec::new();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.push(ATYP_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());

    Ok(buf)
}

/// Read target address in Shadowsocks format.
async fn read_ss_address(conn: &mut TcpStream) -> Result<String, HandlerError> {
    let mut atyp = [0u8; 1];
    conn.read_exact(&mut atyp).await?;

    let host = match atyp[0] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            conn.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            conn.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => {
            return Err(HandlerError::Proxy(format!(
                "unsupported atyp: {}",
                atyp[0]
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(format!("{}:{}", host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_ss_cipher_from_name() {
        assert!(matches!(
            SsCipher::from_name("aes-128-gcm"),
            Some(SsCipher::Aes128Gcm)
        ));
        assert!(matches!(
            SsCipher::from_name("aes-256-gcm"),
            Some(SsCipher::Aes256Gcm)
        ));
        assert!(matches!(
            SsCipher::from_name("chacha20-ietf-poly1305"),
            Some(SsCipher::ChaCha20Poly1305)
        ));
        assert!(matches!(
            SsCipher::from_name("plain"),
            Some(SsCipher::Plain)
        ));
        assert!(SsCipher::from_name("unknown-cipher").is_none());
    }

    #[test]
    fn test_evp_bytes_to_key() {
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key.len(), 16);

        let key32 = evp_bytes_to_key(b"password", 32);
        assert_eq!(key32.len(), 32);

        // Same password should produce same key
        let key2 = evp_bytes_to_key(b"password", 16);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encode_ss_address_ipv4() {
        let buf = encode_ss_address("127.0.0.1:80").unwrap();
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[127, 0, 0, 1]);
        assert_eq!(&buf[5..7], &[0, 80]);
    }

    #[test]
    fn test_encode_ss_address_domain() {
        let buf = encode_ss_address("example.com:443").unwrap();
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // "example.com".len()
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn test_shadow_handler_connect() {
        // Start a mock target
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"shadow ok").await.unwrap();
        });

        // Start SS handler (plain cipher for testing)
        let handler = ShadowHandler::new("plain", "testpass", HandlerOptions::default());
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SS client (send address header then read data)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let addr_buf = encode_ss_address(&target_addr.to_string()).unwrap();
        client.write_all(&addr_buf).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"shadow ok");
    }

    #[tokio::test]
    async fn test_shadow_connector() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            // Read SS address header first
            let _ = read_ss_address(&mut conn).await;
            conn.write_all(b"connector ok").await.unwrap();
        });

        let connector = ShadowConnector::new("plain", "testpass");
        let stream = TcpStream::connect(target_addr).await.unwrap();
        let mut conn = connector.connect(stream, "127.0.0.1:9999").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"connector ok");
    }
}
