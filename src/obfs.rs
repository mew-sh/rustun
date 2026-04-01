use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::handler::{Handler, HandlerError, HandlerOptions};

const MAX_TLS_DATA_LEN: usize = 16384;

// --- HTTP Obfuscation ---

/// HTTP obfuscation transporter - wraps data in HTTP request/response.
pub struct ObfsHttpTransporter;

impl ObfsHttpTransporter {
    pub fn new() -> Self {
        Self
    }

    /// Perform HTTP obfuscation handshake (client side).
    pub async fn handshake(
        &self,
        mut conn: TcpStream,
        host: &str,
    ) -> Result<TcpStream, HandlerError> {
        // Send fake HTTP request (WebSocket upgrade)
        let key = base64_key();
        let req = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            host,
            crate::DEFAULT_USER_AGENT,
            key
        );
        conn.write_all(req.as_bytes()).await?;
        conn.flush().await?;

        // Read response byte-by-byte until we find \r\n\r\n
        let mut response = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = conn.read(&mut b).await?;
            if n == 0 {
                return Err(HandlerError::Proxy("obfs-http: connection closed".into()));
            }
            response.push(b[0]);
            if response.len() >= 4
                && response[response.len() - 4..] == *b"\r\n\r\n"
            {
                break;
            }
        }

        let resp_str = String::from_utf8_lossy(&response);
        if !resp_str.contains("101") {
            return Err(HandlerError::Proxy(format!(
                "obfs-http: unexpected response: {}",
                resp_str.lines().next().unwrap_or("")
            )));
        }

        Ok(conn)
    }
}

/// HTTP obfuscation listener - accepts and unwraps HTTP obfuscated connections.
pub struct ObfsHttpListener;

impl ObfsHttpListener {
    pub fn new() -> Self {
        Self
    }

    /// Accept HTTP obfuscation handshake (server side).
    pub async fn accept_handshake(
        &self,
        mut conn: TcpStream,
    ) -> Result<TcpStream, HandlerError> {
        // Read HTTP request until \r\n\r\n
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = conn.read(&mut buf[total..]).await?;
            if n == 0 {
                return Err(HandlerError::Proxy("obfs-http: connection closed".into()));
            }
            total += n;
            if total >= 4 && buf[total - 4..total] == *b"\r\n\r\n" {
                break;
            }
            if total >= buf.len() {
                return Err(HandlerError::Proxy("obfs-http: request too large".into()));
            }
        }

        // Send fake 101 Switching Protocols response
        let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: dummy\r\n\r\n";
        conn.write_all(resp.as_bytes()).await?;

        Ok(conn)
    }
}

// --- TLS Obfuscation ---

/// TLS obfuscation transporter - wraps data to look like TLS traffic.
pub struct ObfsTlsTransporter;

impl ObfsTlsTransporter {
    pub fn new() -> Self {
        Self
    }

    /// Perform TLS obfuscation handshake (client side).
    /// Sends a fake ClientHello message.
    pub async fn handshake(
        &self,
        mut conn: TcpStream,
        host: &str,
    ) -> Result<TcpStream, HandlerError> {
        let client_hello = build_fake_client_hello(host);
        conn.write_all(&client_hello).await?;

        // Read fake ServerHello
        let mut header = [0u8; 5];
        conn.read_exact(&mut header).await?;

        if header[0] != 0x16 {
            // TLS Handshake
            return Err(HandlerError::Proxy("obfs-tls: invalid response".into()));
        }

        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        conn.read_exact(&mut payload).await?;

        Ok(conn)
    }
}

/// TLS obfuscation listener - accepts and unwraps TLS obfuscated connections.
pub struct ObfsTlsListener;

impl ObfsTlsListener {
    pub fn new() -> Self {
        Self
    }

    /// Accept TLS obfuscation handshake (server side).
    pub async fn accept_handshake(
        &self,
        mut conn: TcpStream,
    ) -> Result<TcpStream, HandlerError> {
        // Read fake ClientHello
        let mut header = [0u8; 5];
        conn.read_exact(&mut header).await?;

        if header[0] != 0x16 {
            return Err(HandlerError::Proxy("obfs-tls: not a TLS record".into()));
        }

        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        conn.read_exact(&mut payload).await?;

        // Send fake ServerHello
        let server_hello = build_fake_server_hello();
        conn.write_all(&server_hello).await?;

        Ok(conn)
    }
}

/// Build a fake TLS ClientHello message.
fn build_fake_client_hello(host: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    // TLS Record header
    buf.push(0x16); // Handshake
    buf.push(0x03);
    buf.push(0x01); // TLS 1.0

    // Placeholder for record length
    let record_len_pos = buf.len();
    buf.push(0x00);
    buf.push(0x00);

    let start = buf.len();

    // Handshake header
    buf.push(0x01); // ClientHello

    // Placeholder for handshake length
    let hs_len_pos = buf.len();
    buf.push(0x00);
    buf.push(0x00);
    buf.push(0x00);

    let hello_start = buf.len();

    // Client version
    buf.push(0x03);
    buf.push(0x03); // TLS 1.2

    // Random (32 bytes)
    let random: [u8; 32] = rand::random();
    buf.extend_from_slice(&random);

    // Session ID (0 length)
    buf.push(0x00);

    // Cipher suites
    let suites = [0x00, 0x2F, 0x00, 0x35, 0xC0, 0x2F, 0xC0, 0x30];
    buf.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    buf.extend_from_slice(&suites);

    // Compression methods
    buf.push(0x01);
    buf.push(0x00);

    // Extensions - SNI
    let sni_data = build_sni_extension(host);
    buf.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    buf.extend_from_slice(&sni_data);

    // Fix lengths
    let hello_len = buf.len() - hello_start;
    buf[hs_len_pos] = 0;
    buf[hs_len_pos + 1] = ((hello_len >> 8) & 0xFF) as u8;
    buf[hs_len_pos + 2] = (hello_len & 0xFF) as u8;

    let record_len = buf.len() - start;
    buf[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
    buf[record_len_pos + 1] = (record_len & 0xFF) as u8;

    buf
}

fn build_sni_extension(host: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.push(0x00);
    ext.push(0x00); // SNI extension type

    let name_len = host.len();
    let list_len = 3 + name_len;
    let ext_len = 2 + list_len;

    ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
    ext.extend_from_slice(&(list_len as u16).to_be_bytes());
    ext.push(0x00); // host_name type
    ext.extend_from_slice(&(name_len as u16).to_be_bytes());
    ext.extend_from_slice(host.as_bytes());
    ext
}

/// Build a fake TLS ServerHello response.
fn build_fake_server_hello() -> Vec<u8> {
    let mut buf = Vec::new();

    // TLS Record header
    buf.push(0x16); // Handshake
    buf.push(0x03);
    buf.push(0x03); // TLS 1.2

    let record_len_pos = buf.len();
    buf.push(0x00);
    buf.push(0x00);

    let start = buf.len();

    // ServerHello
    buf.push(0x02);

    let hs_len_pos = buf.len();
    buf.push(0x00);
    buf.push(0x00);
    buf.push(0x00);

    let hello_start = buf.len();

    // Server version
    buf.push(0x03);
    buf.push(0x03);

    // Random (32 bytes)
    let random: [u8; 32] = rand::random();
    buf.extend_from_slice(&random);

    // Session ID length = 0
    buf.push(0x00);

    // Cipher suite
    buf.push(0x00);
    buf.push(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA

    // Compression method
    buf.push(0x00);

    // Fix lengths
    let hello_len = buf.len() - hello_start;
    buf[hs_len_pos] = 0;
    buf[hs_len_pos + 1] = ((hello_len >> 8) & 0xFF) as u8;
    buf[hs_len_pos + 2] = (hello_len & 0xFF) as u8;

    let record_len = buf.len() - start;
    buf[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
    buf[record_len_pos + 1] = (record_len & 0xFF) as u8;

    buf
}

fn base64_key() -> String {
    use base64::Engine;
    let key: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(key)
}

// --- Obfs4 (placeholder) ---

/// Obfs4 transporter placeholder.
/// Full implementation requires the obfs4 pluggable transport.
pub struct Obfs4Transporter;

impl Obfs4Transporter {
    pub fn new() -> Self {
        Self
    }
}

/// Obfs4 listener placeholder.
pub struct Obfs4Listener;

impl Obfs4Listener {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_build_fake_client_hello() {
        let hello = build_fake_client_hello("example.com");
        assert_eq!(hello[0], 0x16); // TLS Handshake
        assert_eq!(hello[1], 0x03); // TLS 1.0
        assert_eq!(hello[2], 0x01);
        assert!(hello.len() > 50); // Should be substantial
    }

    #[test]
    fn test_build_fake_server_hello() {
        let hello = build_fake_server_hello();
        assert_eq!(hello[0], 0x16); // TLS Handshake
        assert!(hello.len() > 40);
    }

    #[test]
    fn test_build_sni_extension() {
        let ext = build_sni_extension("example.com");
        assert_eq!(ext[0], 0x00);
        assert_eq!(ext[1], 0x00); // SNI type
        assert!(ext.len() > 10);
    }

    #[tokio::test]
    async fn test_obfs_http_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server side
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let obfs = ObfsHttpListener::new();
            let mut conn = obfs.accept_handshake(conn).await.unwrap();
            conn.write_all(b"obfs-http data").await.unwrap();
            conn.flush().await.unwrap();
            // Keep connection alive so client can read
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        // Client side
        let conn = TcpStream::connect(addr).await.unwrap();
        let obfs = ObfsHttpTransporter::new();
        let mut conn = obfs.handshake(conn, "example.com").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"obfs-http data");

        server.await.ok();
    }

    #[tokio::test]
    async fn test_obfs_tls_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server side
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let obfs = ObfsTlsListener::new();
            let mut conn = obfs.accept_handshake(conn).await.unwrap();
            conn.write_all(b"obfs-tls data").await.unwrap();
        });

        // Client side
        let conn = TcpStream::connect(addr).await.unwrap();
        let obfs = ObfsTlsTransporter::new();
        let mut conn = obfs.handshake(conn, "example.com").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"obfs-tls data");
    }
}
