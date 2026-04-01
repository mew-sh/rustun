use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Simple stream multiplexer over a single TCP connection.
/// This is a simplified equivalent of smux used in gost.
///
/// Frame format:
/// [stream_id: u32] [flags: u8] [length: u16] [payload: ...]
///
/// Flags:
/// 0x01 = SYN (new stream)
/// 0x02 = FIN (close stream)
/// 0x04 = DATA
const FLAG_SYN: u8 = 0x01;
const FLAG_FIN: u8 = 0x02;
const FLAG_DATA: u8 = 0x04;

const HEADER_SIZE: usize = 7; // 4 + 1 + 2

/// MuxSession manages multiplexed streams over a single connection.
pub struct MuxSession {
    conn: Arc<Mutex<Option<TcpStream>>>,
    next_stream_id: Arc<Mutex<u32>>,
    closed: Arc<Mutex<bool>>,
}

impl MuxSession {
    pub fn new(conn: TcpStream) -> Self {
        Self {
            conn: Arc::new(Mutex::new(Some(conn))),
            next_stream_id: Arc::new(Mutex::new(1)),
            closed: Arc::new(Mutex::new(false)),
        }
    }

    /// Check if the session is closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    /// Close the session.
    pub fn close(&self) {
        *self.closed.lock().unwrap() = true;
        *self.conn.lock().unwrap() = None;
    }

    /// Open a new stream.
    pub fn open_stream(&self) -> Option<u32> {
        if self.is_closed() {
            return None;
        }
        let mut id = self.next_stream_id.lock().unwrap();
        let stream_id = *id;
        *id += 2; // odd IDs for client, even for server
        Some(stream_id)
    }
}

/// MuxFrame is a multiplexing frame.
#[derive(Debug, Clone)]
pub struct MuxFrame {
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl MuxFrame {
    pub fn new(stream_id: u32, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            flags,
            payload,
        }
    }

    /// Encode the frame to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(self.flags);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from bytes.
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let flags = data[4];
        let length = u16::from_be_bytes([data[5], data[6]]) as usize;

        if data.len() < HEADER_SIZE + length {
            return None;
        }

        let payload = data[HEADER_SIZE..HEADER_SIZE + length].to_vec();
        Some((
            MuxFrame {
                stream_id,
                flags,
                payload,
            },
            HEADER_SIZE + length,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mux_frame_encode_decode() {
        let frame = MuxFrame::new(42, FLAG_DATA, b"hello mux".to_vec());
        let encoded = frame.encode();

        let (decoded, consumed) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flags, FLAG_DATA);
        assert_eq!(decoded.payload, b"hello mux");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_mux_frame_syn() {
        let frame = MuxFrame::new(1, FLAG_SYN, vec![]);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.flags, FLAG_SYN);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_mux_frame_fin() {
        let frame = MuxFrame::new(1, FLAG_FIN, vec![]);
        let encoded = frame.encode();
        let (decoded, _) = MuxFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flags, FLAG_FIN);
    }

    #[test]
    fn test_mux_frame_decode_incomplete() {
        assert!(MuxFrame::decode(&[0, 0, 0]).is_none()); // too short
        assert!(MuxFrame::decode(&[0, 0, 0, 1, 0x04, 0, 5]).is_none()); // payload too short
    }

    #[tokio::test]
    async fn test_mux_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_tcp = TcpStream::connect(addr).await.unwrap();
        let (_server_conn, _) = listener.accept().await.unwrap();

        let session = MuxSession::new(client_tcp);

        assert!(!session.is_closed());

        let id1 = session.open_stream().unwrap();
        let id2 = session.open_stream().unwrap();
        assert_ne!(id1, id2);

        session.close();
        assert!(session.is_closed());
        assert!(session.open_stream().is_none());
    }
}
