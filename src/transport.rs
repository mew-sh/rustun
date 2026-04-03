use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::LARGE_BUFFER_SIZE;

/// Bidirectional data transport between two streams.
///
/// Spawns two copy tasks (A->B and B->A). When either direction finishes
/// or errors, the other task is aborted to prevent task leaks.
pub async fn transport<A, B>(a: A, b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);

    let mut t1 = tokio::spawn(async move { copy_buffer(&mut ar, &mut bw).await });
    let mut t2 = tokio::spawn(async move { copy_buffer(&mut br, &mut aw).await });

    // Wait for either direction to finish, then abort the other.
    // Without aborting, the losing task runs indefinitely as an orphan
    // because it holds one half of a split stream that will never receive
    // data (the peer already closed).
    tokio::select! {
        r = &mut t1 => {
            t2.abort();
            r.map_err(io::Error::other)??;
        }
        r = &mut t2 => {
            t1.abort();
            r.map_err(io::Error::other)??;
        }
    }

    Ok(())
}

/// Copy data from reader to writer with a buffer.
async fn copy_buffer<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; LARGE_BUFFER_SIZE];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await.ok();
            break;
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        total += n as u64;
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_transport() {
        let (mut client_a, server_a) = duplex(1024);
        let (server_b, mut client_b) = duplex(1024);

        let handle = tokio::spawn(async move {
            transport(server_a, server_b).await.ok();
        });

        client_a.write_all(b"hello").await.unwrap();
        client_a.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        handle.await.ok();
    }

    #[tokio::test]
    async fn test_transport_no_leaked_tasks() {
        // Verify that when one side closes, both tasks complete promptly
        let (client_a, server_a) = duplex(1024);
        let (server_b, client_b) = duplex(1024);

        let handle = tokio::spawn(async move {
            transport(server_a, server_b).await.ok();
        });

        // Drop both client ends immediately
        drop(client_a);
        drop(client_b);

        // Transport should complete quickly, not hang forever
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            result.is_ok(),
            "transport should not hang when both sides are dropped"
        );
    }
}
