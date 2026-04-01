use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::LARGE_BUFFER_SIZE;

/// Bidirectional data transport between two streams.
pub async fn transport<A, B>(a: A, b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);

    let t1 = tokio::spawn(async move { copy_buffer(&mut ar, &mut bw).await });
    let t2 = tokio::spawn(async move { copy_buffer(&mut br, &mut aw).await });

    // Wait for either direction to finish
    tokio::select! {
        r = t1 => { r.map_err(io::Error::other)??; }
        r = t2 => { r.map_err(io::Error::other)??; }
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

        // Write from client_a, expect to read from client_b
        client_a.write_all(b"hello").await.unwrap();
        client_a.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        handle.await.ok();
    }
}
