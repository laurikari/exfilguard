use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::timeout_with_context;

/// An I/O stream that returns an already-read prefix before continuing with the inner reader.
/// Writes are passed directly to the inner stream.
pub struct PrefixedIo<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.position < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.position..];
            let read = available.len().min(buf.remaining());
            buf.put_slice(&available[..read]);
            self.position += read;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl<W> AsyncWrite for CountingWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                self.bytes_written = self.bytes_written.saturating_add(written as u64);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A decoded payload copy with its own deadline, separate from client writes.
pub struct PayloadCopy<'a> {
    writer: &'a mut (dyn AsyncWrite + Unpin + Send),
    best_effort: bool,
    error: Option<anyhow::Error>,
}

impl<'a> PayloadCopy<'a> {
    pub fn required(writer: &'a mut (dyn AsyncWrite + Unpin + Send)) -> Self {
        Self {
            writer,
            best_effort: false,
            error: None,
        }
    }

    pub fn best_effort(writer: &'a mut (dyn AsyncWrite + Unpin + Send)) -> Self {
        Self {
            writer,
            best_effort: true,
            error: None,
        }
    }

    pub async fn write(&mut self, bytes: &[u8], limit: Duration) -> Result<()> {
        if self.error.is_some() {
            return Ok(());
        }
        let result = timeout_with_context(
            limit,
            self.writer.write_all(bytes),
            "copying response payload",
        )
        .await;
        match result {
            Err(err) if self.best_effort => {
                self.error = Some(err);
                Ok(())
            }
            result => result,
        }
    }

    pub fn take_error(&mut self) -> Option<anyhow::Error> {
        self.error.take()
    }
}

pub async fn write_all_with_timeout<W: AsyncWrite + Unpin, C: Into<String>>(
    writer: &mut W,
    buf: &[u8],
    timeout: Duration,
    context: C,
) -> Result<()> {
    timeout_with_context(timeout, writer.write_all(buf), context).await
}

pub async fn copy_with_write_timeout<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    timeout: Duration,
    context: &str,
) -> Result<u64> {
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        write_all_with_timeout(writer, &buffer[..read], timeout, context).await?;
        total = total.saturating_add(read as u64);
    }
    Ok(total)
}

pub async fn copy_n_with_write_timeout<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    timeout: Duration,
    context: &str,
) -> Result<u64> {
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..to_read]).await?;
        if read == 0 {
            anyhow::bail!("unexpected EOF while {context}");
        }
        write_all_with_timeout(writer, &buffer[..read], timeout, context).await?;
        total = total.saturating_add(read as u64);
        remaining -= read as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{PayloadCopy, PrefixedIo, copy_with_write_timeout, write_all_with_timeout};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};

    struct ChunkWriter {
        max_chunk: usize,
        data: Vec<u8>,
    }

    impl ChunkWriter {
        fn new(max_chunk: usize) -> Self {
            Self {
                max_chunk,
                data: Vec::new(),
            }
        }
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let to_write = buf.len().min(self.max_chunk);
            self.data.extend_from_slice(&buf[..to_write]);
            Poll::Ready(Ok(to_write))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FailingWriter {
        fail_after: usize,
        written: usize,
    }

    impl FailingWriter {
        fn new(fail_after: usize) -> Self {
            Self {
                fail_after,
                written: 0,
            }
        }
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.written >= self.fail_after {
                return Poll::Ready(Err(std::io::Error::other("boom")));
            }
            let remaining = self.fail_after - self.written;
            let to_write = remaining.min(buf.len());
            self.written += to_write;
            Poll::Ready(Ok(to_write))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn prefixed_io_reads_prefix_before_inner_and_delegates_writes() -> Result<()> {
        let (inner, mut peer) = duplex(64);
        peer.write_all(b"inner").await?;
        peer.shutdown().await?;

        let mut stream = PrefixedIo::new(inner, b"prefix-".to_vec());
        let mut read = Vec::new();
        let mut chunk = [0u8; 2];
        loop {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            read.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(read, b"prefix-inner");

        stream.write_all(b"delegated").await?;
        let mut written = [0u8; 9];
        peer.read_exact(&mut written).await?;
        assert_eq!(&written, b"delegated");
        Ok(())
    }

    #[tokio::test]
    async fn payload_copy_handles_partial_writes() -> Result<()> {
        let mut writer = ChunkWriter::new(3);
        let mut copy = PayloadCopy::best_effort(&mut writer);
        copy.write(b"abcdefghijklmnopqrstuvwxyz", Duration::from_secs(1))
            .await?;
        assert!(copy.take_error().is_none());
        assert_eq!(writer.data, b"abcdefghijklmnopqrstuvwxyz");
        Ok(())
    }

    #[tokio::test]
    async fn payload_copy_only_ignores_best_effort_errors() -> Result<()> {
        let mut writer = FailingWriter::new(3);
        let mut copy = PayloadCopy::best_effort(&mut writer);
        copy.write(b"abcdef", Duration::from_secs(1)).await?;
        copy.write(b"more", Duration::from_secs(1)).await?;
        assert!(copy.take_error().is_some());
        assert_eq!(writer.written, 3);
        let mut writer = FailingWriter::new(3);
        assert!(
            PayloadCopy::required(&mut writer)
                .write(b"abcdef", Duration::from_secs(1))
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn copy_with_write_timeout_handles_partial_writes() -> Result<()> {
        let (mut reader, mut writer) = duplex(16);
        let payload = b"abcdefghijklmnopqrstuvwxyz";
        let write_task = tokio::spawn(async move {
            writer.write_all(payload).await?;
            writer.shutdown().await
        });

        let mut sink = ChunkWriter::new(4);
        let copied = copy_with_write_timeout(
            &mut reader,
            &mut sink,
            Duration::from_secs(1),
            "writing cached response body",
        )
        .await?;

        write_task.await??;
        assert_eq!(copied as usize, payload.len());
        assert_eq!(sink.data, payload);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn write_all_with_timeout_times_out_on_stalled_writer() {
        let handle = tokio::spawn(async {
            let mut writer = PendingWriter;
            write_all_with_timeout(
                &mut writer,
                b"payload",
                Duration::from_secs(1),
                "writing cached response headers",
            )
            .await
        });

        tokio::time::advance(Duration::from_secs(2)).await;
        let err = handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }
}
