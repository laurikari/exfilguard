use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::timeout_with_context;

pub struct TeeWriter<W1, W2> {
    writer1: W1,
    writer2: W2,
    pending: Option<PendingWrite>,
}

impl<W1, W2> TeeWriter<W1, W2> {
    pub fn new(writer1: W1, writer2: W2) -> Self {
        Self {
            writer1,
            writer2,
            pending: None,
        }
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

struct PendingWrite {
    buf: Vec<u8>,
    w1_pos: usize,
    w2_pos: usize,
}

impl<W1, W2> AsyncWrite for TeeWriter<W1, W2>
where
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.pending.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.pending = Some(PendingWrite {
                buf: buf.to_vec(),
                w1_pos: 0,
                w2_pos: 0,
            });
        }

        self.poll_write_pending(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending.is_some() {
            match self.poll_write_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let w1 = Pin::new(&mut self.writer1).poll_flush(cx);
        let w2 = Pin::new(&mut self.writer2).poll_flush(cx);
        match (w1, w2) {
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            (Poll::Ready(Err(e)), _) => Poll::Ready(Err(e)),
            (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            _ => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending.is_some() {
            match self.poll_write_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let w1 = Pin::new(&mut self.writer1).poll_shutdown(cx);
        let w2 = Pin::new(&mut self.writer2).poll_shutdown(cx);
        match (w1, w2) {
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            (Poll::Ready(Err(e)), _) => Poll::Ready(Err(e)),
            (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            _ => Poll::Pending,
        }
    }
}

impl<W1, W2> TeeWriter<W1, W2>
where
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
{
    fn poll_write_pending(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        let mut pending = match this.pending.take() {
            Some(pending) => pending,
            None => return Poll::Ready(Ok(0)),
        };

        let len = pending.buf.len();
        loop {
            let mut made_progress = false;
            let mut saw_pending = false;

            if pending.w1_pos < len {
                match Pin::new(&mut this.writer1).poll_write(cx, &pending.buf[pending.w1_pos..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "tee writer1 write zero",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        pending.w1_pos += n;
                        made_progress = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => saw_pending = true,
                }
            }

            if pending.w2_pos < len {
                match Pin::new(&mut this.writer2).poll_write(cx, &pending.buf[pending.w2_pos..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "tee writer2 write zero",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        pending.w2_pos += n;
                        made_progress = true;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => saw_pending = true,
                }
            }

            if pending.w1_pos == len && pending.w2_pos == len {
                let written = pending.buf.len();
                return Poll::Ready(Ok(written));
            }

            if saw_pending {
                this.pending = Some(pending);
                return Poll::Pending;
            }

            if !made_progress {
                this.pending = Some(pending);
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TeeWriter, copy_with_write_timeout, write_all_with_timeout};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use anyhow::Result;
    use tokio::io::{AsyncWrite, AsyncWriteExt, duplex};

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

    #[tokio::test]
    async fn tee_writer_keeps_outputs_in_sync() -> std::io::Result<()> {
        let writer1 = ChunkWriter::new(1024);
        let writer2 = ChunkWriter::new(3);
        let mut tee = TeeWriter::new(writer1, writer2);

        let payload = b"abcdefghijklmnopqrstuvwxyz";
        tokio::io::AsyncWriteExt::write_all(&mut tee, payload).await?;

        let TeeWriter {
            writer1, writer2, ..
        } = tee;

        assert_eq!(writer1.data, payload);
        assert_eq!(writer2.data, payload);
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
