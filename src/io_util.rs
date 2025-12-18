use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

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
    use super::TeeWriter;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

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
}
