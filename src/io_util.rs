use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

pub struct TeeWriter<W1, W2> {
    writer1: W1,
    writer2: W2,
}

impl<W1, W2> TeeWriter<W1, W2> {
    pub fn new(writer1: W1, writer2: W2) -> Self {
        Self { writer1, writer2 }
    }
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
        let w1 = Pin::new(&mut self.writer1).poll_write(cx, buf);
        let w2 = Pin::new(&mut self.writer2).poll_write(cx, buf);

        match (w1, w2) {
            (Poll::Ready(Ok(n1)), Poll::Ready(Ok(n2))) => {
                if n1 != n2 {
                    // This is a complex case: writers accepted different amounts.
                    // Realistically, we return min(n1, n2) and rely on caller to retry remainder.
                    // But AsyncWrite doesn't guarantee atomic writes for both underlying streams.
                    // For this specific use case (network + file), file write usually accepts all.
                    // We return n1 (client progress) and accept that cache might get out of sync
                    // if n2 < n1. In practice with BufWriter wrapping file, this is rare.
                    // Better: return min(n1, n2).
                    Poll::Ready(Ok(std::cmp::min(n1, n2)))
                } else {
                    Poll::Ready(Ok(n1))
                }
            }
            (Poll::Ready(Err(e)), _) => Poll::Ready(Err(e)),
            (_, Poll::Ready(Err(_))) => {
                // Cache failed. Ideally we disable cache and continue.
                // For now, fail the whole request to be safe/simple.
                Poll::Ready(Err(std::io::Error::other("cache write failed")))
            }
            _ => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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
