#![no_main]

use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, BufReader, ReadBuf};

use exfilguard::proxy::http::fuzzing::stream_chunked_body;

struct CursorRead {
    inner: Cursor<Vec<u8>>,
}

impl CursorRead {
    fn new(data: &[u8]) -> Self {
        Self {
            inner: Cursor::new(data.to_vec()),
        }
    }
}

impl AsyncRead for CursorRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        let read = Read::read(&mut self.inner, unfilled)?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build tokio runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    let max_request_body_size = data.len().max(1).min(64 * 1024);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345));

    runtime().block_on(async {
        let mut reader = BufReader::new(CursorRead::new(data));
        let mut sink = tokio::io::sink();
        let _ = stream_chunked_body(
            &mut reader,
            &mut sink,
            Duration::from_millis(10),
            Duration::from_millis(10),
            peer,
            max_request_body_size,
        )
        .await;
    });
});
