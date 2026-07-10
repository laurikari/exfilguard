#![no_main]

use std::borrow::Cow;
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

/// Tracked text seeds use hex so CRLF and control-byte regressions remain explicit.
/// Arbitrary fuzzer-generated inputs continue to reach the parser unchanged.
fn corpus_bytes(data: &[u8]) -> Cow<'_, [u8]> {
    const HEX_PREFIX: &[u8] = b"hex:";
    let Some(encoded) = data.strip_prefix(HEX_PREFIX) else {
        return Cow::Borrowed(data);
    };
    let digits: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Cow::Borrowed(data);
    }

    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let Some(high) = (pair[0] as char).to_digit(16) else {
            return Cow::Borrowed(data);
        };
        let Some(low) = (pair[1] as char).to_digit(16) else {
            return Cow::Borrowed(data);
        };
        decoded.push(((high << 4) | low) as u8);
    }
    Cow::Owned(decoded)
}

fuzz_target!(|data: &[u8]| {
    let data = corpus_bytes(data);
    let max_request_body_size = data.len().clamp(1, 64 * 1024);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345));

    runtime().block_on(async {
        let mut reader = BufReader::new(CursorRead::new(&data));
        let mut sink = tokio::io::sink();
        let _ = stream_chunked_body(
            &mut reader,
            &mut sink,
            Duration::from_millis(10),
            Duration::from_millis(10),
            None,
            peer,
            max_request_body_size,
            32 * 1024,
        )
        .await;
    });
});
