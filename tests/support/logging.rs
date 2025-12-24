use std::io;
use std::io::Write;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::{self, MakeWriter};

#[derive(Clone)]
struct BufferWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriterHandle;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriterHandle {
            buffer: self.buffer.clone(),
        }
    }
}

struct BufferWriterHandle {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for BufferWriterHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.buffer.lock().unwrap_or_else(|err| err.into_inner());
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Captures tracing output for tests using a shared global subscriber.
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
    _permit: OwnedSemaphorePermit,
}

static LOG_BUFFER: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();
static LOG_SEMAPHORE: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();

impl LogCapture {
    pub async fn new(filter: &str) -> Self {
        let semaphore = LOG_SEMAPHORE
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        let permit = semaphore
            .acquire_owned()
            .await
            .expect("log capture semaphore closed");
        let buffer = LOG_BUFFER
            .get_or_init(|| {
                let buffer = Arc::new(Mutex::new(Vec::new()));
                let writer = BufferWriter {
                    buffer: buffer.clone(),
                };
                let subscriber = fmt::fmt()
                    .with_env_filter(EnvFilter::new(filter))
                    .with_target(false)
                    .with_ansi(false)
                    .compact()
                    .with_writer(writer)
                    .finish();
                let _ = tracing::subscriber::set_global_default(subscriber);
                buffer
            })
            .clone();
        buffer.lock().unwrap_or_else(|err| err.into_inner()).clear();
        Self {
            buffer,
            _permit: permit,
        }
    }

    pub fn text(&self) -> String {
        let guard = self.buffer.lock().unwrap_or_else(|err| err.into_inner());
        String::from_utf8_lossy(&guard).to_string()
    }
}
