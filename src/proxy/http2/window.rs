//! Adaptive receive credit. Reservations cover granted credit as well as received DATA.
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{sync::Notify, time::Instant};

use crate::settings::Settings;

const MIN: u32 = 65_535;
const INITIAL: u32 = 1024 * 1024;

pub(crate) struct Budget {
    limit: u64,
    used: Mutex<u64>,
}
impl Budget {
    pub(crate) fn new(settings: &Settings) -> Arc<Self> {
        let (limit, source) = super::memory::budget(settings.http2_receive_window_budget);
        tracing::info!(bytes = limit, source, "HTTP/2 receive-window budget");
        Arc::new(Self {
            limit,
            used: Mutex::new(0),
        })
    }
    fn reserve(&self, bytes: u64) -> bool {
        let mut used = self.used.lock();
        if bytes > self.limit - *used {
            return false;
        }
        *used += bytes;
        crate::metrics::http2_window_reserved(bytes as i64);
        true
    }
    fn release(&self, bytes: u64) {
        *self.used.lock() -= bytes;
        crate::metrics::http2_window_reserved(-(bytes as i64));
    }
    pub(super) fn session(
        self: &Arc<Self>,
        settings: &Settings,
    ) -> anyhow::Result<(Arc<Window>, Arc<Window>)> {
        let initial = settings.http2_connection_window_size.min(INITIAL);
        if !self.reserve(2 * u64::from(initial)) {
            crate::metrics::http2_window_denied("admission");
            anyhow::bail!("HTTP/2 receive-window budget exhausted");
        }
        let make = || {
            Arc::new(Window {
                budget: self.clone(),
                state: Mutex::new(State {
                    target: initial,
                    charged: initial,
                    forwarded: 0,
                }),
                progress: Notify::new(),
                initial,
                maximum: settings.http2_connection_window_size,
                stream_maximum: settings.http2_stream_window_size,
            })
        };
        crate::metrics::http2_window_target(2 * i64::from(initial));
        Ok((make(), make()))
    }
}
struct State {
    target: u32,
    charged: u32,
    forwarded: u64,
}
pub(super) struct Window {
    budget: Arc<Budget>,
    state: Mutex<State>,
    progress: Notify,
    initial: u32,
    maximum: u32,
    stream_maximum: u32,
}
impl Window {
    pub(super) fn target(&self) -> u32 {
        self.state.lock().target
    }
    pub(super) fn stream_target(&self) -> u32 {
        (self.target() / 2).max(MIN).min(self.stream_maximum)
    }
    fn forwarded(&self) -> u64 {
        self.state.lock().forwarded
    }
    // The lock serializes h2's target change with capacity releases. An increase
    // is charged in full even if an earlier decrease has not drained yet.
    fn resize(&self, desired: u32, apply: impl FnOnce(u32)) {
        let mut state = self.state.lock();
        let old = state.target;
        if desired > old {
            let extra = desired - old;
            if state.charged.checked_add(extra).is_none() || !self.budget.reserve(u64::from(extra))
            {
                crate::metrics::http2_window_denied("growth");
                return;
            }
            state.charged += extra;
        }
        apply(desired);
        state.target = desired;
        crate::metrics::http2_window_target(i64::from(desired) - i64::from(old));
    }
}
impl Drop for Window {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        self.budget.release(u64::from(state.charged));
        crate::metrics::http2_window_target(-i64::from(state.target));
    }
}

// Body ownership keeps the reservation alive after a driver stops. Drop the h2
// stream before its window handle, including on request cancellation.
pub(super) struct Body {
    inner: h2::RecvStream,
    window: Arc<Window>,
}
impl Body {
    pub(super) fn new(inner: h2::RecvStream, window: Arc<Window>) -> Self {
        Self { inner, window }
    }
    pub(super) fn release(&mut self, len: usize, forwarded: bool) -> Result<(), h2::Error> {
        let mut state = self.window.state.lock();
        self.inner.flow_control().release_capacity(len)?;
        // Automatic h2 releases (padding, resets) are intentionally not counted:
        // missing them retains too much reservation, never too little.
        let reclaimed = (state.charged - state.target).min(len as u32);
        state.charged -= reclaimed;
        if reclaimed > 0 {
            self.window.budget.release(u64::from(reclaimed));
        }
        if forwarded {
            state.forwarded = state.forwarded.saturating_add(len as u64);
            self.window.progress.notify_one();
        }
        Ok(())
    }
}
impl Deref for Body {
    type Target = h2::RecvStream;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for Body {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub(super) struct Controller {
    window: Arc<Window>,
    samples: tokio::sync::mpsc::Receiver<(u64, Duration, Duration)>,
    probe: tokio::task::JoinHandle<()>,
    rtt: f64,
    low_since: Option<Instant>,
    last_shrink: Instant,
    last_progress: u64,
    last_activity: Instant,
    last_desired: u32,
    stream_applied: u32,
}
impl Controller {
    pub(super) fn new(window: Arc<Window>, mut ping: h2::PingPong) -> Self {
        let (tx, samples) = tokio::sync::mpsc::channel(1);
        let observed = window.clone();
        let probe = tokio::spawn(async move {
            let mut last = observed.forwarded();
            let mut since = Instant::now();
            loop {
                observed.progress.notified().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                let sent = Instant::now();
                if ping.ping(h2::Ping::opaque()).await.is_err() {
                    break;
                }
                let now = Instant::now();
                let bytes = observed.forwarded();
                if tx
                    .send((bytes.saturating_sub(last), now - since, now - sent))
                    .await
                    .is_err()
                {
                    break;
                }
                last = bytes;
                since = now;
            }
        });
        let stream_applied = window.stream_target();
        let last_desired = window.initial;
        Self {
            window,
            samples,
            probe,
            rtt: 0.0,
            low_since: None,
            last_shrink: Instant::now(),
            last_progress: 0,
            last_activity: Instant::now(),
            last_desired,
            stream_applied,
        }
    }
    pub(super) async fn sample(&mut self) -> Option<(u64, Duration, Duration)> {
        match self.samples.recv().await {
            Some(sample) => Some(sample),
            None => std::future::pending().await,
        }
    }
    pub(super) fn update(
        &mut self,
        sample: Option<(u64, Duration, Duration)>,
        connection: &mut impl Receiver,
    ) {
        let now = Instant::now();
        let current = self.window.target();
        let forwarded = self.window.forwarded();
        if forwarded != self.last_progress {
            self.last_activity = now;
        }
        let desired = if let Some((bytes, elapsed, rtt)) = sample {
            let rtt = rtt.as_secs_f64();
            self.rtt = if self.rtt == 0.0 {
                rtt
            } else {
                self.rtt + (rtt - self.rtt) / 8.0
            };
            let bytes =
                (4.0 * bytes as f64 * self.rtt / elapsed.as_secs_f64().max(0.000001)) as u64;
            bytes
                .max(1)
                .checked_next_power_of_two()
                .unwrap_or(u64::MAX)
                .clamp(
                    u64::from(self.window.initial),
                    u64::from(self.window.maximum),
                ) as u32
        } else if now.duration_since(self.last_activity) >= Duration::from_secs(1) {
            self.window.initial
        } else {
            self.last_desired
        };
        self.last_desired = desired;
        self.last_progress = forwarded;
        let target = if desired > current {
            self.low_since = None;
            desired.min(current.saturating_mul(2))
        } else if desired <= current / 2 {
            let since = *self.low_since.get_or_insert(now);
            if now.duration_since(since) >= Duration::from_secs(5)
                && now.duration_since(self.last_shrink) >= Duration::from_secs(1)
            {
                self.last_shrink = now;
                (current / 2).max(desired)
            } else {
                current
            }
        } else {
            self.low_since = None;
            current
        };
        if target != current {
            self.window
                .resize(target, |size| connection.connection_window(size));
        }
        let target = self.window.stream_target();
        if target != self.stream_applied && connection.stream_window(target).is_ok() {
            self.stream_applied = target;
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.probe.abort();
    }
}

pub(super) trait Receiver {
    fn connection_window(&mut self, size: u32);
    fn stream_window(&mut self, size: u32) -> Result<(), h2::Error>;
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Receiver
    for h2::server::Connection<T, bytes::Bytes>
{
    fn connection_window(&mut self, size: u32) {
        self.set_target_window_size(size);
    }
    fn stream_window(&mut self, size: u32) -> Result<(), h2::Error> {
        self.set_initial_window_size(size)
    }
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Receiver
    for h2::client::Connection<T, bytes::Bytes>
{
    fn connection_window(&mut self, size: u32) {
        self.set_target_window_size(size);
    }
    fn stream_window(&mut self, size: u32) -> Result<(), h2::Error> {
        self.set_initial_window_size(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio::io::AsyncWriteExt;

    fn settings() -> Settings {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "listen='127.0.0.1:3128'\nclients='clients.toml'\npolicies='policies.toml'\n[ca]\nsource='builtin'\ndir='ca'").unwrap();
        Settings::load(&crate::cli::Cli {
            command: None,
            config: Some(path),
        })
        .unwrap()
    }
    fn budget(bytes: u64) -> Arc<Budget> {
        Arc::new(Budget {
            limit: bytes,
            used: Mutex::new(0),
        })
    }

    #[test]
    fn admission_is_atomic_and_growth_stays_within_shared_budget() {
        let budget = budget(4 * u64::from(INITIAL));
        let (a, b) = budget.session(&settings()).unwrap();
        a.resize(3 * INITIAL, |_| {});
        assert_eq!(*budget.used.lock(), budget.limit);
        assert!(budget.session(&settings()).is_err());
        b.resize(2 * INITIAL, |_| {
            panic!("must not advertise unreserved credit")
        });
        assert_eq!(b.target(), INITIAL);
        a.resize(INITIAL, |_| {});
        assert_eq!(
            *budget.used.lock(),
            budget.limit,
            "shrinking does not reclaim credit"
        );
        drop(a);
        assert_eq!(*budget.used.lock(), u64::from(INITIAL));
        assert!(budget.session(&settings()).is_ok());
        drop(b);
        assert_eq!(*budget.used.lock(), 0);
    }

    #[test]
    fn concurrent_admissions_never_overcommit() {
        let budget = budget(8 * u64::from(INITIAL));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let budget = &budget;
                scope.spawn(move || {
                    let settings = settings();
                    for _ in 0..100 {
                        if let Ok((a, b)) = budget.session(&settings) {
                            a.resize(2 * INITIAL, |_| {});
                            assert!(*budget.used.lock() <= budget.limit);
                            drop((a, b));
                        }
                    }
                });
            }
        });
        assert_eq!(*budget.used.lock(), 0);
    }

    // Raw frames deliberately exercise credit granted before the target shrank,
    // including padding and reset releases which are invisible to Body::release.
    async fn frame(
        peer: &mut tokio::io::DuplexStream,
        kind: u8,
        flags: u8,
        id: u32,
        payload: &[u8],
    ) {
        let len = (payload.len() as u32).to_be_bytes();
        let mut header = vec![len[1], len[2], len[3], kind, flags];
        header.extend_from_slice(&id.to_be_bytes());
        peer.write_all(&header).await.unwrap();
        peer.write_all(payload).await.unwrap();
    }
    #[tokio::test]
    async fn old_credit_remains_valid_and_charged_until_consumed() {
        let budget = budget(4 * u64::from(INITIAL));
        let (window, other) = budget.session(&settings()).unwrap();
        let (io, mut peer) = tokio::io::duplex(2 * INITIAL as usize);
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        frame(&mut peer, 4, 0, 0, &[]).await;
        // HPACK static entries: POST, https, /, literal authority.
        frame(&mut peer, 1, 4, 1, &[0x83, 0x87, 0x84, 0x01, 0x01, b'x']).await;
        let mut connection = h2::server::Builder::new()
            .initial_window_size(INITIAL)
            .initial_connection_window_size(INITIAL)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (request, response) = connection.accept().await.unwrap().unwrap();
        let mut body = Body::new(request.into_body(), window.clone());
        tokio::select! {
            _ = super::super::test_support::assert_receive_windows(&mut peer, INITIAL, INITIAL) => {},
            result = connection.accept() => panic!("unexpected request while advertising windows: {result:?}"),
        }
        frame(&mut peer, 4, 1, 0, &[]).await;
        window.resize(MIN, |size| connection.set_target_window_size(size));
        assert_eq!(window.state.lock().charged, INITIAL);
        let driver_window = window.clone();
        let driver = tokio::spawn(async move {
            let _window = driver_window;
            let mut connection = connection;
            while let Some(Ok(_)) = connection.accept().await {}
        });
        let data = vec![42; 16_384];
        frame(&mut peer, 0, 8, 1, &[2, 42, 0, 0]).await;
        for _ in 1..INITIAL / 16_384 {
            frame(&mut peer, 0, 0, 1, &data).await;
        }
        frame(&mut peer, 0, 0, 1, &data[..16_384 - 4]).await;
        let mut received = 0;
        while received < INITIAL as usize - 3 {
            let chunk = tokio::time::timeout(Duration::from_secs(2), body.data())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            received += chunk.len();
            body.release(chunk.len(), true).unwrap();
            assert!(window.state.lock().charged >= MIN);
        }
        assert_eq!(window.state.lock().charged, MIN);
        frame(&mut peer, 3, 0, 1, &8u32.to_be_bytes()).await;
        drop((response, peer, body, window, other));
        driver.abort();
        let _ = driver.await;
        assert_eq!(*budget.used.lock(), 0);
    }

    struct Fake {
        connection: u32,
        stream: u32,
    }
    impl Receiver for Fake {
        fn connection_window(&mut self, size: u32) {
            self.connection = size;
        }
        fn stream_window(&mut self, size: u32) -> Result<(), h2::Error> {
            self.stream = size;
            Ok(())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn controller_grows_shrinks_and_recovers_without_reclaiming_unspent_credit() {
        let budget = budget(256 << 20);
        let (window, other) = budget.session(&settings()).unwrap();
        let (io, _peer) = tokio::io::duplex(4096);
        let (_, mut client) = h2::client::handshake::<_>(io).await.unwrap();
        let mut controller = Controller::new(window.clone(), client.ping_pong().unwrap());
        let mut fake = Fake {
            connection: INITIAL,
            stream: INITIAL / 2,
        };
        for _ in 0..6 {
            controller.update(
                Some((
                    16 << 20,
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                )),
                &mut fake,
            );
        }
        assert_eq!(fake.connection, 64 << 20);
        assert_eq!(fake.stream, 32 << 20);
        let charged = *budget.used.lock();
        for _ in 0..12 {
            tokio::time::advance(Duration::from_secs(1)).await;
            controller.update(None, &mut fake);
        }
        assert_eq!(fake.connection, INITIAL);
        assert_eq!(*budget.used.lock(), charged);
        controller.update(
            Some((
                INITIAL as u64,
                Duration::from_millis(100),
                Duration::from_millis(100),
            )),
            &mut fake,
        );
        assert_eq!(fake.connection, 2 * INITIAL);
        drop((client, controller, window, other));
        tokio::task::yield_now().await;
        assert_eq!(*budget.used.lock(), 0);
    }
}
