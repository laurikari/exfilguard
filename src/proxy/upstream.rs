use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until, timeout_at};
use tracing::debug;

use crate::proxy::{connect::ResolvedTarget, resolver::UpstreamResolver};

const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Attempt to connect to the supplied socket addresses without performing name resolution.
pub async fn connect_to_addrs(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    let (stream, peer) = connect_to_addrs_with(addrs, connect_timeout, TcpStream::connect).await?;
    if let Err(err) = stream.set_nodelay(true) {
        debug!(
            host = %peer.ip(),
            port = peer.port(),
            error = %err,
            "failed to set TCP_NODELAY on upstream stream"
        );
    }
    debug!(host = %peer.ip(), port = peer.port(), "connected to upstream");
    Ok((stream, peer))
}

type ConnectionAttempt<'a, T> =
    Pin<Box<dyn Future<Output = (SocketAddr, std::io::Result<T>)> + Send + 'a>>;

async fn connect_to_addrs_with<T, F, Fut>(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
    connect: F,
) -> Result<(T, SocketAddr)>
where
    T: Send,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>> + Send,
{
    if addrs.is_empty() {
        bail!("no addresses provided for upstream connect");
    }

    let ordered = interleave_address_families(addrs);
    let deadline = Instant::now()
        .checked_add(connect_timeout)
        .ok_or_else(|| anyhow::anyhow!("upstream connect timeout is too large"))?;
    let mut attempted = 0usize;
    match timeout_at(
        deadline,
        race_connection_attempts(&ordered, CONNECTION_ATTEMPT_DELAY, connect, &mut attempted),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!(
            "timed out after {:?} connecting to upstream; attempted {} of {} resolved addresses",
            connect_timeout,
            attempted,
            ordered.len()
        ),
    }
}

async fn race_connection_attempts<T, F, Fut>(
    addrs: &[SocketAddr],
    attempt_delay: Duration,
    connect: F,
    attempted: &mut usize,
) -> Result<(T, SocketAddr)>
where
    T: Send,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>> + Send,
{
    let mut attempts: FuturesUnordered<ConnectionAttempt<'_, T>> = FuturesUnordered::new();
    let mut next_index = 0usize;
    let mut last_err = None;

    start_connection_attempt(&mut attempts, addrs[next_index], &connect);
    *attempted += 1;
    next_index += 1;
    let mut next_attempt_at = Instant::now() + attempt_delay;

    loop {
        if attempts.is_empty() && next_index == addrs.len() {
            return Err(last_err
                .unwrap_or_else(|| anyhow::anyhow!("all upstream connection attempts failed")));
        }

        tokio::select! {
            biased;
            result = attempts.next(), if !attempts.is_empty() => {
                let (addr, result) = result.expect("non-empty connection attempt set");
                match result {
                    Ok(stream) => return Ok((stream, addr)),
                    Err(err) => {
                        last_err = Some(
                            Err::<(), std::io::Error>(err)
                                .with_context(|| format!("failed to connect to {addr}"))
                                .unwrap_err(),
                        );
                    }
                }
            }
            _ = sleep_until(next_attempt_at), if next_index < addrs.len() => {
                start_connection_attempt(&mut attempts, addrs[next_index], &connect);
                *attempted += 1;
                next_index += 1;
                next_attempt_at = Instant::now() + attempt_delay;
            }
        }
    }
}

fn start_connection_attempt<'a, T, F, Fut>(
    attempts: &mut FuturesUnordered<ConnectionAttempt<'a, T>>,
    addr: SocketAddr,
    connect: &'a F,
) where
    T: Send + 'a,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>> + Send + 'a,
{
    let attempt = connect(addr);
    attempts.push(Box::pin(async move { (addr, attempt.await) }));
}

fn interleave_address_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_is_ipv6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let mut ipv4 = addrs.iter().copied().filter(SocketAddr::is_ipv4);
    let mut ipv6 = addrs.iter().copied().filter(SocketAddr::is_ipv6);
    let mut ordered = Vec::with_capacity(addrs.len());

    loop {
        let next_first = if first_is_ipv6 {
            ipv6.next()
        } else {
            ipv4.next()
        };
        let next_second = if first_is_ipv6 {
            ipv4.next()
        } else {
            ipv6.next()
        };
        if next_first.is_none() && next_second.is_none() {
            break;
        }
        ordered.extend(next_first);
        ordered.extend(next_second);
    }

    ordered
}

/// Returns the socket addresses to use for an upstream request, either by reusing a validated
/// CONNECT binding or by resolving the hostname with the standard policy filters applied.
pub(crate) async fn resolve_or_use_binding(
    host: &str,
    port: u16,
    binding: Option<&ResolvedTarget>,
    resolver: &dyn UpstreamResolver,
    resolve_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    if let Some(binding) = binding {
        if host != binding.host() || port != binding.port() {
            bail!(
                "upstream request {}:{} mismatches CONNECT target {}:{}",
                host,
                port,
                binding.host(),
                binding.port()
            );
        }
        return Ok(binding.addresses().to_vec());
    }

    let filtered = resolver
        .resolve_filtered(host, port, resolve_timeout, "upstream")
        .await?;
    Ok(filtered.allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::connect::ResolvedTarget;
    use crate::proxy::resolver::PrivateAddressError;
    use std::future::pending;
    use std::io;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::time::Instant;

    struct ActiveAttempt(Arc<AtomicUsize>);

    impl ActiveAttempt {
        fn new(active: Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self(active)
        }
    }

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("valid test address")
    }

    #[test]
    fn address_families_are_interleaved_without_reordering_each_family() {
        let v6_first = addr("[2001:db8::1]:443");
        let v6_second = addr("[2001:db8::2]:443");
        let v4_first = addr("192.0.2.1:443");
        let v4_second = addr("192.0.2.2:443");

        assert_eq!(
            interleave_address_families(&[v6_first, v6_second, v4_first, v4_second]),
            vec![v6_first, v4_first, v6_second, v4_second]
        );
        assert_eq!(
            interleave_address_families(&[v4_first, v4_second, v6_first, v6_second]),
            vec![v4_first, v6_first, v4_second, v6_second]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_timeout_is_one_budget_across_all_addresses() {
        let addrs = [
            addr("192.0.2.1:443"),
            addr("192.0.2.2:443"),
            addr("192.0.2.3:443"),
        ];
        let start = Instant::now();

        let err = connect_to_addrs_with(&addrs, Duration::from_secs(1), |_| async {
            pending::<io::Result<()>>().await
        })
        .await
        .expect_err("all connection attempts should remain pending");

        assert_eq!(Instant::now() - start, Duration::from_secs(1));
        assert!(
            err.to_string()
                .contains("attempted 3 of 3 resolved addresses"),
            "unexpected timeout error: {err:#}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_task_does_not_launch_overdue_attempts_in_a_burst() {
        let addrs = vec![
            addr("192.0.2.1:443"),
            addr("192.0.2.2:443"),
            addr("192.0.2.3:443"),
            addr("192.0.2.4:443"),
        ];
        let started = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let started = started.clone();
            async move {
                connect_to_addrs_with(&addrs, Duration::from_secs(5), move |_| {
                    let started = started.clone();
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        pending::<io::Result<()>>().await
                    }
                })
                .await
            }
        });

        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            2,
            "executor delay caused overdue attempts to launch together"
        );

        tokio::time::advance(CONNECTION_ATTEMPT_DELAY - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(started.load(Ordering::SeqCst), 3);

        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn later_address_can_win_after_stagger_and_cancels_losers() -> Result<()> {
        let v6_first = addr("[2001:db8::1]:443");
        let v6_second = addr("[2001:db8::2]:443");
        let v4_winner = addr("192.0.2.1:443");
        let started = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();

        let (stream, peer) =
            connect_to_addrs_with(&[v6_first, v6_second, v4_winner], Duration::from_secs(2), {
                let started = started.clone();
                let active = active.clone();
                move |candidate| {
                    let started = started.clone();
                    let active = active.clone();
                    async move {
                        let _active = ActiveAttempt::new(active);
                        started
                            .lock()
                            .expect("started-attempt lock poisoned")
                            .push((candidate, Instant::now()));
                        if candidate == v4_winner {
                            Ok(candidate)
                        } else {
                            pending::<io::Result<SocketAddr>>().await
                        }
                    }
                }
            })
            .await?;

        assert_eq!(stream, v4_winner);
        assert_eq!(peer, v4_winner);
        assert_eq!(Instant::now() - start, CONNECTION_ATTEMPT_DELAY);
        assert_eq!(
            *started.lock().expect("started-attempt lock poisoned"),
            vec![
                (v6_first, start),
                (v4_winner, start + CONNECTION_ATTEMPT_DELAY)
            ]
        );
        assert_eq!(active.load(Ordering::SeqCst), 0, "losing attempt leaked");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_failures_retain_last_address_context() {
        let first = addr("192.0.2.1:443");
        let second = addr("192.0.2.2:443");
        let start = Instant::now();

        let err = connect_to_addrs_with(&[first, second], Duration::from_secs(2), |_| async {
            Err::<(), _>(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        })
        .await
        .expect_err("all connection attempts should fail");

        assert_eq!(Instant::now() - start, CONNECTION_ATTEMPT_DELAY);
        assert!(
            err.to_string().contains(&second.to_string()),
            "last address missing from error: {err:#}"
        );
    }

    #[tokio::test]
    async fn empty_address_list_is_rejected() {
        let err = connect_to_addrs_with(&[], Duration::from_secs(1), |_| async {
            Ok::<(), io::Error>(())
        })
        .await
        .expect_err("empty address list should fail");
        assert_eq!(
            err.to_string(),
            "no addresses provided for upstream connect"
        );
    }

    #[tokio::test]
    async fn binding_reuses_validated_private_target() -> Result<()> {
        let resolver = crate::proxy::resolver::PublicInternetResolver;
        let binding = ResolvedTarget::from_addresses(
            "internal.test".to_string(),
            443,
            vec!["10.0.0.5:443".parse().unwrap()],
        );
        let addrs = resolve_or_use_binding(
            "internal.test",
            443,
            Some(&binding),
            &resolver,
            Duration::from_secs(1),
        )
        .await?;
        assert_eq!(addrs, vec!["10.0.0.5:443".parse().unwrap()]);
        Ok(())
    }

    #[tokio::test]
    async fn direct_resolution_rejects_private_targets_when_disallowed() {
        let resolver = crate::proxy::resolver::PublicInternetResolver;
        let err = resolve_or_use_binding("10.0.0.5", 443, None, &resolver, Duration::from_secs(1))
            .await
            .expect_err("private upstream should be rejected");
        assert!(err.downcast_ref::<PrivateAddressError>().is_some());
    }
}
