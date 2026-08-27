use futures_util::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;

pub(super) const ADDRESS_RACE_DELAY: Duration = Duration::from_millis(250);
const MAX_IN_FLIGHT: usize = 2;

struct InterleavedAddrs<'a> {
    addrs: &'a [SocketAddr],
    primary_ipv6: bool,
    primary_cursor: usize,
    secondary_cursor: usize,
    primary_turn: bool,
    remaining: usize,
}

impl<'a> InterleavedAddrs<'a> {
    fn new(addrs: &'a [SocketAddr]) -> Self {
        Self {
            addrs,
            primary_ipv6: addrs.first().is_some_and(SocketAddr::is_ipv6),
            primary_cursor: 0,
            secondary_cursor: 0,
            primary_turn: true,
            remaining: addrs.len(),
        }
    }

    fn next_family(
        addrs: &[SocketAddr],
        cursor: &mut usize,
        ipv6: bool,
    ) -> Option<(usize, SocketAddr)> {
        while let Some(addr) = addrs.get(*cursor) {
            let index = *cursor;
            *cursor += 1;
            if addr.is_ipv6() == ipv6 {
                return Some((index, *addr));
            }
        }
        None
    }
}

impl Iterator for InterleavedAddrs<'_> {
    type Item = (usize, SocketAddr);

    fn next(&mut self) -> Option<Self::Item> {
        for _ in 0..2 {
            let primary = self.primary_turn;
            self.primary_turn = !self.primary_turn;
            let ipv6 = if primary {
                self.primary_ipv6
            } else {
                !self.primary_ipv6
            };
            let cursor = if primary {
                &mut self.primary_cursor
            } else {
                &mut self.secondary_cursor
            };
            if let Some(addr) = Self::next_family(self.addrs, cursor, ipv6) {
                self.remaining -= 1;
                return Some(addr);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for InterleavedAddrs<'_> {}

async fn indexed_attempt<T, E, Fut>(original_index: usize, future: Fut) -> (usize, Result<T, E>)
where
    Fut: Future<Output = Result<T, E>>,
{
    let permit = crate::runtime::acquire_physical_dial_permit().await;
    let result = future.await;
    if result.is_ok() {
        crate::runtime::retain_physical_dial_permit(permit);
    }
    (original_index, result)
}

pub(super) async fn race_resolved_addrs<T, E, F, Fut>(
    addrs: &[SocketAddr],
    dial: F,
) -> Option<Result<T, E>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    race_resolved_addrs_with_stagger(addrs, ADDRESS_RACE_DELAY, dial).await
}

pub(super) async fn race_resolved_addrs_with_stagger<T, E, F, Fut>(
    addrs: &[SocketAddr],
    stagger: Duration,
    mut dial: F,
) -> Option<Result<T, E>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut queued = InterleavedAddrs::new(addrs);
    let first = queued.next()?;
    let mut attempts = FuturesUnordered::new();
    attempts.push(indexed_attempt(first.0, dial(first.1)));
    let launch_delay = tokio::time::sleep(stagger);
    tokio::pin!(launch_delay);
    let mut last_error = None;

    loop {
        let has_queued = queued.len() != 0;
        tokio::select! {
            completed = attempts.next() => {
                let Some((index, result)) = completed else {
                    break;
                };
                match result {
                    Ok(value) => return Some(Ok(value)),
                    Err(error) => {
                        if last_error.as_ref().is_none_or(|(last_index, _)| index > *last_index) {
                            last_error = Some((index, error));
                        }
                        if attempts.len() < MAX_IN_FLIGHT
                            && let Some((next_index, next_addr)) = queued.next()
                        {
                            attempts.push(indexed_attempt(next_index, dial(next_addr)));
                            launch_delay.as_mut().reset(tokio::time::Instant::now() + stagger);
                        }
                    }
                }
            }
            () = &mut launch_delay, if has_queued && attempts.len() < MAX_IN_FLIGHT => {
                if let Some((next_index, next_addr)) = queued.next() {
                    attempts.push(indexed_attempt(next_index, dial(next_addr)));
                    launch_delay.as_mut().reset(tokio::time::Instant::now() + stagger);
                }
            }
        }
        if attempts.is_empty() && queued.len() == 0 {
            break;
        }
    }

    last_error.map(|(_, error)| Err(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn v4(last: u8) -> SocketAddr {
        ([192, 0, 2, last], 443).into()
    }

    fn v6(last: u16) -> SocketAddr {
        (
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last),
            443,
        )
            .into()
    }

    #[test]
    fn address_order_interleaves_families_stably() {
        let v4_first = [v4(1), v4(2), v6(1), v6(2)];
        assert_eq!(
            InterleavedAddrs::new(&v4_first).collect::<Vec<_>>(),
            vec![(0, v4(1)), (2, v6(1)), (1, v4(2)), (3, v6(2))]
        );
        let v6_first = [v6(1), v6(2), v4(1)];
        assert_eq!(
            InterleavedAddrs::new(&v6_first).collect::<Vec<_>>(),
            vec![(0, v6(1)), (2, v4(1)), (1, v6(2))]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_starts_after_stagger_and_cancels_loser() {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let canceled = Arc::new(AtomicUsize::new(0));
        let addrs = [v4(1), v6(1)];
        let started = tokio::time::Instant::now();
        let winner = race_resolved_addrs_with_stagger(&addrs, Duration::from_millis(250), {
            let canceled = Arc::clone(&canceled);
            move |addr| {
                let guard = Guard(Arc::clone(&canceled));
                async move {
                    let _guard = guard;
                    if addr.is_ipv4() {
                        std::future::pending::<Result<SocketAddr, usize>>().await
                    } else {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(addr)
                    }
                }
            }
        })
        .await;
        assert_eq!(winner, Some(Ok(v6(1))));
        assert_eq!(started.elapsed(), Duration::from_millis(270));
        assert_eq!(canceled.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_first_never_starts_fallback() {
        let starts = Arc::new(AtomicUsize::new(0));
        let addrs = [v4(1), v6(1)];
        let started = tokio::time::Instant::now();
        let result = race_resolved_addrs_with_stagger(&addrs, Duration::from_millis(250), {
            let starts = Arc::clone(&starts);
            move |addr| {
                starts.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok::<_, usize>(addr)
                }
            }
        })
        .await;
        assert_eq!(result, Some(Ok(v4(1))));
        assert_eq!(started.elapsed(), Duration::from_millis(20));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn fast_failure_refills_immediately_and_preserves_last_error() {
        let addrs = [v4(1), v4(2), v6(1)];
        let launches = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let started = tokio::time::Instant::now();
        let result = race_resolved_addrs_with_stagger(&addrs, Duration::from_millis(250), {
            let launches = Arc::clone(&launches);
            move |addr| {
                launches.lock().push((addr, started.elapsed()));
                async move {
                    let delay = if addr == v4(1) {
                        5
                    } else if addr == v6(1) {
                        10
                    } else {
                        1
                    };
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    Err::<(), _>(addr)
                }
            }
        })
        .await;
        assert_eq!(result, Some(Err(v6(1))));
        assert_eq!(
            *launches.lock(),
            vec![
                (v4(1), Duration::ZERO),
                (v6(1), Duration::from_millis(5)),
                (v4(2), Duration::from_millis(15)),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn race_never_exceeds_two_attempts() {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let addrs = [v4(1), v4(2), v6(1), v6(2)];
        let result = race_resolved_addrs_with_stagger(&addrs, Duration::from_millis(10), {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            move |addr| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let guard = Active(Arc::clone(&active));
                async move {
                    let _guard = guard;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err::<(), _>(addr)
                }
            }
        })
        .await;
        assert_eq!(result, Some(Err(v6(2))));
        assert_eq!(peak.load(Ordering::SeqCst), MAX_IN_FLIGHT);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn real_tcp_loser_socket_closes_when_fallback_wins() {
        let first_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        let second_addr = second_listener.local_addr().unwrap();
        let addrs = [first_addr, second_addr];

        let winner = race_resolved_addrs_with_stagger(
            &addrs,
            Duration::from_millis(20),
            move |addr| async move {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                if addr == first_addr {
                    let _stream = stream;
                    std::future::pending::<std::io::Result<tokio::net::TcpStream>>().await
                } else {
                    Ok(stream)
                }
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner.peer_addr().unwrap(), second_addr);

        let (mut first_server, _) = first_listener.accept().await.unwrap();
        let (second_server, _) = second_listener.accept().await.unwrap();
        use tokio::io::AsyncReadExt as _;
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(1), first_server.read(&mut byte))
            .await
            .expect("losing TCP socket stayed open")
            .unwrap();
        assert_eq!(read, 0);
        drop((winner, second_server));
    }
}
