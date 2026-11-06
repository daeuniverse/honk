use std::sync::{Arc, LazyLock, Weak};

use crate::dns::upstream_pool::DnsIdleResources;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const DEFAULT_DNS_SOCKET_LIMIT: usize = 256;
pub(crate) const MAX_EXTRA_UDP_SOCKETS: usize = 16;

static DEFAULT_BUDGET: LazyLock<DnsSocketBudget> =
    LazyLock::new(|| DnsSocketBudget::new(DEFAULT_DNS_SOCKET_LIMIT));
static EXTRA_UDP_SOCKETS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_EXTRA_UDP_SOCKETS)));

#[derive(Debug, Default)]
struct PressureState {
    owners: parking_lot::Mutex<Vec<Weak<DnsIdleResources>>>,
    waiters: parking_lot::Mutex<usize>,
}

struct PressureWaiter<'a>(&'a parking_lot::Mutex<usize>);

impl<'a> PressureWaiter<'a> {
    fn new(waiters: &'a parking_lot::Mutex<usize>) -> Self {
        // Registration precedes the first scan; release hooks take this same
        // mutex after dropping their resource Arcs, so neither handoff is lost.
        *waiters.lock() += 1;
        Self(waiters)
    }
}

impl Drop for PressureWaiter<'_> {
    fn drop(&mut self) {
        *self.0.lock() -= 1;
    }
}

/// Shared DNS physical-socket credits and conservative proxy-stream admission.
#[derive(Clone, Debug)]
pub struct DnsSocketBudget {
    sockets: Arc<Semaphore>,
    proxy_streams: Arc<Semaphore>,
    pressure: Arc<PressureState>,
    limit: usize,
}

impl Default for DnsSocketBudget {
    fn default() -> Self {
        DEFAULT_BUDGET.clone()
    }
}

pub(crate) struct IdlePressureRelease<'a>(pub(crate) &'a DnsSocketBudget);

impl Drop for IdlePressureRelease<'_> {
    fn drop(&mut self) {
        self.0.reclaim_idle_if_waiting();
    }
}

impl DnsSocketBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            sockets: Arc::new(Semaphore::new(limit)),
            proxy_streams: Arc::new(Semaphore::new(limit)),
            pressure: Arc::default(),
            limit,
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    pub(crate) async fn acquire_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        self.acquire_socket_credits_until(1, deadline).await
    }

    pub(crate) async fn acquire_bootstrap_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if self.limit < 2 {
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::SocketAdmissionRefused);
            return Err(
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS bootstrap requires two socket credits"),
            );
        }
        self.acquire_socket_credits_until(2, deadline).await
    }

    async fn acquire_socket_credits_until(
        &self,
        count: u32,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.sockets).try_acquire_many_owned(count) {
            return Ok(permit);
        }
        let _waiting = PressureWaiter::new(&self.pressure.waiters);
        self.reclaim_idle_resources();
        tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.sockets).acquire_many_owned(count),
        )
        .await
        .map_err(|_| {
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::SocketAdmissionTimeout);
            anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                .context("DNS socket admission timed out")
        })?
        .map_err(|_| {
            anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                .context("DNS socket admission is closed")
        })
    }

    pub(crate) async fn acquire_proxy_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.proxy_streams).try_acquire_owned() {
            return Ok(permit);
        }
        let _waiting = PressureWaiter::new(&self.pressure.waiters);
        self.reclaim_idle_resources();
        tokio::time::timeout_at(deadline, Arc::clone(&self.proxy_streams).acquire_owned())
            .await
            .map_err(|_| {
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::ProxyAdmissionTimeout);
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS proxy stream admission timed out")
            })?
            .map_err(|_| {
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS proxy stream admission is closed")
            })
    }

    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sockets).try_acquire_owned().ok()
    }

    pub(crate) fn try_extra_udp(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&EXTRA_UDP_SOCKETS).try_acquire_owned().ok()
    }

    pub(crate) fn shares_admission(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sockets, &other.sockets)
            && Arc::ptr_eq(&self.proxy_streams, &other.proxy_streams)
    }

    pub(crate) fn register_idle_owner(&self, owner: &Arc<DnsIdleResources>) {
        let owner = Arc::downgrade(owner);
        let mut registered = self.pressure.owners.lock();
        registered.retain(|owner| owner.strong_count() != 0);
        if !registered
            .iter()
            .any(|current| Weak::ptr_eq(current, &owner))
        {
            registered.push(owner);
        }
    }

    pub(crate) fn unregister_idle_owner(&self, owner: &Arc<DnsIdleResources>) {
        let owner = Arc::downgrade(owner);
        self.pressure
            .owners
            .lock()
            .retain(|current| current.strong_count() != 0 && !Weak::ptr_eq(current, &owner));
    }

    pub(crate) fn reclaim_idle_if_waiting(&self) {
        let waiting = *self.pressure.waiters.lock() != 0;
        if waiting {
            self.reclaim_idle_resources();
        }
    }

    fn reclaim_idle_resources(&self) {
        let owners = {
            let mut owners = Vec::new();
            self.pressure.owners.lock().retain(|owner| {
                if let Some(owner) = owner.upgrade() {
                    owners.push(owner);
                    true
                } else {
                    false
                }
            });
            owners
        };
        for owner in owners {
            owner.reclaim_idle();
        }
    }

    #[cfg(test)]
    pub(crate) fn available_sockets(&self) -> usize {
        self.sockets.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn available_proxy_streams(&self) -> usize {
        self.proxy_streams.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn socket_admission_timeout_is_not_a_refusal() {
        const NAME: &str =
            "dns::transport::budget::tests::socket_admission_timeout_is_not_a_refusal";
        if crate::test_support::run_exact_in_child("HONK_DNS_ADMISSION_STATS_CHILD", NAME) {
            return;
        }
        let budget = DnsSocketBudget::new(1);
        let _held = budget.try_acquire().unwrap();
        let before = crate::stats::dns_snapshot();

        assert!(budget.try_acquire().is_none());
        let mut cancelled = Box::pin(
            budget.acquire_until(tokio::time::Instant::now() + std::time::Duration::from_secs(1)),
        );
        assert!(futures::poll!(cancelled.as_mut()).is_pending());
        drop(cancelled);
        assert_eq!(crate::stats::dns_snapshot(), before);

        let error = budget
            .acquire_until(tokio::time::Instant::now() + std::time::Duration::from_millis(1))
            .await
            .unwrap_err();
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
        let delta = crate::stats::dns_snapshot().delta(before);
        assert_eq!(delta.socket_admission_timeout, 1);
        assert_eq!(delta.socket_admission_refused, 0);
        assert_eq!(delta.proxy_admission_timeout, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn mandatory_admission_failures_count_only_their_cause() {
        #[derive(Debug)]
        enum Case {
            BootstrapRefusal,
            ProxyTimeout,
        }
        const NAME: &str =
            "dns::transport::budget::tests::mandatory_admission_failures_count_only_their_cause";
        if crate::test_support::run_exact_in_child("HONK_DNS_ADMISSION_STATS_CHILD", NAME) {
            return;
        }
        for (case, expected) in [
            (Case::BootstrapRefusal, [1, 0, 0]),
            (Case::ProxyTimeout, [0, 0, 1]),
        ] {
            let budget = DnsSocketBudget::new(1);
            let _socket = budget.try_acquire().unwrap();
            let _proxy = Arc::clone(&budget.proxy_streams)
                .try_acquire_owned()
                .unwrap();
            let before = crate::stats::dns_snapshot();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
            let error = match case {
                Case::BootstrapRefusal => budget.acquire_bootstrap_until(deadline).await,
                Case::ProxyTimeout => budget.acquire_proxy_until(deadline).await,
            }
            .unwrap_err();
            assert_eq!(
                honk_outbound::proxy::packet_rejection(&error),
                Some(honk_outbound::proxy::PacketRejection::Capacity)
            );
            let delta = crate::stats::dns_snapshot().delta(before);
            assert_eq!(
                [
                    delta.socket_admission_refused,
                    delta.socket_admission_timeout,
                    delta.proxy_admission_timeout,
                ],
                expected,
                "{case:?}"
            );
        }
    }
}
