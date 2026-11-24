use crate::dns::projection::GatewayDnsFill;
use honk_datapath::ScopeId;
use honk_ebpf_common::DomainRouting;
use honk_ebpf_common::xdp_gateway::{
    GATEWAY_REALM_CAPACITY, GatewayDnsKey, GatewayDnsValue, LocalAddressKey,
};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::GatewayDnsMaps;
use parking_lot::Mutex;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

const RENEW_COOLDOWN: Duration = Duration::from_millis(500);
const SATURATION_COOLDOWN: Duration = Duration::from_secs(1);
const RECLAIM_INTERVAL: Duration = Duration::from_millis(250);
static LAST_BANK_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct GatewayDnsCounters {
    pub(crate) bank_id: u64,
    pub(crate) memory_bytes: usize,
    pub(crate) inserted: u64,
    pub(crate) skipped: u64,
    pub(crate) saturated: u64,
    pub(crate) renewals: u64,
    pub(crate) revocations: u64,
    pub(crate) scanned: u64,
    pub(crate) reclaimed: u64,
    pub(crate) reclaim_errors: u64,
}

#[derive(Clone, Default)]
struct Epoch {
    current: u64,
    last_renewed: Option<Instant>,
    revocations: u64,
}

impl Epoch {
    fn accepts(&self, epoch: u64) -> bool {
        epoch != 0 && self.current == epoch
    }

    fn can_renew(&self, epoch: u64, now: Instant) -> bool {
        self.accepts(epoch)
            && self
                .last_renewed
                .is_none_or(|last| now.saturating_duration_since(last) >= RENEW_COOLDOWN)
    }

    fn publish(&mut self, next: u64, watermark: &AtomicU64, set_epoch: impl FnOnce(u64)) {
        // Withdraw kernel authority before any collector can recycle the old hash element.
        set_epoch(next);
        if next != 0 {
            watermark.store(next, Ordering::Release);
        }
        self.revocations += u64::from(self.current != 0);
        self.current = next;
    }

    fn rotate(&mut self, watermark: &AtomicU64, set_epoch: impl FnOnce(u64)) -> Option<u64> {
        let next = watermark.load(Ordering::Relaxed).checked_add(1);
        self.publish(next.unwrap_or(0), watermark, set_epoch);
        next
    }
}

#[derive(Default)]
struct Sweep {
    requested: bool,
    continuing: bool,
    in_flight: bool,
    last: Option<Instant>,
}

impl Sweep {
    fn due(&self, now: Instant) -> bool {
        (self.requested || self.continuing)
            && !self.in_flight
            && self
                .last
                .is_none_or(|last| now.saturating_duration_since(last) >= RECLAIM_INTERVAL)
    }

    fn begin(&mut self, now: Instant) -> bool {
        if !self.due(now) {
            return false;
        }
        // A withdrawal behind the cursor needs a whole subsequent pass, even if this
        // batch reaches the end. Consume that request only when starting from the head.
        if !self.continuing {
            self.requested = false;
        }
        self.last = Some(now);
        self.in_flight = true;
        true
    }
}

struct BankState {
    epochs: Box<[Epoch]>,
    pending: Option<GatewayDnsFill>,
    sweep: Sweep,
    saturated_until: Option<Instant>,
    counters: GatewayDnsCounters,
}

impl BankState {
    fn saturated(&mut self) -> bool {
        if self
            .saturated_until
            .is_some_and(|until| until > Instant::now())
        {
            self.counters.saturated += 1;
            true
        } else {
            false
        }
    }
}

pub(crate) struct GatewayDnsBank {
    maps: GatewayDnsMaps,
    fingerprint: [u8; 32],
    bindings: Box<[(ScopeId, u32)]>,
    watermarks: Box<[AtomicU64]>,
    state: Mutex<BankState>,
    _memory: MemoryReservation,
}

impl GatewayDnsBank {
    pub(crate) fn new(
        budget: &Arc<MemoryBudget>,
        fingerprint: [u8; 32],
        realms: &[(ScopeId, u32)],
    ) -> io::Result<Arc<Self>> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gateway DNS scope binding",
            )
        };
        let capacity = realms
            .iter()
            .map(|&(_, id)| id)
            .max()
            .and_then(|max| max.checked_add(1))
            .ok_or_else(invalid)?;
        for (index, &(scope, id)) in realms.iter().enumerate() {
            if scope == ScopeId::HOST
                || id == 0
                || id > GATEWAY_REALM_CAPACITY
                || realms[..index].iter().any(|&(s, r)| s == scope || r == id)
            {
                return Err(invalid());
            }
        }
        // Realm zero is reserved; WAN slots exist but never receive a binding or a nonzero epoch.
        let maps = GatewayDnsMaps::new(GATEWAY_REALM_CAPACITY + 1)?;
        let user_bytes = size_of::<Self>() - size_of::<GatewayDnsMaps>() + maps.memory_bytes()
            + 2 * size_of::<usize>() // Arc's strong and weak counts
            + std::mem::size_of_val(realms)
            + capacity as usize * (size_of::<Epoch>() + size_of::<AtomicU64>());
        let memory_bytes = maps
            .object_fds()
            .into_iter()
            .try_fold(user_bytes, |total, fd| {
                total
                    .checked_add(honk_xsk::kernel_memory_bytes(fd)?)
                    .ok_or_else(|| io::Error::other("gateway DNS memory size overflow"))
            })?;
        let memory = budget.reserve(memory_bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "gateway DNS memory budget exhausted",
            )
        })?;
        let bank_id = LAST_BANK_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map_err(|_| io::Error::other("gateway DNS bank identity exhausted"))?
            + 1;
        let mut bindings: Box<[(ScopeId, u32)]> = realms.into();
        bindings.sort_unstable_by_key(|(scope, _)| scope.as_u64());
        Ok(Arc::new(Self {
            maps,
            fingerprint,
            bindings,
            watermarks: (0..capacity).map(|_| AtomicU64::new(0)).collect(),
            state: Mutex::new(BankState {
                epochs: vec![Epoch::default(); capacity as usize].into_boxed_slice(),
                pending: None,
                sweep: Sweep::default(),
                saturated_until: None,
                counters: GatewayDnsCounters {
                    bank_id,
                    memory_bytes,
                    ..Default::default()
                },
            }),
            _memory: memory,
        }))
    }

    pub(crate) fn maps(&self) -> &GatewayDnsMaps {
        &self.maps
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn scopes(&self) -> impl Iterator<Item = ScopeId> + '_ {
        self.bindings.iter().map(|&(scope, _)| scope)
    }

    fn realm(&self, scope: u64) -> Option<u32> {
        self.bindings
            .binary_search_by_key(&scope, |(scope, _)| scope.as_u64())
            .ok()
            .map(|index| self.bindings[index].1)
    }

    fn rotate(&self, state: &mut BankState, realm: u32) -> Option<u64> {
        let watermark = &self.watermarks[realm as usize];
        state.sweep.requested |= watermark.load(Ordering::Relaxed) != 0;
        state.epochs[realm as usize].rotate(watermark, |next| self.maps.set_epoch(realm, next))
    }

    fn close_realm(&self, state: &mut BankState, realm: u32) {
        let i = realm as usize;
        if state.epochs[i].current != 0 {
            state.epochs[i].publish(0, &self.watermarks[i], |next| {
                self.maps.set_epoch(realm, next)
            });
            state.sweep.requested = true;
        }
        if state.pending.is_some_and(|row| row.realm == realm) {
            state.pending = None;
        }
    }

    pub(crate) fn activate(&self, active: impl Fn(ScopeId) -> bool) -> bool {
        let mut state = self.state.lock();
        let mut eligible = false;
        let mut opened = false;
        for &(scope, realm) in &self.bindings {
            if active(scope) {
                eligible = true;
                opened |= self.rotate(&mut state, realm).is_some();
            } else {
                self.close_realm(&mut state, realm);
            }
        }
        // An auxiliary-only bank can commit before its first link appears.
        opened || !eligible
    }

    pub(crate) fn set_binding(&self, scope: ScopeId, active: bool) -> io::Result<()> {
        let Some(realm) = self.realm(scope.as_u64()) else {
            return Ok(());
        };
        let mut state = self.state.lock();
        if active {
            self.rotate(&mut state, realm)
                .ok_or_else(|| io::Error::other("gateway DNS export epoch exhausted"))?;
        } else {
            self.close_realm(&mut state, realm);
        }
        Ok(())
    }

    pub(crate) fn queue_fill(&self, fill: GatewayDnsFill) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.pending.is_some() || !state.epochs[fill.realm as usize].accepts(fill.epoch) {
            return false;
        }
        state.pending = Some(fill);
        true
    }

    pub(crate) fn take_fill(&self) -> Option<GatewayDnsFill> {
        self.state.lock().pending.take()
    }

    #[cfg(any(feature = "ebpf", test))]
    pub(crate) fn discard_fill(&self, query: crate::dns::projection::QueryScope) {
        let mut state = self.state.lock();
        if state.pending.is_some_and(|fill| fill.query == query) {
            state.pending = None;
        }
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock();
        for &(_, realm) in &self.bindings {
            self.close_realm(&mut state, realm);
        }
    }

    pub(crate) fn revoke(&self, scope: u64) {
        if let Some(realm) = self.realm(scope) {
            let mut state = self.state.lock();
            if state.epochs[realm as usize].current != 0 {
                self.rotate(&mut state, realm);
            }
        }
    }

    pub(crate) fn ticket(&self, scope: ScopeId) -> Option<(u32, u64)> {
        let realm = self.realm(scope.as_u64())?;
        let mut state = self.state.lock();
        let epoch = state.epochs[realm as usize].current;
        (epoch != 0 && !state.saturated()).then_some((realm, epoch))
    }

    pub(crate) fn insert(
        &self,
        realm: u32,
        epoch: u64,
        ip: IpAddr,
        bitmap: DomainRouting,
        expires_at: Instant,
    ) -> bool {
        {
            let mut state = self.state.lock();
            if !state
                .epochs
                .get(realm as usize)
                .is_some_and(|slot| slot.accepts(epoch))
            {
                state.counters.skipped += 1;
                return false;
            }
            if state.saturated() {
                return false;
            }
        }
        let Some(deadline) = kernel_deadline(expires_at) else {
            self.skip(1);
            return false;
        };
        let key = GatewayDnsKey {
            export_epoch: epoch,
            realm_id: realm,
            reserved: 0,
            canonical_dst: LocalAddressKey::from(ip).address,
        };
        let value = GatewayDnsValue {
            valid_before_mono_ns: deadline,
            bitmap,
        };
        match self.maps.insert(&key, &value) {
            Ok(()) => {
                let mut state = self.state.lock();
                state.counters.inserted += 1;
                if !state.epochs[realm as usize].accepts(epoch) {
                    state.sweep.requested = true;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                if let Ok(Some(existing)) = self.maps.lookup(&key)
                    && let Some(now) = monotonic_ns()
                    && eligible_extension(existing.valid_before_mono_ns, deadline, now)
                {
                    return true;
                }
                self.skip(1);
            }
            Err(err)
                if matches!(
                    err.raw_os_error(),
                    Some(libc::E2BIG | libc::ENOSPC | libc::ENOMEM)
                ) =>
            {
                let mut state = self.state.lock();
                state.counters.saturated += 1;
                state.sweep.requested |= state.saturated_until.is_none();
                state.saturated_until = Some(Instant::now() + SATURATION_COOLDOWN);
            }
            Err(_) => self.skip(1),
        }
        false
    }

    pub(crate) fn renew(&self, realm: u32, epoch: u64) -> Option<u64> {
        let mut state = self.state.lock();
        let now = Instant::now();
        if !state.epochs.get(realm as usize)?.can_renew(epoch, now) {
            state.counters.skipped += 1;
            return None;
        }
        let next = self.rotate(&mut state, realm)?;
        state.epochs[realm as usize].last_renewed = Some(now);
        state.counters.renewals += 1;
        Some(next)
    }

    pub(crate) fn needs_reclaim(&self) -> bool {
        let state = self.state.lock();
        state.sweep.requested || state.sweep.continuing || state.sweep.in_flight
    }

    pub(crate) fn reclaim_due(&self, now: Instant) -> bool {
        self.state.lock().sweep.due(now)
    }

    pub(crate) fn reclaim(&self) {
        if !self.state.lock().sweep.begin(Instant::now()) {
            return;
        }
        let result = self.maps.reclaim(|key| {
            self.watermarks
                .get(key.realm_id as usize)
                .is_some_and(|watermark| {
                    let latest = watermark.load(Ordering::Acquire);
                    key.export_epoch < latest
                        || (key.export_epoch == latest
                            && self.state.lock().epochs[key.realm_id as usize].current == 0)
                })
        });
        let mut state = self.state.lock();
        state.sweep.in_flight = false;
        match result {
            Ok((scanned, deleted, end)) => {
                state.sweep.continuing = !end;
                state.counters.scanned += scanned as u64;
                state.counters.reclaimed += deleted as u64;
                if deleted != 0 {
                    state.saturated_until = None;
                }
            }
            Err(_) => {
                state.sweep.continuing = true;
                state.sweep.requested = true;
                state.counters.reclaim_errors += 1;
            }
        }
    }

    pub(crate) fn skip(&self, count: usize) {
        self.state.lock().counters.skipped += count as u64;
    }

    pub(crate) fn realm_revocations(&self, output: &mut [(u32, u64); 64]) -> usize {
        let state = self.state.lock();
        for (row, &(_, realm)) in output.iter_mut().zip(&self.bindings) {
            *row = (realm, state.epochs[realm as usize].revocations);
        }
        self.bindings.len().min(output.len())
    }

    pub(crate) fn stats(&self) -> GatewayDnsCounters {
        let state = self.state.lock();
        GatewayDnsCounters {
            revocations: self
                .bindings
                .iter()
                .map(|&(_, realm)| state.epochs[realm as usize].revocations)
                .fold(0, u64::saturating_add),
            ..state.counters
        }
    }
}

fn monotonic_ns() -> Option<u64> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).ok()?;
    u64::try_from(time.tv_sec())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_nsec()).ok()?)
}

fn kernel_deadline(expires_at: Instant) -> Option<u64> {
    let mono = monotonic_ns()?;
    // A paused or shifted Tokio clock cannot authorize a kernel deadline. Bracket
    // the real sample strictly so even a frozen clock coinciding with it fails.
    let before = Instant::now();
    let real = std::time::Instant::now();
    let now = Instant::now();
    if before.into_std() >= real || real >= now.into_std() {
        return None;
    }
    let remaining = expires_at.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    mono.checked_add(u64::try_from(remaining.as_nanos()).ok()?)
}

fn eligible_extension(old: u64, new: u64, now: u64) -> bool {
    old <= now && now < new && new.saturating_sub(old) > 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_retains_high_water_and_exhaustion_never_reissues_an_epoch() {
        let mut slot = Epoch::default();
        let watermark = AtomicU64::new(u64::MAX - 2);
        assert_eq!(
            slot.rotate(&watermark, |next| assert_eq!(next, u64::MAX - 1)),
            Some(u64::MAX - 1)
        );
        slot.publish(0, &watermark, |next| assert_eq!(next, 0));
        assert!(!slot.accepts(u64::MAX - 1));
        assert_eq!(
            slot.rotate(&watermark, |next| assert_eq!(next, u64::MAX)),
            Some(u64::MAX)
        );
        for _ in 0..2 {
            assert_eq!(slot.rotate(&watermark, |next| assert_eq!(next, 0)), None);
            assert_eq!(watermark.load(Ordering::Acquire), u64::MAX);
            assert!(!slot.accepts(0));
        }
    }

    #[test]
    fn renewal_requires_expiry_extension_and_current_epoch_outside_cooldown() {
        let now = Instant::now();
        let slot = Epoch {
            current: 2,
            last_renewed: Some(now),
            revocations: 0,
        };
        assert!(!eligible_extension(100, 1_000_000_101, 99));
        assert!(!eligible_extension(100, 1_000_000_100, 100));
        assert!(eligible_extension(100, 1_000_000_101, 100));
        assert!(!eligible_extension(100, 1_000_000_101, 1_000_000_101));
        assert!(!slot.can_renew(2, now + Duration::from_millis(499)));
        assert!(!slot.can_renew(1, now + RENEW_COOLDOWN));
        assert!(slot.can_renew(2, now + RENEW_COOLDOWN));
    }

    #[tokio::test(start_paused = true)]
    async fn paused_clock_cannot_authorize_a_kernel_deadline() {
        assert!(kernel_deadline(Instant::now() + Duration::from_secs(30)).is_none());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(kernel_deadline(Instant::now() + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn new_withdrawal_behind_cursor_survives_the_last_batch() {
        let mut sweep = Sweep {
            requested: true,
            ..Default::default()
        };
        let now = Instant::now();
        assert!(sweep.begin(now));
        assert!(!sweep.requested);
        sweep.requested = true;
        sweep.in_flight = false;
        sweep.continuing = true;
        assert!(!sweep.begin(now));
        assert!(sweep.begin(now + RECLAIM_INTERVAL));
        sweep.in_flight = false;
        sweep.continuing = false;
        assert!(sweep.begin(now + RECLAIM_INTERVAL * 2));
        assert!(!sweep.requested);
        sweep.in_flight = false;
        assert!(!sweep.due(now + RECLAIM_INTERVAL * 3));
    }
}
