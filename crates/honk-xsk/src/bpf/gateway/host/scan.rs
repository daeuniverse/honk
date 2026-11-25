use super::*;
use honk_ebpf_common::xdp_gateway::HOLD_IDLE_NS;
use honk_netstack::MemoryReservation;
use std::ops::Range;

const ROWS_PER_TURN: usize = 2048;
pub(super) const INITIAL_BATCH: usize = 256;

#[derive(Default)]
pub(super) struct Cursor<K, V> {
    bucket: u32,
    next_probe_ns: u64,
    pending: Range<usize>,
    keys: Box<[K]>,
    values: Box<[V]>,
    _memory: Option<MemoryReservation>,
}

impl<K: Copy + Default, V: Copy + Default> Cursor<K, V> {
    fn prepare(&mut self, budget: &Arc<MemoryBudget>) -> io::Result<()> {
        if self.keys.is_empty() {
            self.resize(INITIAL_BATCH, budget)?;
        }
        Ok(())
    }

    pub(super) fn resize(&mut self, len: usize, budget: &Arc<MemoryBudget>) -> io::Result<()> {
        let bytes = len * (size_of::<K>() + size_of::<V>());
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "Host flow batch memory"))?;
        fn array<T: Copy + Default>(len: usize) -> io::Result<Box<[T]>> {
            let mut items = Vec::new();
            items.try_reserve_exact(len).map_err(io::Error::other)?;
            items.resize(len, T::default());
            Ok(items.into_boxed_slice())
        }
        let keys = array(len)?;
        let values = array(len)?;
        self.keys = keys;
        self.values = values;
        self._memory = Some(memory);
        Ok(())
    }

    pub(super) fn turn(
        &mut self,
        fd: BorrowedFd<'_>,
        entries: u32,
        budget: &Arc<MemoryBudget>,
        mut remaining: usize,
        empty_probe: Option<(u64, u64)>,
        mut visit: impl FnMut(&K, V) -> io::Result<bool>,
    ) -> io::Result<(usize, bool)> {
        if empty_probe.is_some_and(|(now, _)| now < self.next_probe_ns) {
            return Ok((0, true));
        }
        self.prepare(budget)?;
        let mut batch = INITIAL_BATCH.min(entries as usize);
        let mut removed = 0;
        loop {
            while remaining != 0 && !self.pending.is_empty() {
                let i = self.pending.start;
                removed += usize::from(visit(&self.keys[i], self.values[i])?);
                self.pending.start += 1;
                remaining -= 1;
            }
            if self.pending.is_empty() && self.bucket == entries {
                // Even an empty table is visited at most once this turn.
                self.bucket = 0;
                return Ok((removed, true));
            }
            if remaining == 0 {
                return Ok((removed, false));
            }
            match lookup_hash_batch(
                fd,
                entries,
                self.bucket,
                &mut self.keys[..batch],
                &mut self.values[..batch],
            )? {
                HashBatch::Rows { count, next } => {
                    // No newly-created row can yet meet this table's retirement age.
                    if self.bucket == 0
                        && count == 0
                        && next == entries
                        && let Some((now, idle)) = empty_probe
                    {
                        self.next_probe_ns = now.saturating_add(idle);
                    }
                    self.bucket = next;
                    self.pending = 0..count;
                    batch = INITIAL_BATCH.min(entries as usize);
                }
                HashBatch::ShortBucket(next) => {
                    // Never split a kernel bucket. Keep its snapshot across turns when it
                    // exceeds the visit budget, and revalidate each candidate before deletion.
                    batch = (batch * 2).min(entries as usize);
                    if self.keys.len() < batch {
                        self.resize(batch, budget)?;
                    }
                    self.bucket = next;
                }
            }
        }
    }
}

impl HostFlows {
    pub(in crate::bpf::gateway) fn prepare_scans(
        &mut self,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<()> {
        self.endpoint_scan
            .get_mut()
            .map_err(|_| invalid_data("Host metadata scan poisoned"))?
            .prepare(budget)?;
        self.udp_scan
            .get_mut()
            .map_err(|_| invalid_data("Host UDP scan poisoned"))?
            .prepare(budget)?;
        self.direct_tcp_scan
            .get_mut()
            .map_err(|_| invalid_data("Host TCP scan poisoned"))?
            .prepare(budget)?;
        self.cleanup
            .get_mut()
            .map_err(|_| invalid_data("Host retirement poisoned"))?
            .prepare(budget)
    }
}

impl GatewayMaps {
    /// Bounded Host-only sweeps independent of traversal of the shared 65,536-slot hold.
    pub fn retire_host_flows(
        &self,
        now_ns: u64,
        arbitration: &GatewayArbitration,
        budget: &Arc<MemoryBudget>,
        mut retained: impl FnMut(&GatewayKey) -> bool,
    ) -> io::Result<usize> {
        let Some(host) = &self.host else { return Ok(0) };
        let endpoints = host
            .endpoint_scan
            .lock()
            .map_err(|_| invalid_data("Host metadata scan poisoned"))?
            .turn(
                host.meta.as_fd(),
                HOST_META_ENTRIES,
                budget,
                ROWS_PER_TURN,
                Some((now_ns, ENDPOINT_HORIZON_NS)),
                |key, meta| {
                    if now_ns
                        .checked_sub(meta.born_ns)
                        .is_none_or(|age| age <= ENDPOINT_HORIZON_NS)
                    {
                        return Ok(false);
                    }
                    let Some(owner) = lookup::<_, HostFlowOwner>(host.hold.as_fd(), key)? else {
                        return Ok(false);
                    };
                    if owner.stamp != meta.stamp
                        || owner.binding != meta.binding
                        || owner.socket_cookie != meta.socket_cookie
                    {
                        return Ok(false);
                    }
                    self.retire_endpoint(key, owner, now_ns, arbitration, &mut retained)
                },
            )?;
        let tcp = host
            .direct_tcp_scan
            .lock()
            .map_err(|_| invalid_data("Host TCP scan poisoned"))?
            .turn(
                host.direct_tcp.as_fd(),
                HOST_DIRECT_TCP_ENTRIES,
                budget,
                ROWS_PER_TURN,
                Some((now_ns, HOLD_IDLE_NS)),
                |key, owner| {
                    self.retire_native(host.direct_tcp.as_fd(), key, owner, now_ns, arbitration)
                },
            )?;
        let udp = host
            .udp_scan
            .lock()
            .map_err(|_| invalid_data("Host UDP scan poisoned"))?
            .turn(
                host.hold.as_fd(),
                HOST_HOLD_ENTRIES,
                budget,
                ROWS_PER_TURN,
                Some((now_ns, HOLD_IDLE_NS)),
                |key, owner| {
                    if !owner.is_direct() {
                        return Ok(false);
                    }
                    self.retire_native(host.hold.as_fd(), key, owner, now_ns, arbitration)
                },
            )?;
        Ok(endpoints.0 + tcp.0 + udp.0)
    }

    pub(super) fn retire_endpoint(
        &self,
        key: &GatewayKey,
        owner: HostFlowOwner,
        now_ns: u64,
        arbitration: &GatewayArbitration,
        retained: impl FnOnce(&GatewayKey) -> bool,
    ) -> io::Result<bool> {
        if !owner.is_endpoint()
            || now_ns
                .checked_sub(owner.last_seen_ns)
                .is_none_or(|age| age <= ENDPOINT_HORIZON_NS)
            || self.drained_host_binding(key.realm_id, owner.last_seen_ns)? != Some(owner.binding)
            || retained(key)
        {
            return Ok(false);
        }
        let fd = self.host_flows()?.hold.as_fd();
        Ok(arbitration
            .with_guard(&Self::guard_key(key), || {
                if lookup::<_, HostFlowOwner>(fd, key)? != Some(owner) {
                    return Ok(false);
                }
                self.delete_host_meta(key, owner)?;
                bpf(BPF_MAP_DELETE_ELEM, &mut elem(fd, key, 0, 0))?;
                Ok(true)
            })?
            .unwrap_or(false))
    }

    pub(super) fn retire_native(
        &self,
        fd: BorrowedFd<'_>,
        key: &GatewayKey,
        owner: HostFlowOwner,
        now_ns: u64,
        arbitration: &GatewayArbitration,
    ) -> io::Result<bool> {
        if now_ns
            .checked_sub(owner.last_seen_ns)
            .is_none_or(|age| age <= HOLD_IDLE_NS)
        {
            return Ok(false);
        }
        Ok(arbitration
            .with_guard(&Self::guard_key(key), || {
                if lookup::<_, HostFlowOwner>(fd, key)? != Some(owner) {
                    return Ok(false);
                }
                if !self.host_realms().contains(&key.realm_id)
                    || !owner.is_direct()
                    || owner.binding == 0
                    || (key.proto == 6 && owner.socket_cookie == 0)
                    || !matches!(key.proto, 6 | 17)
                {
                    return Err(invalid_data("invalid Host native flow owner"));
                }
                bpf(BPF_MAP_DELETE_ELEM, &mut elem(fd, key, 0, 0))?;
                Ok(true)
            })?
            .unwrap_or(false))
    }
}
