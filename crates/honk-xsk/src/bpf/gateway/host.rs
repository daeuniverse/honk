use super::*;
use honk_ebpf_common::xdp_gateway::{
    FRAGMENT_TTL_NS, HOLD_REFRESH_NS, HOST_DIRECT_TCP_ENTRIES, HOST_GUARD_REALM, HOST_HOLD_ENTRIES,
    HOST_META_ENTRIES, HOST_PRIVATE_DELAY_NS, HostBindingKey, HostFlowMeta, HostFlowOwner,
};

mod cleanup;
mod scan;
pub(super) const MAX_HOST_REALMS: usize = 4;
// A first fragment can arrive just before the next hold refresh. Its last legal
// tail can then spend the entire private-delay allowance upstream of the TUN filter.
pub(super) const ENDPOINT_HORIZON_NS: u64 =
    HOLD_REFRESH_NS + FRAGMENT_TTL_NS + HOST_PRIVATE_DELAY_NS;

enum Binding {
    Offline(u64),
    Active {
        id: u64,
        pair: Arc<AuxDevicePair>,
        needs_drain: bool,
        pending: u64,
        drained_before_ns: u64,
    },
    Draining(u64),
}

pub(super) struct HostFlows {
    meta: OwnedFd,
    hold: OwnedFd,
    direct_tcp: OwnedFd,
    endpoint_scan: Mutex<scan::Cursor<GatewayKey, HostFlowMeta>>,
    udp_scan: Mutex<scan::Cursor<GatewayKey, HostFlowOwner>>,
    direct_tcp_scan: Mutex<scan::Cursor<GatewayKey, HostFlowOwner>>,
    cleanup: Mutex<cleanup::Cleanup>,
    gates: OwnedFd,
    devices: OwnedFd,
    realms: [u32; MAX_HOST_REALMS],
    len: usize,
    bindings: [Mutex<Binding>; MAX_HOST_REALMS],
}

impl HostFlows {
    pub(super) fn new(realms: &[u32]) -> io::Result<Option<Box<Self>>> {
        if realms.is_empty() {
            return Ok(None);
        }
        let mut ids = [0; MAX_HOST_REALMS];
        ids[..realms.len()].copy_from_slice(realms);
        // Each outer map retains the original map objects, including the kernel's
        // automatic invalidation of individual DEVMAP slots on NETDEV_UNREGISTER.
        let readonly = aya_obj::generated::BPF_F_RDONLY_PROG;
        let root = |name: &[u8], template: OwnedFd| {
            create_with_flags::<HostBindingKey, u32>(
                13,
                MAX_HOST_REALMS as u32,
                name,
                template.as_raw_fd(),
                readonly,
            )
        };
        let gates = root(
            b"HOST_GATES",
            create_with_flags::<u32, u32>(2, 1, b"honk_host_gate", -1, readonly)?,
        )?;
        let devices = root(b"HOST_DEVICES", create_map(14, 4, 2, b"honk_host_devs")?)?;
        Ok(Some(Box::new(Self {
            // HASH with flags zero preallocates every element. This FD's memlock charge
            // belongs to the same capture budget as the hold table, including when empty.
            meta: create::<GatewayKey, HostFlowMeta>(1, HOST_META_ENTRIES, b"HOST_FLOW_META", -1)?,
            hold: create::<GatewayKey, HostFlowOwner>(1, HOST_HOLD_ENTRIES, b"HOST_HOLD", -1)?,
            direct_tcp: create::<GatewayKey, HostFlowOwner>(
                1,
                HOST_DIRECT_TCP_ENTRIES,
                b"HOST_DIRECT_TCP",
                -1,
            )?,
            udp_scan: Mutex::default(),
            cleanup: Mutex::default(),
            endpoint_scan: Mutex::default(),
            direct_tcp_scan: Mutex::default(),
            gates,
            devices,
            realms: ids,
            len: realms.len(),
            bindings: std::array::from_fn(|_| Mutex::new(Binding::Offline(0))),
        })))
    }

    fn binding(&self, realm: u32) -> io::Result<std::sync::MutexGuard<'_, Binding>> {
        let index = self.realms[..self.len]
            .iter()
            .position(|&candidate| candidate == realm)
            .ok_or_else(|| invalid_data("unknown gateway Host execution realm"))?;
        self.bindings[index]
            .lock()
            .map_err(|_| invalid_data("gateway Host binding poisoned"))
    }
}

impl GatewayMaps {
    fn host_flows(&self) -> io::Result<&HostFlows> {
        self.host
            .as_deref()
            .ok_or_else(|| invalid_data("gateway Host maps unavailable"))
    }

    pub fn host_realms(&self) -> &[u32] {
        self.host
            .as_ref()
            .map_or(&[], |host| &host.realms[..host.len])
    }

    pub fn host_meta_fd(&self) -> Option<BorrowedFd<'_>> {
        self.host.as_ref().map(|host| host.meta.as_fd())
    }

    pub fn host_hold_fd(&self) -> Option<BorrowedFd<'_>> {
        self.host.as_ref().map(|host| host.hold.as_fd())
    }

    pub fn host_direct_tcp_fd(&self) -> Option<BorrowedFd<'_>> {
        self.host.as_ref().map(|host| host.direct_tcp.as_fd())
    }

    pub fn host_bindings_fd(&self) -> Option<BorrowedFd<'_>> {
        self.host.as_ref().map(|host| host.gates.as_fd())
    }

    pub fn host_devices_fd(&self) -> Option<BorrowedFd<'_>> {
        self.host.as_ref().map(|host| host.devices.as_fd())
    }

    pub fn bind_host_realm(&self, realm: u32, binding: u64) -> io::Result<()> {
        let capture = self.require_realm_binding(realm, true)?;
        let pair = capture
            .iter()
            .find(|(id, _)| *id == realm)
            .and_then(|(_, pair)| pair.as_ref())
            .ok_or_else(|| invalid_data("missing gateway Host device pair"))?;
        let host = self.host_flows()?;
        let mut slot = host.binding(realm)?;
        if !matches!(*slot, Binding::Offline(previous) if binding > previous) {
            return Err(invalid_data("gateway Host binding occupied or reused"));
        }
        let key = HostBindingKey {
            realm,
            binding,
            reserved: 0,
        };
        update(host.devices.as_fd(), &key, &pair.device_fd(), 1)?;
        if let Err(error) = update(host.gates.as_fd(), &key, &pair.gate_fd(), 1) {
            bpf(
                BPF_MAP_DELETE_ELEM,
                &mut elem(host.devices.as_fd(), &key, 0, 0),
            )?;
            return Err(error);
        }
        *slot = Binding::Active {
            id: binding,
            pair: Arc::clone(pair),
            needs_drain: false,
            pending: 0,
            drained_before_ns: 0,
        };
        Ok(())
    }

    fn guard_key(key: &GatewayKey) -> GatewayKey {
        GatewayKey {
            realm_id: HOST_GUARD_REALM,
            ..*key
        }
    }

    /// Sample in the BPF monotonic clock domain before synchronizing the packet writers.
    /// Only bindings with an idle candidate need to ask their sole reader for a drain.
    pub fn request_host_drain(
        &self,
        arbitration: &GatewayArbitration,
        cutoff_mono_ns: u64,
    ) -> io::Result<()> {
        let Some(host) = self.host.as_ref() else {
            return Ok(());
        };
        let mut candidates = [(0u32, 0u64); MAX_HOST_REALMS];
        let mut count = 0;
        for &realm in self.host_realms() {
            if let Binding::Active {
                id,
                needs_drain: true,
                pending: 0,
                drained_before_ns,
                ..
            } = *host.binding(realm)?
                && cutoff_mono_ns > drained_before_ns
            {
                candidates[count] = (realm, id);
                count += 1;
            }
        }
        if count != 0 {
            arbitration.synchronize_readers()?;
            for &(realm, old) in &candidates[..count] {
                if let Binding::Active {
                    id,
                    needs_drain,
                    pending,
                    drained_before_ns,
                    ..
                } = &mut *host.binding(realm)?
                    && *id == old
                    && *pending == 0
                    && cutoff_mono_ns > *drained_before_ns
                {
                    *needs_drain = false;
                    *pending = cutoff_mono_ns;
                }
            }
        }
        Ok(())
    }

    pub fn host_pending_drain(&self, realm: u32, binding: u64) -> io::Result<Option<u64>> {
        Ok(match *self.host_flows()?.binding(realm)? {
            Binding::Active { id, pending, .. } if id == binding && pending != 0 => Some(pending),
            _ => None,
        })
    }

    /// Publish a MONOTONIC sample taken before a producer grace period, after all
    /// records preceding that grace have drained into this exact binding's stack.
    pub fn host_input_drained(
        &self,
        realm: u32,
        binding: u64,
        cutoff_mono_ns: u64,
    ) -> io::Result<()> {
        let mut slot = self.host_flows()?.binding(realm)?;
        match &mut *slot {
            Binding::Active {
                id,
                pending,
                drained_before_ns,
                ..
            } if *id == binding && *pending != 0 && *pending == cutoff_mono_ns => {
                *drained_before_ns = *pending;
                *pending = 0;
                Ok(())
            }
            _ => Err(invalid_data("foreign gateway Host input drain")),
        }
    }

    pub(super) fn drained_host_binding(
        &self,
        realm: u32,
        last_seen_ns: u64,
    ) -> io::Result<Option<u64>> {
        Ok(match &mut *self.host_flows()?.binding(realm)? {
            Binding::Active {
                id,
                drained_before_ns,
                needs_drain,
                ..
            } => {
                if drained_before_ns
                    .checked_sub(last_seen_ns)
                    .is_some_and(|age| age > ENDPOINT_HORIZON_NS)
                {
                    Some(*id)
                } else {
                    *needs_drain = true;
                    None
                }
            }
            _ => None,
        })
    }

    /// Obtain the identity once at admission. A concurrent retire/reuse cannot turn an
    /// observation of one hold into authority to use the next hold's process metadata.
    pub fn lookup_host_meta(
        &self,
        arbitration: &GatewayArbitration,
        key: &GatewayKey,
        binding: u64,
    ) -> io::Result<Option<HostFlowMeta>> {
        let host = self.host_flows()?;
        let slot = host.binding(key.realm_id)?;
        let Binding::Active { id, pair, .. } = &*slot else {
            return Ok(None);
        };
        if *id != binding {
            return Ok(None);
        }
        let Some(before) = lookup::<_, HostFlowOwner>(host.hold.as_fd(), key)? else {
            return Ok(None);
        };
        if !before.is_endpoint() || before.binding != binding {
            return Ok(None);
        }
        arbitration
            .with_guard(&Self::guard_key(key), || {
                if lookup::<_, u32>(pair.object_fds()[1], &0u32)? != Some(1) {
                    return Ok(None);
                }
                pair.verify()?;
                if lookup::<_, HostFlowOwner>(host.hold.as_fd(), key)?.is_none_or(|hold| {
                    hold.stamp != before.stamp
                        || hold.binding != binding
                        || hold.socket_cookie != before.socket_cookie
                }) {
                    return Ok(None);
                }
                let value: Option<HostFlowMeta> = lookup(host.meta.as_fd(), key)?;
                Ok(value.filter(|meta| {
                    meta.stamp == before.stamp
                        && meta.binding == binding
                        && meta.socket_cookie == before.socket_cookie
                        && usize::from(meta.pname_len) <= meta.pname.len()
                        && meta.reserved == [0; 3]
                        && (meta.socket_cookie != 0 || (meta.pid == 0 && meta.pname_len == 0))
                }))
            })?
            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }

    pub(super) fn delete_host_meta(
        &self,
        key: &GatewayKey,
        owner: HostFlowOwner,
    ) -> io::Result<()> {
        if !owner.is_endpoint() {
            return Err(invalid_data("invalid gateway Host Endpoint incarnation"));
        }
        let meta = self.host_flows()?.meta.as_fd();
        if let Some(current) = lookup::<_, HostFlowMeta>(meta, key)? {
            if current.stamp != owner.stamp
                || current.binding != owner.binding
                || current.socket_cookie != owner.socket_cookie
            {
                return Err(invalid_data(
                    "gateway Host metadata belongs to another owner",
                ));
            }
            bpf(BPF_MAP_DELETE_ELEM, &mut elem(meta, key, 0, 0))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
