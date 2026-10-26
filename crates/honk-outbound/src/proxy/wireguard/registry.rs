//! Tunnel registry: one live tunnel per (our private key, peer public key, endpoint) in a registry.
//!
//! Two WireGuard sessions with the same keys *to the same peer* invalidate each other's
//! handshakes, so every acquirer of an identical tunnel config shares one tunnel, DNS-fork
//! runtimes included. Subscription lists routinely reuse one key pair across many endpoints
//! (WARP-style), which are independent peers, so the endpoint is part of the key. A differing
//! config for the same key and endpoint retires the incumbent and closes its flows.
//!
//! Sharing is scoped to the owner of the runtimes: a control plane creates one registry that its
//! generations (reload successors) and DNS forks inherit, and closes it at terminal teardown. A
//! process running several planes gives each its own tunnels; dials without a runtime use one
//! process-wide registry that nothing closes.
//!
//! Memory: every tunnel's netstack draws its flows' buffers from one process budget, the share set
//! by [`init_memory_share`], so the tunnels together stay within it however the flows spread over
//! them, registries included. What the budget cannot see is a tunnel's fixed cost (scratch
//! buffers, the socket), which caps the number of live tunnels; at the cap an unused tunnel is
//! retired to make room, and when every tunnel is in use the new one is refused with a local
//! `Capacity` rejection. ponytail: the cap is per registry, so n planes may hold n times as many
//! tunnels; production has one plane, a process-wide counter if embedders run many.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, OnceLock};

use honk_config::node::{Node, WireGuardConfig};
use honk_netstack::MemoryBudget;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::Mutex;
use tokio::task::JoinHandle;

use super::tunnel::{Failure, Shared, Tunnel};
use crate::proxy::PacketRejection;

/// Everything that shapes one tunnel. UDP permission (`network`) is a flow policy, not tunnel state.
#[derive(Clone, Debug)]
pub(crate) struct TunnelConfig {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) wg: WireGuardConfig,
    /// The node that built the tunnel, for logs only; not part of its identity.
    pub(super) name: String,
}

impl PartialEq for TunnelConfig {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port && self.wg == other.wg
    }
}

impl Eq for TunnelConfig {}

impl TunnelConfig {
    pub(crate) fn from_node(node: &Node) -> anyhow::Result<Self> {
        let mut wg = node
            .wireguard()
            .ok_or_else(|| anyhow::anyhow!("node '{}' is not a WireGuard node", node.name))?
            .clone();
        wg.network = None;
        Ok(Self {
            host: node.host().to_string(),
            port: node.port,
            wg,
            name: node.name.clone(),
        })
    }

    /// One scan per dial, before a tunnel exists; per-packet checks use [`AllowedIps`].
    pub(crate) fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.wg.allowed_ips.iter().any(|net| net.contains(&ip))
    }

    /// Whether the tunnel has an address in `ip`'s family to source packets from.
    pub(crate) fn has_local_for(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(_) => self.wg.local_v4.is_some(),
            IpAddr::V6(_) => self.wg.local_v6.is_some(),
        }
    }

    fn key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.wg.private_key_bytes());
        hasher.update(self.wg.public_key_bytes());
        hasher.update(&(self.host.len() as u64).to_le_bytes());
        hasher.update(self.host.as_bytes());
        hasher.update(&self.port.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// The peer's allowed IPs as sorted, disjoint networks per family, so the per-packet check is a
/// binary search instead of a scan under the tunnel lock.
#[derive(Debug, Default)]
pub(super) struct AllowedIps {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

impl AllowedIps {
    pub(super) fn new(networks: &[IpNet]) -> Self {
        let mut allowed = Self::default();
        for network in IpNet::aggregate(&networks.to_vec()) {
            match network {
                IpNet::V4(network) => allowed.v4.push(network),
                IpNet::V6(network) => allowed.v6.push(network),
            }
        }
        allowed
    }

    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => {
                let after = self.v4.partition_point(|network| network.network() <= ip);
                after > 0 && self.v4[after - 1].contains(&ip)
            }
            IpAddr::V6(ip) => {
                let after = self.v6.partition_point(|network| network.network() <= ip);
                after > 0 && self.v6[after - 1].contains(&ip)
            }
        }
    }
}

/// Share when the process never set one: the netstack's own default limit.
pub(super) const DEFAULT_SHARE: usize = 256 << 20;
/// What one live tunnel costs outside the budget, rounded up. Measured from the code: the receive
/// scratch (64 KiB), the GRO batch (8 x 64 KiB), the send batch (64 x 1.47 KiB) and the segment
/// table add up to about 0.7 MiB; a stack with no flows holds nothing else. 4 MiB leaves room for
/// the socket, the task and the tunnel state. The kernel receive queue (up to 64 MiB, see
/// `socket.rs`) is a limit that only fills when packets arrive faster than the owner drains them,
/// and what honest peers put in flight is bounded by the budget, so it is not counted here.
const TUNNEL_FIXED_BYTES: usize = 4 << 20;
/// One descriptor per tunnel lives outside the control plane's descriptor partition.
const MAX_TUNNELS: usize = 128;

/// The process-wide memory budget and the bound on live tunnels derived from it.
#[derive(Clone, Debug)]
pub(super) struct Limits {
    pub(super) budget: Arc<MemoryBudget>,
    pub(super) max_tunnels: usize,
}

impl Limits {
    /// A share below one tunnel's fixed cost still admits one tunnel.
    pub(super) fn new(share: usize) -> Self {
        Self {
            budget: MemoryBudget::new(share),
            max_tunnels: (share / TUNNEL_FIXED_BYTES).clamp(1, MAX_TUNNELS),
        }
    }

    fn current() -> Self {
        LIMITS.get_or_init(|| Self::new(DEFAULT_SHARE)).clone()
    }
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

/// Process-wide byte budget for every WireGuard netstack together; initialize before the first
/// tunnel, or the netstack default applies.
pub fn init_memory_share(bytes: u64) -> io::Result<()> {
    let share = usize::try_from(bytes).unwrap_or(usize::MAX);
    if LIMITS.get_or_init(|| Limits::new(share)).budget.limit() != share {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "WireGuard memory share is already initialized to a different value",
        ));
    }
    Ok(())
}

/// The live tunnels and their owner tasks. Every control plane owns one, shared by its generations
/// and DNS forks, so two planes never see (or close) each other's tunnels; node-only dials share
/// the process-wide [`standalone`](Registry::standalone) one. Tests build private ones so their
/// limits never see each other's tunnels.
#[derive(Default)]
pub(crate) struct Registry {
    tunnels: Mutex<HashMap<[u8; 32], Arc<Shared>>>,
    /// Every spawned tunnel with its owner task, replaced ones included, so shutdown joins them all.
    owners: Mutex<Vec<(Arc<Shared>, JoinHandle<()>)>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("tunnels", &self.tunnels.lock().len())
            .finish_non_exhaustive()
    }
}

static STANDALONE: LazyLock<Arc<Registry>> = LazyLock::new(Registry::new);

impl Registry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::default()
    }

    /// The registry of dials that have no runtime (honk-tool, hand-built nodes). No control plane
    /// owns it, so none closes it; its tunnels end by idling out.
    pub(crate) fn standalone() -> Arc<Self> {
        Arc::clone(&STANDALONE)
    }

    fn live_equal(&self, cfg: &TunnelConfig) -> Option<Tunnel> {
        let map = self.tunnels.lock();
        map.get(&cfg.key())
            .filter(|shared| !shared.is_dead() && shared.cfg == *cfg)
            .map(|shared| Tunnel(Arc::clone(shared)))
    }

    pub(super) fn install(
        self: &Arc<Self>,
        cfg: TunnelConfig,
        candidates: Vec<SocketAddr>,
        limits: &Limits,
    ) -> anyhow::Result<Tunnel> {
        let key = cfg.key();
        let mut map = self.tunnels.lock();
        if let Some(existing) = map.get(&key).filter(|shared| !shared.is_dead()) {
            if existing.cfg == cfg {
                return Ok(Tunnel(Arc::clone(existing)));
            }
            // Not the node's fault: flows on the old settings are closed, not scored against it.
            existing.fail(Failure::Closed);
        }
        map.retain(|_, shared| !shared.is_dead());
        while map.len() >= limits.max_tunnels {
            let victim = map
                .iter()
                .filter(|(victim, shared)| **victim != key && shared.is_unused())
                .min_by_key(|(_, shared)| shared.created)
                .map(|(victim, _)| *victim);
            let Some(victim) = victim else {
                return Err(PacketRejection::Capacity.into());
            };
            if let Some(shared) = map.remove(&victim) {
                shared.fail(Failure::Idle);
            }
        }
        let (shared, owner) = Shared::spawn(cfg, candidates, &limits.budget, Arc::downgrade(self))?;
        map.insert(key, Arc::clone(&shared));
        let mut owners = self.owners.lock();
        owners.retain(|(_, owner)| !owner.is_finished());
        owners.push((Arc::clone(&shared), owner));
        Ok(Tunnel(shared))
    }

    /// Drop `shared` unless a replacement already took its slot.
    pub(super) fn remove(&self, shared: &Arc<Shared>) {
        let mut map = self.tunnels.lock();
        let key = shared.cfg.key();
        if map.get(&key).is_some_and(|live| Arc::ptr_eq(live, shared)) {
            map.remove(&key);
        }
    }

    /// Fail every flow a closing runtime opened, on whichever tunnel carries it.
    pub(crate) fn close_scope(&self, scope: u64) {
        let tunnels: Vec<_> = self.tunnels.lock().values().cloned().collect();
        for shared in tunnels {
            shared.close_scope(scope);
        }
    }

    pub(super) async fn shutdown_where(&self, select: impl Fn(&Shared) -> bool) -> usize {
        let (selected, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut *self.owners.lock())
            .into_iter()
            .partition(|(shared, _)| select(shared));
        self.owners.lock().extend(kept);
        let count = selected
            .iter()
            .filter(|(shared, _)| !shared.is_dead())
            .count();
        for (shared, _) in &selected {
            shared.fail(Failure::Closed);
        }
        for (_, owner) in selected {
            let _ = owner.await;
        }
        count
    }

    /// The shared tunnel for `cfg`, created (and its handshake started lazily) when none is live.
    pub(crate) async fn acquire(self: &Arc<Self>, cfg: TunnelConfig) -> anyhow::Result<Tunnel> {
        if let Some(tunnel) = self.live_equal(&cfg) {
            crate::runtime::start_scoped_dial();
            // A handshake that never completed may have been aimed at an address the name has left.
            if tunnel.0.take_resolve_due()
                && cfg.host.parse::<IpAddr>().is_err()
                && let Ok(ips) = crate::bootstrap::resolve(&cfg.host).await
            {
                tunnel.0.set_candidates(endpoints(&ips, cfg.port));
            }
            return Ok(tunnel);
        }
        crate::runtime::admit_physical_dial(async {
            let ips = crate::bootstrap::resolve(&cfg.host).await?;
            anyhow::ensure!(!ips.is_empty(), "resolve {}: no addresses", cfg.host);
            let candidates = endpoints(&ips, cfg.port);
            self.install(cfg, candidates, &Limits::current())
        })
        .await
    }

    /// Close every tunnel of this registry and wait for their owner tasks, replaced ones included.
    /// For teardown, after every runtime sharing the registry has been closed. Returns how many
    /// live tunnels it closed.
    pub(crate) async fn shutdown(&self) -> usize {
        self.shutdown_where(|_| true).await
    }

    #[cfg(test)]
    pub(super) fn contains(&self, cfg: &TunnelConfig) -> bool {
        self.tunnels.lock().contains_key(&cfg.key())
    }
}

/// Resolved addresses as endpoint candidates: families alternate, the resolver's first family
/// leading, so one unreachable family costs a single retransmission step.
pub(super) fn endpoints(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    let addrs: Vec<SocketAddr> = ips
        .iter()
        .map(|ip| SocketAddr::new(ip.to_canonical(), port))
        .collect();
    let Some(first) = addrs.first() else {
        return addrs;
    };
    let (same, other): (Vec<_>, Vec<_>) = addrs
        .iter()
        .copied()
        .partition(|addr| addr.is_ipv6() == first.is_ipv6());
    let mut ordered = Vec::with_capacity(addrs.len());
    let (mut same, mut other) = (same.into_iter(), other.into_iter());
    loop {
        let (a, b) = (same.next(), other.next());
        if a.is_none() && b.is_none() {
            break;
        }
        for addr in a.into_iter().chain(b) {
            if !ordered.contains(&addr) {
                ordered.push(addr);
            }
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear(networks: &[IpNet], ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        networks.iter().any(|network| network.contains(&ip))
    }

    /// A deterministic xorshift, so the failing address is reproducible.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn allowed_ips_agree_with_a_linear_scan_over_overlapping_nets() {
        let mut state = 0x9e37_79b9_7f4a_7c15;
        let mut networks: Vec<IpNet> = Vec::new();
        for _ in 0..4096 {
            let bits = next(&mut state);
            if bits & 1 == 0 {
                let prefix = 8 + (bits >> 8) % 25;
                let addr = std::net::Ipv4Addr::from((bits >> 16) as u32);
                networks.push(format!("{addr}/{prefix}").parse().unwrap());
            } else {
                let prefix = 16 + (bits >> 8) % 113;
                let addr =
                    std::net::Ipv6Addr::from(u128::from(bits) << 64 | u128::from(next(&mut state)));
                networks.push(format!("{addr}/{prefix}").parse().unwrap());
            }
        }
        // Edges of every net too: first and last address, one outside on each side.
        let mut probes: Vec<IpAddr> = Vec::new();
        for network in &networks {
            probes.extend([network.network(), network.broadcast()]);
            match network {
                IpNet::V4(n) => {
                    probes.push(IpAddr::V4(std::net::Ipv4Addr::from(
                        u32::from(n.network()).wrapping_sub(1),
                    )));
                    probes.push(IpAddr::V4(std::net::Ipv4Addr::from(
                        u32::from(n.broadcast()).wrapping_add(1),
                    )));
                }
                IpNet::V6(n) => {
                    probes.push(IpAddr::V6(std::net::Ipv6Addr::from(
                        u128::from(n.network()).wrapping_sub(1),
                    )));
                    probes.push(IpAddr::V6(std::net::Ipv6Addr::from(
                        u128::from(n.broadcast()).wrapping_add(1),
                    )));
                }
            }
        }
        for _ in 0..20_000 {
            let bits = next(&mut state);
            probes.push(IpAddr::V4(std::net::Ipv4Addr::from((bits >> 8) as u32)));
            probes.push(IpAddr::V6(std::net::Ipv6Addr::from(
                u128::from(bits) << 64 | u128::from(next(&mut state)),
            )));
        }
        let allowed = AllowedIps::new(&networks);
        let mut hits = 0;
        for ip in probes {
            let expected = linear(&networks, ip);
            hits += usize::from(expected);
            assert_eq!(allowed.contains(ip), expected, "{ip}");
        }
        assert!(
            hits > 1000,
            "the probe set must exercise both outcomes: {hits}"
        );
    }

    #[test]
    fn allowed_ips_canonicalize_mapped_addresses_and_handle_the_default_pair() {
        let default = AllowedIps::new(&["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);
        assert!(default.contains("203.0.113.9".parse().unwrap()));
        assert!(default.contains("2001:db8::1".parse().unwrap()));
        let narrow = AllowedIps::new(&["10.0.0.0/24".parse().unwrap()]);
        assert!(narrow.contains("::ffff:10.0.0.7".parse().unwrap()));
        assert!(!narrow.contains("::ffff:10.0.1.7".parse().unwrap()));
        assert!(!narrow.contains("fd00::1".parse().unwrap()));
    }
}
