use std::sync::Arc;

use honk_config::node::Node;

use crate::proxy::wireguard::{Tunnel, TunnelConfig, TunnelRegistry, WarmHold};

static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One node runtime's view of its tunnel. The tunnel itself lives in its plane's registry (shared
/// by every runtime of the plane with the same config); this slot caches it, holds it warm while a
/// policy retains it, and closes the flows this runtime opened when it shuts down.
#[derive(Debug)]
pub struct WireGuardRuntime {
    registry: Arc<TunnelRegistry>,
    scope: u64,
    /// Single-flight tunnel acquisition: first dial, warm-up and speculative commit converge.
    acquiring: tokio::sync::Mutex<()>,
    slot: parking_lot::Mutex<Slot>,
}

#[derive(Default)]
struct Slot {
    tunnel: Option<Tunnel>,
    hold: Option<WarmHold>,
    retained: bool,
    closed: bool,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("cached", &self.tunnel.is_some())
            .field("retained", &self.retained)
            .field("closed", &self.closed)
            .finish()
    }
}

impl Slot {
    fn live(&self) -> Option<Tunnel> {
        self.tunnel.clone().filter(|tunnel| !tunnel.is_dead())
    }
}

impl WireGuardRuntime {
    pub(super) fn new(registry: Arc<TunnelRegistry>) -> Self {
        Self {
            registry,
            scope: NEXT_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            acquiring: tokio::sync::Mutex::new(()),
            slot: parking_lot::Mutex::new(Slot::default()),
        }
    }

    pub(crate) fn scope(&self) -> u64 {
        self.scope
    }

    /// The registry of the plane this runtime belongs to.
    pub(crate) fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    pub(crate) async fn tunnel(&self, node: &Node) -> anyhow::Result<Tunnel> {
        {
            let slot = self.slot.lock();
            anyhow::ensure!(!slot.closed, "WireGuard runtime is closed");
            if let Some(tunnel) = slot.live() {
                return Ok(tunnel);
            }
        }
        let _acquiring = self.acquiring.lock().await;
        if let Some(tunnel) = self.slot.lock().live() {
            return Ok(tunnel);
        }
        let tunnel = self
            .registry
            .acquire(TunnelConfig::from_node(node)?)
            .await?;
        self.install(tunnel.clone())?;
        Ok(tunnel)
    }

    /// Publish `tunnel` as the reusable one. Rejected once the runtime is closed, so a late
    /// speculative commit cannot resurrect state in a terminal runtime.
    pub(crate) fn install(&self, tunnel: Tunnel) -> anyhow::Result<()> {
        let mut slot = self.slot.lock();
        if slot.closed {
            // The tunnel may have been created for this call alone; do not leave it running.
            tunnel.release(self.scope);
            anyhow::bail!("WireGuard runtime is closed");
        }
        tunnel.attach(self.scope);
        // The new claim is taken before the old one is dropped: the tunnel is the same when a
        // retained runtime installs it again, and must stay pinned throughout.
        let hold = slot.retained.then(|| tunnel.hold(self.scope)).flatten();
        if let Some(old) = slot.tunnel.replace(tunnel.clone())
            && !old.same(&tunnel)
        {
            old.detach(self.scope);
        }
        slot.hold = hold;
        Ok(())
    }

    /// Occupancy of the reusable slot: one usable tunnel or none.
    pub(super) fn client_count(&self) -> usize {
        usize::from(self.slot.lock().live().is_some())
    }

    pub(super) fn is_warm(&self) -> bool {
        self.slot
            .lock()
            .live()
            .is_some_and(|tunnel| tunnel.is_established())
    }

    pub(super) fn set_retained(&self, retained: bool) {
        let mut slot = self.slot.lock();
        slot.retained = retained;
        if retained {
            if slot.hold.is_none() {
                slot.hold = slot.live().and_then(|tunnel| tunnel.hold(self.scope));
            }
        } else {
            // Last policy release: stop pinning the tunnel and forget the cached handle. Flows keep
            // their own handles, and the registry tears an unused tunnel down after its idle period.
            slot.hold = None;
            if let Some(tunnel) = slot.tunnel.take() {
                tunnel.detach(self.scope);
            }
        }
    }

    pub(super) fn shutdown(&self) {
        {
            let mut slot = self.slot.lock();
            slot.closed = true;
            slot.retained = false;
            slot.hold = None;
            slot.tunnel = None;
        }
        // Also forgets this runtime as a user of the tunnels and retires those left unused.
        self.registry.close_scope(self.scope);
    }
}

#[cfg(test)]
impl WireGuardRuntime {
    pub(crate) fn cached(&self) -> Option<Tunnel> {
        self.slot.lock().tunnel.clone()
    }
}

#[allow(dead_code)]
fn _config_is_send() {
    fn assert_send<T: Send + Sync>() {}
    assert_send::<WireGuardRuntime>();
}
