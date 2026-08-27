use crate::control::*;
use std::collections::{HashMap, HashSet};

/// Build the eBPF conntrack key for a flow: IPs as 16-byte v4-mapped
/// addresses, ports in host byte order, `l4proto` as the IANA number.
pub(crate) fn build_tuples_key(
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    src_ip: std::net::IpAddr,
    src_port: u16,
    l4proto: u8,
) -> TuplesKey {
    // mem::zeroed, NOT TuplesKey::default(): the struct has 3 implicit
    // padding bytes after l4proto (37 field bytes in a 40-byte repr(C)
    // layout), and Rust does not guarantee padding is zeroed on field-wise
    // initialization.  The kernel hashes all 40 key bytes, and the datapath
    // writes keys from a zeroed scratch buffer — a garbage-padded userspace
    // key never matches (lookups/deletes silently ENOENT).
    let mut key: TuplesKey = unsafe { std::mem::zeroed() };
    match dst_ip {
        std::net::IpAddr::V4(ip) => {
            key.dst_ip[10] = 0xff;
            key.dst_ip[11] = 0xff;
            key.dst_ip[12..16].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => key.dst_ip.copy_from_slice(&ip.octets()),
    }
    match src_ip {
        std::net::IpAddr::V4(ip) => {
            key.src_ip[10] = 0xff;
            key.src_ip[11] = 0xff;
            key.src_ip[12..16].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => key.src_ip.copy_from_slice(&ip.octets()),
    }
    key.dst_port = dst_port;
    key.src_port = src_port;
    key.l4proto = l4proto;
    key
}

/// Result from the eBPF routing handoff map lookup.
#[derive(Debug, Clone)]
pub(super) struct HandoffResult {
    pub(super) outbound: u8,
    pub(super) mark: u32,
    pub(super) must: u8,
    pub(super) decision_token: u32,
    pub(super) dscp: u8,
    pub(super) mac: [u8; 6],
    pub(super) pname: [u8; 16],
    pub(super) pid: u32,
}

impl From<RoutingHandoffEntry> for HandoffResult {
    fn from(entry: RoutingHandoffEntry) -> Self {
        Self {
            outbound: entry.result.outbound,
            mark: entry.result.mark,
            must: entry.result.must,
            decision_token: entry.result.decision_token,
            dscp: entry.result.dscp,
            mac: entry.result.mac,
            pname: entry.result.pname,
            pid: entry.result.pid,
        }
    }
}

impl HandoffResult {
    /// Convert the eBPF process name byte array to an optional string.
    /// Treats the array as NUL-terminated or fixed-length, trimming trailing
    /// NULs and whitespace.
    pub(super) fn process_name(&self) -> Option<String> {
        let bytes: Vec<u8> = self.pname.iter().copied().take_while(|&b| b != 0).collect();
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Resolve the process executable path from /proc. The process may have
    /// exited between the cgroup hook and now — any failure just omits the
    /// field. Off the runtime workers: even a /proc readlink is blocking I/O.
    pub(super) async fn process_path(&self) -> Option<String> {
        if self.pid == 0 {
            return None;
        }
        let pid = self.pid;
        tokio::task::spawn_blocking(move || {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .await
        .ok()
        .flatten()
    }

    /// Convert the eBPF MAC address to canonical lower-case colon form.
    pub(super) fn mac_address(&self) -> Option<String> {
        if self.mac == [0u8; 6] {
            return None;
        }
        Some(
            self.mac
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::control) struct TcpFlowKey {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    l4proto: u8,
}

impl TcpFlowKey {
    pub(in crate::control) fn from_tuples(tuples: &TuplesKey) -> Self {
        Self {
            src_ip: *tuples.src_ip.as_bytes(),
            dst_ip: *tuples.dst_ip.as_bytes(),
            src_port: tuples.src_port,
            dst_port: tuples.dst_port,
            l4proto: tuples.l4proto,
        }
    }

    pub(in crate::control) fn from_redirect(tuple: &RedirectTuple) -> Self {
        Self {
            src_ip: *tuple.src_ip.as_bytes(),
            dst_ip: *tuple.dst_ip.as_bytes(),
            src_port: tuple.src_port,
            dst_port: tuple.dst_port,
            l4proto: tuple.l4proto,
        }
    }
}

#[derive(Default)]
pub(in crate::control) struct TcpFlowPins {
    inner: parking_lot::Mutex<HashMap<TcpFlowKey, usize>>,
}

impl TcpFlowPins {
    fn retain(&self, key: TcpFlowKey) {
        *self.inner.lock().entry(key).or_default() += 1;
    }

    fn release(&self, key: TcpFlowKey) -> Option<bool> {
        let mut pins = self.inner.lock();
        let owners = pins.get_mut(&key)?;
        if *owners > 1 {
            *owners -= 1;
            Some(false)
        } else {
            pins.remove(&key);
            Some(true)
        }
    }

    pub(in crate::control) fn snapshot(&self) -> HashSet<TcpFlowKey> {
        self.inner.lock().keys().copied().collect()
    }

    #[cfg(test)]
    pub(in crate::control) fn retain_for_test(&self, key: TcpFlowKey) {
        self.retain(key);
    }

    #[cfg(test)]
    pub(in crate::control) fn release_for_test(&self, key: TcpFlowKey) -> Option<bool> {
        self.release(key)
    }
}

pub(super) struct TcpFlowGuard {
    stream: TcpStream,
    tuples: TuplesKey,
    pin_key: Option<TcpFlowKey>,
    pins: Arc<TcpFlowPins>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    tracker_id: Option<String>,
}

impl TcpFlowGuard {
    fn new(
        stream: TcpStream,
        tuples: TuplesKey,
        pins: Arc<TcpFlowPins>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        tracker: Arc<ConnectionTracker>,
    ) -> Self {
        let pin_key = TcpFlowKey::from_tuples(&tuples);
        pins.retain(pin_key);
        Self {
            stream,
            tuples,
            pin_key: Some(pin_key),
            pins,
            ebpf,
            tracker,
            tracker_id: None,
        }
    }

    pub(super) fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    #[cfg(test)]
    pub(super) fn track(&mut self, entry: crate::connection_tracker::ConnectionEntry) {
        assert!(
            self.tracker_id.is_none(),
            "TCP flow tracker attached more than once"
        );
        self.tracker_id = Some(self.tracker.register(entry));
    }

    pub(super) fn track_if_enabled(
        &mut self,
        make_entry: impl FnOnce() -> crate::connection_tracker::ConnectionEntry,
    ) -> Option<String> {
        assert!(
            self.tracker_id.is_none(),
            "TCP flow tracker attached more than once"
        );
        let id = self.tracker.register_if_enabled(make_entry)?;
        self.tracker_id = Some(id.clone());
        Some(id)
    }

    fn untrack(&mut self) {
        if let Some(id) = self.tracker_id.take() {
            self.tracker.remove(&id);
        }
    }

    fn release_pin(&mut self) -> Option<bool> {
        let key = self.pin_key.take()?;
        match self.pins.release(key) {
            Some(last_owner) => Some(last_owner),
            None => {
                error!(?key, "TCP flow pin release found no owner");
                None
            }
        }
    }

    pub(super) async fn retire(mut self) {
        self.untrack();
        let now_ns = match crate::control::janitor::monotonic_now_ns() {
            Ok(now_ns) => now_ns,
            Err(error) => {
                error!(%error, "TCP flow retirement could not read monotonic clock");
                return;
            }
        };
        let retire_cutoff_ns = now_ns.saturating_sub(1);
        let ebpf = Arc::clone(&self.ebpf);
        let mut backend = ebpf.write().await;
        if self.release_pin() != Some(true) {
            return;
        }

        let current = match backend.tcp_conn_state_lookup(&self.tuples) {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow retirement lookup failed");
                return;
            }
        };
        match backend.conn_state_remove_if_unchanged(&[(self.tuples, current)], retire_cutoff_ns) {
            Ok(removed) => {
                if removed != 0 {
                    crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
                }
                debug!(removed, ?self.tuples, "TCP flow conn-state retired");
            }
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow conditional retirement failed");
            }
        }
    }
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        self.untrack();
        self.release_pin();
    }
}

impl ControlPlaneHandle {
    /// `/proc/<pid>/exe` is display-only enrichment. Never hold first-packet
    /// delivery behind the blocking pool used to resolve it.
    pub(super) fn spawn_process_path_enrichment(
        &self,
        conn_id: String,
        handoff: Option<&HandoffResult>,
    ) {
        let Some(handoff) = handoff.filter(|handoff| handoff.pid != 0).cloned() else {
            return;
        };
        let tracker = Arc::clone(&self.connection_tracker);
        tokio::spawn(async move {
            if let Some(process_path) = handoff.process_path().await {
                tracker.update_process_path(&conn_id, process_path);
            }
        });
    }
    /// Look up the eBPF routing handoff entry for a connection, consuming it.
    ///
    /// Only a read lock is taken: `routing_handoff_take` performs raw bpf()
    /// map operations, which the kernel serializes internally — no userspace
    /// backend state is touched.  The lock's sole role here is to keep the
    /// backend (and its map fds) alive against `cleanup()`, which takes the
    /// write lock.
    pub(super) async fn lookup_handoff(&self, tuples: &TuplesKey) -> Option<HandoffResult> {
        self.ebpf
            .read()
            .await
            .routing_handoff_take(tuples)
            .ok()
            .flatten()
            .map(Into::into)
    }

    /// Staged UDP transitions consume their handoff atomically at commit, so
    /// initialization may only inspect it. Legacy socket ingress keeps the
    /// existing take-once behavior.
    pub(super) async fn lookup_udp_handoff(
        &self,
        tuples: &TuplesKey,
        decision_token: u32,
    ) -> anyhow::Result<Option<HandoffResult>> {
        if decision_token == 0 {
            return Ok(self.lookup_handoff(tuples).await);
        }
        let entry = self
            .ebpf
            .read()
            .await
            .routing_handoff_lookup(tuples)?
            .ok_or_else(|| anyhow::anyhow!("staged UDP flow has no routing handoff"))?;
        if entry.result.decision_token != decision_token {
            anyhow::bail!(
                "staged UDP handoff token mismatch: expected {}, found {}",
                decision_token,
                entry.result.decision_token
            );
        }
        Ok(Some(entry.into()))
    }

    pub(super) async fn adopt_tcp_flow(
        &self,
        stream: TcpStream,
        tuples: TuplesKey,
    ) -> anyhow::Result<(TcpFlowGuard, Option<HandoffResult>)> {
        let backend = self.ebpf.read().await;
        match backend.tcp_conn_state_lookup(&tuples) {
            Ok(Some(_)) => {}
            Ok(None) => anyhow::bail!("accepted TCP flow has no conn-state: {tuples:?}"),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "accepted TCP flow conn-state lookup failed for {tuples:?}: {error}"
                ));
            }
        }

        let flow = TcpFlowGuard::new(
            stream,
            tuples,
            Arc::clone(&self.tcp_flow_pins),
            Arc::clone(&self.ebpf),
            Arc::clone(&self.connection_tracker),
        );
        let handoff = backend
            .routing_handoff_take(&tuples)
            .ok()
            .flatten()
            .map(Into::into);
        Ok((flow, handoff))
    }

    pub(super) async fn outbound_index_to_name(&self, index: u8) -> String {
        match OutboundIndex::from_user(index as u32) {
            OutboundIndex::Direct => "direct".into(),
            OutboundIndex::Block => "block".into(),
            OutboundIndex::MustRules => "must_rules".into(),
            OutboundIndex::ControlPlaneRouting => "control_plane_routing".into(),
            _ => {
                let config = self.config.read().await;
                // Map user index back to the group name (same order as
                // outbound_name_to_id above).
                let user_idx = index.saturating_sub(OutboundIndex::UserBase as u8);
                config
                    .groups
                    .get(user_idx as usize)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| config.routing.default_outbound.clone())
            }
        }
    }

    #[cfg(feature = "ebpf")]
    pub(super) async fn outbound_name_to_index(&self, outbound_name: &str) -> u8 {
        match outbound_name {
            "direct" => OutboundIndex::Direct as u8,
            "block" => OutboundIndex::Block as u8,
            "must_rules" => OutboundIndex::MustRules as u8,
            "control_plane_routing" => OutboundIndex::ControlPlaneRouting as u8,
            _ => {
                let config = self.config.read().await;
                config
                    .groups
                    .iter()
                    .position(|group| group.name == outbound_name)
                    .and_then(|index| u8::try_from(index).ok())
                    .and_then(|index| (OutboundIndex::UserBase as u8).checked_add(index))
                    .unwrap_or(OutboundIndex::ControlPlaneRouting as u8)
            }
        }
    }

    /// Clash mode override (approximate clash semantics), applied after the
    /// eBPF handoff / userspace Router produced an outbound and before
    /// `resolve_outbound_nodes`:
    ///
    /// - mode `Direct` forces `direct`;
    /// - mode `Global` forces the current GLOBAL selection (a group or node
    ///   name, resolved via the normal path; when it resolves to nothing the
    ///   original routing result is kept);
    /// - `block` results and `must` results (dae `(must)` rules / eBPF
    ///   handoff must flag) are never overridden — both are final routing
    ///   decisions that mode switches must not bypass.
    pub(super) async fn apply_mode_override(&self, outbound_name: String, must: bool) -> String {
        let Some(ref mode_state) = self.mode_state else {
            return outbound_name;
        };
        if must || outbound_name == "block" {
            return outbound_name;
        }
        let state = { mode_state.read().clone() };
        // The GLOBAL selection needs a config lookup to decide whether it
        // resolves to a group/node; only do it in Global mode.
        let mut selection_resolvable = false;
        if state.is_global() && !state.global_selection.is_empty() {
            let selection = &state.global_selection;
            selection_resolvable = *selection == "direct" || *selection == "block" || {
                let config = self.config.read().await;
                config.groups.iter().any(|g| g.name == *selection)
                    || config.nodes.iter().any(|n| n.name == *selection)
            };
            if !selection_resolvable {
                debug!(
                    "clash Global selection '{}' does not resolve; keeping routed outbound '{}'",
                    selection, outbound_name
                );
            }
        }
        state.override_outbound(&outbound_name, false, selection_resolvable)
    }
}

#[cfg(test)]
#[path = "tcp_flow_lifecycle_tests.rs"]
mod tcp_flow_lifecycle_tests;
