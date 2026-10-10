#[cfg(feature = "native-api")]
use super::observation::ConnectionObservation;
use super::routing::RoutingDecision;
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
    pub(super) routing_generation: u64,
    pub(super) dscp: u8,
    pub(super) mac: [u8; 6],
    pub(super) pname: [u8; 16],
    pub(super) pid: u32,
    #[cfg(feature = "native-api")]
    pub(super) trace_id: u32,
    #[cfg(feature = "native-api")]
    pub(super) capture: Option<crate::observe::flows::kernel::CapturedKernelRoute>,
    #[cfg(feature = "native-api")]
    pub(super) capture_gap: Option<&'static str>,
}

impl From<RoutingHandoffEntry> for HandoffResult {
    fn from(entry: RoutingHandoffEntry) -> Self {
        Self {
            outbound: entry.result.outbound,
            mark: entry.result.mark,
            must: entry.result.must,
            decision_token: entry.result.decision_token,
            routing_generation: entry.routing_generation,
            dscp: entry.result.dscp,
            mac: entry.result.mac,
            pname: entry.result.pname,
            pid: entry.result.pid,
            #[cfg(feature = "native-api")]
            trace_id: entry.trace_id,
            #[cfg(feature = "native-api")]
            capture: None,
            #[cfg(feature = "native-api")]
            capture_gap: Some("kernel_trace_not_captured"),
        }
    }
}

impl HandoffResult {
    fn captured(
        backend: &dyn crate::ebpf::EbpfBackend,
        key: &TuplesKey,
        entry: RoutingHandoffEntry,
        atomic: bool,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> Self {
        let handoff = Self::from(entry);
        #[cfg(feature = "native-api")]
        if !observation.is_recording() {
            return handoff;
        }
        #[cfg(feature = "native-api")]
        let handoff = {
            let mut handoff = handoff;
            match backend.capture_kernel_route(key, (&entry).into()) {
                Ok(mut capture) => {
                    if !atomic {
                        capture.gap = Some("kernel_handoff_nonatomic_take");
                        capture.ambiguous = true;
                    }
                    if key.dst_port != 53 {
                        let state = if key.l4proto == 6 {
                            backend.tcp_conn_state_lookup(key)
                        } else {
                            backend.udp_conn_state_lookup(key)
                        };
                        if !state.ok().flatten().is_some_and(|state| {
                            state.trace_id == entry.trace_id
                                && state.decision_token == entry.result.decision_token
                        }) {
                            capture.gap = Some("kernel_trace_conn_incarnation_mismatch");
                            capture.ambiguous = true;
                        }
                    }
                    handoff.capture_gap = capture.gap;
                    handoff.capture = Some(capture);
                }
                Err(gap) => {
                    handoff.capture_gap = Some(if atomic {
                        gap
                    } else {
                        "kernel_handoff_nonatomic_take"
                    })
                }
            }
            handoff
        };
        #[cfg(not(feature = "native-api"))]
        let _ = (backend, key, atomic);
        handoff
    }
    /// Convert the eBPF process name byte array to an optional string: bytes
    /// up to the first NUL (or the whole array), lossily decoded and trimmed.
    pub(super) fn process_name(&self) -> Option<String> {
        let end = self
            .pname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.pname.len());
        let name = String::from_utf8_lossy(&self.pname[..end]);
        let trimmed = name.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
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
        use std::fmt::Write as _;

        if self.mac == [0u8; 6] {
            return None;
        }
        let mut mac = String::with_capacity(17);
        write!(
            mac,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
        .expect("writing to a String cannot fail");
        Some(mac)
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
        owner: crate::connection_tracker::ConnectionOwner,
    ) -> Option<String> {
        assert!(
            self.tracker_id.is_none(),
            "TCP flow tracker attached more than once"
        );
        if !self.tracker.is_enabled() {
            return None;
        }
        let id = self.tracker.register_owned(make_entry(), owner);
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

    pub(super) async fn retire(mut self) -> bool {
        let now_ns = match crate::control::janitor::monotonic_now_ns() {
            Ok(now_ns) => now_ns,
            Err(error) => {
                error!(%error, "TCP flow retirement could not read monotonic clock");
                return false;
            }
        };
        let retire_cutoff_ns = now_ns.saturating_sub(1);
        let ebpf = Arc::clone(&self.ebpf);
        let mut backend = ebpf.write().await;
        match self.release_pin() {
            Some(false) => return true,
            Some(true) => {}
            None => return false,
        }

        let current = match backend.tcp_conn_state_lookup(&self.tuples) {
            Ok(Some(current)) => current,
            Ok(None) => return true,
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow retirement lookup failed");
                return false;
            }
        };
        match backend.conn_state_remove_if_unchanged(&[(self.tuples, current)], retire_cutoff_ns) {
            Ok(removed) => {
                if removed != 0 {
                    crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
                }
                debug!(removed, ?self.tuples, "TCP flow conn-state retired");
                true
            }
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow conditional retirement failed");
                false
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

pub(super) struct ModeDecision {
    pub(super) name: String,
    pub(super) constraint: crate::control::reload::OutboundConstraint,
    #[cfg(feature = "native-api")]
    pub(super) group_id: Option<String>,
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
    pub(super) async fn lookup_handoff(
        &self,
        tuples: &TuplesKey,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> Option<HandoffResult> {
        let backend = self.ebpf.read().await;
        backend
            .routing_handoff_take_observed(tuples)
            .ok()
            .flatten()
            .map(|(entry, atomic)| {
                HandoffResult::captured(
                    backend.as_ref(),
                    tuples,
                    entry,
                    atomic,
                    #[cfg(feature = "native-api")]
                    observation,
                )
            })
    }

    /// Staged UDP transitions consume their handoff atomically at commit, so
    /// initialization may only inspect it. Legacy socket ingress consumes the
    /// tuple once; UDP/53 retains only the non-must controller handoff.
    pub(super) async fn lookup_udp_handoff(
        &self,
        tuples: &TuplesKey,
        decision_token: u32,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<Option<HandoffResult>> {
        if decision_token == 0 {
            let handoff = self
                .lookup_handoff(
                    tuples,
                    #[cfg(feature = "native-api")]
                    observation,
                )
                .await;
            return Ok(if tuples.dst_port == 53 {
                handoff.filter(|handoff| {
                    handoff.outbound == OutboundIndex::ControlPlaneRouting as u8
                        && handoff.must == 0
                })
            } else {
                handoff
            });
        }
        let backend = self.ebpf.read().await;
        let entry = backend
            .routing_handoff_lookup(tuples)?
            .ok_or_else(|| anyhow::anyhow!("staged UDP flow has no routing handoff"))?;
        if entry.result.decision_token != decision_token {
            anyhow::bail!(
                "staged UDP handoff token mismatch: expected {}, found {}",
                decision_token,
                entry.result.decision_token
            );
        }
        Ok(Some(HandoffResult::captured(
            backend.as_ref(),
            tuples,
            entry,
            true,
            #[cfg(feature = "native-api")]
            observation,
        )))
    }

    pub(super) async fn adopt_tcp_flow(
        &self,
        stream: TcpStream,
        tuples: TuplesKey,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
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
            .routing_handoff_take_observed(&tuples)
            .ok()
            .flatten()
            .map(|(entry, atomic)| {
                HandoffResult::captured(
                    backend.as_ref(),
                    &tuples,
                    entry,
                    atomic,
                    #[cfg(feature = "native-api")]
                    observation,
                )
            });
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
    ///
    /// The route's rule mark survives only on a routed `direct` flow that
    /// remains `direct`.
    pub(super) async fn apply_mode_override(&self, route: &mut RoutingDecision) -> ModeDecision {
        let decision = self.mode_override(route.outbound.clone(), route.must).await;
        let replacement = (decision.name != route.outbound).then(|| decision.name.clone());
        route.apply_final_outbound(replacement);
        decision
    }

    /// Preserve exact native target identity until the selected generation is pinned.
    async fn mode_override(&self, outbound_name: String, must: bool) -> ModeDecision {
        let mut result = ModeDecision {
            name: outbound_name,
            constraint: Default::default(),
            #[cfg(feature = "native-api")]
            group_id: None,
        };
        let Some(mode_state) = &self.mode_state else {
            return result;
        };
        if must || result.name == "block" {
            return result;
        }
        let state = mode_state.read().clone();
        #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
        if state.is_native() {
            let config = self.config.read().await;
            let state = mode_state.read().clone();
            let Some(native) = &self.native else {
                result.name = "block".into();
                return result;
            };
            let catalog = native.catalog.snapshot();
            match state.native_override(&result.name, must, &config, &catalog.groups) {
                crate::mode::ModeOverride::Unchanged => {}
                crate::mode::ModeOverride::Direct => result.name = "direct".into(),
                crate::mode::ModeOverride::Block => result.name = "block".into(),
                crate::mode::ModeOverride::Node(id) => {
                    result.name = config
                        .nodes
                        .iter()
                        .find(|node| node.id == id)
                        .expect("validated mode target")
                        .name
                        .clone();
                    result.constraint = crate::control::reload::OutboundConstraint::Node(id);
                }
                crate::mode::ModeOverride::Group(name) => {
                    result.group_id = catalog.groups.get(&name).cloned();
                    result.name = name;
                }
            }
            return result;
        }
        let selection = state.global_selection();
        let selection_resolvable = if state.is_global() && !selection.is_empty() {
            let config = self.config.read().await;
            matches!(selection, "direct" | "block")
                || config.groups.iter().any(|group| group.name == selection)
                || config.nodes.iter().any(|node| node.name == selection)
        } else {
            false
        };
        result.name = state.override_outbound(&result.name, false, selection_resolvable);
        result
    }
}

#[cfg(test)]
#[path = "tcp_flow_lifecycle_tests.rs"]
mod tcp_flow_lifecycle_tests;

#[cfg(all(test, feature = "native-api"))]
#[test]
fn handoff_capture_follows_admission_without_changing_authority() {
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let entry = RoutingHandoffEntry {
        result: honk_ebpf_common::RoutingResult {
            outbound: 2,
            mark: 0x42,
            must: 1,
            ..Default::default()
        },
        routing_generation: 9,
        ..Default::default()
    };
    for admitted in [false, true] {
        let native =
            crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
        native.core.flows.set_recording(admitted);
        let observation = ConnectionObservation::begin(
            Some(&native.core),
            crate::observe::vocab::Network::Tcp,
            "127.0.0.1:31000".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        );
        native.core.flows.set_recording(!admitted);
        let result =
            HandoffResult::captured(&backend, &TuplesKey::default(), entry, false, &observation);
        assert_eq!(
            result.capture_gap,
            Some(if admitted {
                "kernel_handoff_nonatomic_take"
            } else {
                "kernel_trace_not_captured"
            })
        );
        assert_eq!(
            (
                result.outbound,
                result.mark,
                result.must,
                result.routing_generation
            ),
            (2, 0x42, 1, 9)
        );
    }
}
