#[cfg(feature = "native-api")]
use super::observation::ConnectionObservation;
use super::routing::RoutingDecision;
use crate::control::*;
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

/// Build the eBPF conntrack key for a flow: IPs as 16-byte v4-mapped
/// addresses, ports in host byte order, `l4proto` as the IANA number.
pub(crate) fn build_tuples_key(
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    src_ip: std::net::IpAddr,
    src_port: u16,
    l4proto: u8,
) -> TuplesKey {
    let mut key = TuplesKey::default();
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
pub(in crate::control) struct HandoffResult {
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
                    if key.dst_port != 53
                        && !(key.l4proto == 17
                            && honk_ebpf_common::conn::is_stateless_udp_ports(
                                key.src_port,
                                key.dst_port,
                            ))
                    {
                        let state = backend.conn_state_lookup(key);
                        if !state.ok().flatten().is_some_and(|state| {
                            state.incarnation == entry.incarnation
                                && state.trace_id == entry.trace_id
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
                    handoff.capture_gap = Some(gap);
                }
            }
            handoff
        };
        #[cfg(not(feature = "native-api"))]
        let _ = (backend, key);
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

    #[cfg(test)]
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
    pub(in crate::control) fn contains(&self, tuples: &TuplesKey) -> bool {
        self.inner
            .lock()
            .contains_key(&TcpFlowKey::from_tuples(tuples))
    }

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

    #[cfg(test)]
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

struct LocalPin {
    pins: Arc<TcpFlowPins>,
    key: Option<TcpFlowKey>,
}

impl LocalPin {
    fn release_once(&mut self) -> anyhow::Result<()> {
        if let Some(key) = self.key.take() {
            anyhow::ensure!(
                self.pins.release(key).is_some(),
                "TCP flow lost its local pin"
            );
        }
        Ok(())
    }

    fn release(mut self) -> anyhow::Result<()> {
        self.release_once()
    }
}

impl Drop for LocalPin {
    fn drop(&mut self) {
        if let Err(error) = self.release_once() {
            error!(%error, "TCP flow pin release found no owner");
        }
    }
}

struct FlowPin {
    local: Option<LocalPin>,
    kernel: Option<crate::ebpf::TcpPin>,
}

impl FlowPin {
    fn new(pins: Arc<TcpFlowPins>, key: TcpFlowKey, kernel: crate::ebpf::TcpPin) -> Self {
        pins.retain(key);
        Self {
            local: Some(LocalPin {
                pins,
                key: Some(key),
            }),
            kernel: Some(kernel),
        }
    }

    fn release(&mut self) -> anyhow::Result<()> {
        let local = self
            .local
            .take()
            .ok_or_else(|| anyhow::anyhow!("TCP retirement lost its local pin"))
            .and_then(LocalPin::release);
        let native = self
            .kernel
            .take()
            .map(crate::ebpf::TcpPin::release)
            .unwrap_or(Ok(()));
        match (local, native) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(local), Err(native)) => {
                Err(local.context(format!("native TCP pin release also failed: {native:#}")))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

#[derive(Default)]
pub(in crate::control) struct RetireAck {
    pub(in crate::control) close: Option<crate::connection_tracker::CloseCompletion>,
    pub(in crate::control) outbound: Option<crate::stats::ActiveConnectionGuard>,
}

pub(in crate::control) struct TcpFlowGuard {
    stream: Option<TcpStream>,
    pub(in crate::control) tuples: TuplesKey,
    pub(in crate::control) incarnation: u64,
    pin: FlowPin,
    retirement: Arc<crate::control::retirement_worker::RetirementPort>,
    tracker: Arc<ConnectionTracker>,
    tracker_id: Option<String>,
    ack: RetireAck,
}

impl TcpFlowGuard {
    pub(in crate::control) fn new(
        stream: TcpStream,
        tuples: TuplesKey,
        incarnation: u64,
        pins: Arc<TcpFlowPins>,
        tracker: Arc<ConnectionTracker>,
        retirement: Arc<crate::control::retirement_worker::RetirementPort>,
        kernel: crate::ebpf::TcpPin,
    ) -> Self {
        let pin_key = TcpFlowKey::from_tuples(&tuples);
        Self {
            stream: Some(stream),
            tuples,
            incarnation,
            pin: FlowPin::new(pins, pin_key, kernel),
            retirement,
            tracker,
            tracker_id: None,
            ack: RetireAck::default(),
        }
    }

    pub(in crate::control) fn stream_mut(&mut self) -> &mut TcpStream {
        self.stream
            .as_mut()
            .expect("accepted socket is closed only by retirement")
    }

    /// Fully close the accepted socket while its redirect entry still exists,
    /// so the client's reply or RST reaches daens instead of the host
    /// forwarding path.
    pub(in crate::control) fn close_transport(&mut self) {
        self.stream = None;
    }

    #[cfg(test)]
    pub(in crate::control) fn track(&mut self, entry: crate::connection_tracker::ConnectionEntry) {
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

    pub(in crate::control) fn release_pin(&mut self) -> anyhow::Result<()> {
        self.pin.release()
    }

    pub(in crate::control) fn finish_retirement(mut self, success: bool) {
        let close = self.ack.close.take();
        let outbound = self.ack.outbound.take();
        drop(self);
        drop(outbound);
        if let Some(close) = close {
            close.0.finish(success);
        }
    }

    pub(in crate::control) async fn retire(mut self, ack: RetireAck) -> bool {
        self.ack = ack;
        let sender = self.retirement.sink.lock().clone();
        let Some(sender) = sender else {
            error!(?self.tuples, "TCP retirement worker is unavailable");
            return false;
        };
        // Before this admission point cancellation only drops the guard. After
        // it, the joined worker owns the socket, pins and tracker to completion.
        let Ok(permit) = sender.reserve_owned().await else {
            error!(?self.tuples, "TCP retirement worker closed admission");
            return false;
        };
        let (completion, result) = tokio::sync::oneshot::channel();
        permit.send(crate::control::retirement_worker::TcpRetirement {
            flow: self,
            completion,
        });
        result.await.unwrap_or(false)
    }
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        self.untrack();
    }
}

#[derive(Clone, Debug)]
pub(in crate::control) struct ModeDecision {
    pub(in crate::control) name: String,
    pub(in crate::control) constraint: crate::control::reload::OutboundConstraint,
    #[cfg(feature = "native-api")]
    pub(in crate::control) group_id: Option<String>,
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
    /// Read immutable UDP admission metadata without consuming tuple ownership.
    /// The caller carries its original incarnation through deferred admission.
    pub(super) async fn lookup_udp_handoff(
        &self,
        tuples: &TuplesKey,
        owner: crate::ebpf::UdpFlowOwner,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<Option<HandoffResult>> {
        let backend = self.ebpf.read().await;
        let tc = backend.tc()?;
        let entry = tc.verify_udp_admission(tuples, owner)?;
        Ok(entry
            .filter(|entry| {
                tuples.dst_port != 53
                    || owner.token != 0
                    || (entry.result.outbound == OutboundIndex::ControlPlaneRouting as u8
                        && entry.result.must == 0)
            })
            .map(|entry| {
                HandoffResult::captured(
                    tc,
                    tuples,
                    entry,
                    #[cfg(feature = "native-api")]
                    observation,
                )
            }))
    }

    /// sock_ops publishes a child's proof after the kernel queued it; measured on x86 the gap is
    /// under 20 us, so a few millisecond-granular retries cover it without delaying a real refusal.
    const CHILD_PROOF_RETRIES: u32 = 3;
    const CHILD_PROOF_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

    pub(in crate::control) async fn adopt_tcp_flow(
        &self,
        stream: TcpStream,
        tuples: TuplesKey,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<(TcpFlowGuard, Option<HandoffResult>)> {
        use std::os::fd::AsFd;
        let mut retries = Self::CHILD_PROOF_RETRIES;
        let (backend, adoption) = loop {
            let backend = self.ebpf.read().await;
            match backend.tc()?.adopt_tcp(
                stream.as_fd(),
                &tuples,
                Arc::clone(&self.retirement.pin_errors),
            ) {
                Err(error) if retries > 0 && error.is::<crate::ebpf::TcpChildProofPending>() => {
                    retries -= 1;
                    drop(backend);
                    tokio::time::sleep(Self::CHILD_PROOF_RETRY_DELAY).await;
                }
                result => break (backend, result?),
            }
        };
        // The local pin joins the native pin before releasing backendR.
        let flow = TcpFlowGuard::new(
            stream,
            tuples,
            adoption.incarnation,
            Arc::clone(&self.tcp_flow_pins),
            Arc::clone(&self.connection_tracker),
            Arc::clone(&self.retirement),
            adoption.pin,
        );
        let tc = backend.tc()?;
        let handoff = adoption.handoff.map(|entry| {
            HandoffResult::captured(
                tc,
                &tuples,
                entry,
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
        if must || outbound_name == "block" || self.mode_state.is_none() {
            return ModeDecision {
                name: outbound_name,
                constraint: Default::default(),
                #[cfg(feature = "native-api")]
                group_id: None,
            };
        }
        let config = self.config.read().await;
        let state = self.mode_state.as_ref().map(|state| state.read());
        mode_decision(
            state.as_deref(),
            &config,
            #[cfg(feature = "native-api")]
            self.native
                .as_ref()
                .map(|native| native.catalog.snapshot())
                .as_deref(),
            outbound_name,
            must,
        )
    }
}

pub(in crate::control) fn mode_decision(
    state: Option<&crate::mode::ModeState>,
    config: &honk_config::Config,
    #[cfg(feature = "native-api")] catalog: Option<&crate::observe::catalog::CatalogIdentity>,
    outbound: String,
    must: bool,
) -> ModeDecision {
    let mut result = ModeDecision {
        name: outbound,
        constraint: Default::default(),
        #[cfg(feature = "native-api")]
        group_id: None,
    };
    let Some(state) = state else {
        return result;
    };
    if must || result.name == "block" {
        return result;
    }
    #[cfg(all(feature = "native-api", any(feature = "clash-api", test)))]
    if state.is_native() {
        let Some(catalog) = catalog else {
            result.name = "block".into();
            return result;
        };
        match state.native_override(&result.name, must, config, &catalog.groups) {
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
    #[cfg(feature = "native-api")]
    let _ = catalog;
    let selection = state.global_selection();
    let resolvable = state.is_global()
        && !selection.is_empty()
        && (matches!(selection, "direct" | "block")
            || config.groups.iter().any(|group| group.name == selection)
            || config.nodes.iter().any(|node| node.name == selection));
    result.name = state.override_outbound(&result.name, must, resolvable);
    result
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
        let result = HandoffResult::captured(&backend, &TuplesKey::default(), entry, &observation);
        assert_eq!(result.capture_gap, Some("kernel_trace_not_captured"));
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
