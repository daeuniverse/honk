//! TCP conntrack: SYN claim and classification, publication, and per-packet state refresh.

use super::{
    ConntrackArgs, allocate_flow_incarnation, build_routing_meta, conntrack_output,
    is_new_tcp_connection, occupancy_add, tcp_live_pinned,
};
use crate::{
    auxiliary::auxiliary_expired,
    event::{send_dae_event, send_flow_expired},
    maps::{
        CONN_STATE_MAP, CONNTRACK_ARGS_MAP, TCP_PUBLISHING, increment_bpf_stat, tuple_retiring,
    },
    tcp_binding::{SYN_OWNER_ABSENT, SYN_OWNER_FRESH, SYN_OWNER_REFUSE, native_syn_owner},
};
use aya_ebpf_bindings::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
};
use honk_ebpf_common::{
    conn::{
        BpfStatsKey, ConnState, FlowMapValue, OCCUPANCY_INSERTS, TCP_SYN_ORIGINAL_INTERCEPT,
        TcpState, tcp_conn_state_expired,
    },
    redirect_need::TuplesKey,
};
use network_types::tcp::TcpHdr;

const TCP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000;

/// What this invocation may do with a wire SYN, decided once by [`TcpPublisher::acquire`].
/// Identity and the replacement CAS precondition stay in the publisher/scratch so
/// the claim guard fits its existing 32-byte share of the BPF call-chain stack.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpSyn {
    NonSyn = 0,
    /// Sole publisher replacing the entry seen at claim time.
    Fresh = 1,
    /// Retransmission of a publication that still owns its tuple: a complete original
    /// publication, or one no child has consumed yet.
    Cached = 2,
}

/// The NOEXIST claim spans classification and the final tuple-map access.
pub struct TcpPublisher {
    key: core::ptr::NonNull<TuplesKey>,
    pub incarnation: u64,
    expected_incarnation: u64,
    pub syn: TcpSyn,
    claimed: u8,
}

const _: () = assert!(core::mem::size_of::<TcpPublisher>() == 32);

impl TcpPublisher {
    #[inline(always)]
    pub fn new(key: &TuplesKey) -> Self {
        Self {
            key: core::ptr::NonNull::from(key),
            incarnation: 0,
            expected_incarnation: 0,
            syn: TcpSyn::NonSyn,
            claimed: 0,
        }
    }

    #[inline(always)]
    fn claim(&mut self) -> bool {
        let key = unsafe { self.key.as_ref() };
        if self.claimed != 0 || tuple_retiring(key) {
            return false;
        }
        // Zero is exclusion only, never fresh-publication authority. Cached
        // SYNs neither allocate an incarnation nor gain replacement permission.
        // Pass a stack value: with `&0`, which Rust promotes to a static, the
        // netns SYN-follow test never saw the fresh incarnation published.
        let zero = 0u64;
        if let Err(error) = TCP_PUBLISHING.insert(key, &zero, BPF_NOEXIST as u64) {
            // A concurrent same-tuple SYN is ordinary exclusion, not saturation.
            if error != -crate::errno::EEXIST {
                increment_bpf_stat(BpfStatsKey::TcpPublisherClaimFailure);
            }
            return false;
        }
        self.claimed = 1;
        self.expected_incarnation = crate::flow::conn_incarnation(key).unwrap_or(0);
        true
    }

    #[inline(always)]
    fn select_fresh(&mut self) -> bool {
        let Some(incarnation) = allocate_flow_incarnation() else {
            return false;
        };
        let key = unsafe { self.key.as_ref() };
        let Some(claim) = TCP_PUBLISHING.get_ptr_mut(key) else {
            return false;
        };
        unsafe { claim.write_volatile(incarnation) };
        self.incarnation = incarnation;
        self.syn = TcpSyn::Fresh;
        true
    }

    #[inline(always)]
    pub fn is_fresh(&self) -> bool {
        // One-hot kinds keep freshness a bit test; equality multiplies the floor verifier's walk.
        (self.syn as u8) & (TcpSyn::Fresh as u8) != 0
    }

    #[inline(always)]
    pub fn acquire(&mut self, ctx: &aya_ebpf::programs::TcContext, tcph: &TcpHdr) -> bool {
        if !is_new_tcp_connection(tcph)
            || crate::maps::PARAM.load().tcp_daens_netns_id < 0
            || !self.claim()
        {
            return false;
        }
        let key = unsafe { self.key.as_ref() };
        let Some(state) = crate::flow::tcp_syn_state(key) else {
            return self.select_fresh();
        };
        if state.incarnation != self.expected_incarnation {
            return false;
        }
        if !state.published || state.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT == 0 {
            return self.select_fresh();
        }
        let isn = u32::from_be_bytes(tcph.seq);
        let owner = native_syn_owner(ctx, key, isn);
        if owner == SYN_OWNER_REFUSE {
            return false;
        } else if owner == SYN_OWNER_FRESH {
            return self.select_fresh();
        } else if owner == SYN_OWNER_ABSENT {
            // No listener or pending request is read: whatever request exists is judged by the
            // tuple's own publication, and its child is proven at establishment.
            if state.tcp_syn_isn != isn
                || state.state != TcpState::TcpStateActive as u8
                || tcp_live_pinned(state.incarnation)
            {
                return self.select_fresh();
            }
            match pending_syn_publication(key, state.incarnation) {
                Publication::Missing => return false,
                Publication::Stale => return self.select_fresh(),
                Publication::Valid => {}
            }
            self.incarnation = state.incarnation;
            self.syn = TcpSyn::Cached;
        } else {
            if state.incarnation != owner || state.tcp_syn_isn != isn {
                return false;
            }
            self.incarnation = owner;
            self.syn = TcpSyn::Cached;
        }
        true
    }

    /// Deterministic competing-SYN driver: bypass retransmission classification explicitly.
    #[cfg(feature = "routing-test")]
    #[inline(always)]
    pub fn acquire_fresh(&mut self) -> bool {
        self.claim() && self.select_fresh()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    Valid,
    /// Present and consistent but aged out: a new SYN may replace it.
    Stale,
    /// Absent or inconsistent: ownership cannot be established, so the SYN is refused.
    Missing,
}

#[inline(always)]
fn pending_syn_publication(key: &TuplesKey, incarnation: u64) -> Publication {
    if tuple_retiring(key) {
        return Publication::Missing;
    }
    let Some(handoff) = crate::flow::handoff_identity(key) else {
        return Publication::Missing;
    };
    let Some(redirect) =
        crate::flow::redirect_identity(&honk_ebpf_common::RedirectTuple::from_tuples(key))
    else {
        return Publication::Missing;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    if incarnation == 0
        || handoff.incarnation != incarnation
        || redirect.incarnation != incarnation
        || handoff.decision_token != 0
        || redirect.decision_token != 0
        || now < handoff.last_seen_ns
        || now < redirect.last_seen_ns
    {
        return Publication::Missing;
    }
    if auxiliary_expired(key, incarnation, now - handoff.last_seen_ns, true)
        || auxiliary_expired(key, incarnation, now - redirect.last_seen_ns, false)
    {
        Publication::Stale
    } else {
        Publication::Valid
    }
}

impl Drop for TcpPublisher {
    #[inline(always)]
    fn drop(&mut self) {
        if self.claimed == 0 {
            return;
        }
        let key = unsafe { self.key.as_ref() };
        let claim = if self.is_fresh() { self.incarnation } else { 0 };
        if let Some(owner) = TCP_PUBLISHING.get_ptr(key)
            && unsafe { *owner } == claim
        {
            let _ = TCP_PUBLISHING.remove(key);
        }
    }
}

#[inline(always)]
fn update_tcp_locked(state: &mut ConnState, args: &ConntrackArgs, now: u64, fin_rst: bool) {
    if now.saturating_sub(state.last_seen_ns) > TCP_CONN_STATE_UPDATE_INTERVAL_NS {
        state.last_seen_ns = now;
    }
    if fin_rst {
        state.state = TcpState::TcpStateClosing as u8;
    }
    if args.has_routing() {
        if args.has_mac() {
            let mut i = 0;
            while i < 6 {
                unsafe {
                    state
                        .mac
                        .as_mut_ptr()
                        .add(i)
                        .write_volatile(args.mac.as_ptr().add(i).read_volatile())
                };
                i += 1;
            }
        }
        if args.has_pname() {
            let mut i = 0;
            while i < 16 {
                unsafe {
                    state
                        .pname
                        .as_mut_ptr()
                        .add(i)
                        .write_volatile(args.pname.as_ptr().add(i).read_volatile())
                };
                i += 1;
            }
        }
        state.pid = args.pid;
        state.trace_id = args.trace_id;
        state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
    }
}

#[inline(always)]
fn syn_owner_holds(state: &ConnState, args: &ConntrackArgs, syn: TcpSyn) -> bool {
    syn == TcpSyn::NonSyn
        || (state.incarnation == args.incarnation
            && state.tcp_syn_isn == args.tcp_syn_isn
            && state.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT != 0)
}

/// Existing-entry path for established packets and retransmitted SYNs.
#[inline(always)]
fn observe_tcp(
    key: &TuplesKey,
    args: &ConntrackArgs,
    ptr_opt: Option<*mut FlowMapValue<ConnState>>,
    output: *mut ConnState,
    now: u64,
    fin_rst: bool,
    syn: TcpSyn,
) -> *mut ConnState {
    let Some(ptr) = ptr_opt else {
        return core::ptr::null_mut();
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let state = unsafe { &mut (*ptr).value };
    if !syn_owner_holds(state, args, syn) {
        unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
        return core::ptr::null_mut();
    }
    let expired = tcp_conn_state_expired(state, now.saturating_sub(state.last_seen_ns));
    if !expired {
        update_tcp_locked(state, args, now, fin_rst);
    }
    unsafe {
        crate::flow::copy_payload(output, state);
        bpf_spin_unlock(&mut (*ptr).lock);
    }
    let incarnation = unsafe { (*output).incarnation };
    if expired {
        if !tcp_live_pinned(incarnation) {
            send_flow_expired(key, incarnation);
            return core::ptr::null_mut();
        }
        unsafe { bpf_spin_lock(&mut (*ptr).lock) };
        let state = unsafe { &mut (*ptr).value };
        let owned = state.incarnation == incarnation && syn_owner_holds(state, args, syn);
        if owned {
            update_tcp_locked(state, args, now, fin_rst);
            unsafe { crate::flow::copy_payload(output, state) };
        }
        unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
        if !owned {
            return core::ptr::null_mut();
        }
    }
    output
}

/// Fresh-SYN path: publish a new entry, or replace the one seen at claim time.
#[inline(always)]
fn publish_fresh_tcp(
    key: &TuplesKey,
    args: &ConntrackArgs,
    ptr_opt: Option<*mut FlowMapValue<ConnState>>,
    output: *mut ConnState,
    now: u64,
    expected_incarnation: u64,
) -> *mut ConnState {
    let incarnation = args.incarnation;
    if incarnation == 0
        || TCP_PUBLISHING
            .get_ptr(key)
            .is_none_or(|owner| unsafe { *owner } != incarnation)
    {
        return core::ptr::null_mut();
    }
    let new_state = unsafe { &mut *output };
    *new_state = unsafe { core::mem::zeroed() };
    new_state.incarnation = incarnation;
    new_state.tcp_syn_isn = args.tcp_syn_isn;
    new_state.state = TcpState::TcpStateActive as u8;
    new_state.last_seen_ns = now;
    new_state.pid = args.pid;
    new_state.trace_id = if args.has_routing() {
        args.trace_id
    } else if ptr_opt.is_some() {
        u32::MAX
    } else {
        0
    };
    if args.has_routing() {
        update_tcp_locked(new_state, args, now, false);
    }
    if let Some(ptr) = ptr_opt {
        unsafe { bpf_spin_lock(&mut (*ptr).lock) };
        let owned = unsafe { (*ptr).value.incarnation == expected_incarnation };
        if owned {
            unsafe { crate::flow::copy_payload(&raw mut (*ptr).value, new_state) };
        }
        unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
        if !owned {
            return core::ptr::null_mut();
        }
    } else if expected_incarnation != 0 {
        return core::ptr::null_mut();
    } else if CONN_STATE_MAP
        .insert(key, &FlowMapValue::new(*new_state), BPF_NOEXIST as u64)
        .is_ok()
    {
        occupancy_add(OCCUPANCY_INSERTS);
    } else {
        let stats_key = BpfStatsKey::TcpConnOverflow as u32;
        if let Some(counter) = crate::maps::BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe { *counter += 1 };
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::TcpConnOverflow as u32,
            args.pid,
            args.pname_or_null(),
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
        return core::ptr::null_mut();
    }
    output
}

/// Returns invocation-local scratch, never a borrowed map payload.
fn __mark_tcp_seen(
    key: *const TuplesKey,
    syn: TcpSyn,
    fin_rst: bool,
    args: *mut ConntrackArgs,
    expected_incarnation: u64,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &mut *args };
    if tuple_retiring(key) {
        return core::ptr::null_mut();
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(output) = conntrack_output() else {
        return core::ptr::null_mut();
    };
    let ptr_opt = CONN_STATE_MAP.get_ptr_mut(key);
    match syn {
        TcpSyn::NonSyn | TcpSyn::Cached => {
            observe_tcp(key, args, ptr_opt, output, now, fin_rst, syn)
        }
        TcpSyn::Fresh => publish_fresh_tcp(key, args, ptr_opt, output, now, expected_incarnation),
    }
}

/// Commit only this captured SYN's routing fields; preserve concurrent lifecycle refreshes.
#[inline(always)]
pub fn publish_tcp_routing(key: &TuplesKey, snapshot: &ConnState) -> bool {
    if tuple_retiring(key)
        || snapshot.incarnation == 0
        || TCP_PUBLISHING
            .get_ptr(key)
            .is_none_or(|owner| unsafe { *owner } != snapshot.incarnation)
    {
        return false;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.incarnation == snapshot.incarnation;
    if owned {
        current.meta = snapshot.meta;
        current.trace_id = snapshot.trace_id;
        let mut i = 0;
        while i < 6 {
            unsafe {
                current
                    .mac
                    .as_mut_ptr()
                    .add(i)
                    .write_volatile(snapshot.mac.as_ptr().add(i).read_volatile())
            };
            i += 1;
        }
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    owned
}

/// A fresh SYN becomes pending-reuse eligible only after both redirect
/// publications are complete. Native and incomplete decisions retain flag zero.
#[inline(always)]
pub fn commit_tcp_intercept(key: &TuplesKey, syn_isn: u32, incarnation: u64) -> bool {
    if key.l4proto != crate::transport::IPPROTO_TCP
        || incarnation == 0
        || tuple_retiring(key)
        || TCP_PUBLISHING
            .get_ptr(key)
            .is_none_or(|owner| unsafe { *owner } != incarnation)
    {
        return false;
    }
    let Some(handoff) = crate::flow::handoff_identity(key) else {
        return false;
    };
    let Some(redirect) =
        crate::flow::redirect_identity(&honk_ebpf_common::RedirectTuple::from_tuples(key))
    else {
        return false;
    };
    if handoff.incarnation != incarnation
        || redirect.incarnation != incarnation
        || handoff.decision_token != 0
        || redirect.decision_token != 0
    {
        return false;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.incarnation == incarnation
        && current.tcp_syn_isn == syn_isn
        && current.tcp_syn_flags == 0
        && (unsafe { current.meta.raw } & honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED != 0);
    if owned {
        current.tcp_syn_flags = TCP_SYN_ORIGINAL_INTERCEPT;
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    owned
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_tcp_seen`].
#[inline(always)]
pub fn mark_tcp_seen(
    key: &TuplesKey,
    tcph: &TcpHdr,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
    trace_id: u32,
    syn: &TcpPublisher,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);
    args.trace_id = trace_id;
    if is_new_tcp_connection(tcph) == (syn.syn == TcpSyn::NonSyn) {
        return None;
    }
    let mut expected_incarnation = 0;
    if syn.syn != TcpSyn::NonSyn {
        if !syn.is_fresh() && args.has_routing() {
            return None;
        }
        args.incarnation = syn.incarnation;
        args.tcp_syn_isn = u32::from_be_bytes(tcph.seq);
        expected_incarnation = syn.expected_incarnation;
    }

    let key_ptr: *const TuplesKey = key;
    let args_ptr: *mut ConntrackArgs = args;
    let result = __mark_tcp_seen(
        key_ptr,
        syn.syn,
        tcph.fin() != 0 || tcph.rst() != 0,
        args_ptr,
        expected_incarnation,
    );
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}
