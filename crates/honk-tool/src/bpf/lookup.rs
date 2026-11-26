//! Cross-map tuple and domain-bitmap correlation for `honk-tool bpf lookup`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use honk_ebpf_common::conn::{ConnState, TCP_SYN_ORIGINAL_INTERCEPT, TcpState, UdpDecisionState};
use honk_ebpf_common::redirect_need::{DomainRouting, RoutingHandoffEntry, TuplesKey};
use honk_ebpf_common::{
    FlowMapValue, OutboundIndex, ROUTING_FACT_CAPACITY, ROUTING_META_FLAG_OFFLOAD,
    ROUTING_META_FLAG_PUBLISHED, ROUTING_META_FLAG_WAN_USERSPACE, RedirectEntry, RedirectTuple,
    RoutingPolicyDescriptor,
};

use crate::json::{JsonBuf, write_stdout};

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<FlowMapValue<[u8; 72]>>() == size_of::<FlowMapValue<ConnState>>());
    assert!(
        offset_of!(FlowMapValue<[u8; 72]>, value) == offset_of!(FlowMapValue<ConnState>, value)
    );
    assert!(size_of::<FlowMapValue<[u8; 40]>>() == size_of::<FlowMapValue<RedirectEntry>>());
    assert!(
        offset_of!(FlowMapValue<[u8; 40]>, value) == offset_of!(FlowMapValue<RedirectEntry>, value)
    );
    assert!(size_of::<FlowMapValue<[u8; 72]>>() == size_of::<FlowMapValue<RoutingHandoffEntry>>());
    assert!(
        offset_of!(FlowMapValue<[u8; 72]>, value)
            == offset_of!(FlowMapValue<RoutingHandoffEntry>, value)
    );
    assert!(size_of::<TuplesKey>() == 40);
    assert!(size_of::<RedirectTuple>() == 40);
    assert!(size_of::<DomainRouting>() == 32);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BpfProto {
    Tcp,
    Udp,
}

impl BpfProto {
    pub fn iana(self) -> u8 {
        match self {
            Self::Tcp => libc::IPPROTO_TCP as u8,
            Self::Udp => libc::IPPROTO_UDP as u8,
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct LookupArgs {
    /// Match tuples where src or dst equals IP, and query IP in domain-routing.
    #[arg(long, conflicts_with_all = ["sip", "dip"])]
    pub ip: Option<IpAddr>,
    /// Match tuples with this source IP.
    #[arg(long)]
    pub sip: Option<IpAddr>,
    /// Match tuples with this destination IP, and query it in domain-routing.
    #[arg(long)]
    pub dip: Option<IpAddr>,
    /// Match tuples with this source port.
    #[arg(long)]
    pub sport: Option<u16>,
    /// Match tuples with this destination port.
    #[arg(long)]
    pub dport: Option<u16>,
    /// Match tuples with this layer-4 protocol.
    #[arg(long, value_enum)]
    pub proto: Option<BpfProto>,
    /// Maximum correlated flows to print (0 = all).
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// BPF pin root.
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub pin_root: PathBuf,
    /// Output machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FlowFilter {
    pub ip: Option<IpAddr>,
    pub sip: Option<IpAddr>,
    pub dip: Option<IpAddr>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub proto: Option<BpfProto>,
    pub limit: usize,
}

impl FlowFilter {
    pub fn from_args(args: &LookupArgs) -> anyhow::Result<Self> {
        anyhow::ensure!(
            args.ip.is_some() || args.sip.is_some() || args.dip.is_some(),
            "specify at least one of --ip, --sip, or --dip"
        );
        Ok(Self {
            ip: args.ip.as_ref().map(IpAddr::to_canonical),
            sip: args.sip.as_ref().map(IpAddr::to_canonical),
            dip: args.dip.as_ref().map(IpAddr::to_canonical),
            sport: args.sport,
            dport: args.dport,
            proto: args.proto,
            limit: args.limit,
        })
    }

    fn matches(&self, tuple: &FlowTuple) -> bool {
        let src_ip = tuple.src_ip.to_canonical();
        let dst_ip = tuple.dst_ip.to_canonical();
        if let Some(ip) = self.ip.as_ref().map(IpAddr::to_canonical)
            && src_ip != ip
            && dst_ip != ip
        {
            return false;
        }
        if let Some(sip) = self.sip.as_ref().map(IpAddr::to_canonical)
            && src_ip != sip
        {
            return false;
        }
        if let Some(dip) = self.dip.as_ref().map(IpAddr::to_canonical)
            && dst_ip != dip
        {
            return false;
        }
        if let Some(sport) = self.sport
            && tuple.src_port != sport
        {
            return false;
        }
        if let Some(dport) = self.dport
            && tuple.dst_port != dport
        {
            return false;
        }
        if let Some(proto) = self.proto
            && tuple.l4proto != proto.iana()
        {
            return false;
        }
        true
    }
}

pub enum DomainSnapshot<'a> {
    Unpublished,
    Published {
        descriptor: RoutingPolicyDescriptor,
        entries: &'a [([u8; 16], [u8; 32])],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FlowTuple {
    pub l4proto: u8,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FlowTuple {
    pub fn proto_name(&self) -> &'static str {
        match self.l4proto {
            6 => "tcp",
            17 => "udp",
            _ => "other",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainEntryState {
    Unpublished,
    Absent,
    KnownZero,
    Matched(Vec<u32>),
}

impl DomainEntryState {
    pub fn status_str(&self) -> &'static str {
        match self {
            Self::Unpublished => "unpublished",
            Self::Absent => "absent",
            Self::KnownZero => "known_zero",
            Self::Matched(_) => "matched",
        }
    }

    pub fn predicates(&self) -> &[u32] {
        match self {
            Self::Matched(bits) => bits,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainIpCorrelation {
    pub ip: IpAddr,
    pub state: DomainEntryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedConnState {
    pub wan_ingress: bool,
    pub state_raw: u8,
    pub original_intercept: bool,
    pub decision_token: u32,
    pub last_seen_ns: u64,
    pub published: bool,
    pub offload: bool,
    pub wan_userspace: bool,
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
    pub dscp: u8,
    pub pid: u32,
    pub pname: String,
    pub trace_id: u32,
    pub incarnation: u64,
    pub tcp_syn_isn: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRedirect {
    pub last_seen_ns: u64,
    pub from_wan: bool,
    pub outbound: u8,
    pub ifindex: u32,
    pub decision_token: u32,
    pub incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedHandoff {
    pub last_seen_ns: u64,
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
    pub dscp: u8,
    pub pid: u32,
    pub pname: String,
    pub decision_token: u32,
    pub routing_generation: u64,
    pub trace_id: u32,
    pub incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelatedFlow {
    pub tuple: FlowTuple,
    pub disposition: &'static str,
    pub explanation: &'static str,
    pub anomalies: Vec<&'static str>,
    pub domain_state: DomainEntryState,
    pub conn_state: Option<DecodedConnState>,
    pub redirect_track: Option<DecodedRedirect>,
    pub routing_handoff: Option<DecodedHandoff>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationReport {
    pub policy_published: bool,
    pub policy_generation: Option<u64>,
    pub policy_slot: Option<u32>,
    pub policy_features: Option<u32>,
    pub domain_lookups: Vec<DomainIpCorrelation>,
    pub total_matched_flows: usize,
    pub flows: Vec<CorrelatedFlow>,
}

pub fn run(args: LookupArgs) -> anyhow::Result<()> {
    let filter = FlowFilter::from_args(&args)?;
    let domain_policy = super::try_open_domain_policy(&args.pin_root)?;

    let conn_entries = super::flow_entries::<[u8; 40], [u8; 72]>(&args.pin_root, "CONN_STATE_MAP")?;
    let redirect_entries =
        super::flow_entries::<[u8; 40], [u8; 40]>(&args.pin_root, "REDIRECT_TRACK")?;
    let handoff_entries =
        super::flow_entries::<[u8; 40], [u8; 72]>(&args.pin_root, "ROUTING_HANDOFF_MAP")?;

    let mut target_ips = initial_domain_ips(&filter);
    collect_matched_dst_ips(
        &filter,
        &mut target_ips,
        conn_entries
            .iter()
            .map(|(k, _)| k)
            .chain(redirect_entries.iter().map(|(k, _)| k))
            .chain(handoff_entries.iter().map(|(k, _)| k)),
    );

    let mut fetched_domain_entries = Vec::new();
    let domain_snapshot = match &domain_policy {
        None => DomainSnapshot::Unpublished,
        Some((descriptor, fd)) => {
            use std::os::fd::AsRawFd as _;
            for &ip in &target_ips {
                let key = encode_ip_key(ip);
                let mut val = [0u8; 32];
                if super::map_lookup(fd.as_raw_fd(), &key, &mut val)? {
                    fetched_domain_entries.push((key, val));
                }
            }
            DomainSnapshot::Published {
                descriptor: *descriptor,
                entries: &fetched_domain_entries,
            }
        }
    };

    let report = correlate_payload_records(
        &filter,
        domain_snapshot,
        &conn_entries,
        &redirect_entries,
        &handoff_entries,
    );
    let rendered = if args.json {
        render_json(&report)
    } else {
        render_text(&report)
    };
    write_stdout(&rendered)
}

#[cfg(test)]
pub fn correlate_wire_records(
    filter: &FlowFilter,
    domain: DomainSnapshot<'_>,
    conn_wire: &[([u8; 40], [u8; 80])],
    redirect_wire: &[([u8; 40], [u8; 48])],
    handoff_wire: &[([u8; 40], [u8; 80])],
) -> CorrelationReport {
    let conn: Vec<([u8; 40], [u8; 72])> = conn_wire
        .iter()
        .map(|(k, v)| (*k, v[8..80].try_into().unwrap()))
        .collect();
    let redirect: Vec<([u8; 40], [u8; 40])> = redirect_wire
        .iter()
        .map(|(k, v)| (*k, v[8..48].try_into().unwrap()))
        .collect();
    let handoff: Vec<([u8; 40], [u8; 72])> = handoff_wire
        .iter()
        .map(|(k, v)| (*k, v[8..80].try_into().unwrap()))
        .collect();
    correlate_payload_records(filter, domain, &conn, &redirect, &handoff)
}

pub fn correlate_payload_records(
    filter: &FlowFilter,
    domain: DomainSnapshot<'_>,
    conn_records: &[([u8; 40], [u8; 72])],
    redirect_records: &[([u8; 40], [u8; 40])],
    handoff_records: &[([u8; 40], [u8; 72])],
) -> CorrelationReport {
    #[derive(Default)]
    struct Bucket {
        conn: Option<DecodedConnState>,
        redirect: Option<DecodedRedirect>,
        handoff: Option<DecodedHandoff>,
    }

    let mut buckets: BTreeMap<FlowTuple, Bucket> = BTreeMap::new();
    for (key, payload) in conn_records {
        let tuple = decode_tuple_key(key);
        if filter.matches(&tuple) {
            buckets.entry(tuple).or_default().conn = Some(decode_conn_payload(payload));
        }
    }
    for (key, payload) in redirect_records {
        let tuple = decode_tuple_key(key);
        if filter.matches(&tuple) {
            buckets.entry(tuple).or_default().redirect = Some(decode_redirect_payload(payload));
        }
    }
    for (key, payload) in handoff_records {
        let tuple = decode_tuple_key(key);
        if filter.matches(&tuple) {
            buckets.entry(tuple).or_default().handoff = Some(decode_handoff_payload(payload));
        }
    }

    let mut target_ips = initial_domain_ips(filter);
    for tuple in buckets.keys() {
        if !target_ips.contains(&tuple.dst_ip) {
            target_ips.push(tuple.dst_ip);
        }
    }

    let (policy_published, policy_generation, policy_slot, policy_features, domain_entries) =
        match domain {
            DomainSnapshot::Unpublished => (false, None, None, None, &[][..]),
            DomainSnapshot::Published {
                descriptor,
                entries,
            } => (
                true,
                Some(descriptor.generation),
                Some(descriptor.slot),
                Some(descriptor.features),
                entries,
            ),
        };

    let lookup_domain_ip = |ip: IpAddr| -> DomainEntryState {
        if !policy_published {
            return DomainEntryState::Unpublished;
        }
        let wanted = encode_ip_key(ip);
        match domain_entries.iter().find(|(k, _)| *k == wanted) {
            None => DomainEntryState::Absent,
            Some((_, raw)) => {
                let bits = decode_domain_bitmap(raw);
                if bits.is_empty() {
                    DomainEntryState::KnownZero
                } else {
                    DomainEntryState::Matched(bits)
                }
            }
        }
    };

    let domain_lookups: Vec<DomainIpCorrelation> = target_ips
        .iter()
        .map(|&ip| DomainIpCorrelation {
            ip,
            state: lookup_domain_ip(ip),
        })
        .collect();

    let total_matched_flows = buckets.len();
    let max_flows = if filter.limit == 0 {
        total_matched_flows
    } else {
        filter.limit
    };

    let mut flows = Vec::with_capacity(total_matched_flows.min(max_flows));
    for (tuple, bucket) in buckets.into_iter().take(max_flows) {
        let (disposition, explanation) =
            classify_disposition(&tuple, &bucket.conn, &bucket.redirect, &bucket.handoff);
        let anomalies = detect_anomalies(&tuple, &bucket.conn, &bucket.redirect, &bucket.handoff);
        let domain_state = lookup_domain_ip(tuple.dst_ip);
        flows.push(CorrelatedFlow {
            tuple,
            disposition,
            explanation,
            anomalies,
            domain_state,
            conn_state: bucket.conn,
            redirect_track: bucket.redirect,
            routing_handoff: bucket.handoff,
        });
    }

    CorrelationReport {
        policy_published,
        policy_generation,
        policy_slot,
        policy_features,
        domain_lookups,
        total_matched_flows,
        flows,
    }
}

fn initial_domain_ips(filter: &FlowFilter) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Some(ip) = filter.ip.as_ref().map(IpAddr::to_canonical) {
        ips.push(ip);
    }
    if let Some(dip) = filter.dip.as_ref().map(IpAddr::to_canonical)
        && !ips.contains(&dip)
    {
        ips.push(dip);
    }
    ips
}

fn collect_matched_dst_ips<'a>(
    filter: &FlowFilter,
    ips: &mut Vec<IpAddr>,
    keys: impl Iterator<Item = &'a [u8; 40]>,
) {
    for raw in keys {
        let tuple = decode_tuple_key(raw);
        if filter.matches(&tuple) && !ips.contains(&tuple.dst_ip) {
            ips.push(tuple.dst_ip);
        }
    }
}

pub fn encode_ip_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3],
            ]
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn decode_ip_key(b: &[u8; 16]) -> IpAddr {
    if b[..10] == [0; 10] && b[10] == 0xff && b[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*b))
    }
}

pub fn decode_tuple_key(b: &[u8; 40]) -> FlowTuple {
    let src_bytes: [u8; 16] = b[0..16].try_into().unwrap();
    let dst_bytes: [u8; 16] = b[16..32].try_into().unwrap();
    FlowTuple {
        src_ip: decode_ip_key(&src_bytes),
        dst_ip: decode_ip_key(&dst_bytes),
        src_port: u16::from_ne_bytes([b[32], b[33]]),
        dst_port: u16::from_ne_bytes([b[34], b[35]]),
        l4proto: b[36],
    }
}

pub fn decode_domain_bitmap(b: &[u8; 32]) -> Vec<u32> {
    let mut bits = Vec::new();
    for (word_idx, chunk) in b.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_ne_bytes(*chunk);
        if word == 0 {
            continue;
        }
        for bit in 0..32u32 {
            let idx = (word_idx as u32) * 32 + bit;
            if (idx as usize) < ROUTING_FACT_CAPACITY && (word & (1u32 << bit)) != 0 {
                bits.push(idx);
            }
        }
    }
    bits
}

fn decode_c_comm(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

fn decode_conn_payload(p: &[u8; 72]) -> DecodedConnState {
    let tcp_syn_flags = u16::from_ne_bytes([p[2], p[3]]);
    let meta_raw = u64::from_ne_bytes(p[16..24].try_into().unwrap());
    DecodedConnState {
        wan_ingress: p[0] != 0,
        state_raw: p[1],
        original_intercept: (tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT) != 0,
        decision_token: u32::from_ne_bytes([p[4], p[5], p[6], p[7]]),
        last_seen_ns: u64::from_ne_bytes(p[8..16].try_into().unwrap()),
        published: (meta_raw & ROUTING_META_FLAG_PUBLISHED) != 0,
        offload: (meta_raw & ROUTING_META_FLAG_OFFLOAD) != 0,
        wan_userspace: (meta_raw & ROUTING_META_FLAG_WAN_USERSPACE) != 0,
        outbound: p[16],
        mark: u32::from_ne_bytes([p[17], p[18], p[19], p[20]]),
        must: p[21] != 0,
        dscp: p[22],
        pid: u32::from_ne_bytes([p[48], p[49], p[50], p[51]]),
        pname: decode_c_comm(&p[32..48]),
        trace_id: u32::from_ne_bytes([p[52], p[53], p[54], p[55]]),
        incarnation: u64::from_ne_bytes(p[56..64].try_into().unwrap()),
        tcp_syn_isn: u32::from_ne_bytes([p[64], p[65], p[66], p[67]]),
    }
}

fn decode_redirect_payload(p: &[u8; 40]) -> DecodedRedirect {
    DecodedRedirect {
        last_seen_ns: u64::from_ne_bytes(p[0..8].try_into().unwrap()),
        from_wan: p[20] != 0,
        outbound: p[21],
        ifindex: u32::from_ne_bytes([p[24], p[25], p[26], p[27]]),
        decision_token: u32::from_ne_bytes([p[28], p[29], p[30], p[31]]),
        incarnation: u64::from_ne_bytes(p[32..40].try_into().unwrap()),
    }
}

fn decode_handoff_payload(p: &[u8; 72]) -> DecodedHandoff {
    DecodedHandoff {
        last_seen_ns: u64::from_ne_bytes(p[0..8].try_into().unwrap()),
        mark: u32::from_ne_bytes([p[8], p[9], p[10], p[11]]),
        must: p[12] != 0,
        outbound: p[19],
        pname: decode_c_comm(&p[20..36]),
        pid: u32::from_ne_bytes([p[36], p[37], p[38], p[39]]),
        dscp: p[40],
        decision_token: u32::from_ne_bytes([p[44], p[45], p[46], p[47]]),
        routing_generation: u64::from_ne_bytes(p[48..56].try_into().unwrap()),
        trace_id: u32::from_ne_bytes([p[56], p[57], p[58], p[59]]),
        incarnation: u64::from_ne_bytes(p[64..72].try_into().unwrap()),
    }
}

pub fn outbound_label(outbound: u8) -> String {
    if outbound == OutboundIndex::Direct as u8 {
        "direct".to_owned()
    } else if outbound == OutboundIndex::Block as u8 {
        "block".to_owned()
    } else if outbound == OutboundIndex::MustRules as u8 {
        "must_rules".to_owned()
    } else if outbound == OutboundIndex::ControlPlaneRouting as u8 {
        "control_plane_routing".to_owned()
    } else if outbound == OutboundIndex::LogicalOr as u8 {
        "logical_or".to_owned()
    } else if outbound == OutboundIndex::LogicalAnd as u8 {
        "logical_and".to_owned()
    } else {
        format!("user_group({})", outbound - OutboundIndex::UserBase as u8)
    }
}

fn state_label(l4proto: u8, state_raw: u8) -> &'static str {
    if l4proto == libc::IPPROTO_TCP as u8 {
        if state_raw == TcpState::TcpStateActive as u8 {
            "active"
        } else if state_raw == TcpState::TcpStateClosing as u8 {
            "closing"
        } else {
            "unknown"
        }
    } else if l4proto == libc::IPPROTO_UDP as u8 {
        if state_raw == UdpDecisionState::None as u8 {
            "none"
        } else if state_raw == UdpDecisionState::Preparing as u8 {
            "preparing"
        } else if state_raw == UdpDecisionState::Pending as u8 {
            "pending"
        } else if state_raw == UdpDecisionState::DirectArmed as u8 {
            "direct_armed"
        } else if state_raw == UdpDecisionState::Proxy as u8 {
            "proxy"
        } else if state_raw == UdpDecisionState::Block as u8 {
            "block"
        } else if state_raw == UdpDecisionState::Aborted as u8 {
            "aborted"
        } else {
            "unknown"
        }
    } else {
        "unknown"
    }
}

fn classify_disposition(
    tuple: &FlowTuple,
    conn: &Option<DecodedConnState>,
    redirect: &Option<DecodedRedirect>,
    handoff: &Option<DecodedHandoff>,
) -> (&'static str, &'static str) {
    let direct_idx = OutboundIndex::Direct as u8;
    let block_idx = OutboundIndex::Block as u8;
    let cp_idx = OutboundIndex::ControlPlaneRouting as u8;

    let Some(c) = conn else {
        let stateless_udp = tuple.l4proto == libc::IPPROTO_UDP as u8
            && redirect
                .as_ref()
                .is_none_or(|r| r.decision_token == 0 && r.incarnation == 0)
            && handoff
                .as_ref()
                .is_none_or(|h| h.decision_token == 0 && h.incarnation == 0);
        return if stateless_udp {
            (
                "stateless_userspace_udp",
                "stateless UDP auxiliary state without conn-state (such as port-53 traffic)",
            )
        } else {
            (
                "orphan_auxiliary_state",
                "auxiliary redirect/handoff state present without a matching conn-state entry",
            )
        };
    };

    if c.wan_ingress {
        return (
            "reverse_bypass",
            "reverse-learned conn-state entry; packets pass natively without entering userspace",
        );
    }

    if tuple.l4proto == libc::IPPROTO_UDP as u8 {
        if c.state_raw == UdpDecisionState::Preparing as u8 {
            return (
                "udp_preparing",
                "in-flight UDP claim; packets drop in eBPF until publication finishes",
            );
        }
        if c.state_raw == UdpDecisionState::Aborted as u8 {
            return (
                "udp_aborted",
                "failed unpublished UDP claim; packets drop in eBPF until janitor retirement",
            );
        }
        if c.state_raw == UdpDecisionState::Pending as u8 {
            return (
                "nfqueue_pending",
                "LAN UDP held on NFQUEUE 320 awaiting userspace routing verdict",
            );
        }
        if c.state_raw == UdpDecisionState::DirectArmed as u8 {
            return (
                "nfqueue_direct_armed",
                "NFQUEUE direct verdict armed awaiting queued packet acceptance",
            );
        }
        if c.state_raw == UdpDecisionState::Block as u8 {
            return (
                "kernel_drop_block",
                "UDP flow committed as block; dropped in eBPF (TC_ACT_SHOT) without entering userspace",
            );
        }
        if !c.published {
            return (
                "reverse_bypass",
                "unpublished conn-state entry; packets pass natively without entering userspace",
            );
        }
        if c.state_raw == UdpDecisionState::Proxy as u8 {
            return (
                "userspace_proxy",
                "token-bound LAN UDP flow redirected to userspace outbound group",
            );
        }
        if c.outbound == direct_idx && (c.offload || c.must) && !c.wan_userspace {
            return (
                "native_direct_offload",
                "cached direct offload in eBPF; packets pass natively and never enter userspace",
            );
        }
        if c.outbound == block_idx && redirect.is_none() && handoff.is_none() {
            return (
                "kernel_drop_block",
                "cached block decision; dropped in eBPF (TC_ACT_SHOT) without entering userspace",
            );
        }
        if c.outbound == block_idx {
            return (
                "userspace_reject",
                "redirected to userspace for block rejection",
            );
        }
        if c.outbound == cp_idx {
            return (
                "userspace_control_plane_routing",
                "redirected to userspace control-plane routing for domain sniffing or mode evaluation",
            );
        }
        if c.outbound == direct_idx && c.wan_userspace {
            return (
                "userspace_marked_direct",
                "WAN UDP redirected through userspace to apply configured socket mark",
            );
        }
        return (
            "userspace_proxy",
            "UDP flow redirected to userspace outbound group",
        );
    }

    if !c.published {
        return (
            "reverse_bypass",
            "unpublished conn-state entry; packets pass natively without entering userspace",
        );
    }
    if c.outbound == direct_idx
        && (c.offload || c.must)
        && !c.original_intercept
        && redirect.is_none()
        && handoff.is_none()
    {
        return (
            "native_direct_offload",
            "cached direct offload in eBPF; packets pass natively and never enter userspace",
        );
    }
    if c.outbound == block_idx && !c.original_intercept && redirect.is_none() && handoff.is_none() {
        return (
            "kernel_drop_block",
            "cached block decision; dropped in eBPF (TC_ACT_SHOT) without entering userspace",
        );
    }
    if c.outbound == block_idx {
        return (
            "userspace_reject",
            "redirected to userspace for block rejection",
        );
    }
    if c.outbound == cp_idx {
        return (
            "userspace_control_plane_routing",
            "redirected to userspace control-plane routing for SNI/HTTP sniffing or mode evaluation",
        );
    }
    if c.outbound == direct_idx && c.mark != 0 {
        return (
            "userspace_marked_direct",
            "redirected to userspace to dial with configured direct socket mark",
        );
    }
    (
        "userspace_proxy",
        "TCP flow redirected via dae0/daens to userspace outbound group",
    )
}

fn detect_anomalies(
    tuple: &FlowTuple,
    conn: &Option<DecodedConnState>,
    redirect: &Option<DecodedRedirect>,
    handoff: &Option<DecodedHandoff>,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    let Some(c) = conn else {
        return out;
    };

    let mut incarnations = Vec::with_capacity(3);
    if c.incarnation != 0 {
        incarnations.push(c.incarnation);
    }
    if let Some(r) = redirect
        && r.incarnation != 0
    {
        incarnations.push(r.incarnation);
    }
    if let Some(h) = handoff
        && h.incarnation != 0
    {
        incarnations.push(h.incarnation);
    }
    if let Some(&first) = incarnations.first()
        && incarnations.iter().any(|&inc| inc != first)
    {
        out.push("incarnation_mismatch");
    }

    if tuple.l4proto == libc::IPPROTO_UDP as u8 && c.decision_token != 0 {
        let redirect_mismatch = redirect
            .as_ref()
            .is_some_and(|r| r.decision_token != c.decision_token);
        let handoff_mismatch = handoff
            .as_ref()
            .is_some_and(|h| h.decision_token != c.decision_token);
        if redirect_mismatch || handoff_mismatch {
            out.push("token_mismatch");
        }
        if c.state_raw == UdpDecisionState::Pending as u8 {
            if redirect.is_none() {
                out.push("missing_redirect_track");
            }
            if handoff.is_none() {
                out.push("missing_routing_handoff");
            }
        }
    }

    if tuple.l4proto == libc::IPPROTO_TCP as u8 && c.original_intercept {
        if redirect.is_none() {
            out.push("missing_redirect_track");
        }
        if handoff.is_none() {
            out.push("missing_routing_handoff");
        }
    }

    out
}

fn render_text(report: &CorrelationReport) -> String {
    let mut out = String::new();
    if let (true, Some(generation), Some(slot), Some(features)) = (
        report.policy_published,
        report.policy_generation,
        report.policy_slot,
        report.policy_features,
    ) {
        let _ = writeln!(
            out,
            "routing_policy: published generation={generation} slot={slot} features={features:#x}"
        );
    } else {
        let _ = writeln!(out, "routing_policy: unpublished");
    }

    for dom in &report.domain_lookups {
        match &dom.state {
            DomainEntryState::Unpublished => {
                let _ = writeln!(out, "domain_routing {}: unpublished", dom.ip);
            }
            DomainEntryState::Absent => {
                let _ = writeln!(out, "domain_routing {}: absent", dom.ip);
            }
            DomainEntryState::KnownZero => {
                let _ = writeln!(out, "domain_routing {}: known_zero predicates=[]", dom.ip);
            }
            DomainEntryState::Matched(bits) => {
                let _ = writeln!(
                    out,
                    "domain_routing {}: matched predicates={bits:?}",
                    dom.ip
                );
            }
        }
    }

    if report.flows.is_empty() {
        let _ = writeln!(
            out,
            "disposition: no_flow_state (no matching tuple in conn-state, redirect-track, or routing-handoff; traffic either bypassed TC hooks/special/mark/local-socket checks, dropped before publication such as dead-outbound TC_ACT_SHOT or new_flow_rate_limited, used per-packet must UDP/53, or already expired)"
        );
        return out;
    }

    for flow in &report.flows {
        let _ = writeln!(
            out,
            "flow {} {}:{} -> {}:{} disposition={}",
            flow.tuple.proto_name(),
            flow.tuple.src_ip,
            flow.tuple.src_port,
            flow.tuple.dst_ip,
            flow.tuple.dst_port,
            flow.disposition
        );
        let _ = writeln!(out, "  explanation: {}", flow.explanation);
        if !flow.anomalies.is_empty() {
            let _ = writeln!(out, "  anomalies: {}", flow.anomalies.join(", "));
        }
        if let Some(c) = &flow.conn_state {
            let _ = write!(
                out,
                "  conn_state: state={} out={}({}) mark={:#x} must={} published={} offload={} wan_userspace={} wan_ingress={} orig_intercept={} token={:#x} inc={} trace={} seen={}",
                state_label(flow.tuple.l4proto, c.state_raw),
                c.outbound,
                outbound_label(c.outbound),
                c.mark,
                c.must,
                c.published,
                c.offload,
                c.wan_userspace,
                c.wan_ingress,
                c.original_intercept,
                c.decision_token,
                c.incarnation,
                c.trace_id,
                c.last_seen_ns
            );
            if c.pid != 0 || !c.pname.is_empty() {
                let _ = write!(out, " pid={} pname={:?}", c.pid, c.pname);
            }
            out.push('\n');
        }
        if let Some(r) = &flow.redirect_track {
            let _ = writeln!(
                out,
                "  redirect_track: out={}({}) from_wan={} ifindex={} token={:#x} inc={} seen={}",
                r.outbound,
                outbound_label(r.outbound),
                r.from_wan,
                r.ifindex,
                r.decision_token,
                r.incarnation,
                r.last_seen_ns
            );
        }
        if let Some(h) = &flow.routing_handoff {
            let _ = write!(
                out,
                "  routing_handoff: out={}({}) mark={:#x} must={} dscp={} token={:#x} generation={} inc={} trace={} seen={}",
                h.outbound,
                outbound_label(h.outbound),
                h.mark,
                h.must,
                h.dscp,
                h.decision_token,
                h.routing_generation,
                h.incarnation,
                h.trace_id,
                h.last_seen_ns
            );
            if h.pid != 0 || !h.pname.is_empty() {
                let _ = write!(out, " pid={} pname={:?}", h.pid, h.pname);
            }
            out.push('\n');
        }
    }
    let _ = writeln!(
        out,
        "-- {}/{} correlated flow(s)",
        report.flows.len(),
        report.total_matched_flows
    );
    out
}

pub fn render_json(report: &CorrelationReport) -> String {
    let mut b = JsonBuf::new();
    b.raw("{");
    let mut f = true;

    b.key(&mut f, "routing_policy");
    b.raw("{");
    let mut pf = true;
    b.key(&mut pf, "published");
    b.bool(report.policy_published);
    b.key(&mut pf, "generation");
    match report.policy_generation {
        Some(g) => b.uint(g),
        None => b.null(),
    }
    b.key(&mut pf, "slot");
    b.opt_u32(report.policy_slot);
    b.key(&mut pf, "features");
    b.opt_u32(report.policy_features);
    b.raw("}");

    b.key(&mut f, "domain_routing");
    b.raw("[");
    for (i, dom) in report.domain_lookups.iter().enumerate() {
        if i > 0 {
            b.raw(",");
        }
        b.raw("{");
        let mut df = true;
        b.key(&mut df, "ip");
        b.str(&dom.ip.to_string());
        b.key(&mut df, "status");
        b.str(dom.state.status_str());
        b.key(&mut df, "predicates");
        b.u32_slice(dom.state.predicates());
        b.raw("}");
    }
    b.raw("]");

    b.key(&mut f, "disposition");
    if report.flows.is_empty() {
        b.str("no_flow_state");
    } else if report.flows.len() == 1 {
        b.str(report.flows[0].disposition);
    } else {
        b.str("multiple_flows");
    }

    b.key(&mut f, "total_matched_flows");
    b.usize(report.total_matched_flows);

    b.key(&mut f, "flows");
    b.raw("[");
    for (i, flow) in report.flows.iter().enumerate() {
        if i > 0 {
            b.raw(",");
        }
        b.raw("{");
        let mut ff = true;
        b.key(&mut ff, "proto");
        b.str(flow.tuple.proto_name());
        b.key(&mut ff, "src_ip");
        b.str(&flow.tuple.src_ip.to_string());
        b.key(&mut ff, "src_port");
        b.uint(flow.tuple.src_port);
        b.key(&mut ff, "dst_ip");
        b.str(&flow.tuple.dst_ip.to_string());
        b.key(&mut ff, "dst_port");
        b.uint(flow.tuple.dst_port);
        b.key(&mut ff, "disposition");
        b.str(flow.disposition);
        b.key(&mut ff, "explanation");
        b.str(flow.explanation);
        b.key(&mut ff, "anomalies");
        b.str_slice(&flow.anomalies);
        b.key(&mut ff, "domain_status");
        b.str(flow.domain_state.status_str());
        b.key(&mut ff, "domain_predicates");
        b.u32_slice(flow.domain_state.predicates());

        b.key(&mut ff, "conn_state");
        match &flow.conn_state {
            None => b.null(),
            Some(c) => {
                b.raw("{");
                let mut cf = true;
                b.key(&mut cf, "state");
                b.str(state_label(flow.tuple.l4proto, c.state_raw));
                b.key(&mut cf, "outbound");
                b.uint(c.outbound);
                b.key(&mut cf, "outbound_role");
                b.str(&outbound_label(c.outbound));
                b.key(&mut cf, "mark");
                b.uint(c.mark);
                b.key(&mut cf, "must");
                b.bool(c.must);
                b.key(&mut cf, "dscp");
                b.uint(c.dscp);
                b.key(&mut cf, "published");
                b.bool(c.published);
                b.key(&mut cf, "offload");
                b.bool(c.offload);
                b.key(&mut cf, "wan_userspace");
                b.bool(c.wan_userspace);
                b.key(&mut cf, "wan_ingress");
                b.bool(c.wan_ingress);
                b.key(&mut cf, "original_intercept");
                b.bool(c.original_intercept);
                b.key(&mut cf, "decision_token");
                b.uint(c.decision_token);
                b.key(&mut cf, "incarnation");
                b.uint(c.incarnation);
                b.key(&mut cf, "trace_id");
                b.uint(c.trace_id);
                b.key(&mut cf, "pid");
                b.uint(c.pid);
                b.key(&mut cf, "pname");
                b.str(&c.pname);
                b.key(&mut cf, "last_seen_ns");
                b.uint(c.last_seen_ns);
                b.raw("}");
            }
        }

        b.key(&mut ff, "redirect_track");
        match &flow.redirect_track {
            None => b.null(),
            Some(r) => {
                b.raw("{");
                let mut rf = true;
                b.key(&mut rf, "outbound");
                b.uint(r.outbound);
                b.key(&mut rf, "outbound_role");
                b.str(&outbound_label(r.outbound));
                b.key(&mut rf, "from_wan");
                b.bool(r.from_wan);
                b.key(&mut rf, "ifindex");
                b.uint(r.ifindex);
                b.key(&mut rf, "decision_token");
                b.uint(r.decision_token);
                b.key(&mut rf, "incarnation");
                b.uint(r.incarnation);
                b.key(&mut rf, "last_seen_ns");
                b.uint(r.last_seen_ns);
                b.raw("}");
            }
        }

        b.key(&mut ff, "routing_handoff");
        match &flow.routing_handoff {
            None => b.null(),
            Some(h) => {
                b.raw("{");
                let mut hf = true;
                b.key(&mut hf, "outbound");
                b.uint(h.outbound);
                b.key(&mut hf, "outbound_role");
                b.str(&outbound_label(h.outbound));
                b.key(&mut hf, "mark");
                b.uint(h.mark);
                b.key(&mut hf, "must");
                b.bool(h.must);
                b.key(&mut hf, "dscp");
                b.uint(h.dscp);
                b.key(&mut hf, "decision_token");
                b.uint(h.decision_token);
                b.key(&mut hf, "routing_generation");
                b.uint(h.routing_generation);
                b.key(&mut hf, "incarnation");
                b.uint(h.incarnation);
                b.key(&mut hf, "trace_id");
                b.uint(h.trace_id);
                b.key(&mut hf, "pid");
                b.uint(h.pid);
                b.key(&mut hf, "pname");
                b.str(&h.pname);
                b.key(&mut hf, "last_seen_ns");
                b.uint(h.last_seen_ns);
                b.raw("}");
            }
        }

        b.raw("}");
    }
    b.raw("]}");
    b.finish()
}
