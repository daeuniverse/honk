//! Compiles user-space routing rules into eBPF MatchSet arrays and populates
//! the BPF maps for hardware-accelerated packet classification.
//!
//! Mirrors the Go `routing_matcher_builder.go` (`control/routing_matcher_builder.go`)
//! in dae-core: each rule is split into type-specific `match_set` entries, and
//! IP/MAC prefixes are stored in LPM trie maps while domain rules are evaluated
//! in userspace (domain is not available during eBPF TCP SYN classification).

use crate::ebpf::{EbpfBackend, LpmKeepSet, maps};
use crate::routing::CompiledRoute;
use honk_config::types::DialMode;
use honk_ebpf_common::*;
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

/// Global cache of domain routing bitmaps from the last eBPF push.
/// Keyed by rule name. DNS snooping reads this to push resolved IPs.
pub static DOMAIN_BITMAPS: LazyLock<parking_lot::RwLock<HashMap<String, Vec<DomainRouting>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(HashMap::new()));

/// Generation counter incremented on each eBPF routing push.
/// Domain route caches use this to detect stale entries after rule reload.
pub static DOMAIN_BITMAPS_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// A single condition present in a compiled route.
#[derive(Debug)]
struct Condition<'a> {
    /// dae `!matcher(...)`: the kernel inverts this match_set's result
    /// (`good_subrule == match_not` fails the rule).
    not: bool,
    kind: ConditionKind<'a>,
}

#[derive(Debug)]
enum ConditionKind<'a> {
    /// Domain conditions are represented in eBPF as a `DomainSet`
    /// placeholder; DNS snooping populates the actual IP bitmap.
    Domain,
    SourceIp {
        nets: &'a [ipnet::IpNet],
    },
    Ip {
        nets: &'a [ipnet::IpNet],
    },
    Mac {
        macs: &'a [String],
    },
    SourcePort {
        ranges: &'a [crate::routing::PortRange],
    },
    Port {
        ranges: &'a [crate::routing::PortRange],
    },
    Protocol {
        protocols: &'a [String],
    },
    IpVersion {
        versions: &'a [u8],
    },
    Dscp {
        values: &'a [u8],
    },
    ProcessName {
        names: &'a [String],
    },
}

/// Result of pushing routing rules to eBPF.
#[derive(Debug, Clone)]
pub struct RoutingPushResult {
    /// Number of MatchSet entries produced.
    pub match_set_count: usize,
    /// Domain routing bitmaps keyed by outbound name.
    /// DNS snooping uses these to push resolved IPs into DOMAIN_ROUTING_MAP.
    pub domain_bitmaps: HashMap<String, Vec<DomainRouting>>,
}

/// LPM update plan for one ruleset generation.
///
/// Entries are merged by their raw 20-byte key so that several rules
/// referencing the same prefix OR their rule-index bits together before the
/// entries reach the backend.  The real backend cannot read-modify-write an
/// LPM trie (a lookup returns the longest-prefix *match*, not the exact
/// entry) and therefore overwrites values; without this merge the last rule
/// pushed for a shared prefix would clobber the earlier ones.
#[derive(Debug, Default, Clone)]
struct LpmPushPlan {
    dest: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
    source: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
    mac: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
}

/// Immutable, fully compiled inputs for one routing generation.
///
/// Keeping this value alive with the active generation lets a failed reload
/// replay the exact bytes that were previously accepted, without rebuilding
/// from mutable configuration or geo databases.
#[derive(Debug, Clone)]
pub struct RoutingPushPlan {
    match_sets: Vec<MatchSet>,
    domain_bitmaps: HashMap<String, Vec<DomainRouting>>,
    lpm: LpmPushPlan,
    group_bitmaps: RoutingGroupBitmaps,
    /// Any route references a domain-class matcher (negated or not). Modes
    /// that can re-evaluate a sniffed name must keep direct decisions in
    /// userspace until the destination is domain-judged; the control-plane
    /// mode policy combines this bit with `dial_mode`.
    pub has_domain_rules: bool,
}

impl RoutingPushPlan {
    pub fn result(&self) -> RoutingPushResult {
        RoutingPushResult {
            match_set_count: self.match_sets.len(),
            domain_bitmaps: self.domain_bitmaps.clone(),
        }
    }

    pub fn semantically_eq(&self, other: &Self) -> bool {
        self.has_domain_rules == other.has_domain_rules
            && self.group_bitmaps == other.group_bitmaps
            && match_sets_eq(&self.match_sets, &other.match_sets)
            && domain_bitmaps_eq(&self.domain_bitmaps, &other.domain_bitmaps)
            && lpm_plans_eq(&self.lpm, &other.lpm)
    }
}
fn match_sets_eq(left: &[MatchSet], right: &[MatchSet]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.not == right.not
                && left.match_type == right.match_type
                && left.outbound == right.outbound
                && left.must == right.must
                && left.mark == right.mark
                && match_value_eq(left, right)
        })
}

fn match_value_eq(left: &MatchSet, right: &MatchSet) -> bool {
    match MatchType::from_u8(left.match_type) {
        Some(
            MatchType::DomainSet
            | MatchType::IpSet
            | MatchType::SourceIpSet
            | MatchType::Mac
            | MatchType::Fallback,
        ) => true,
        Some(MatchType::Port | MatchType::SourcePort) => unsafe {
            let left = left.value.port_range;
            let right = right.value.port_range;
            left.port_start == right.port_start && left.port_end == right.port_end
        },
        Some(MatchType::L4Proto) => unsafe {
            left.value.l4proto_type as u8 == right.value.l4proto_type as u8
        },
        Some(MatchType::IpVersion) => unsafe {
            left.value.ip_version as u8 == right.value.ip_version as u8
        },
        Some(MatchType::ProcessName) => unsafe { left.value.pname == right.value.pname },
        Some(MatchType::Dscp) => unsafe { left.value.dscp == right.value.dscp },
        Some(MatchType::MustRules | MatchType::Upstream | MatchType::QType) | None => false,
    }
}

fn domain_bitmaps_eq(
    left: &HashMap<String, Vec<DomainRouting>>,
    right: &HashMap<String, Vec<DomainRouting>>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(name, left)| {
            right.get(name).is_some_and(|right| {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| left.bitmap == right.bitmap)
            })
        })
}

fn lpm_plans_eq(left: &LpmPushPlan, right: &LpmPushPlan) -> bool {
    lpm_maps_eq(&left.dest, &right.dest)
        && lpm_maps_eq(&left.source, &right.source)
        && lpm_maps_eq(&left.mac, &right.mac)
}

fn lpm_maps_eq(
    left: &HashMap<[u8; 20], (LpmKey, DomainRouting)>,
    right: &HashMap<[u8; 20], (LpmKey, DomainRouting)>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(raw, (left_key, left_bitmap))| {
            right.get(raw).is_some_and(|(right_key, right_bitmap)| {
                left_key.prefix_len == right_key.prefix_len
                    && left_key.data == right_key.data
                    && left_bitmap.bitmap == right_bitmap.bitmap
            })
        })
}

impl LpmPushPlan {
    fn insert(
        map: &mut HashMap<[u8; 20], (LpmKey, DomainRouting)>,
        key: LpmKey,
        bitmap: DomainRouting,
    ) {
        map.entry(maps::lpm_key_bytes(&key))
            .and_modify(|(_, cur)| {
                for (w, b) in cur.bitmap.iter_mut().zip(bitmap.bitmap.iter()) {
                    *w |= b;
                }
            })
            .or_insert((key, bitmap));
    }

    fn add_dest(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.dest, key, bitmap);
    }

    fn add_source(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.source, key, bitmap);
    }

    fn add_mac(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.mac, key, bitmap);
    }

    fn merge_generation(
        target: &mut HashMap<[u8; 20], (LpmKey, DomainRouting)>,
        source: &HashMap<[u8; 20], (LpmKey, DomainRouting)>,
        generation: u32,
    ) {
        for (raw, (key, bitmap)) in source {
            let shifted = bitmap.for_generation(generation);
            target
                .entry(*raw)
                .and_modify(|(_, current)| {
                    for (word, value) in current.bitmap.iter_mut().zip(shifted.bitmap) {
                        *word |= value;
                    }
                })
                .or_insert((*key, shifted));
        }
    }

    fn transition(
        active: Option<&Self>,
        active_generation: u32,
        next: &Self,
        next_generation: u32,
    ) -> Self {
        let mut combined = Self::default();
        if let Some(active) = active {
            Self::merge_generation(&mut combined.dest, &active.dest, active_generation);
            Self::merge_generation(&mut combined.source, &active.source, active_generation);
            Self::merge_generation(&mut combined.mac, &active.mac, active_generation);
        }
        Self::merge_generation(&mut combined.dest, &next.dest, next_generation);
        Self::merge_generation(&mut combined.source, &next.source, next_generation);
        Self::merge_generation(&mut combined.mac, &next.mac, next_generation);
        combined
    }

    /// Push complete physical-generation bitmaps. Each value retains the
    /// active bank while preparing the inactive bank, so packet evaluation
    /// cannot observe rule/LPM disagreement before the selector flips.
    fn apply(&self, ebpf: &mut dyn EbpfBackend) -> anyhow::Result<()> {
        for (key, bitmap) in self.dest.values() {
            ebpf.add_dest_lpm_bitmap(key, bitmap)?;
        }
        for (key, bitmap) in self.source.values() {
            ebpf.add_source_lpm_bitmap(key, bitmap)?;
        }
        for (key, bitmap) in self.mac.values() {
            ebpf.add_mac_lpm_bitmap(key, bitmap)?;
        }
        Ok(())
    }

    /// Raw keys needed by either bank during one atomic transition.
    fn keep_set(&self) -> LpmKeepSet {
        LpmKeepSet {
            dest: self.dest.keys().copied().collect(),
            source: self.source.keys().copied().collect(),
            mac: self.mac.keys().copied().collect(),
        }
    }
}

/// Compiles routing rules into eBPF data structures and pushes them
/// to the BPF maps.
pub struct RoutingMatcherBuilder;

impl RoutingMatcherBuilder {
    /// Build MatchSet entries from compiled routing rules and push to eBPF.
    ///
    /// `fallback_outbound` is the configured default outbound (e.g. `direct`).
    /// It is installed as the final `MT_FALLBACK` rule; the eBPF datapath
    /// treats `ControlPlaneRouting` as a logical composition marker, so the
    /// fallback must be a real outbound (Direct, Block, or a user group).
    ///
    /// In `domain++` mode, generic port-based proxy rules are pushed with
    /// `ControlPlaneRouting` as their final outbound so that the userspace
    /// control plane can sniff the domain first.  `domain` and `domain+`
    /// preserve the initial IP-rule decision when no domain decision is
    /// available, so their port rules remain kernel-routable.
    ///
    /// ## Two-phase commit
    ///
    /// Each physical rule bank has four packed metadata entries, one per
    /// `(l4proto × ipversion)` group. Clearing first would expose an empty
    /// generation and fail closed every new flow while a reload is publishing.
    /// Instead we:
    ///
    /// 1. compile the whole ruleset (MatchSets + LPM plan + group bitmaps)
    ///    without touching any map;
    /// 2. fill the inactive `ROUTING_MAP` bank;
    /// 3. prune keys referenced by neither bank, then publish LPM values
    ///    containing both the active and staged generation;
    /// 4. write the staged generation's exploded introspection metadata and
    ///    all four packed `RoutingGroupMeta` entries;
    /// 5. flip the one-slot generation selector only after that bank is
    ///    complete. Physical tail slots are harmless because the packed count
    ///    bounds evaluation; retired LPM keys leave on the next transition.
    ///
    /// The datapath reads the selector once, then one packed group entry. It
    /// therefore evaluates either the complete old generation or the complete
    /// replacement and never observes a mixed count/bitmap pair.
    pub fn compile(
        routes: &[CompiledRoute],
        outbound_name_to_id: &HashMap<String, u8>,
        fallback_outbound: &str,
        dial_mode: DialMode,
    ) -> anyhow::Result<RoutingPushPlan> {
        // Phase 1: compile the ruleset without touching any BPF map.
        // Domain-class rules are scanned over the full (unsorted,
        // uncapped) ruleset: even a rule that never reaches the kernel bank
        // can still re-route a sniffed flow in userspace.
        let has_domain_rules = routes.iter().any(|r| r.has_domain_conditions());
        let mut routes: Vec<&CompiledRoute> = routes.iter().collect();
        routes.sort_by_key(|r| r.priority);

        let mut match_sets: Vec<MatchSet> = Vec::with_capacity(routes.len() * 2);
        let mut domain_bitmaps: HashMap<String, Vec<DomainRouting>> = HashMap::new();
        let mut lpm_plan = LpmPushPlan::default();
        // (l4proto × ipversion) group bitmaps over logical rule indices:
        // bit N of group g is set when the MatchSet at index N within its
        // generation belongs to group g.
        let mut group_bitmaps: RoutingGroupBitmaps =
            [[0; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];

        for route in routes.iter().take(MAX_MATCH_SET_LEN as usize) {
            // Skip rules whose conditions are unsupported in eBPF.
            // Domain/geosite matching is evaluated by DNS snooping: the
            // DomainSet match type is pushed, and resolved IPs are inserted
            // into DOMAIN_ROUTING_MAP so the eBPF fast path can match them.
            if Self::has_unsupported_ebpf_conditions(route)
                || Self::collect_conditions(route).is_empty()
            {
                debug!(
                    "Skipping eBPF push for rule '{}' (unsupported or empty conditions)",
                    route.name
                );
                continue;
            }
            let outbound = outbound_name_to_id
                .get(route.outbound.as_str())
                .copied()
                .unwrap_or(OutboundIndex::Direct as u8);

            // Only domain++ must defer generic proxy rules until userspace
            // can inspect the domain.  `domain` may re-route after a
            // successful reality check, while `domain+` never re-routes;
            // neither needs a control-plane marker for the initial route.
            let punt_to_control_plane = dial_mode == DialMode::DomainPlusPlus
                && !route.ports.is_empty()
                && route.domain_suffixes.is_empty()
                && route.domain_keywords.is_empty()
                && route.geosite_domains.is_empty()
                && route.process_names.is_empty()
                && route.mac_addresses.is_empty()
                && route.dscp_values.is_empty()
                && !route.outbound.eq_ignore_ascii_case("direct")
                && !route.outbound.eq_ignore_ascii_case("block");
            let effective_outbound = if punt_to_control_plane {
                OutboundIndex::ControlPlaneRouting as u8
            } else {
                outbound
            };

            info!(
                "rule '{}' outbound='{}' -> id={} (cp={})",
                route.name, route.outbound, effective_outbound, punt_to_control_plane
            );

            let rule_start = match_sets.len();
            Self::append_rule(
                route,
                effective_outbound,
                route.must,
                route.mark,
                &mut match_sets,
                &mut domain_bitmaps,
                &mut lpm_plan,
            )?;
            // Every MatchSet of this rule's chain shares the same group
            // membership, derived from the chain's L4Proto/IpVersion
            // entries, so the eBPF group pre-filter never splits a chain.
            let group_mask = Self::rule_group_mask(&match_sets[rule_start..]);
            Self::set_group_bits(&mut group_bitmaps, rule_start, match_sets.len(), group_mask);
        }

        // Always install a final fallback entry so unmatched traffic has a
        // defined behavior. The fallback must be a real outbound; using
        // ControlPlaneRouting here is invalid because the eBPF route loop
        // treats it as a logical operator and would leave ctx.result unset,
        // causing the "lan_ingress route fail: -1" drops.
        let fallback_outbound = outbound_name_to_id
            .get(fallback_outbound)
            .copied()
            .unwrap_or(OutboundIndex::Direct as u8);

        // Ensure the fallback fits even if the ruleset is at capacity.
        if match_sets.len() >= MAX_MATCH_SET_LEN as usize {
            warn!(
                "Generated {} match sets exceed eBPF MAX_MATCH_SET_LEN ({}); truncating to make room for fallback",
                match_sets.len(),
                MAX_MATCH_SET_LEN
            );
            match_sets.truncate(MAX_MATCH_SET_LEN as usize - 1);
            // Truncation can cut a rule chain mid-way; drop the group
            // bitmap bits of the removed tail so no group ever skips the
            // fallback slot that reused its index.
            Self::clear_group_bits_from(&mut group_bitmaps, match_sets.len());
        }
        let fallback_idx = match_sets.len();
        match_sets.push(MatchSet {
            value: MatchSetValue { raw: [0; 16] },
            not: 0,
            match_type: MatchType::Fallback as u8,
            outbound: fallback_outbound,
            must: 0,
            mark: 0,
        });
        // The fallback is the terminal rule for every flow: all groups.
        Self::set_group_bits(
            &mut group_bitmaps,
            fallback_idx,
            fallback_idx + 1,
            Self::ALL_GROUPS,
        );

        Ok(RoutingPushPlan {
            match_sets,
            domain_bitmaps,
            lpm: lpm_plan,
            group_bitmaps,
            has_domain_rules,
        })
    }

    pub fn push_plan(
        ebpf: &mut dyn EbpfBackend,
        plan: &RoutingPushPlan,
    ) -> anyhow::Result<RoutingPushResult> {
        Self::push_transition(ebpf, None, plan)
    }

    pub fn push_transition(
        ebpf: &mut dyn EbpfBackend,
        active: Option<&RoutingPushPlan>,
        plan: &RoutingPushPlan,
    ) -> anyhow::Result<RoutingPushResult> {
        let active_generation = ebpf.active_routing_generation()?;
        anyhow::ensure!(
            active_generation < honk_ebpf_common::ROUTING_GENERATION_COUNT as u32,
            "invalid active routing generation {active_generation}"
        );
        let generation = active_generation ^ 1;
        let lpm = LpmPushPlan::transition(
            active.map(|plan| &plan.lpm),
            active_generation,
            &plan.lpm,
            generation,
        );
        ebpf.set_routing_rules(generation, &plan.match_sets)?;
        ebpf.prune_lpm_entries(&lpm.keep_set())?;
        lpm.apply(ebpf)?;
        ebpf.publish_routing_generation(
            generation,
            plan.match_sets.len() as u32,
            &plan.group_bitmaps,
        )?;

        info!(
            "Pushed {} MatchSet entries to eBPF ROUTING_MAP",
            plan.match_sets.len()
        );
        Ok(plan.result())
    }

    pub fn build_and_push(
        ebpf: &mut dyn EbpfBackend,
        routes: &[CompiledRoute],
        outbound_name_to_id: &HashMap<String, u8>,
        fallback_outbound: &str,
        dial_mode: DialMode,
    ) -> anyhow::Result<RoutingPushResult> {
        let plan = Self::compile(routes, outbound_name_to_id, fallback_outbound, dial_mode)?;
        let result = Self::push_plan(ebpf, &plan)?;
        Self::activate_projection(&plan);
        Ok(result)
    }

    pub fn activate_projection(plan: &RoutingPushPlan) {
        let mut domain_bitmaps = DOMAIN_BITMAPS.write();
        *domain_bitmaps = plan.domain_bitmaps.clone();
        DOMAIN_BITMAPS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Split one `CompiledRoute` into type-specific MatchSets and record the
    /// corresponding LPM updates into the push plan (no BPF map writes here).
    fn append_rule(
        route: &CompiledRoute,
        outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
        domain_bitmaps: &mut HashMap<String, Vec<DomainRouting>>,
        lpm_plan: &mut LpmPushPlan,
    ) -> anyhow::Result<()> {
        let conditions = Self::collect_conditions(route);
        let n = conditions.len();

        for (i, cond) in conditions.iter().enumerate() {
            let is_last = i == n - 1;
            let sub_outbound = if is_last {
                outbound
            } else {
                OutboundIndex::LogicalAnd as u8
            };
            let not = cond.not as u8;

            match &cond.kind {
                ConditionKind::SourceIp { nets } => {
                    let idx = match_sets.len() as u32;
                    // Negated LPM matchers still install their entries; the
                    // kernel inverts the lookup result via the not flag.
                    if let Err(e) = Self::plan_source_lpm_routes(lpm_plan, nets, idx) {
                        warn!("SourceIp LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not,
                        match_type: MatchType::SourceIpSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                ConditionKind::Ip { nets } => {
                    let idx = match_sets.len() as u32;
                    if let Err(e) = Self::plan_dest_lpm_routes(lpm_plan, nets, idx) {
                        warn!("DestIp LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not,
                        match_type: MatchType::IpSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                ConditionKind::Mac { macs } => {
                    let idx = match_sets.len() as u32;
                    if let Err(e) = Self::plan_mac_lpm_routes(lpm_plan, macs, idx) {
                        warn!("Mac LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not,
                        match_type: MatchType::Mac as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                ConditionKind::SourcePort { ranges } => {
                    Self::push_port_match_sets(
                        ranges,
                        true,
                        not,
                        sub_outbound,
                        must,
                        mark,
                        match_sets,
                    );
                }
                ConditionKind::Port { ranges } => {
                    Self::push_port_match_sets(
                        ranges,
                        false,
                        not,
                        sub_outbound,
                        must,
                        mark,
                        match_sets,
                    );
                }
                ConditionKind::Protocol { protocols } => {
                    let mask = Self::protocol_mask(protocols);
                    match_sets.push(MatchSet {
                        value: MatchSetValue {
                            l4proto_type: L4ProtoType::from_u8(mask).unwrap_or(L4ProtoType::Tcp),
                        },
                        not,
                        match_type: MatchType::L4Proto as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                ConditionKind::IpVersion { versions } => {
                    let mask = Self::ip_version_mask(versions);
                    match_sets.push(MatchSet {
                        value: MatchSetValue {
                            ip_version: IpVersionType::from_u8(mask).unwrap_or(IpVersionType::V4),
                        },
                        not,
                        match_type: MatchType::IpVersion as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                ConditionKind::Dscp { values } => {
                    Self::push_dscp_match_sets(values, not, sub_outbound, must, mark, match_sets);
                }
                ConditionKind::ProcessName { names } => {
                    Self::push_process_name_match_sets(
                        names,
                        not,
                        sub_outbound,
                        must,
                        mark,
                        match_sets,
                    );
                }
                // Domain: push a DomainSet placeholder in ROUTING_MAP.
                // The actual domain→IP mapping will be populated by DNS snooping:
                // when DNS resolves a domain to IPs, those IPs are pushed to
                // DOMAIN_ROUTING_MAP with the bitmap pointing to this match_set.
                ConditionKind::Domain => {
                    let idx = match_sets.len() as u32;
                    // A negated DomainSet must NOT receive DNS-snooped bitmap
                    // pushes: they record IPs whose domain matched the rule in
                    // userspace, which is exactly the complement the kernel
                    // would then veto. Leaving the bit unset makes the kernel
                    // treat every flow as "not x", mirroring the userspace
                    // unknown-domain semantics; the domain veto itself stays
                    // on the userspace routing path.
                    if not == 0 {
                        let bitmap = Self::bitmap_for_rule(idx);
                        domain_bitmaps
                            .entry(route.name.clone())
                            .or_default()
                            .push(bitmap);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not,
                        match_type: MatchType::DomainSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
            }
        }

        Ok(())
    }

    /// Return the list of conditions present in a route, in evaluation order.
    fn collect_conditions<'a>(route: &'a CompiledRoute) -> Vec<Condition<'a>> {
        let mut conditions = Vec::new();

        macro_rules! collect_side {
            ($not:expr, $domain_suffixes:expr, $domain_keywords:expr, $geosite_domains:expr,
             $source_ip_nets:expr, $ip_nets:expr, $mac_addresses:expr, $source_ports:expr,
             $ports:expr, $protocols:expr, $ip_versions:expr, $dscp_values:expr,
             $process_names:expr) => {
                let has_domain = !$domain_suffixes.is_empty()
                    || !$domain_keywords.is_empty()
                    || !$geosite_domains.is_empty();
                if has_domain {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Domain,
                    });
                }
                if !$source_ip_nets.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::SourceIp {
                            nets: $source_ip_nets,
                        },
                    });
                }
                if !$ip_nets.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Ip { nets: $ip_nets },
                    });
                }
                if !$mac_addresses.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Mac {
                            macs: $mac_addresses,
                        },
                    });
                }
                if !$source_ports.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::SourcePort {
                            ranges: $source_ports,
                        },
                    });
                }
                if !$ports.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Port { ranges: $ports },
                    });
                }
                if !$protocols.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Protocol {
                            protocols: $protocols,
                        },
                    });
                }
                if !$ip_versions.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::IpVersion {
                            versions: $ip_versions,
                        },
                    });
                }
                if !$dscp_values.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::Dscp {
                            values: $dscp_values,
                        },
                    });
                }
                if !$process_names.is_empty() {
                    conditions.push(Condition {
                        not: $not,
                        kind: ConditionKind::ProcessName {
                            names: $process_names,
                        },
                    });
                }
            };
        }

        collect_side!(
            false,
            &route.domain_suffixes,
            &route.domain_keywords,
            &route.geosite_domains,
            &route.source_ip_nets,
            &route.ip_nets,
            &route.mac_addresses,
            &route.source_ports,
            &route.ports,
            &route.protocols,
            &route.ip_versions,
            &route.dscp_values,
            &route.process_names
        );
        collect_side!(
            true,
            &route.not_domain_suffixes,
            &route.not_domain_keywords,
            &route.not_geosite_domains,
            &route.not_source_ip_nets,
            &route.not_ip_nets,
            &route.not_mac_addresses,
            &route.not_source_ports,
            &route.not_ports,
            &route.not_protocols,
            &route.not_ip_versions,
            &route.not_dscp_values,
            &route.not_process_names
        );

        conditions
    }

    /// Returns true if the route contains any condition that cannot be
    /// evaluated by the eBPF datapath and must be left to userspace.
    ///
    /// All conditions we currently generate have an eBPF representation:
    /// domain/geosite via `DomainSet` + DNS snooping, IP/MAC via LPM tries,
    /// ports/protocol/ipversion/dscp directly, and process names via pname.
    fn has_unsupported_ebpf_conditions(_route: &CompiledRoute) -> bool {
        false
    }

    /// Record destination IP prefixes for DEST_LPM_ROUTING_MAP into the plan.
    fn plan_dest_lpm_routes(
        plan: &mut LpmPushPlan,
        nets: &[ipnet::IpNet],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for (i, net) in nets.iter().enumerate() {
            let lpm_key = maps::cidr_to_lpm_key(&net.to_string())?;
            if lpm_key.prefix_len == 0 {
                warn!("dest LPM: zero prefix for {}", net);
            }
            if i < 3 {
                debug!(
                    "dest LPM insert {}: prefix_len={} data={:?}",
                    net, lpm_key.prefix_len, lpm_key.data
                );
            }
            plan.add_dest(lpm_key, bitmap);
        }

        info!(
            "Planned {} destination IP routes for rule {}",
            nets.len(),
            rule_index
        );
        Ok(())
    }

    /// Record source IP prefixes for SOURCE_LPM_ROUTING_MAP into the plan.
    fn plan_source_lpm_routes(
        plan: &mut LpmPushPlan,
        nets: &[ipnet::IpNet],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for net in nets {
            let lpm_key = maps::cidr_to_lpm_key(&net.to_string())?;
            plan.add_source(lpm_key, bitmap);
        }

        info!(
            "Planned {} source IP routes for rule {}",
            nets.len(),
            rule_index
        );
        Ok(())
    }

    /// Record MAC addresses for MAC_LPM_ROUTING_MAP into the plan.
    ///
    /// Each MAC is encoded as an IPv6-like 16-byte prefix with the MAC in
    /// bytes 10–15 and prefix_len=128 (exact match), matching Go dae-core's
    /// approach of storing MAC entries in LPM tries.
    fn plan_mac_lpm_routes(
        plan: &mut LpmPushPlan,
        macs: &[String],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if macs.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for mac_str in macs {
            let mac_bytes = match parse_mac_to_bytes(mac_str) {
                Some(b) => b,
                None => {
                    warn!("Invalid MAC address '{}', skipping", mac_str);
                    continue;
                }
            };

            // Encode MAC as IPv6-like address: MAC occupies bytes 10-15.
            // The LPM trie compares the full 16-byte key with prefix_len=128
            // for exact MAC match.
            let mut addr: [u8; 16] = [0; 16];
            addr[10..16].copy_from_slice(&mac_bytes);

            // Convert to u32 chunks matching the LpmKey data layout.
            let mut data = [0u32; 4];
            for (i, chunk) in addr.chunks(4).enumerate() {
                data[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }

            let lpm_key = LpmKey {
                prefix_len: 128,
                data,
            };
            plan.add_mac(lpm_key, bitmap);
        }

        info!("Planned {} MAC routes for rule {}", macs.len(), rule_index);
        Ok(())
    }

    /// Append one MatchSet per port range, ORing multiple ranges with LogicalOr.
    fn push_port_match_sets(
        ranges: &[crate::routing::PortRange],
        is_source: bool,
        not: u8,
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = ranges.len();
        for (i, r) in ranges.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            match_sets.push(MatchSet {
                value: MatchSetValue {
                    port_range: honk_ebpf_common::PortRange {
                        port_start: r.start,
                        port_end: r.end,
                    },
                },
                not,
                match_type: if is_source {
                    MatchType::SourcePort as u8
                } else {
                    MatchType::Port as u8
                },
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    /// Append one MatchSet per DSCP value, ORing multiple values with LogicalOr.
    fn push_dscp_match_sets(
        values: &[u8],
        not: u8,
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = values.len();
        for (i, &v) in values.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            match_sets.push(MatchSet {
                value: MatchSetValue { dscp: v },
                not,
                match_type: MatchType::Dscp as u8,
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    fn process_name_value(name: &str) -> [u32; TASK_COMM_LEN / 4] {
        let mut bytes = [0u8; TASK_COMM_LEN];
        let len = name.len().min(TASK_COMM_LEN - 1);
        bytes[..len].copy_from_slice(&name.as_bytes()[..len]);

        let mut value = [0u32; TASK_COMM_LEN / 4];
        let (chunks, _) = bytes.as_chunks::<4>();
        for (word, chunk) in value.iter_mut().zip(chunks) {
            *word = u32::from_ne_bytes(*chunk);
        }

        value
    }

    /// Append one MatchSet per process name, ORing multiple names with LogicalOr.
    /// Linux reserves the final TASK_COMM_LEN byte for a trailing NUL.
    fn push_process_name_match_sets(
        names: &[String],
        not: u8,
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = names.len();
        for (i, name) in names.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            let pname = Self::process_name_value(name);
            match_sets.push(MatchSet {
                value: MatchSetValue { pname },
                not,
                match_type: MatchType::ProcessName as u8,
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    /// Return a DomainRouting bitmap with a single bit set for `rule_index`.
    fn bitmap_for_rule(rule_index: u32) -> DomainRouting {
        let mut bitmap = [0u32; ROUTING_BITMAP_WORDS];
        let wi = (rule_index / 32) as usize;
        if wi < bitmap.len() {
            bitmap[wi] = 1u32 << (rule_index % 32);
        }
        DomainRouting { bitmap }
    }

    /// Group mask selecting every (l4proto × ipversion) routing group.
    const ALL_GROUPS: u8 = (1 << ROUTING_GROUP_COUNT) - 1;

    /// Compute the (l4proto × ipversion) group mask of a rule from its
    /// compiled MatchSet chain.
    ///
    /// The chain is scanned — rather than the source conditions — so the
    /// mask is derived from exactly the values `eval_match` will compare
    /// against: an L4Proto entry restricts the rule to the tcp groups iff
    /// `value & Tcp != 0` and to the udp groups iff `value & Udp != 0`;
    /// an IpVersion entry does the same for the address family.  A rule
    /// without such entries can match any flow and belongs to all groups.
    ///
    fn rule_group_mask(chain: &[MatchSet]) -> u8 {
        let mut l4 = 0b11u8; // bit 0: tcp allowed, bit 1: udp allowed
        let mut ip = 0b11u8; // bit 0: v4 allowed, bit 1: v6 allowed
        for ms in chain {
            // A negated L4Proto/IpVersion entry matches the complement
            // protocols/families, so it must not narrow the group mask —
            // the pre-filter would otherwise skip a rule that can match.
            if ms.not != 0 {
                continue;
            }
            match MatchType::from_u8(ms.match_type) {
                Some(MatchType::L4Proto) => {
                    let v = unsafe { ms.value.l4proto_type as u8 };
                    let mut allowed = 0u8;
                    if v & (L4ProtoType::Tcp as u8) != 0 {
                        allowed |= 0b01;
                    }
                    if v & (L4ProtoType::Udp as u8) != 0 {
                        allowed |= 0b10;
                    }
                    l4 &= allowed;
                }
                Some(MatchType::IpVersion) => {
                    let v = unsafe { ms.value.ip_version as u8 };
                    let mut allowed = 0u8;
                    if v & (IpVersionType::V4 as u8) != 0 {
                        allowed |= 0b01;
                    }
                    if v & (IpVersionType::V6 as u8) != 0 {
                        allowed |= 0b10;
                    }
                    ip &= allowed;
                }
                _ => {}
            }
        }
        let mut mask = 0u8;
        if l4 & 0b01 != 0 && ip & 0b01 != 0 {
            mask |= 1 << ROUTING_GROUP_TCP4;
        }
        if l4 & 0b01 != 0 && ip & 0b10 != 0 {
            mask |= 1 << ROUTING_GROUP_TCP6;
        }
        if l4 & 0b10 != 0 && ip & 0b01 != 0 {
            mask |= 1 << ROUTING_GROUP_UDP4;
        }
        if l4 & 0b10 != 0 && ip & 0b10 != 0 {
            mask |= 1 << ROUTING_GROUP_UDP6;
        }
        mask
    }

    /// Set the bitmap bits for logical MatchSet indices `[start, end)` in
    /// every group selected by `group_mask` (bit g = group g). MatchSets are
    /// never duplicated across groups.
    fn set_group_bits(bitmaps: &mut RoutingGroupBitmaps, start: usize, end: usize, group_mask: u8) {
        for (g, words) in bitmaps.iter_mut().enumerate() {
            if (group_mask >> g) & 1 == 0 {
                continue;
            }
            for idx in start..end {
                let word = idx / 32;
                if word < words.len() {
                    words[word] |= 1u32 << (idx % 32);
                }
            }
        }
    }

    /// Clear the bitmap bits at indices `>= from` in every group.  Used
    /// when ruleset truncation drops MatchSets whose bits were already
    /// recorded.
    fn clear_group_bits_from(bitmaps: &mut RoutingGroupBitmaps, from: usize) {
        for words in bitmaps.iter_mut() {
            for (w, word) in words.iter_mut().enumerate() {
                let base = w * 32;
                if base >= from {
                    *word = 0;
                } else if base + 32 > from {
                    *word &= (1u32 << (from - base)) - 1;
                }
            }
        }
    }

    /// Convert protocol strings to L4 protocol mask (1=TCP, 2=UDP).
    fn protocol_mask(protocols: &[String]) -> u8 {
        if protocols.is_empty() {
            return 0; // match any
        }
        let mut mask = 0u8;
        for proto in protocols {
            match proto.to_lowercase().as_str() {
                "tcp" => mask |= 1,
                "udp" => mask |= 2,
                _ => {}
            }
        }
        mask
    }

    /// Convert IP version values to bitmask (4=1, 6=2).
    fn ip_version_mask(versions: &[u8]) -> u8 {
        if versions.is_empty() {
            return 0;
        }
        let mut mask = 0u8;
        for &v in versions {
            match v {
                4 => mask |= 1,
                6 => mask |= 2,
                _ => {}
            }
        }
        mask
    }
}

/// Parse a MAC address string into a 6-byte array.
///
/// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`,
/// or `aabbccddeeff`.
fn parse_mac_to_bytes(s: &str) -> Option<[u8; 6]> {
    let stripped: String = s
        .chars()
        .filter(|&c| c != ':' && c != '-' && c != '.')
        .collect();
    if stripped.len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for i in 0..6 {
        bytes[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::RoutingPushPhase;
    use crate::ebpf::mock::{MockEbpfBackend, MockRoutingPublicationWrite};

    #[test]
    fn test_protocol_mask() {
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&[]), 0);
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&["tcp".into()]), 1);
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&["udp".into()]), 2);
        assert_eq!(
            RoutingMatcherBuilder::protocol_mask(&["tcp".into(), "udp".into()]),
            3
        );
    }

    #[test]
    fn every_routing_push_phase_surfaces_an_injected_failure() {
        let dest_nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let source_nets: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let cases = [
            (RoutingPushPhase::Rules, make_route("rules", "direct")),
            (
                RoutingPushPhase::DestinationLpm,
                CompiledRoute {
                    ip_nets: dest_nets.clone(),
                    ip_trie: crate::routing::BinaryLpmTrie::from_nets(&dest_nets),
                    ..make_route("dest", "direct")
                },
            ),
            (
                RoutingPushPhase::SourceLpm,
                CompiledRoute {
                    source_ip_nets: source_nets.clone(),
                    source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&source_nets),
                    ..make_route("source", "direct")
                },
            ),
            (
                RoutingPushPhase::MacLpm,
                CompiledRoute {
                    mac_addresses: vec!["aa:bb:cc:dd:ee:ff".into()],
                    ..make_route("mac", "direct")
                },
            ),
            (RoutingPushPhase::Meta, make_route("meta", "direct")),
            (RoutingPushPhase::PruneLpm, make_route("prune", "direct")),
        ];
        let outbound_map = HashMap::from([("direct".to_string(), OutboundIndex::Direct as u8)]);

        for (phase, route) in cases {
            let mut backend = MockEbpfBackend::new();
            backend.fail_next_routing_phase(phase);
            let result = RoutingMatcherBuilder::build_and_push(
                &mut backend,
                &[route],
                &outbound_map,
                "direct",
                DialMode::Ip,
            );
            assert!(result.is_err(), "{phase:?} fault was not surfaced");
        }
    }

    #[test]
    fn every_failed_phase_replays_the_exact_active_plan_selector_last() {
        let old_dest: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let old_source: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let old_route = CompiledRoute {
            ip_nets: old_dest.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&old_dest),
            source_ip_nets: old_source.clone(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&old_source),
            mac_addresses: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..make_route("old", "direct")
        };
        let outbound_map = HashMap::from([("direct".to_string(), OutboundIndex::Direct as u8)]);
        let old_plan =
            RoutingMatcherBuilder::compile(&[old_route], &outbound_map, "direct", DialMode::Ip)
                .unwrap();
        let new_dest: Vec<ipnet::IpNet> = vec!["172.16.0.0/12".parse().unwrap()];
        let new_source: Vec<ipnet::IpNet> = vec!["100.64.0.0/10".parse().unwrap()];
        let new_route = CompiledRoute {
            ip_nets: new_dest.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&new_dest),
            source_ip_nets: new_source.clone(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&new_source),
            mac_addresses: vec!["11:22:33:44:55:66".into()],
            ..make_route("new", "direct")
        };
        let new_plan =
            RoutingMatcherBuilder::compile(&[new_route], &outbound_map, "direct", DialMode::Ip)
                .unwrap();

        for phase in [
            RoutingPushPhase::Rules,
            RoutingPushPhase::DestinationLpm,
            RoutingPushPhase::SourceLpm,
            RoutingPushPhase::MacLpm,
            RoutingPushPhase::Meta,
            RoutingPushPhase::PruneLpm,
        ] {
            let mut backend = MockEbpfBackend::new();
            RoutingMatcherBuilder::push_plan(&mut backend, &old_plan).unwrap();
            let accepted = backend.routing_snapshot();
            backend.fail_next_routing_phase(phase);
            assert!(
                RoutingMatcherBuilder::push_transition(&mut backend, Some(&old_plan), &new_plan,)
                    .is_err()
            );
            RoutingMatcherBuilder::push_transition(&mut backend, Some(&old_plan), &old_plan)
                .unwrap();
            assert_eq!(backend.routing_snapshot(), accepted, "{phase:?}");
            assert_eq!(
                backend.routing_meta_write_order.last(),
                Some(&0),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn packed_group_metadata_is_complete_before_selector_flip() {
        let mut backend = MockEbpfBackend::new();
        let mut bitmaps = [[0u32; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];
        for (group, words) in bitmaps.iter_mut().enumerate() {
            for (word, value) in words.iter_mut().enumerate() {
                *value = ((group + 1) * 100 + word) as u32;
            }
        }

        backend.publish_routing_generation(1, 42, &bitmaps).unwrap();

        for (group, bitmap) in bitmaps.iter().enumerate() {
            assert_eq!(
                backend.active_routing_group_meta(group as u32),
                Some(RoutingGroupMeta {
                    rule_count: 42,
                    bitmap: *bitmap,
                })
            );
        }
        let expected_tail = [
            MockRoutingPublicationWrite::Packed(routing_group_meta_index(1, 0)),
            MockRoutingPublicationWrite::Packed(routing_group_meta_index(1, 1)),
            MockRoutingPublicationWrite::Packed(routing_group_meta_index(1, 2)),
            MockRoutingPublicationWrite::Packed(routing_group_meta_index(1, 3)),
            MockRoutingPublicationWrite::Selector(1),
        ];
        assert_eq!(
            &backend.routing_publication_order
                [backend.routing_publication_order.len() - expected_tail.len()..],
            &expected_tail
        );
    }

    #[test]
    fn test_ip_version_mask() {
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[]), 0);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[4]), 1);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[6]), 2);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[4, 6]), 3);
    }

    #[test]
    fn test_bitmap_for_rule() {
        let dr = RoutingMatcherBuilder::bitmap_for_rule(5);
        assert_eq!(dr.bitmap[0], 1 << 5);

        let dr = RoutingMatcherBuilder::bitmap_for_rule(32);
        assert_eq!(dr.bitmap[1], 1 << 0);
    }

    #[test]
    fn test_parse_mac_to_bytes() {
        assert_eq!(
            parse_mac_to_bytes("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("AA-BB-CC-DD-EE-FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("aabb.ccdd.eeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac_to_bytes("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac_to_bytes(""), None);
    }

    #[test]
    fn test_process_name_value_matches_kernel_pname_truncation() {
        let value = RoutingMatcherBuilder::process_name_value("systemd-resolved");
        let bytes: Vec<u8> = value.into_iter().flat_map(u32::to_ne_bytes).collect();
        assert_eq!(bytes.as_slice(), b"systemd-resolve\0");
    }

    fn make_route(name: &str, outbound: &str) -> CompiledRoute {
        CompiledRoute {
            name: name.into(),
            rule_type: name.into(),
            rule_payload: String::new(),
            priority: 0,
            domain_patterns: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            ip_nets: Vec::new(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            source_ip_nets: Vec::new(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            ports: Vec::new(),
            source_ports: Vec::new(),
            protocols: Vec::new(),
            process_names: Vec::new(),
            mac_addresses: Vec::new(),
            geosite_domains: Vec::new(),
            geosite_matcher: Default::default(),
            ip_versions: Vec::new(),
            dscp_values: Vec::new(),
            not_domain_patterns: Vec::new(),
            not_domain_suffixes: Vec::new(),
            not_domain_keywords: Vec::new(),
            not_ip_nets: Vec::new(),
            not_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            not_source_ip_nets: Vec::new(),
            not_source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            not_ports: Vec::new(),
            not_source_ports: Vec::new(),
            not_protocols: Vec::new(),
            not_process_names: Vec::new(),
            not_mac_addresses: Vec::new(),
            not_geosite_domains: Vec::new(),
            not_geosite_matcher: Default::default(),
            not_ip_versions: Vec::new(),
            not_dscp_values: Vec::new(),
            outbound: outbound.into(),
            must: false,
            mark: 0,
        }
    }

    #[test]
    fn test_push_ip_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("private", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2); // IpSet + fallback
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        assert!(backend.source_lpm_bitmap.is_empty());
    }

    #[test]
    fn test_push_source_ip_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let route = CompiledRoute {
            source_ip_nets: nets.clone(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("src-lan", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        assert_eq!(backend.source_lpm_bitmap.len(), 1);
        assert!(backend.dest_lpm_bitmap.is_empty());
    }

    #[test]
    fn test_plan_has_domain_rules_flag() {
        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        let plan = RoutingMatcherBuilder::compile(
            &[make_route("ip-only", "direct")],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        assert!(!plan.has_domain_rules);

        let mut suffix_route = make_route("suffix", "direct");
        suffix_route.domain_suffixes = vec!["example.com".into()];
        let plan =
            RoutingMatcherBuilder::compile(&[suffix_route], &outbound_map, "direct", DialMode::Ip)
                .unwrap();
        assert!(plan.has_domain_rules);

        // Negated domain matchers also set the metadata bit: in modes that
        // permit SNI re-evaluation, userspace could veto this kernel result.
        let mut negated_route = make_route("negated", "direct");
        negated_route.not_domain_keywords = vec!["ads".into()];
        let plan =
            RoutingMatcherBuilder::compile(&[negated_route], &outbound_map, "direct", DialMode::Ip)
                .unwrap();
        assert!(plan.has_domain_rules);
    }

    #[test]
    fn test_push_port_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        let port_rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(port_rule.match_type, MatchType::Port as u8);
        assert_eq!(port_rule.outbound, OutboundIndex::UserBase as u8);
        let fallback = backend.active_routing_rule(1).unwrap();
        assert_eq!(fallback.match_type, MatchType::Fallback as u8);
    }

    #[test]
    fn test_push_port_rule_punted_in_domainpp() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::DomainPlusPlus,
        )
        .unwrap();

        let port_rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(port_rule.match_type, MatchType::Port as u8);
        assert_eq!(
            port_rule.outbound,
            OutboundIndex::ControlPlaneRouting as u8,
            "port-based proxy rule should be punted to userspace in domain++ mode"
        );
    }

    #[test]
    fn test_push_port_rule_stays_kernel_routable_without_forced_reroute() {
        for dial_mode in [DialMode::Domain, DialMode::DomainPlus] {
            let mut backend = MockEbpfBackend::new();
            let route = CompiledRoute {
                ports: vec![crate::routing::PortRange {
                    start: 443,
                    end: 443,
                }],
                ..make_route("https", "proxy")
            };
            let mut outbound_map = HashMap::new();
            outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
            outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

            RoutingMatcherBuilder::build_and_push(
                &mut backend,
                &[route],
                &outbound_map,
                "direct",
                dial_mode,
            )
            .unwrap();

            assert_eq!(
                backend.active_routing_rule(0).unwrap().outbound,
                OutboundIndex::UserBase as u8,
                "{dial_mode:?} must preserve the initial port decision"
            );
        }
    }

    #[test]
    fn test_push_protocol_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            protocols: vec!["udp".into()],
            ..make_route("udp", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        let proto_rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(proto_rule.match_type, MatchType::L4Proto as u8);
        assert_eq!(proto_rule.outbound, OutboundIndex::UserBase as u8);
    }

    #[test]
    fn test_push_mac_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            mac_addresses: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..make_route("device", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        assert_eq!(backend.mac_lpm_bitmap.len(), 1);
    }

    #[test]
    fn test_push_domain_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            domain_suffixes: vec!["google.com".into()],
            ..make_route("google", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        let result = RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(result.match_set_count, 2);
        assert!(result.domain_bitmaps.contains_key("google"));
        assert_eq!(
            backend.active_routing_rule(0).unwrap().match_type,
            MatchType::DomainSet as u8
        );
    }

    #[test]
    fn test_push_must_and_mark_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange { start: 22, end: 22 }],
            must: true,
            mark: 99,
            ..make_route("ssh", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "proxy",
            DialMode::Ip,
        )
        .unwrap();

        let rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(rule.must, 1);
        assert_eq!(rule.mark, 99);
        let fallback = backend.active_routing_rule(1).unwrap();
        assert_eq!(fallback.match_type, MatchType::Fallback as u8);
        assert_eq!(fallback.outbound, OutboundIndex::Direct as u8);
    }

    #[test]
    fn test_push_multiple_rules_and_priority_order() {
        let mut backend = MockEbpfBackend::new();
        let route1 = CompiledRoute {
            priority: 10,
            ports: vec![crate::routing::PortRange { start: 80, end: 80 }],
            ..make_route("http", "proxy")
        };
        let route2 = CompiledRoute {
            priority: 5,
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route1, route2],
            &outbound_map,
            "block",
            DialMode::Ip,
        )
        .unwrap();

        // priority 5 first, then priority 10, then fallback
        assert_eq!(backend.active_routing_rule_count(), 3);
        assert_eq!(
            backend.active_routing_rule(0).unwrap().outbound,
            OutboundIndex::Direct as u8
        );
        assert_eq!(
            backend.active_routing_rule(1).unwrap().outbound,
            OutboundIndex::UserBase as u8
        );
    }

    #[test]
    fn reload_retains_previous_lpm_keys_for_one_transition() {
        let mut backend = MockEbpfBackend::new();
        let outbound_map = HashMap::from([("direct".to_string(), OutboundIndex::Direct as u8)]);

        let old_nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let old_plan = RoutingMatcherBuilder::compile(
            &[CompiledRoute {
                ip_nets: old_nets.clone(),
                ip_trie: crate::routing::BinaryLpmTrie::from_nets(&old_nets),
                ..make_route("old", "direct")
            }],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        RoutingMatcherBuilder::push_plan(&mut backend, &old_plan).unwrap();

        let new_nets: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let new_plan = RoutingMatcherBuilder::compile(
            &[CompiledRoute {
                ip_nets: new_nets.clone(),
                ip_trie: crate::routing::BinaryLpmTrie::from_nets(&new_nets),
                ..make_route("new", "direct")
            }],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        RoutingMatcherBuilder::push_transition(&mut backend, Some(&old_plan), &new_plan).unwrap();

        let old_key = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("10.0.0.0/8").unwrap());
        let new_key = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("192.168.0.0/16").unwrap());
        assert_eq!(backend.dest_lpm_bitmap.len(), 2);
        assert_eq!(
            backend.dest_lpm_bitmap[&old_key].bitmap[ROUTING_BITMAP_WORDS_PER_GENERATION],
            1
        );
        assert_eq!(backend.dest_lpm_bitmap[&new_key].bitmap[0], 1);
        assert_eq!(backend.active_routing_rule_count(), 2);

        RoutingMatcherBuilder::push_transition(&mut backend, Some(&new_plan), &new_plan).unwrap();
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        assert!(!backend.dest_lpm_bitmap.contains_key(&old_key));
        assert!(backend.dest_lpm_bitmap.contains_key(&new_key));
    }

    #[test]
    fn reload_prunes_retired_lpm_keys_before_writing_replacement() {
        let mut backend = MockEbpfBackend::new();
        let outbound_map = HashMap::from([("direct".to_string(), OutboundIndex::Direct as u8)]);
        let compile = |name: &str, cidr: &str| {
            let nets = vec![cidr.parse().unwrap()];
            RoutingMatcherBuilder::compile(
                &[CompiledRoute {
                    ip_nets: nets.clone(),
                    ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
                    ..make_route(name, "direct")
                }],
                &outbound_map,
                "direct",
                DialMode::Ip,
            )
            .unwrap()
        };
        let first = compile("first", "10.0.0.0/8");
        let second = compile("second", "192.168.0.0/16");
        let third = compile("third", "172.16.0.0/12");

        RoutingMatcherBuilder::push_plan(&mut backend, &first).unwrap();
        RoutingMatcherBuilder::push_transition(&mut backend, Some(&first), &second).unwrap();
        let accepted = backend.routing_snapshot();
        let first_key = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("10.0.0.0/8").unwrap());
        let second_key = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("192.168.0.0/16").unwrap());

        backend.fail_next_routing_phase(RoutingPushPhase::DestinationLpm);
        assert!(
            RoutingMatcherBuilder::push_transition(&mut backend, Some(&second), &third).is_err()
        );

        assert!(!backend.dest_lpm_bitmap.contains_key(&first_key));
        assert!(backend.dest_lpm_bitmap.contains_key(&second_key));
        assert_eq!(backend.routing_snapshot(), accepted);
        RoutingMatcherBuilder::push_transition(&mut backend, Some(&second), &second).unwrap();
        assert_eq!(backend.routing_snapshot(), accepted);
    }

    #[test]
    fn test_shared_cidr_across_rules_merges_bits() {
        // Two rules referencing the same CIDR in one push must produce a
        // single LPM entry with both rule bits set (the real backend
        // overwrites LPM values; merging happens in the plan).
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route_a = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("a", "direct")
        };
        let route_b = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("b", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route_a, route_b],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        let snapshot = backend.routing_snapshot();
        assert_eq!(snapshot.dest_lpm.len(), 1);
        assert_eq!(
            snapshot.dest_lpm[0].1[0], 0b11,
            "shared CIDR must carry both rule indices (0 and 1)"
        );
    }

    #[test]
    fn test_push_does_not_clear_routes_first() {
        // Regression guard for the two-phase commit: build_and_push must not
        // reset the rule count to 0 at any point (the eBPF datapath SHOTs
        // new flows while the count is 0).  With the mock, the observable
        // invariant is that a reload leaves a valid count and no stale maps.
        let mut backend = MockEbpfBackend::new();
        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange { start: 80, end: 80 }],
            ..make_route("http", "direct")
        };
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            std::slice::from_ref(&route),
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        // Reload with the identical ruleset: everything must stay consistent.
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        assert!(backend.domain_routes.is_empty());
        assert!(backend.ip_routes.is_empty());
    }

    fn mock_group_word(backend: &MockEbpfBackend, g: u32, w: u32) -> u32 {
        backend.active_routing_group_word(g as usize, w as usize)
    }

    #[test]
    fn test_group_mask_tcp_only_chain() {
        // A chain carrying an L4Proto(tcp) entry belongs to the tcp
        // groups only.
        let chain = [MatchSet {
            value: MatchSetValue {
                l4proto_type: L4ProtoType::Tcp,
            },
            match_type: MatchType::L4Proto as u8,
            ..Default::default()
        }];
        let mask = RoutingMatcherBuilder::rule_group_mask(&chain);
        assert_eq!(mask, (1 << ROUTING_GROUP_TCP4) | (1 << ROUTING_GROUP_TCP6));
    }

    #[test]
    fn test_group_mask_udp_only_chain() {
        let chain = [MatchSet {
            value: MatchSetValue {
                l4proto_type: L4ProtoType::Udp,
            },
            match_type: MatchType::L4Proto as u8,
            ..Default::default()
        }];
        let mask = RoutingMatcherBuilder::rule_group_mask(&chain);
        assert_eq!(mask, (1 << ROUTING_GROUP_UDP4) | (1 << ROUTING_GROUP_UDP6));
    }

    #[test]
    fn test_group_mask_without_proto_entries_covers_all_groups() {
        // No L4Proto/IpVersion entry: the rule can match any flow.
        let port_chain = [MatchSet {
            value: MatchSetValue {
                port_range: honk_ebpf_common::PortRange {
                    port_start: 443,
                    port_end: 443,
                },
            },
            match_type: MatchType::Port as u8,
            ..Default::default()
        }];
        assert_eq!(
            RoutingMatcherBuilder::rule_group_mask(&port_chain),
            RoutingMatcherBuilder::ALL_GROUPS
        );

        let fallback_chain = [MatchSet {
            match_type: MatchType::Fallback as u8,
            ..Default::default()
        }];
        assert_eq!(
            RoutingMatcherBuilder::rule_group_mask(&fallback_chain),
            RoutingMatcherBuilder::ALL_GROUPS
        );
    }

    #[test]
    fn test_ipversion_rules_narrow_to_selected_groups() {
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);
        for (versions, expected_value, expected_groups) in [
            (
                vec![4],
                IpVersionType::V4,
                (1 << ROUTING_GROUP_TCP4) | (1 << ROUTING_GROUP_UDP4),
            ),
            (
                vec![6],
                IpVersionType::V6,
                (1 << ROUTING_GROUP_TCP6) | (1 << ROUTING_GROUP_UDP6),
            ),
            (
                vec![4, 6],
                IpVersionType::Any,
                RoutingMatcherBuilder::ALL_GROUPS,
            ),
        ] {
            let route = CompiledRoute {
                ip_versions: versions,
                ..make_route("ip-version", "proxy")
            };
            let plan =
                RoutingMatcherBuilder::compile(&[route], &outbound_map, "direct", DialMode::Ip)
                    .unwrap();
            let stored_value = unsafe { plan.match_sets[0].value.ip_version };
            assert_eq!(stored_value, expected_value);
            for (group, bitmap) in plan.group_bitmaps.iter().enumerate() {
                let included = bitmap[0] & 1 != 0;
                assert_eq!(included, expected_groups & (1 << group) != 0);
            }
        }
    }

    #[test]
    fn test_push_tcp_rule_not_in_udp_groups() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            protocols: vec!["tcp".into()],
            ..make_route("tcp-only", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        // One L4Proto MatchSet at index 0, fallback at index 1.
        assert_eq!(backend.active_routing_rule_count(), 2);
        for g in [ROUTING_GROUP_TCP4, ROUTING_GROUP_TCP6] {
            assert_eq!(
                mock_group_word(&backend, g, 0) & 0b11,
                0b11,
                "tcp group {g} must contain the rule (bit 0) and the fallback (bit 1)"
            );
        }
        for g in [ROUTING_GROUP_UDP4, ROUTING_GROUP_UDP6] {
            assert_eq!(
                mock_group_word(&backend, g, 0) & 0b11,
                0b10,
                "udp group {g} must skip the tcp-only rule but keep the fallback"
            );
        }
    }

    #[test]
    fn test_push_no_proto_rule_in_all_groups() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        // Port rule at index 0 (no protocol constraint) + fallback at 1:
        // every group sees both.
        for g in 0..ROUTING_GROUP_COUNT as u32 {
            assert_eq!(mock_group_word(&backend, g, 0) & 0b11, 0b11, "group {g}");
        }
    }

    #[test]
    fn test_group_bitmap_bits_match_global_indices() {
        // 40 tcp+port rules produce 40 two-entry chains (indices 0..79)
        // plus the fallback at index 80. This crosses both the 32- and
        // 64-entry boundaries, and every bit must retain its global index.
        let mut backend = MockEbpfBackend::new();
        let routes: Vec<CompiledRoute> = (0..40u16)
            .map(|i| CompiledRoute {
                protocols: vec!["tcp".into()],
                ports: vec![crate::routing::PortRange {
                    start: 1000 + i,
                    end: 1000 + i,
                }],
                ..make_route(&format!("r{i}"), "proxy")
            })
            .collect();

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &routes,
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 81);
        for g in [ROUTING_GROUP_TCP4, ROUTING_GROUP_TCP6] {
            assert_eq!(mock_group_word(&backend, g, 0), u32::MAX, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 1), u32::MAX, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 2), 0x1ffff, "group {g}");
        }
        // UDP groups carry only the fallback at global index 80.
        for g in [ROUTING_GROUP_UDP4, ROUTING_GROUP_UDP6] {
            assert_eq!(mock_group_word(&backend, g, 0), 0, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 1), 0, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 2), 1 << 16, "group {g}");
        }
    }

    #[test]
    fn staged_domain_routes_switch_with_the_rule_bank() {
        let mut backend = MockEbpfBackend::new();
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);
        let old_plan = RoutingMatcherBuilder::compile(
            &[CompiledRoute {
                ports: vec![crate::routing::PortRange {
                    start: 1000,
                    end: 1000,
                }],
                ..make_route("old", "proxy")
            }],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        RoutingMatcherBuilder::push_plan(&mut backend, &old_plan).unwrap();

        let key = crate::ebpf::maps::ip_addr_to_lpm_key("203.0.113.7".parse().unwrap());
        let old_bitmap = RoutingMatcherBuilder::bitmap_for_rule(0);
        backend.set_domain_ip_bitmap(&key, &old_bitmap).unwrap();
        let accepted = backend.routing_snapshot();

        let routes = (0..33u16)
            .map(|index| CompiledRoute {
                protocols: vec!["tcp".into()],
                ports: vec![crate::routing::PortRange {
                    start: 2000 + index,
                    end: 2000 + index,
                }],
                ..make_route(&format!("new-{index}"), "proxy")
            })
            .collect::<Vec<_>>();
        let next_plan =
            RoutingMatcherBuilder::compile(&routes, &outbound_map, "direct", DialMode::Ip).unwrap();
        let next_generation = backend.active_routing_generation().unwrap() ^ 1;
        let next_bitmap = RoutingMatcherBuilder::bitmap_for_rule(64);
        backend
            .stage_domain_routing_generation(next_generation, &[(key, next_bitmap)])
            .unwrap();
        assert_eq!(backend.routing_snapshot(), accepted);

        RoutingMatcherBuilder::push_transition(&mut backend, Some(&old_plan), &next_plan).unwrap();
        let switched = backend.routing_snapshot();
        assert_eq!(backend.active_routing_rule_count(), 67);
        assert_eq!(switched.domain.len(), 1);
        assert_eq!(switched.domain[0].1[2], 1);
    }

    #[test]
    fn domain_bitmaps_cover_first_middle_and_last_logical_rules() {
        for index in [0, 63, 64, 127] {
            let logical = RoutingMatcherBuilder::bitmap_for_rule(index);
            let logical_word = index as usize / 32;
            let bit = 1u32 << (index % 32);
            assert_eq!(logical.bitmap[logical_word], bit);

            for generation in 0..ROUTING_GENERATION_COUNT as u32 {
                let physical = logical.for_generation(generation);
                let physical_word =
                    generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION + logical_word;
                assert_eq!(physical.bitmap[physical_word], bit);
                assert_eq!(
                    physical
                        .bitmap
                        .iter()
                        .enumerate()
                        .filter(|(_, word)| **word != 0)
                        .map(|(word, _)| word)
                        .collect::<Vec<_>>(),
                    vec![physical_word]
                );
            }
        }
    }

    #[test]
    fn test_clear_group_bits_from() {
        let mut bitmaps: RoutingGroupBitmaps =
            [[u32::MAX; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];
        RoutingMatcherBuilder::clear_group_bits_from(&mut bitmaps, 34);
        for words in bitmaps.iter() {
            assert_eq!(words[0], u32::MAX);
            assert_eq!(words[1], 0b11);
            assert_eq!(words[2], 0);
            assert_eq!(words[3], 0);
        }
    }

    #[test]
    fn test_push_negated_port_rule_marks_not() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            not_ports: vec![crate::routing::PortRange { start: 53, end: 53 }],
            ..make_route("not-dns", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        let rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(rule.match_type, MatchType::Port as u8);
        assert_eq!(rule.not, 1);
        assert_eq!(rule.outbound, OutboundIndex::UserBase as u8);
    }

    #[test]
    fn test_push_negated_ip_rule_installs_lpm_and_marks_not() {
        // A negated LPM matcher still needs its entries installed; the
        // kernel inverts the lookup result via the not flag.
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route = CompiledRoute {
            not_ip_nets: nets.clone(),
            not_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("not-private", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        let rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(rule.match_type, MatchType::IpSet as u8);
        assert_eq!(rule.not, 1);
    }

    #[test]
    fn test_negated_l4proto_rule_stays_in_all_groups() {
        // The rule matches the complement protocols, so the group
        // pre-filter must not skip it for any flow.
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            not_protocols: vec!["tcp".into()],
            ..make_route("not-tcp", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.active_routing_rule_count(), 2);
        let rule = backend.active_routing_rule(0).unwrap();
        assert_eq!(rule.match_type, MatchType::L4Proto as u8);
        assert_eq!(rule.not, 1);
        for g in 0..ROUTING_GROUP_COUNT as u32 {
            assert_eq!(
                mock_group_word(&backend, g, 0) & 0b11,
                0b11,
                "group {g} must contain the negated-proto rule and the fallback"
            );
        }
    }

    #[test]
    fn test_negated_ipversion_rule_stays_in_all_groups() {
        let route = CompiledRoute {
            not_ip_versions: vec![6],
            ..make_route("not-v6", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);
        let plan = RoutingMatcherBuilder::compile(&[route], &outbound_map, "direct", DialMode::Ip)
            .unwrap();
        let rule_index = 0usize;
        for words in plan.group_bitmaps.iter() {
            assert_ne!(
                words[rule_index / 32] & (1 << (rule_index % 32)),
                0,
                "negated ipversion rule must be in every group"
            );
        }
    }

    #[test]
    fn test_negated_domain_pushes_not_domainset_without_bitmap() {
        let route = CompiledRoute {
            not_domain_suffixes: vec!["x.com".into()],
            ..make_route("not-x", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);
        let plan = RoutingMatcherBuilder::compile(&[route], &outbound_map, "direct", DialMode::Ip)
            .unwrap();

        assert_eq!(plan.match_sets[0].match_type, MatchType::DomainSet as u8);
        assert_eq!(plan.match_sets[0].not, 1);
        assert!(
            !plan.domain_bitmaps.contains_key("not-x"),
            "a negated DomainSet must not receive DNS-snooped bitmap pushes"
        );
    }

    #[test]
    fn test_mixed_domain_rule_registers_only_positive_bitmap() {
        let route = CompiledRoute {
            domain_suffixes: vec!["google.com".into()],
            not_domain_suffixes: vec!["mail.google.com".into()],
            ..make_route("mixed", "proxy")
        };
        let outbound_map = HashMap::from([("proxy".to_string(), OutboundIndex::UserBase as u8)]);
        let plan = RoutingMatcherBuilder::compile(&[route], &outbound_map, "direct", DialMode::Ip)
            .unwrap();

        assert_eq!(plan.match_sets[0].match_type, MatchType::DomainSet as u8);
        assert_eq!(plan.match_sets[0].not, 0);
        assert_eq!(plan.match_sets[1].match_type, MatchType::DomainSet as u8);
        assert_eq!(plan.match_sets[1].not, 1);
        let bitmaps = plan.domain_bitmaps.get("mixed").unwrap();
        assert_eq!(bitmaps.len(), 1, "only the positive DomainSet registers");
        assert_eq!(bitmaps[0].bitmap[0], 1, "bitmap points at match_set 0");
    }

    #[test]
    fn test_negated_combined_chain_marks_each_set() {
        let route = CompiledRoute {
            ip_nets: vec!["10.10.10.24/32".parse().unwrap()],
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&["10.10.10.24/32".parse().unwrap()]),
            not_ports: vec![crate::routing::PortRange { start: 53, end: 53 }],
            ..make_route("host24", "direct")
        };
        let outbound_map = HashMap::from([("direct".to_string(), OutboundIndex::Direct as u8)]);
        let plan = RoutingMatcherBuilder::compile(&[route], &outbound_map, "direct", DialMode::Ip)
            .unwrap();

        assert_eq!(plan.match_sets[0].match_type, MatchType::IpSet as u8);
        assert_eq!(plan.match_sets[0].not, 0);
        assert_eq!(plan.match_sets[0].outbound, OutboundIndex::LogicalAnd as u8);
        assert_eq!(plan.match_sets[1].match_type, MatchType::Port as u8);
        assert_eq!(plan.match_sets[1].not, 1);
        assert_eq!(plan.match_sets[1].outbound, OutboundIndex::Direct as u8);
    }
}
