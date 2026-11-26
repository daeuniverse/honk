//! `honk-tool route` — offline routing policy simulation and native eBPF
//! offloadability inspection without starting the engine or touching BPF maps.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use honk_config::Config;
use honk_config::types::DialMode;
use honk_core::control::routing_matcher::RoutingPushPlan;
use honk_core::routing::native::{MatchResult, TraceError, missing_input};
use honk_core::routing::{
    CompiledCondition, CompiledPredicate, PredicateInput, RouteAction, Router,
};
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, OutboundIndex,
};

use crate::json::{JsonBuf, write_stdout};

const MIN_TRACE_STEPS: usize = 4096;
const TRACE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RouteProto {
    Tcp,
    Udp,
}

impl RouteProto {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Args)]
pub struct RouteArgs {
    /// Configuration file path.
    #[arg(short = 'c', long, default_value = "/etc/honk/config.dae")]
    pub config: PathBuf,
    /// Layer-4 protocol.
    #[arg(long, value_enum)]
    pub proto: RouteProto,
    /// Domain name (SNI or DNS hostname).
    #[arg(long)]
    pub domain: Option<String>,
    /// Destination IPv4 or IPv6 address.
    #[arg(long)]
    pub dip: Option<IpAddr>,
    /// Destination port (1..=65535).
    #[arg(long)]
    pub dport: Option<u16>,
    /// Source IPv4 or IPv6 address.
    #[arg(long)]
    pub sip: Option<IpAddr>,
    /// Source port (1..=65535).
    #[arg(long)]
    pub sport: Option<u16>,
    /// Originating process name.
    #[arg(long)]
    pub pname: Option<String>,
    /// DSCP value (0..=63 or 0x00..=0x3f).
    #[arg(long, value_parser = parse_dscp)]
    pub dscp: Option<u8>,
    /// Source MAC address.
    #[arg(long)]
    pub mac: Option<String>,
    /// Output machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

struct ConditionTrace {
    expression: String,
    result: &'static str,
    missing_inputs: Vec<&'static str>,
}

struct RuleTrace {
    index: usize,
    kind: &'static str,
    expression: String,
    outbound: String,
    must: bool,
    mark: u32,
    result: &'static str,
    missing_inputs: Vec<&'static str>,
    conditions: Vec<ConditionTrace>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct KernelOutcome {
    must: bool,
    mark: u32,
    domain_final: bool,
    lan_disposition: &'static str,
    wan_disposition: &'static str,
}

struct RouteReport {
    decision: &'static str,
    outbound: Option<String>,
    matched_rule: Option<usize>,
    matched_fallback: bool,
    must: Option<bool>,
    mark: Option<u32>,
    missing_inputs: Vec<&'static str>,
    dial_mode: String,
    clash_mode: &'static str,
    domain_predicates: usize,
    native_compilable: bool,
    native_error: Option<String>,
    domain_final: Option<bool>,
    lan_disposition: Option<&'static str>,
    wan_disposition: Option<&'static str>,
    rules: Vec<RuleTrace>,
}

pub fn run(args: RouteArgs) -> anyhow::Result<()> {
    validate_args(&args)?;
    let canonical_mac = args.mac.as_deref().map(parse_mac).transpose()?;

    let config_str = args
        .config
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("configuration path is not valid UTF-8"))?;
    let mut config = Config::from_file(config_str)?;
    config.validate()?;
    config.ensure_builtin_nodes();

    let router =
        Router::from_config_in_data_dir(&config.routing, Path::new(&config.global.data_dir))?;
    let report = build_report(&config, &router, &args, canonical_mac.as_deref())?;
    let rendered = if args.json {
        render_json(&report)
    } else {
        render_text(&report)
    };
    write_stdout(&rendered)
}

fn parse_dscp(raw: &str) -> Result<u8, String> {
    let trimmed = raw.trim();
    let value = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .map_or_else(|| trimmed.parse::<u8>(), |hex| u8::from_str_radix(hex, 16))
        .map_err(|_| format!("invalid DSCP value '{raw}'"))?;
    if value > 63 {
        return Err(format!("DSCP value {value} exceeds maximum 63"));
    }
    Ok(value)
}

fn validate_args(args: &RouteArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.domain.is_some() || args.dip.is_some(),
        "specify at least --domain or --dip"
    );
    if let Some(port) = args.dport {
        anyhow::ensure!(port != 0, "--dport must be between 1 and 65535");
    }
    if let Some(port) = args.sport {
        anyhow::ensure!(port != 0, "--sport must be between 1 and 65535");
    }
    if let Some(domain) = &args.domain {
        anyhow::ensure!(valid_domain_name(domain), "invalid --domain '{domain}'");
    }
    Ok(())
}

fn valid_domain_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
        })
}

fn parse_mac(raw: &str) -> anyhow::Result<String> {
    let valid_shape = match raw.len() {
        12 => raw.bytes().all(|b| b.is_ascii_hexdigit()),
        14 => {
            raw.split('.')
                .all(|part| part.len() == 4 && part.bytes().all(|b| b.is_ascii_hexdigit()))
                && raw.matches('.').count() == 2
        }
        17 => [':', '-'].into_iter().any(|sep| {
            raw.matches(sep).count() == 5
                && raw
                    .split(sep)
                    .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        }),
        _ => false,
    };
    anyhow::ensure!(valid_shape, "invalid --mac '{raw}'");
    let hex: Vec<u8> = raw.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    let mut octets = [0u8; 6];
    for (i, slot) in octets.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap();
        *slot = u8::from_str_radix(pair, 16).unwrap();
    }
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    ))
}

fn result_label(result: MatchResult) -> &'static str {
    match result {
        MatchResult::Matched => "matched",
        MatchResult::NotMatched => "not_matched",
        MatchResult::Indeterminate => "indeterminate",
        MatchResult::Skipped => "skipped",
    }
}

fn normalize_domain(domain: &str) -> &str {
    if domain == "." {
        domain
    } else {
        domain.strip_suffix('.').unwrap_or(domain)
    }
}

fn build_report(
    config: &Config,
    router: &Router,
    args: &RouteArgs,
    mac: Option<&str>,
) -> anyhow::Result<RouteReport> {
    let input = PredicateInput {
        domain: args.domain.as_deref().map(normalize_domain),
        dst_ip: args.dip.as_ref().map(IpAddr::to_canonical),
        dst_port: args.dport,
        src_ip: args.sip.as_ref().map(IpAddr::to_canonical),
        src_port: args.sport,
        protocol: args.proto.as_str(),
        process_name: args.pname.as_deref(),
        mac,
        dscp: args.dscp,
    };
    let steps = MIN_TRACE_STEPS.max(router.trace_steps());
    let deadline = Instant::now() + TRACE_TIMEOUT;
    let evaluation = router
        .simulate(input, steps, deadline)
        .map_err(|err| match err {
            TraceError::Steps => anyhow::anyhow!("routing trace exceeded step limit ({steps})"),
            TraceError::Deadline => anyhow::anyhow!("routing trace timed out"),
        })?;

    let mut configured_order: Vec<_> = config.routing.rules.iter().collect();
    configured_order.sort_by_key(|rule| rule.priority);

    let compiled_routes = router.compiled_routes();
    let mut missing_inputs = Vec::new();
    let mut rules = Vec::with_capacity(evaluation.rules.len());

    for (index, evaluated) in evaluation.rules.iter().enumerate() {
        if let Some((compiled, configured)) =
            compiled_routes.get(index).zip(configured_order.get(index))
        {
            let mut rule_missing = Vec::new();
            let mut conditions = Vec::with_capacity(compiled.conditions.len());
            for (cond_res, cond) in evaluated.conditions.iter().zip(&compiled.conditions) {
                let cond_missing = if *cond_res == MatchResult::Indeterminate {
                    let name = missing_input(&cond.predicate);
                    if !rule_missing.contains(&name) {
                        rule_missing.push(name);
                    }
                    vec![name]
                } else {
                    Vec::new()
                };
                conditions.push(ConditionTrace {
                    expression: router.condition_display(cond, &configured.condition),
                    result: result_label(*cond_res),
                    missing_inputs: cond_missing,
                });
            }
            if evaluated.result != MatchResult::Indeterminate {
                rule_missing.clear();
            }
            for &name in &rule_missing {
                if !missing_inputs.contains(&name) {
                    missing_inputs.push(name);
                }
            }
            rules.push(RuleTrace {
                index,
                kind: "rule",
                expression: router
                    .configured_rule_expression(&compiled.conditions, &configured.condition),
                outbound: compiled.action.outbound.clone(),
                must: compiled.action.must,
                mark: compiled.action.mark.map_or(0, |m| m.get()),
                result: result_label(evaluated.result),
                missing_inputs: rule_missing,
                conditions,
            });
        } else {
            let fallback = router.fallback();
            rules.push(RuleTrace {
                index,
                kind: "fallback",
                expression: format!("fallback: {}", fallback.outbound),
                outbound: fallback.outbound.clone(),
                must: fallback.must,
                mark: fallback.mark.map_or(0, |m| m.get()),
                result: result_label(evaluated.result),
                missing_inputs: Vec::new(),
                conditions: Vec::new(),
            });
        }
    }

    let dial_mode =
        config.global.dial_mode.parse::<DialMode>().map_err(|_| {
            anyhow::anyhow!("invalid global.dial_mode '{}'", config.global.dial_mode)
        })?;
    let (clash_mode, mode_flags) = configured_mode_flags(config);
    let compile_err = compile_native_plan(config, router, dial_mode).err();
    let native_compilable = compile_err.is_none();

    let candidates: Vec<usize> = evaluation
        .rules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            matches!(r.result, MatchResult::Matched | MatchResult::Indeterminate).then_some(i)
        })
        .collect();

    let (matched_rule, matched_fallback) = match candidates.as_slice() {
        [only] if *only < compiled_routes.len() => (Some(*only), false),
        [only] if *only == compiled_routes.len() => (None, true),
        _ => (None, false),
    };

    let mut must = None;
    let mut mark = None;
    let mut domain_final = None;
    let mut lan_disposition = None;
    let mut wan_disposition = None;

    if evaluation.outbound.is_some() && !candidates.is_empty() {
        let port_cases: &[Option<u16>] = match args.dport {
            Some(_) => std::slice::from_ref(&args.dport),
            None => &[Some(53), Some(443)],
        };
        let outcomes: Vec<KernelOutcome> = candidates
            .iter()
            .flat_map(|&idx| {
                port_cases.iter().map(move |&port| {
                    compute_kernel_outcome(
                        router,
                        idx,
                        dial_mode,
                        mode_flags,
                        args.domain.is_some(),
                        port,
                    )
                })
            })
            .collect();
        let first = outcomes[0];
        if outcomes.iter().all(|o| o.must == first.must) {
            must = Some(first.must);
        }
        if outcomes.iter().all(|o| o.mark == first.mark) {
            mark = Some(first.mark);
        }
        if native_compilable && outcomes.iter().all(|o| *o == first) {
            domain_final = Some(first.domain_final);
            lan_disposition = Some(first.lan_disposition);
            wan_disposition = Some(first.wan_disposition);
        }
    }

    Ok(RouteReport {
        decision: if evaluation.outbound.is_some() {
            "determinate"
        } else {
            "indeterminate"
        },
        outbound: evaluation.outbound.map(str::to_owned),
        matched_rule,
        matched_fallback,
        must,
        mark,
        missing_inputs,
        dial_mode: config.global.dial_mode.clone(),
        clash_mode,
        domain_predicates: router.domain_predicate_count(),
        native_compilable,
        native_error: compile_err.map(|e| e.to_string()),
        domain_final,
        lan_disposition,
        wan_disposition,
        rules,
    })
}

fn compile_native_plan(
    config: &Config,
    router: &Router,
    dial_mode: DialMode,
) -> anyhow::Result<RoutingPushPlan> {
    let max_groups = OutboundIndex::MustRules as usize - OutboundIndex::UserBase as usize;
    anyhow::ensure!(
        config.groups.len() <= max_groups,
        "too many routing groups ({} > {max_groups})",
        config.groups.len()
    );
    let mut outbound_ids = HashMap::with_capacity(config.groups.len() + 2);
    outbound_ids.insert("direct".into(), OutboundIndex::Direct as u8);
    outbound_ids.insert("block".into(), OutboundIndex::Block as u8);
    for (i, group) in config.groups.iter().enumerate() {
        outbound_ids.insert(group.name.clone(), OutboundIndex::UserBase as u8 + i as u8);
    }
    RoutingPushPlan::compile(router, &outbound_ids, dial_mode)
}

fn configured_mode_flags(config: &Config) -> (&'static str, u32) {
    if config.experimental.native_api.enabled
        || config
            .experimental
            .clash_api
            .external_controller
            .trim()
            .is_empty()
    {
        return ("rule", DATAPATH_FLAG_OFFLOAD_RULE_DIRECT);
    }
    let raw = config.experimental.clash_api.default_mode.trim();
    if raw.eq_ignore_ascii_case("direct") {
        ("direct", DATAPATH_FLAG_OFFLOAD_ALL)
    } else if raw.eq_ignore_ascii_case("global") {
        let first_is_direct = config
            .groups
            .first()
            .map(|g| g.name.as_str())
            .or_else(|| config.nodes.first().map(|n| n.name.as_str()))
            == Some("direct");
        let bits = if first_is_direct {
            DATAPATH_FLAG_OFFLOAD_ALL
        } else {
            0
        };
        ("global", bits)
    } else {
        ("rule", DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)
    }
}

fn predicate_is_empty(predicate: &CompiledPredicate) -> bool {
    match predicate {
        CompiledPredicate::DestinationPort(ranges) | CompiledPredicate::SourcePort(ranges) => {
            ranges.is_empty()
        }
        CompiledPredicate::Protocol(mask) | CompiledPredicate::IpVersion(mask) => *mask == 0,
        CompiledPredicate::Dscp(values) => values.is_empty(),
        CompiledPredicate::ProcessName(names) => names.is_empty(),
        CompiledPredicate::Domain(_)
        | CompiledPredicate::DestinationIp(_)
        | CompiledPredicate::SourceIp(_)
        | CompiledPredicate::Mac(_) => false,
    }
}

fn rule_folded_false(conditions: &[CompiledCondition]) -> bool {
    conditions.is_empty()
        || conditions
            .iter()
            .any(|c| !c.not && predicate_is_empty(&c.predicate))
}

fn is_generic_port_rule(conditions: &[CompiledCondition]) -> bool {
    conditions
        .iter()
        .any(|c| !c.not && matches!(c.predicate, CompiledPredicate::DestinationPort(_)))
        && conditions.iter().all(|c| {
            !matches!(
                c.predicate,
                CompiledPredicate::Domain(_)
                    | CompiledPredicate::ProcessName(_)
                    | CompiledPredicate::Mac(_)
                    | CompiledPredicate::Dscp(_)
            )
        })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KernelTarget {
    Direct,
    Block,
    UserGroup,
    ControlPlaneRouting,
}

fn compute_kernel_outcome(
    router: &Router,
    candidate_idx: usize,
    dial_mode: DialMode,
    mode_flags: u32,
    domain_supplied: bool,
    dport: Option<u16>,
) -> KernelOutcome {
    let compiled = router.compiled_routes();
    let action: &RouteAction = compiled
        .get(candidate_idx)
        .map_or_else(|| router.fallback(), |route| &route.action);

    let prefix_end = (candidate_idx + 1).min(compiled.len());
    let domain_prefix = compiled[..prefix_end]
        .iter()
        .filter(|route| !rule_folded_false(&route.conditions))
        .any(|route| {
            route
                .conditions
                .iter()
                .filter(|c| !predicate_is_empty(&c.predicate))
                .any(|c| matches!(c.predicate, CompiledPredicate::Domain(_)))
        });

    let has_domain_rules = router.domain_predicate_count() != 0;
    let domain_reroute =
        has_domain_rules && matches!(dial_mode, DialMode::Domain | DialMode::DomainPlusPlus);
    let mut domain_final = !domain_reroute || (has_domain_rules && domain_supplied);
    if domain_reroute
        && !domain_prefix
        && action.outbound == "direct"
        && !action.must
        && (mode_flags & DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0)
    {
        domain_final = true;
    }

    let configured_mark = action.mark.map_or(0, |m| m.get());
    let configured_must = action.must;

    if dport == Some(53) && !configured_must {
        return KernelOutcome {
            must: false,
            mark: configured_mark,
            domain_final,
            lan_disposition: "userspace_dns",
            wan_disposition: "userspace_dns",
        };
    }

    let punt_generic = candidate_idx < compiled.len()
        && !configured_must
        && dial_mode == DialMode::DomainPlusPlus
        && is_generic_port_rule(&compiled[candidate_idx].conditions)
        && action.outbound != "direct"
        && action.outbound != "block";

    let mut target = if punt_generic {
        KernelTarget::ControlPlaneRouting
    } else {
        match action.outbound.as_str() {
            "direct" => KernelTarget::Direct,
            "block" => KernelTarget::Block,
            _ => KernelTarget::UserGroup,
        }
    };
    let mut kernel_mark = configured_mark;

    if dport != Some(53)
        && (mode_flags & DATAPATH_FLAG_OFFLOAD_ALL != 0)
        && !configured_must
        && target != KernelTarget::Block
    {
        if target != KernelTarget::Direct {
            target = KernelTarget::Direct;
            kernel_mark = 0;
        }
        domain_final = true;
    }

    let (lan_disposition, wan_disposition) = match target {
        KernelTarget::Direct => {
            let lan_offload = dport != Some(53)
                && !configured_must
                && ((mode_flags & DATAPATH_FLAG_OFFLOAD_ALL != 0)
                    || (mode_flags & DATAPATH_FLAG_OFFLOAD_RULE_DIRECT != 0 && domain_final));
            let lan = if configured_must || lan_offload {
                "native_direct_offload"
            } else {
                "userspace_control_plane_routing"
            };
            let wan = if !configured_must && !domain_final {
                "userspace_control_plane_routing"
            } else if kernel_mark == 0 {
                "native_direct_offload"
            } else {
                "userspace_marked_direct"
            };
            (lan, wan)
        }
        KernelTarget::Block => {
            if dport == Some(53) {
                ("kernel_drop", "kernel_drop")
            } else {
                ("userspace_reject", "kernel_drop")
            }
        }
        KernelTarget::ControlPlaneRouting => (
            "userspace_control_plane_routing",
            "userspace_control_plane_routing",
        ),
        KernelTarget::UserGroup => ("userspace_proxy", "userspace_proxy"),
    };

    KernelOutcome {
        must: configured_must,
        mark: configured_mark,
        domain_final,
        lan_disposition,
        wan_disposition,
    }
}

fn render_text(report: &RouteReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "decision: {}", report.decision);
    if let Some(outbound) = &report.outbound {
        let _ = write!(out, "outbound: {outbound}");
        if let Some(must) = report.must {
            let _ = write!(out, " (must={must}");
            if let Some(mark) = report.mark {
                let _ = write!(out, ", mark={mark:#x}");
            }
            out.push(')');
        }
        out.push('\n');
    }
    if let Some(rule_idx) = report.matched_rule {
        let _ = writeln!(out, "matched_rule: {rule_idx}");
    } else if report.matched_fallback {
        let _ = writeln!(out, "matched_rule: fallback");
    }
    if !report.missing_inputs.is_empty() {
        let _ = writeln!(out, "missing_inputs: {}", report.missing_inputs.join(", "));
    }
    let _ = writeln!(
        out,
        "native_bpf: compilable={} dial_mode={} clash_mode={} domain_predicates={}",
        report.native_compilable, report.dial_mode, report.clash_mode, report.domain_predicates
    );
    if let Some(err) = &report.native_error {
        let _ = writeln!(out, "native_bpf_error: {err}");
    }
    if let (Some(domain_final), Some(lan), Some(wan)) = (
        report.domain_final,
        report.lan_disposition,
        report.wan_disposition,
    ) {
        let _ = writeln!(
            out,
            "kernel_disposition: domain_final={domain_final} lan={lan} wan={wan}"
        );
    }
    for rule in &report.rules {
        let tag = if rule.kind == "fallback" {
            "fallback".to_owned()
        } else {
            rule.index.to_string()
        };
        let _ = write!(out, "[{tag}] {} {}", rule.result, rule.expression);
        if rule.kind == "rule" {
            let _ = write!(out, " -> {}", rule.outbound);
        }
        if rule.must {
            out.push_str(" (must)");
        }
        if rule.mark != 0 {
            let _ = write!(out, " mark={:#x}", rule.mark);
        }
        if !rule.missing_inputs.is_empty() {
            let _ = write!(out, " [missing: {}]", rule.missing_inputs.join(", "));
        }
        out.push('\n');
    }
    out
}

fn render_json(report: &RouteReport) -> String {
    let mut b = JsonBuf::new();
    b.raw("{");
    let mut f = true;
    b.key(&mut f, "decision");
    b.str(report.decision);
    b.key(&mut f, "outbound");
    b.opt_str(report.outbound.as_deref());
    b.key(&mut f, "matched_rule");
    b.opt_usize(report.matched_rule);
    b.key(&mut f, "matched_fallback");
    b.bool(report.matched_fallback);
    b.key(&mut f, "must");
    b.opt_bool(report.must);
    b.key(&mut f, "mark");
    b.opt_u32(report.mark);
    b.key(&mut f, "missing_inputs");
    b.str_slice(&report.missing_inputs);

    b.key(&mut f, "native_bpf");
    b.raw("{");
    let mut nf = true;
    b.key(&mut nf, "compilable");
    b.bool(report.native_compilable);
    b.key(&mut nf, "error");
    b.opt_str(report.native_error.as_deref());
    b.key(&mut nf, "dial_mode");
    b.str(&report.dial_mode);
    b.key(&mut nf, "clash_mode");
    b.str(report.clash_mode);
    b.key(&mut nf, "domain_predicates");
    b.usize(report.domain_predicates);
    b.key(&mut nf, "domain_final");
    b.opt_bool(report.domain_final);
    b.key(&mut nf, "lan_disposition");
    b.opt_str(report.lan_disposition);
    b.key(&mut nf, "wan_disposition");
    b.opt_str(report.wan_disposition);
    b.raw("}");

    b.key(&mut f, "rules");
    b.raw("[");
    for (i, rule) in report.rules.iter().enumerate() {
        if i > 0 {
            b.raw(",");
        }
        b.raw("{");
        let mut rf = true;
        b.key(&mut rf, "index");
        b.usize(rule.index);
        b.key(&mut rf, "kind");
        b.str(rule.kind);
        b.key(&mut rf, "expression");
        b.str(&rule.expression);
        b.key(&mut rf, "outbound");
        b.str(&rule.outbound);
        b.key(&mut rf, "must");
        b.bool(rule.must);
        b.key(&mut rf, "mark");
        b.uint(rule.mark);
        b.key(&mut rf, "result");
        b.str(rule.result);
        b.key(&mut rf, "missing_inputs");
        b.str_slice(&rule.missing_inputs);
        b.key(&mut rf, "conditions");
        b.raw("[");
        for (ci, cond) in rule.conditions.iter().enumerate() {
            if ci > 0 {
                b.raw(",");
            }
            b.raw("{");
            let mut cf = true;
            b.key(&mut cf, "expression");
            b.str(&cond.expression);
            b.key(&mut cf, "result");
            b.str(cond.result);
            b.key(&mut cf, "missing_inputs");
            b.str_slice(&cond.missing_inputs);
            b.raw("}");
        }
        b.raw("]}");
    }
    b.raw("]}");
    b.finish()
}
