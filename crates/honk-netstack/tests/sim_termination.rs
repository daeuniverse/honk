//! End-to-end validation of the transparent terminator in virtual time: close-order matrix,
//! TIME_WAIT tombstone, loss/reorder/duplication, many flows, and a memory-pressure soak.
//!
//! Every scenario asserts exactly-once ordered delivery (the drivers compare each byte against a
//! per-flow stream), that the terminator only ever sources packets from an accepted flow's
//! original destination, and that every stack's flow, TIME_WAIT, half-open and memory accounting
//! returns to zero once the handles are closed and TIME_WAIT has expired.

pub mod sim;

use honk_netstack::{DropReason, MemoryBudget, Stack};
use sim::app::{Plan, Role};
use sim::engine::{Host, Outcome, Sim, epoch};
use sim::extra::{Fleet, Tap, tcp_flags};
use sim::honk::HonkHost;
use sim::honk_server::{HonkServerHost, ServerOpts};
use sim::smol::{Family, SmolConfig, SmolHost};
use std::cell::Cell;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const SEED: u64 = 0x5445_524D_494E_4154;
const ACK: u8 = honk_netstack::wire::tcp::ACK;
const FIN: u8 = honk_netstack::wire::tcp::FIN;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn run_for<A: Host, B: Host>(sim: &mut Sim<A, B>, d: Duration) {
    let deadline = sim.now() + d;
    sim.run(deadline, |_| false);
}

fn assert_zero(stack: &Stack, what: &str) {
    let s = stack.stats();
    assert_eq!(
        (s.flows, s.timewait_entries, s.half_open, s.memory_committed),
        (0, 0, 0, 0),
        "{what}: {s:?}"
    );
}

fn assert_transparent(b: &HonkServerHost) {
    let a = &b.io.audit;
    assert!(a.tcp_packets > 0, "{a:?}");
    assert_eq!(
        a.foreign, 0,
        "a reply was not sourced from an original destination: {a:?}"
    );
}

/// A lossy, reordering, duplicating path in both directions.
fn rough_path(rate: u64, rtt: Duration) -> sim::engine::SimConfig {
    let mut cfg = sim::path(SEED, rate, rtt, 0.01);
    for l in [&mut cfg.a_to_b, &mut cfg.b_to_a] {
        l.loss = 0.01;
        l.jitter = rtt / 8;
        l.reorder = 0.03;
        l.reorder_hold = rtt / 3;
        l.duplicate = 0.005;
    }
    cfg
}

#[derive(Clone, Copy, Debug)]
enum Order {
    /// Both sides send and shut down at once: the FINs cross.
    Crossing,
    ClientFirst,
    ServerFirst,
}

fn plan_for(order: Order) -> Plan {
    let mut plan = match order {
        Order::Crossing => {
            let mut p = Plan::upload(150_000);
            p.server_bytes = 150_000;
            p
        }
        _ => Plan::request_response(60_000, 180_000),
    };
    plan.flows = 4;
    plan.fin_after_peer = match order {
        Order::Crossing => None,
        Order::ClientFirst => Some(Role::Server),
        Order::ServerFirst => Some(Role::Client),
    };
    plan
}

#[test]
fn close_order_decides_who_keeps_time_wait_and_everything_drains() {
    for order in [Order::Crossing, Order::ClientFirst, Order::ServerFirst] {
        for family in [Family::V4, Family::V6] {
            let cfg = rough_path(30_000_000, Duration::from_millis(30));
            let plan = plan_for(order);
            let server = HonkServerHost::with(
                family,
                MIB,
                plan.clone(),
                None,
                ServerOpts {
                    close_when_done: true,
                    ..ServerOpts::default()
                },
            );
            let mut s = Sim::new(&cfg, HonkHost::new(family, MIB, plan.clone()), server);
            let m = sim::finish(&mut s, SEED, secs(300));
            assert!(
                m.retransmitted_bytes > 0,
                "{order:?}: the path never lost anything"
            );
            run_for(&mut s, secs(20));
            assert_transparent(&s.b);
            let n = plan.flows;
            // The terminator closed its handles when its side completed.
            let t = s.b.io.stack.stats();
            assert_eq!(t.flows, 0, "{order:?} {family:?}: {t:?}");
            match order {
                Order::ClientFirst => assert_eq!(t.timewait_entries, 0, "passive closer: {t:?}"),
                Order::ServerFirst => assert_eq!(t.timewait_entries, n, "active closer: {t:?}"),
                Order::Crossing => {}
            }
            s.a.close_all();
            run_for(&mut s, secs(1));
            let c = s.a.io.stack.stats();
            match order {
                Order::ClientFirst => assert_eq!(c.timewait_entries, n, "active closer: {c:?}"),
                Order::ServerFirst => assert_eq!(c.timewait_entries, 0, "passive closer: {c:?}"),
                Order::Crossing => {}
            }
            run_for(&mut s, secs(70));
            assert_zero(&s.a.io.stack, "client");
            assert_zero(&s.b.io.stack, "terminator");
        }
    }
}

#[test]
fn a_lost_final_ack_is_repaired_by_the_time_wait_tombstone() {
    // The server closes first and drops its handle at once: only the compact entry is left when the
    // client's FIN arrives. The ACK of that FIN is lost, so the client retransmits the FIN into
    // the tombstone, which must acknowledge it instead of resetting.
    let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(40), 0.0);
    let mut plan = Plan::request_response(10_000, 30_000);
    plan.fin_after_peer = Some(Role::Client);
    let server = HonkServerHost::with(
        Family::V4,
        MIB,
        plan.clone(),
        None,
        ServerOpts {
            close_when_done: true,
            ..ServerOpts::default()
        },
    );
    let mut sent_fin = false;
    let mut dropped = false;
    let server = Tap::new(server, move |p| {
        match tcp_flags(p) {
            Some((f, _)) if f & FIN != 0 => sent_fin = true,
            Some((f, 0)) if f == ACK && sent_fin && !dropped => {
                dropped = true;
                return true;
            }
            _ => {}
        }
        false
    });
    let client_fins = Rc::new(Cell::new(0u32));
    let seen = client_fins.clone();
    let client = Tap::new(HonkHost::new(Family::V4, MIB, plan.clone()), move |p| {
        if tcp_flags(p).is_some_and(|(f, _)| f & FIN != 0) {
            seen.set(seen.get() + 1);
        }
        false
    });
    let mut s = Sim::new(&cfg, client, server);
    sim::finish(&mut s, SEED, secs(60));
    let id = s.a.host.app.flows[0].id;
    let closed = s.run(s.now() + secs(30), |s| {
        s.a.host.io.stack.tcp_state(id) == Some(honk_netstack::TcpState::Closed)
    });
    assert_eq!(
        closed,
        Outcome::Stopped,
        "the client never completed its close"
    );
    assert_eq!(
        s.b.dropped, 1,
        "the tap must have eaten the ACK of the client's FIN"
    );
    assert!(
        client_fins.get() >= 2,
        "the client never retransmitted its FIN"
    );
    let t = s.b.host.io.stack.stats();
    assert_eq!((t.flows, t.timewait_entries), (0, 1), "{t:?}");
    assert_eq!(
        s.b.host.io.audit.rsts, 0,
        "the tombstone answered a late FIN with RST"
    );
    assert_transparent(&s.b.host);
    s.a.host.close_all();
    run_for(&mut s, secs(70));
    assert_zero(&s.a.host.io.stack, "client");
    assert_zero(&s.b.host.io.stack, "terminator");
}

#[test]
fn bulk_both_ways_survives_loss_reorder_and_duplication() {
    for (family, order) in [
        (Family::V4, Order::Crossing),
        (Family::V6, Order::ClientFirst),
    ] {
        let cfg = rough_path(50_000_000, Duration::from_millis(50));
        let mut plan = plan_for(order);
        plan.client_bytes = 2 * MIB;
        plan.server_bytes = 2 * MIB;
        plan.flows = 3;
        let mut s = sim::honk_to_transparent(&cfg, family, MIB, &plan, None);
        let m = sim::finish(&mut s, SEED, secs(600));
        assert!(m.retransmitted_bytes > 0, "{m:?}");
        let (fwd, rev) = (s.a_to_b.stats(), s.b_to_a.stats());
        assert!(fwd.reordered > 0 && rev.reordered > 0, "{fwd:?} {rev:?}");
        assert!(fwd.duplicated + rev.duplicated > 0);
        assert_transparent(&s.b);
        s.b.io.close_all();
        s.a.close_all();
        run_for(&mut s, secs(130));
        assert_zero(&s.a.io.stack, "client");
        assert_zero(&s.b.io.stack, "terminator");
    }
}

#[test]
fn half_close_keeps_the_other_direction_flowing() {
    // The server has nothing to say and shuts down at once; the client's upload must still land
    // in full after the server's FIN. Then the reverse: a download after the client's FIN.
    for (name, plan) in [
        ("server FIN first", Plan::upload(MIB)),
        ("client FIN first", Plan::download(MIB)),
    ] {
        let cfg = rough_path(30_000_000, Duration::from_millis(40));
        let mut s = sim::honk_to_transparent(&cfg, Family::V4, 256 * 1024, &plan, None);
        sim::finish(&mut s, SEED, secs(300));
        assert_transparent(&s.b);
        s.b.io.close_all();
        s.a.close_all();
        run_for(&mut s, secs(130));
        assert_zero(&s.a.io.stack, name);
        assert_zero(&s.b.io.stack, name);
    }
}

#[test]
fn hundreds_of_flows_with_deferred_accept_complete_and_drain() {
    let cfg = sim::path(SEED, 100_000_000, Duration::from_millis(20), 0.002);
    let mut plan = Plan::request_response(20_000, 60_000);
    plan.flows = 400;
    let mut s = sim::honk_to_transparent(
        &cfg,
        Family::V4,
        256 * 1024,
        &plan,
        Some(Duration::from_millis(1500)),
    );
    sim::finish(&mut s, SEED, secs(300));
    assert_transparent(&s.b);
    let t = s.b.io.stack.stats();
    // A deferred SYN retransmitted during the hold never made a second flow.
    assert_eq!(t.flows, 400, "{t:?}");
    s.b.io.close_all();
    s.a.close_all();
    run_for(&mut s, secs(130));
    assert_zero(&s.a.io.stack, "client");
    assert_zero(&s.b.io.stack, "terminator");
}

#[test]
fn smoltcp_clients_in_every_close_order_against_the_terminator() {
    for order in [Order::Crossing, Order::ClientFirst, Order::ServerFirst] {
        for family in [Family::V4, Family::V6] {
            let mut sockets = SmolConfig::buffers(MIB);
            sockets.family = family;
            let cfg = rough_path(30_000_000, Duration::from_millis(40));
            let plan = plan_for(order);
            let mut s: Sim<SmolHost, HonkServerHost> =
                sim::smol_to_transparent(&cfg, &sockets, MIB, &plan, None);
            sim::finish(&mut s, SEED, secs(300));
            assert_transparent(&s.b);
            s.b.io.close_all();
            run_for(&mut s, secs(130));
            assert_zero(&s.b.io.stack, "terminator");
        }
    }
}

/// What a multi-source run measured.
#[derive(Debug)]
struct Soak {
    /// Per source: from its start until its last flow completed.
    latency: Vec<Duration>,
    peak_budget: usize,
    /// SYNs refused for lack of flow table or memory floors.
    syn_drops: u64,
    elapsed: Duration,
}

/// `flows[k]` flows from source `k` (starting `stagger` apart) against one terminator whose memory
/// is the shared `budget_bytes`. Checks the invariants that must hold under any pressure.
fn soak(flows: &[usize], budget_bytes: usize, stagger: Duration, bound: Duration) -> Soak {
    let stride = *flows.iter().max().unwrap();
    let mut base = Plan::request_response(48_000, 96_000);
    base.app_chunk = 8 * 1024;
    let budget = MemoryBudget::new(budget_bytes);
    let b = budget.clone();
    let mut plan = base.clone();
    plan.flows = flows.len() * stride;
    let server = HonkServerHost::with(
        Family::V4,
        256 * 1024,
        plan,
        None,
        ServerOpts {
            per_source: Some(stride),
            close_when_done: true,
            config: Some(Box::new(move |cfg| cfg.shared_budget = Some(b))),
        },
    );
    let server_ip: IpAddr = Family::V4.address(Role::Server).into();
    let fleet = Fleet::new(flows, server_ip, 256 * 1024, &base, stagger);
    let cfg = sim::path(SEED, 200_000_000, Duration::from_millis(20), 0.0);
    let mut s = Sim::new(&cfg, fleet, server);
    let mut peak = 0;
    let outcome = s.run(epoch() + bound, |s| {
        peak = peak.max(budget.used());
        // The budget is a hard limit, and an admitted flow is never reset by memory pressure:
        // the drivers panic on any read/write error.
        assert!(budget.used() <= budget.limit());
        s.a.finished()
            && s.b
                .app
                .flows
                .iter()
                .enumerate()
                .all(|(i, f)| s.b.io.admitted[i].is_none() || f.completed.is_some())
    });
    assert_eq!(
        outcome,
        Outcome::Stopped,
        "terminator {:?}",
        s.b.io.stack.stats()
    );
    let total: usize = flows.iter().sum();
    assert_eq!(
        s.b.io.admitted.iter().flatten().count(),
        total,
        "every flow was admitted"
    );
    let latency = (0..flows.len())
        .map(|k| {
            let c = s.a.clients[k].as_ref().unwrap();
            c.app
                .flows
                .iter()
                .filter_map(|f| f.completed)
                .max()
                .unwrap()
                - s.a.start_of(k)
        })
        .collect();
    let syn_drops = s.b.io.stack.stats().drops[DropReason::Capacity as usize];
    assert_transparent(&s.b);
    let elapsed = s.elapsed();
    s.a.close_all();
    s.b.io.close_all();
    run_for(&mut s, secs(130));
    for c in s.a.live() {
        assert_zero(&c.io.stack, "client");
    }
    assert_zero(&s.b.io.stack, "terminator");
    assert_eq!(budget.used(), 0, "the shared budget did not drain");
    Soak {
        latency,
        peak_budget: peak,
        syn_drops,
        elapsed,
    }
}

fn seconds(v: &[Duration]) -> Vec<f64> {
    v.iter().map(Duration::as_secs_f64).collect()
}

#[test]
fn soak_staggered_sources_under_a_small_shared_budget_all_progress() {
    // 40 sources x 8 flows arrive 60 ms apart against a budget that funds about twenty flows: the
    // load is pressure, not a storm. Every flow of every source is admitted and completes.
    let flows = vec![8; 40];
    let r = soak(&flows, 3 * MIB / 2, Duration::from_millis(60), secs(600));
    eprintln!("staggered sources: {r:?}");
    let t = seconds(&r.latency);
    assert!(
        r.syn_drops > 0,
        "the budget was never under pressure: {r:?}"
    );
    assert!(
        t.iter().all(|&v| v < 30.0),
        "a source waited far longer than its transfer takes: {t:?}"
    );
    assert!(sim::app::jain(&t) > 0.5, "latencies are unfair: {t:?}");
}

#[test]
fn soak_a_syn_herd_beyond_the_budget_is_served_in_retry_waves_without_loss() {
    // 15 sources x 8 flows dial at the same instant, three times what the budget funds. The
    // refused SYNs are silent drops; clients retry on their backoff (1, 2, 4 s ...) and every
    // flow is admitted by the last wave. Admission is first come first served, so this bounds
    // time-to-admit, not fairness: that is the TC per-source budget's job (design 3.2).
    let flows = vec![8; 15];
    let r = soak(&flows, 3 * MIB, Duration::ZERO, secs(600));
    eprintln!("syn herd: {r:?}");
    assert!(r.syn_drops > 0, "no SYN was refused: {r:?}");
    assert!(r.elapsed < secs(60), "{r:?}");
}

#[test]
fn soak_a_greedy_source_cannot_starve_polite_ones() {
    // One source opens 120 flows, twenty others 4 each, all at once.
    let mut flows = vec![4; 21];
    flows[0] = 120;
    let r = soak(&flows, 3 * MIB, Duration::ZERO, secs(600));
    eprintln!("greedy source: {r:?}");
    let polite = *r.latency[1..].iter().max().unwrap();
    assert!(r.syn_drops > 0, "no SYN was refused: {r:?}");
    assert!(
        polite < r.latency[0],
        "polite sources ({polite:?}) finished after the greedy one ({:?})",
        r.latency[0]
    );
}
