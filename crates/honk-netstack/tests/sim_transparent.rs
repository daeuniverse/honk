//! honk and smoltcp clients against a honk transparent terminator, end to end in virtual time.

pub mod sim;

use sim::app::Plan;
use sim::smol::{Family, SmolConfig};
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const SEED: u64 = 0x5452_414E_5350_4152;

/// Closes every flow on both sides and lets TIME_WAIT run out: nothing may stay charged.
fn assert_returns_to_zero<A: sim::engine::Host>(
    sim: &mut sim::engine::Sim<A, sim::honk_server::HonkServerHost>,
) {
    sim.b.io.close_all();
    let deadline = sim.now() + Duration::from_secs(130);
    sim.run(deadline, |_| false);
    let stats = sim.b.io.stack.stats();
    assert_eq!(stats.flows, 0, "{stats:?}");
    assert_eq!(stats.timewait_entries, 0, "{stats:?}");
    assert_eq!(stats.half_open, 0, "{stats:?}");
    assert_eq!(stats.memory_committed, 0, "{stats:?}");
}

#[test]
fn honk_client_and_transparent_honk_exchange_bulk_data_both_ways_through_loss() {
    let mut cfg = sim::path(SEED, 20_000_000, Duration::from_millis(40), 0.01);
    cfg.b_to_a = cfg.b_to_a.loss(0.01);
    let plan = Plan::request_response(MIB, 2 * MIB);
    let mut s = sim::honk_to_transparent(&cfg, Family::V4, MIB, &plan, None);
    let m = sim::finish(&mut s, SEED, Duration::from_secs(300));
    assert!(m.retransmitted_bytes > 0, "{m:?}");
    assert_returns_to_zero(&mut s);
}

#[test]
fn simultaneous_bulk_transfers_over_ipv6_and_many_flows() {
    let cfg = sim::path(SEED, 50_000_000, Duration::from_millis(20), 0.002);
    let mut plan = Plan::upload(300_000);
    plan.flows = 6;
    plan.server_bytes = 300_000;
    let mut s = sim::honk_to_transparent(&cfg, Family::V6, 256 * 1024, &plan, None);
    sim::finish(&mut s, SEED, Duration::from_secs(120));
    assert_returns_to_zero(&mut s);
}

#[test]
fn deferred_accept_survives_syn_retransmissions_without_a_second_flow() {
    let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(40), 0.0);
    let mut plan = Plan::request_response(50_000, 200_000);
    plan.flows = 4;
    // Longer than the client's 1 s SYN timer: several SYNs arrive while the flow is held.
    let mut s = sim::honk_to_transparent(
        &cfg,
        Family::V4,
        MIB,
        &plan,
        Some(Duration::from_millis(2500)),
    );
    sim::finish(&mut s, SEED, Duration::from_secs(60));
    assert_returns_to_zero(&mut s);
}

#[test]
fn smoltcp_client_against_transparent_honk() {
    for (family, loss) in [(Family::V4, 0.0), (Family::V6, 0.01)] {
        let mut sockets = SmolConfig::buffers(MIB);
        sockets.family = family;
        let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(50), loss);
        let mut plan = Plan::request_response(200_000, MIB);
        plan.flows = 3;
        let mut s = sim::smol_to_transparent(&cfg, &sockets, MIB, &plan, None);
        sim::finish(&mut s, SEED, Duration::from_secs(300));
        assert_returns_to_zero(&mut s);
    }
}
