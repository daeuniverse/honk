//! Deterministic, sans-I/O integration harness. `engine::Host` is the packet/timer seam and
//! `app::StreamIo` is the byte-stream seam; the application drivers do not depend on smoltcp.

pub mod app;
pub mod engine;
pub mod link;
pub mod rng;
pub mod smol;
pub mod wire;

use app::{Metrics, Plan, Role};
use engine::{Outcome, Sim, SimConfig, epoch};
use smol::{SmolConfig, SmolHost};
use std::time::Duration;

pub fn smoltcp_pair(cfg: &SimConfig, sockets: &SmolConfig, plan: &Plan) -> Sim<SmolHost, SmolHost> {
    Sim::new(
        cfg,
        SmolHost::new(sockets, plan.clone(), Role::Client),
        SmolHost::new(sockets, plan.clone(), Role::Server),
    )
}

/// Fails with the seed, per-flow progress and link statistics if a transfer stalls.
pub fn finish(sim: &mut Sim<SmolHost, SmolHost>, seed: u64, bound: Duration) -> Metrics {
    let outcome = sim.run(epoch() + bound, |s| {
        s.a.app.finished() && s.b.app.finished()
    });
    assert_eq!(
        outcome,
        Outcome::Stopped,
        "seed={seed}; client={:?}; server={:?}; forward={:?}; reverse={:?}",
        sim.a.app.flows,
        sim.b.app.flows,
        sim.a_to_b.stats(),
        sim.b_to_a.stats()
    );
    let a = sim.a_to_b.stats();
    let b = sim.b_to_a.stats();
    Metrics::new(
        &sim.a.app,
        &sim.b.app,
        sim.elapsed(),
        a.wire.tcp_retrans_bytes + b.wire.tcp_retrans_bytes,
        a.max_queue_bytes.max(b.max_queue_bytes),
    )
}

pub fn bdp_bytes(bps: u64, rtt: Duration) -> usize {
    (u128::from(bps) * rtt.as_nanos()).div_ceil(8_000_000_000) as usize
}

pub fn path(seed: u64, rate_bps: u64, rtt: Duration, loss: f64) -> SimConfig {
    let q = bdp_bytes(rate_bps, rtt).max(1420);
    let a_to_b = link::LinkConfig::new(rtt / 2).rate(rate_bps, q).loss(loss);
    let b_to_a = link::LinkConfig::new(rtt / 2).rate(rate_bps, q);
    SimConfig {
        seed,
        a_to_b,
        b_to_a,
        mtu: 1420,
    }
}
