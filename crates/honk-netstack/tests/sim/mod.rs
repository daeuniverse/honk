//! Deterministic, sans-I/O integration harness. `engine::Host` is the packet/timer seam and
//! `app::StreamIo` is the byte-stream seam; the application drivers do not depend on smoltcp.

pub mod app;
pub mod engine;
pub mod honk;
pub mod honk_server;
pub mod link;
pub mod rng;
pub mod smol;
pub mod wire;

use app::{Driver, Metrics, Plan, Role};
use engine::{Host, Outcome, Sim, SimConfig, epoch};
use honk::HonkHost;
use honk_server::HonkServerHost;
use smol::{SmolConfig, SmolHost};
use std::fmt::Debug;
use std::time::Duration;

/// A host whose application driver the completion check and metrics can inspect.
pub trait AppHost: Host {
    type Id: Copy + Debug;
    fn app(&self) -> &Driver<Self::Id>;
}

impl AppHost for SmolHost {
    type Id = usize;
    fn app(&self) -> &Driver<usize> {
        &self.app
    }
}

impl AppHost for HonkHost {
    type Id = honk_netstack::FlowId;
    fn app(&self) -> &Driver<honk_netstack::FlowId> {
        &self.app
    }
}

impl AppHost for HonkServerHost {
    type Id = usize;
    fn app(&self) -> &Driver<usize> {
        &self.app
    }
}

pub fn smoltcp_pair(cfg: &SimConfig, sockets: &SmolConfig, plan: &Plan) -> Sim<SmolHost, SmolHost> {
    Sim::new(
        cfg,
        SmolHost::new(sockets, plan.clone(), Role::Client),
        SmolHost::new(sockets, plan.clone(), Role::Server),
    )
}

/// honk client against a smoltcp listener; `honk_buffer` caps honk's per-flow rings.
pub fn honk_pair(
    cfg: &SimConfig,
    server: &SmolConfig,
    honk_buffer: usize,
    plan: &Plan,
) -> Sim<HonkHost, SmolHost> {
    Sim::new(
        cfg,
        HonkHost::new(server.family, honk_buffer, plan.clone()),
        SmolHost::new(server, plan.clone(), Role::Server),
    )
}

/// Fails with the seed, per-flow progress and link statistics if a transfer stalls.
pub fn finish<A: AppHost, B: AppHost>(sim: &mut Sim<A, B>, seed: u64, bound: Duration) -> Metrics {
    let outcome = sim.run(epoch() + bound, |s| {
        s.a.app().finished() && s.b.app().finished()
    });
    assert_eq!(
        outcome,
        Outcome::Stopped,
        "seed={seed}; client={:?}; server={:?}; forward={:?}; reverse={:?}",
        sim.a.app().flows,
        sim.b.app().flows,
        sim.a_to_b.stats(),
        sim.b_to_a.stats()
    );
    let a = sim.a_to_b.stats();
    let b = sim.b_to_a.stats();
    Metrics::new(
        sim.a.app(),
        sim.b.app(),
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

/// honk client against a honk transparent terminator (`defer` holds each SYN-ACK that long).
pub fn honk_to_transparent(
    cfg: &SimConfig,
    family: smol::Family,
    buffer: usize,
    plan: &Plan,
    defer: Option<Duration>,
) -> Sim<HonkHost, HonkServerHost> {
    Sim::new(
        cfg,
        HonkHost::new(family, buffer, plan.clone()),
        HonkServerHost::new(family, buffer, plan.clone(), defer),
    )
}

/// smoltcp client against a honk transparent terminator.
pub fn smol_to_transparent(
    cfg: &SimConfig,
    sockets: &SmolConfig,
    buffer: usize,
    plan: &Plan,
    defer: Option<Duration>,
) -> Sim<SmolHost, HonkServerHost> {
    Sim::new(
        cfg,
        SmolHost::new(sockets, plan.clone(), Role::Client),
        HonkServerHost::new(sockets.family, buffer, plan.clone(), defer),
    )
}
