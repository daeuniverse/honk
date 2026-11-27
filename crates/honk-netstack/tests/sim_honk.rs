pub mod sim;
#[path = "sim_honk/sink.rs"]
mod sink;

use sim::app::Plan;
use sim::engine::PullBudget;
use sim::engine::{Outcome, Sim, epoch};
use sim::honk::HonkHost;
use sim::smol::{Family, SmolConfig};
use sink::{Sink, SinkConfig};
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const SEED: u64 = 0x0048_4F4E_4B53_494D;

fn honk_stats<B: sim::engine::Host>(
    s: &sim::engine::Sim<sim::honk::HonkHost, B>,
) -> honk_netstack::TcpStats {
    s.a.io.stack.tcp_stats(s.a.app.flows[0].id).expect("flow")
}

fn server(buffer: usize) -> SmolConfig {
    SmolConfig::buffers(buffer)
}

#[test]
fn honk_completes_upload_and_download_through_one_percent_data_loss() {
    for (plan, lossy_forward) in [
        (Plan::upload(2 * MIB), true),
        (Plan::download(2 * MIB), false),
    ] {
        let mut cfg = sim::path(SEED, 20_000_000, Duration::from_millis(65), 0.0);
        if lossy_forward {
            cfg.a_to_b = cfg.a_to_b.loss(0.01);
        } else {
            cfg.b_to_a = cfg.b_to_a.loss(0.01);
        }
        let mut s = sim::honk_pair(&cfg, &server(MIB), MIB, &plan);
        let m = sim::finish(&mut s, SEED, Duration::from_secs(300));
        assert!(m.retransmitted_bytes > 0, "{m:?}");
    }
}

#[test]
fn honk_request_response_over_ipv6_and_many_flows() {
    let cfg = sim::path(SEED, 50_000_000, Duration::from_millis(20), 0.0);
    let mut sock = server(256 * 1024);
    sock.family = Family::V6;
    let mut plan = Plan::request_response(3000, 200_000);
    plan.flows = 8;
    let mut s = sim::honk_pair(&cfg, &sock, 256 * 1024, &plan);
    let m = sim::finish(&mut s, SEED, Duration::from_secs(60));
    assert!(m.jain > 0.5, "{m:?}");
}

#[test]
fn honk_pull_budget_one_delivers_the_same_streams_as_unlimited() {
    let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(30), 0.01);
    let plan = Plan::request_response(64 * 1024, 512 * 1024);
    for budget in [PullBudget::Packets(1), PullBudget::Unlimited] {
        let mut s = sim::honk_pair(&cfg, &server(MIB), MIB, &plan);
        s.budget_a = budget;
        sim::finish(&mut s, SEED, Duration::from_secs(300));
    }
}

/// 4 MiB upload into a smoltcp listener over 20 Mbit/s, 65 ms and a 1-BDP drop-tail queue. The
/// smoltcp receiver keeps four OOO ranges and one SACK block, so slow-start overshoot is a
/// multi-hole recovery that one-hole-per-RTT NewReno needs tens of seconds to repair.
#[test]
fn honk_upload_to_smoltcp_over_shallow_queue_beats_smoltcp() {
    let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(65), 0.0);
    let plan = Plan::upload(4 * MIB);
    let bound = Duration::from_secs(120);
    let mut smol = sim::smoltcp_pair(&cfg, &server(MIB), &plan);
    let base = sim::finish(&mut smol, SEED, bound);
    let mut honk = sim::honk_pair(&cfg, &server(MIB), MIB, &plan);
    let ours = sim::finish(&mut honk, SEED, bound);
    let st = honk_stats(&honk);
    println!("smoltcp {base:?}\nhonk {ours:?}\n{st:?}");
    // Slow-start overshoot must be repaired by recovery, not by timeouts.
    assert_eq!(st.rto_count, 0, "{st:?}");
    // 20 Mbit/s of IP bytes carries 1368 payload bytes per 1420.
    assert!(
        (2_000_000..=2_500_000).contains(&st.delivery_rate),
        "the rate estimate must see the bottleneck: {st:?}"
    );
    assert!(
        ours.goodput_mbps >= base.goodput_mbps,
        "{ours:?} vs {base:?}"
    );
    assert!(
        ours.retransmitted_bytes < base.retransmitted_bytes,
        "{ours:?} vs {base:?}"
    );
}

/// honk uploads to the scripted receiver; returns the finished simulation and its metrics.
fn upload_to_sink(
    cfg: &sim::engine::SimConfig,
    sink: SinkConfig,
    bytes: usize,
    bound: Duration,
) -> (Sim<HonkHost, Sink>, u64) {
    let plan = Plan::upload(bytes);
    let server = Family::V4.address(sim::app::Role::Server).into();
    let mut s = Sim::new(
        cfg,
        HonkHost::new(Family::V4, MIB, plan),
        Sink::new(server, sink),
    );
    let outcome = s.run(epoch() + bound, |s| s.a.app.finished());
    let stats = honk_stats(&s);
    assert_eq!(
        outcome,
        Outcome::Stopped,
        "stalled; {stats:?}; {:?}",
        s.a_to_b.stats()
    );
    assert_eq!(
        s.b.received, bytes as u64,
        "exactly-once, in-order delivery"
    );
    let retrans = s.a_to_b.stats().wire.tcp_retrans_bytes;
    (s, retrans)
}

/// Phase 0 comparison on identical links and server: honk client versus smoltcp client.
#[test]
#[ignore = "comparison grid; run with --ignored --nocapture"]
fn honk_vs_smoltcp_grid() {
    println!("| direction | loss % | RTT ms | buffer KiB | smoltcp Mbit/s | honk Mbit/s | ratio |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for upload in [true, false] {
        for loss in [0.0, 0.01] {
            for rtt in [1, 65] {
                let buffer = 4 * MIB;
                let mut cfg = sim::path(SEED, 100_000_000, Duration::from_millis(rtt), 0.0);
                let plan = if upload {
                    cfg.a_to_b = cfg.a_to_b.loss(loss);
                    Plan::upload(8 * MIB)
                } else {
                    cfg.b_to_a = cfg.b_to_a.loss(loss);
                    Plan::download(8 * MIB)
                };
                let bound = Duration::from_secs(3600);
                let mut smol = sim::smoltcp_pair(&cfg, &server(buffer), &plan);
                let base = sim::finish(&mut smol, SEED, bound).goodput_mbps;
                let mut honk = sim::honk_pair(&cfg, &server(buffer), buffer, &plan);
                let ours = sim::finish(&mut honk, SEED, bound).goodput_mbps;
                println!(
                    "| {} | {:.0} | {rtt} | {} | {base:.3} | {ours:.3} | {:.2} |",
                    if upload { "upload" } else { "download" },
                    loss * 100.0,
                    buffer / 1024,
                    ours / base
                );
            }
        }
    }
}

/// Link reordering that holds 2% of the packets for less than a quarter RTT. A recovery started
/// before the held packet arrives is spurious; the DSACK of its retransmission must give the
/// window back, and the widened reorder window must keep the next ones from starting.
#[test]
fn honk_undoes_spurious_recoveries_caused_by_link_reordering() {
    let rtt = Duration::from_millis(40);
    let mut cfg = sim::path(SEED, 50_000_000, rtt, 0.0);
    cfg.a_to_b.queue_bytes = 4 * sim::bdp_bytes(50_000_000, rtt);
    cfg.a_to_b.reorder = 0.02;
    cfg.a_to_b.reorder_hold = rtt / 5;
    let bytes = 16 * MIB;
    let sink = SinkConfig {
        sack: true,
        max_ranges: 32,
        drop_ooo: false,
    };
    let plan = Plan::upload(bytes);
    let server = Family::V4.address(sim::app::Role::Server).into();
    let mut s = Sim::new(
        &cfg,
        HonkHost::new(Family::V4, MIB, plan),
        Sink::new(server, sink),
    );
    // Watch the window across the first spurious recovery, millisecond by millisecond.
    let mut before_loss = 0;
    let mut restored = None;
    let mut t = Duration::ZERO;
    while !s.a.app.finished() {
        t += Duration::from_millis(1);
        assert!(t < Duration::from_secs(60), "stalled: {:?}", honk_stats(&s));
        s.run(epoch() + t, |s| s.a.app.finished());
        let st = honk_stats(&s);
        if st.loss_events == 0 {
            before_loss = before_loss.max(st.cwnd);
        }
        if st.undo_count == 1 && restored.is_none() {
            restored = Some(st.cwnd);
        }
    }
    let st = honk_stats(&s);
    assert_eq!(
        s.b.received, bytes as u64,
        "exactly-once, in-order delivery"
    );
    assert!(
        st.loss_events >= 1,
        "the scenario must provoke a recovery: {st:?}"
    );
    assert_eq!(
        st.undo_count, st.loss_events,
        "every recovery here is spurious and must be undone: {st:?}"
    );
    assert_eq!(st.spurious_recoveries, st.undo_count);
    assert!(
        restored.unwrap() >= before_loss,
        "cwnd {} after the undo, {before_loss} before the loss",
        restored.unwrap()
    );
    let retrans = s.a_to_b.stats().wire.tcp_retrans_bytes;
    assert!(
        retrans < bytes as u64 / 50,
        "{retrans} B retransmitted: {st:?}"
    );
    let mbps = bytes as f64 * 8.0 / s.elapsed().as_secs_f64() / 1e6;
    assert!(mbps > 40.0, "{mbps:.1} Mbit/s of 50: {st:?}");
}

/// RFC 6582 on a path whose receiver has no SACK and keeps no out-of-order data: every hole costs a
/// round trip unless the retransmission timer is left running ("impatient" variant) and its
/// go-back-N repair takes over. Restarting the timer on every partial ACK takes over 90 s here.
#[test]
fn honk_repairs_a_receiver_without_sack_or_reassembly_in_seconds() {
    let cfg = sim::path(SEED, 20_000_000, Duration::from_millis(65), 0.0);
    let sink = SinkConfig {
        sack: false,
        max_ranges: 0,
        drop_ooo: true,
    };
    let (s, retrans) = upload_to_sink(&cfg, sink, 4 * MIB, Duration::from_secs(60));
    let st = honk_stats(&s);
    assert!(
        s.b.dropped_ooo > 100,
        "the scenario must overflow the queue: {st:?}"
    );
    assert!(
        s.elapsed() < Duration::from_secs(10),
        "{:?}: {st:?}",
        s.elapsed()
    );
    assert!(retrans < 4 * 4 * MIB as u64, "{retrans} B retransmitted");
}
