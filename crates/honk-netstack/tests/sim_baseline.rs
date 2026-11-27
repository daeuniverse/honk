pub mod sim;

use sim::app::{Plan, fill_pattern, jain};
use sim::engine::{Host, Outcome, PullBudget, epoch};
use sim::link::{GilbertElliott, Link, LinkConfig};
use sim::smol::{Family, SmolConfig};
use sim::wire::WireTracker;
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const WAN_SEED: u64 = 0x0006_501C_0B1C;

#[test]
fn smoltcp_wan_upload_no_loss() {
    let cfg = sim::path(WAN_SEED, 20_000_000, Duration::from_millis(65), 0.0);
    let mut s = sim::smoltcp_pair(
        &cfg,
        &SmolConfig::buffers(256 * 1024),
        &Plan::upload(2 * MIB),
    );
    let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(60));
    assert!(m.goodput_mbps > 5.0, "{m:?}");
    assert_eq!(s.a_to_b.stats().dropped_loss, 0);
    assert_eq!(s.a_to_b.stats().dropped_queue, 0);
    assert_eq!(m.retransmitted_bytes, 0, "{m:?}");
    assert!(m.max_queue_bytes <= cfg.a_to_b.queue_bytes);
    assert_eq!(m.jain, 1.0);
}

#[test]
fn smoltcp_wan_upload_one_percent_data_loss() {
    let cfg = sim::path(WAN_SEED, 20_000_000, Duration::from_millis(65), 0.01);
    let mut s = sim::smoltcp_pair(
        &cfg,
        &SmolConfig::buffers(256 * 1024),
        &Plan::upload(2 * MIB),
    );
    let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(300));
    assert!(s.a_to_b.stats().dropped_loss > 0);
    assert_eq!(
        s.b_to_a.stats().dropped_loss,
        0,
        "only the data direction is lossy"
    );
    assert!(m.retransmitted_bytes > 0, "{m:?}");
    assert!(m.max_queue_bytes <= cfg.a_to_b.queue_bytes);
}

#[test]
fn smoltcp_bulk_download_and_request_response_over_ipv6() {
    for plan in [
        Plan::download(512 * 1024),
        Plan::request_response(4097, 65539),
    ] {
        let mut cfg = sim::path(0x60_6D0, 20_000_000, Duration::from_millis(65), 0.0);
        cfg.b_to_a.loss = 0.01;
        let mut sockets = SmolConfig::buffers(256 * 1024);
        sockets.family = Family::V6;
        let mut s = sim::smoltcp_pair(&cfg, &sockets, &plan);
        let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(300));
        assert!(m.goodput_mbps > 0.0);
        assert_eq!(s.a_to_b.stats().dropped_loss, 0);
    }
}

#[test]
fn smoltcp_many_flow_reports_per_flow_fairness() {
    let cfg = sim::path(0x8F10, 20_000_000, Duration::from_millis(65), 0.0);
    let mut s = sim::smoltcp_pair(
        &cfg,
        &SmolConfig::buffers(128 * 1024),
        &Plan::many_flow(8, 256 * 1024),
    );
    let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(300));
    assert_eq!(m.flow_goodput_mbps.len(), 8);
    assert!(m.flow_goodput_mbps.iter().all(|&x| x > 0.0));
    assert!(m.jain > 0.8 && m.jain <= 1.0 + f64::EPSILON, "{m:?}");
}

#[test]
fn per_flow_goodput_waits_for_peer_delivery_not_local_enqueue() {
    use sim::app::{Driver, Metrics, Role};
    let plan = Plan::many_flow(2, 1000);
    let mut client = Driver::new(plan.clone(), Role::Client, 0..2, epoch());
    let mut server = Driver::new(plan, Role::Server, 0..2, epoch());
    for (i, (c, s)) in client.flows.iter_mut().zip(&mut server.flows).enumerate() {
        c.sent = 1000;
        c.fin = true;
        c.shutdown = true;
        c.completed = Some(epoch() + Duration::from_secs(i as u64 + 1));
        s.received = 1000;
        s.fin = true;
        s.shutdown = true;
        s.completed = Some(epoch() + Duration::from_secs(4));
    }
    let m = Metrics::new(&client, &server, Duration::from_secs(4), 0, 0);
    assert_eq!(
        m.flow_goodput_mbps,
        vec![0.002, 0.002],
        "equal delivered rates despite different enqueue times"
    );
    assert_eq!(m.jain, 1.0);
}

#[test]
fn pulling_one_n_or_unlimited_delivers_the_same_bytes_and_fins() {
    let mut cfg = sim::path(0x00B0_D6E7, 10_000_000, Duration::from_millis(65), 0.01);
    cfg.a_to_b.reorder = 0.02;
    cfg.a_to_b.reorder_hold = Duration::from_millis(2);
    cfg.a_to_b.duplicate = 0.01;
    let plan = Plan::request_response(128 * 1024 + 7, 192 * 1024 + 3);
    let sockets = SmolConfig::buffers(128 * 1024);
    let mut delivered = Vec::new();
    for budget in [
        PullBudget::Packets(1),
        PullBudget::Packets(7),
        PullBudget::Unlimited,
    ] {
        let mut s = sim::smoltcp_pair(&cfg, &sockets, &plan);
        s.budget_a = budget;
        s.budget_b = budget;
        sim::finish(&mut s, cfg.seed, Duration::from_secs(300));
        delivered.push((
            s.a.app.flows[0].received,
            s.b.app.flows[0].received,
            s.a.app.flows[0].fin,
            s.b.app.flows[0].fin,
        ));
    }
    assert!(delivered.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn a_zero_pull_budget_can_resume_without_losing_obligations() {
    let cfg = sim::path(0x00B0_D6E7, 20_000_000, Duration::from_millis(65), 0.0);
    let plan = Plan::upload(256 * 1024 + 1);
    let mut s = sim::smoltcp_pair(&cfg, &SmolConfig::buffers(256 * 1024), &plan);
    s.budget_a = PullBudget::Packets(0);
    s.budget_b = PullBudget::Packets(0);
    assert_eq!(
        s.run(epoch() + Duration::from_secs(3), |_| false),
        Outcome::Deadline
    );
    assert_eq!(s.a_to_b.stats().sent_packets, 0);
    assert_eq!(s.b_to_a.stats().sent_packets, 0);
    s.budget_a = PullBudget::Packets(1);
    s.budget_b = PullBudget::Packets(1);
    let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(60));
    assert!(m.completion >= Duration::from_secs(3));
}

#[test]
fn zero_pull_budget_still_services_future_timer_deadlines() {
    struct TimedHost {
        fired: u32,
    }
    impl Host for TimedHost {
        fn receive(&mut self, _: std::time::Instant, _: &[u8]) {
            panic!("no packet expected")
        }
        fn poll_transmit(&mut self, _: std::time::Instant, _: &mut [u8]) -> Option<usize> {
            panic!("zero budget must never pull")
        }
        fn poll_timeout(&self) -> Option<std::time::Instant> {
            (self.fired < 3).then(|| epoch() + Duration::from_secs(u64::from(self.fired + 1)))
        }
        fn handle_timeout(&mut self, now: std::time::Instant) {
            assert_eq!(
                Some(now),
                self.poll_timeout(),
                "deliver each timer at its target instant"
            );
            self.fired += 1;
        }
        fn poll_app(&mut self, _: std::time::Instant) {}
    }
    let cfg = sim::path(1, 20_000_000, Duration::from_millis(65), 0.0);
    let mut s = sim::engine::Sim::new(&cfg, TimedHost { fired: 0 }, TimedHost { fired: 0 });
    s.budget_a = PullBudget::Packets(0);
    s.budget_b = PullBudget::Packets(0);
    assert_eq!(
        s.run(epoch() + Duration::from_secs(4), |_| false),
        Outcome::Deadline
    );
    assert_eq!(s.a.fired, 3);
    assert_eq!(s.b.fired, 3);
}

#[test]
fn pausing_mid_transfer_retains_pending_data_and_ack_work() {
    let cfg = sim::path(0x57A11, 20_000_000, Duration::from_millis(65), 0.0);
    let mut s = sim::smoltcp_pair(
        &cfg,
        &SmolConfig::buffers(256 * 1024),
        &Plan::upload(512 * 1024),
    );
    assert_eq!(
        s.run(epoch() + Duration::from_secs(30), |s| s.b.app.flows[0]
            .received
            >= 32768),
        Outcome::Stopped
    );
    let sent = (s.a_to_b.stats().sent_packets, s.b_to_a.stats().sent_packets);
    let resume = s.now() + Duration::from_secs(3);
    s.budget_a = PullBudget::Packets(0);
    s.budget_b = PullBudget::Packets(0);
    assert_eq!(s.run(resume, |_| false), Outcome::Deadline);
    assert_eq!(
        (s.a_to_b.stats().sent_packets, s.b_to_a.stats().sent_packets),
        sent
    );
    s.budget_a = PullBudget::Packets(7);
    s.budget_b = PullBudget::Packets(1);
    sim::finish(&mut s, cfg.seed, Duration::from_secs(60));
}

#[test]
fn delivery_checker_rejects_corruption_reorder_duplicate_and_premature_fin() {
    use sim::app::{Driver, Role, StreamError, StreamIo};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    struct Reader {
        data: Vec<u8>,
        offset: usize,
        fin: bool,
    }
    impl StreamIo for Reader {
        type Id = ();
        fn connected(&self, _: ()) -> bool {
            true
        }
        fn read(&mut self, _: (), out: &mut [u8]) -> Result<usize, StreamError> {
            let n = out.len().min(self.data.len() - self.offset);
            if n == 0 && !self.fin {
                return Err(StreamError::WouldBlock);
            }
            out[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        }
        fn write(&mut self, _: (), _: &[u8]) -> Result<usize, StreamError> {
            panic!("upload sink must not send")
        }
        fn shutdown(&mut self, _: ()) -> Result<(), StreamError> {
            Ok(())
        }
    }

    let plan = Plan::upload(64);
    let mut valid = vec![0; 64];
    fill_pattern(&mut valid, sim::rng::mix(plan.seed ^ 0x43), 0);
    let mut corrupt = valid.clone();
    corrupt[31] ^= 1;
    let reorder = [valid[32..].to_vec(), valid[..32].to_vec()].concat();
    let duplicate = [valid.clone(), valid[..1].to_vec()].concat();
    let premature_fin = valid[..32].to_vec();
    for data in [corrupt, reorder, duplicate, premature_fin] {
        let mut d = Driver::new(plan.clone(), Role::Server, [()], epoch());
        let mut reader = Reader {
            data,
            offset: 0,
            fin: true,
        };
        assert!(catch_unwind(AssertUnwindSafe(|| d.poll(&mut reader, epoch()))).is_err());
    }
    let mut d = Driver::new(plan, Role::Server, [()], epoch());
    let mut reader = Reader {
        data: valid,
        offset: 0,
        fin: false,
    };
    d.poll(&mut reader, epoch());
    assert!(
        !d.finished(),
        "all bytes without FIN must not count as completion"
    );
    reader.fin = true;
    d.poll(&mut reader, epoch());
    d.assert_finished();
}

#[test]
fn a_blackholed_path_stops_at_the_virtual_completion_bound() {
    let cfg = sim::path(0xB1AC, 20_000_000, Duration::from_millis(65), 1.0);
    let mut s = sim::smoltcp_pair(&cfg, &SmolConfig::buffers(16384), &Plan::upload(64));
    let bound = Duration::from_secs(10);
    assert_eq!(
        s.run(epoch() + bound, |s| s.a.app.finished()
            && s.b.app.finished()),
        Outcome::Deadline
    );
    assert_eq!(s.elapsed(), bound);
    assert!(!s.a.app.finished());
    assert!(!s.b.app.finished());
}

#[test]
fn a_too_small_output_buffer_does_not_consume_the_next_packet() {
    let sockets = SmolConfig::buffers(16384);
    let mut host = sim::smol::SmolHost::new(&sockets, Plan::upload(32), sim::app::Role::Client);
    host.poll_app(epoch());
    assert_eq!(host.poll_transmit(epoch(), &mut [0; 1]), None);
    assert!(host.poll_transmit(epoch(), &mut [0; 1420]).is_some());
}

#[test]
fn byte_pattern_is_chunking_independent_and_detects_shift_or_cross_flow() {
    let mut whole = vec![0; 1001];
    fill_pattern(&mut whole, 43, 0);
    for chunk in [1, 7, 8, 13, 511] {
        let mut split = vec![0; whole.len()];
        for (i, c) in split.chunks_mut(chunk).enumerate() {
            fill_pattern(c, 43, i * chunk);
        }
        assert_eq!(split, whole);
    }
    let mut wrong = vec![0; whole.len()];
    fill_pattern(&mut wrong, 43, 1);
    assert_ne!(wrong, whole);
    fill_pattern(&mut wrong, 44, 0);
    assert_ne!(wrong, whole);
    assert_eq!(jain(&[8.0, 8.0, 8.0, 8.0]), 1.0);
    assert_eq!(jain(&[8.0, 0.0, 0.0, 0.0]), 0.25);
}

#[test]
fn fixed_delay_duplication_and_fifo_rate_are_exact() {
    let now = epoch();
    let mut cfg = LinkConfig::new(Duration::from_millis(7)).rate(8000, 300);
    cfg.duplicate = 1.0;
    let mut link = Link::new(cfg, 0);
    link.send(now, &[1; 100]);
    link.send(now, &[2; 100]);
    assert_eq!(link.stats().duplicated, 2);
    assert_eq!(link.stats().dropped_queue, 1);
    assert_eq!(link.stats().max_queue_bytes, 300);
    assert_eq!(link.next_arrival(), Some(now + Duration::from_millis(107)));
    assert!(link.pop_due(now + Duration::from_millis(106)).is_none());
    assert_eq!(
        link.pop_due(now + Duration::from_millis(107)),
        Some(vec![1; 100])
    );
    assert_eq!(link.next_arrival(), Some(now + Duration::from_millis(207)));
    assert_eq!(
        link.pop_due(now + Duration::from_millis(207)),
        Some(vec![1; 100])
    );
    assert_eq!(
        link.pop_due(now + Duration::from_millis(307)),
        Some(vec![2; 100])
    );
    assert!(link.next_arrival().is_none());
    link.send(now + Duration::from_secs(1), &[3; 100]);
    assert_eq!(
        link.stats().dropped_queue,
        1,
        "the FIFO drained and recovered its capacity"
    );
}

fn link_trace(cfg: LinkConfig, seed: u64) -> (Vec<(Duration, Vec<u8>)>, sim::link::LinkStats) {
    let mut link = Link::new(cfg, seed);
    for i in 0..1000u32 {
        link.send(
            epoch() + Duration::from_micros(u64::from(i) * 100),
            &i.to_be_bytes(),
        );
    }
    let mut packets = Vec::new();
    while let Some(t) = link.next_arrival() {
        packets.push((t - epoch(), link.pop_due(t).unwrap()));
    }
    (packets, link.stats())
}

#[test]
fn jitter_loss_reordering_and_duplication_are_seeded() {
    let mut cfg = LinkConfig::new(Duration::from_millis(5));
    cfg.jitter = Duration::from_millis(2);
    cfg.loss = 0.1;
    cfg.reorder = 0.2;
    cfg.reorder_hold = Duration::from_millis(20);
    cfg.duplicate = 0.1;
    let (a, stats) = link_trace(cfg.clone(), 1);
    let (b, same) = link_trace(cfg.clone(), 1);
    let (c, _) = link_trace(cfg, 2);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(stats.dropped_loss, same.dropped_loss);
    assert!((70..130).contains(&stats.dropped_loss), "{stats:?}");
    assert!(stats.duplicated > 50 && stats.reordered > 100);
    let ids: Vec<_> = a
        .iter()
        .map(|(_, p)| u32::from_be_bytes(p[..].try_into().unwrap()))
        .collect();
    assert!(
        ids.windows(2).any(|w| w[1] < w[0]),
        "later packets overtake held packets"
    );
}

#[test]
fn gilbert_elliott_state_produces_contiguous_bad_runs() {
    let mut cfg = LinkConfig::new(Duration::ZERO);
    // Deterministically alternate good and bad every packet: first packet enters bad and drops,
    // second leaves bad and survives. This tests both transition directions without statistics.
    cfg.burst = Some(GilbertElliott {
        p_good_to_bad: 1.0,
        p_bad_to_good: 1.0,
        loss_good: 0.0,
        loss_bad: 1.0,
    });
    let (trace, stats) = link_trace(cfg.clone(), 0);
    let ids: Vec<_> = trace
        .iter()
        .map(|(_, p)| u32::from_be_bytes(p[..].try_into().unwrap()))
        .collect();
    assert_eq!(ids, (1..1000).step_by(2).collect::<Vec<_>>());
    assert_eq!(stats.dropped_loss, 500);

    cfg.burst = Some(GilbertElliott {
        p_good_to_bad: 0.03,
        p_bad_to_good: 0.15,
        loss_good: 0.0,
        loss_bad: 1.0,
    });
    let (trace, stats) = link_trace(cfg, 43);
    let ids: Vec<_> = trace
        .iter()
        .map(|(_, p)| u32::from_be_bytes(p[..].try_into().unwrap()))
        .collect();
    assert!(stats.dropped_loss > 50);
    assert!(
        ids.windows(2).any(|w| w[1] >= w[0] + 4),
        "burst loss must have runs of multiple missing packets"
    );
}

#[test]
fn tcp_wire_observer_counts_only_repeated_payload_including_seq_wrap() {
    fn packet(seq: u32, n: usize) -> Vec<u8> {
        let mut p = vec![0; 40 + n];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((40 + n) as u16).to_be_bytes());
        p[9] = 6;
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 0x50;
        p
    }
    let mut t = WireTracker::default();
    t.observe(&packet(u32::MAX - 9, 20));
    t.observe(&packet(10, 20));
    assert_eq!(t.stats.tcp_retrans_bytes, 0);
    t.observe(&packet(0, 20));
    assert_eq!(t.stats.tcp_retrans_bytes, 20);
    t.observe(&packet(20, 20));
    assert_eq!(
        t.stats.tcp_retrans_bytes, 30,
        "10-byte prefix was sent before; 10-byte suffix is new"
    );
}

/// Phase 0's repeatable reference, not a claim about steady-state capacity or a kernel baseline.
#[test]
#[ignore = "Phase 0 grid; run with --ignored --nocapture to print the reference table"]
fn phase0_smoltcp_grid() {
    const SEED: u64 = 0x5048_4153_4530;
    println!(
        "smoltcp=0.14.0 (crates.io, exact pin), CUBIC; features=std,proto-ipv4,proto-ipv6,medium-ip,socket-tcp,socket-tcp-cubic,socket-udp"
    );
    println!(
        "IPv4, MTU=1420, Nagle=off, ACK-delay=10ms, timestamps=off (default), RTO initial/min=1000ms max=60000ms; assembler=4 intervals; SACK=one block"
    );
    println!(
        "8MiB upload per cell, 100Mbit/s each direction (IP bytes), queue=1 BDP including packet in service, data-direction iid loss only, no jitter/reorder/duplicate; seed={SEED:#x}, unlimited pull"
    );
    println!(
        "| RX=TX KiB/host/flow | loss % | RTT ms | goodput Mbit/s | completion s | retrans bytes | max queue B | Jain |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|");
    for buffer in [16 * 1024, 256 * 1024, MIB] {
        for loss in [0.0, 0.01] {
            for rtt in [1, 65, 150] {
                let cfg = sim::path(SEED, 100_000_000, Duration::from_millis(rtt), loss);
                let mut s =
                    sim::smoltcp_pair(&cfg, &SmolConfig::buffers(buffer), &Plan::upload(8 * MIB));
                let m = sim::finish(&mut s, cfg.seed, Duration::from_secs(3600));
                println!(
                    "| {} | {:.0} | {} | {:.3} | {:.3} | {} | {} | {:.3} |",
                    buffer / 1024,
                    loss * 100.0,
                    rtt,
                    m.goodput_mbps,
                    m.completion.as_secs_f64(),
                    m.retransmitted_bytes,
                    m.max_queue_bytes,
                    m.jain
                );
            }
        }
    }
}
