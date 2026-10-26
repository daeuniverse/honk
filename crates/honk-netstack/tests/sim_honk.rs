pub mod sim;

use sim::app::Plan;
use sim::engine::PullBudget;
use sim::smol::{Family, SmolConfig};
use std::time::Duration;

const MIB: usize = 1024 * 1024;
const SEED: u64 = 0x0048_4F4E_4B53_494D;

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
