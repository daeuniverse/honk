//! DNS micro-benchmarks (cache, framing, endpoint parse, forwarder path).
//!
//! Run with:
//!   cargo bench -p honk-core --bench dns
//!
//! Focuses on hot-path userspace costs that matter under concurrent DNS load.

use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput};
use honk_config::dns::{DnsRouting, DnsUpstream};
use honk_config::types::DnsProtocol;
use honk_core::dns::cache::DnsCache;
use honk_core::dns::endpoint::DnsEndpoint;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query};
use honk_core::dns::routing::DnsRouter;
use honk_core::dns::transport::{DialContext, TcpPool, force_dns_id_zero, restore_dns_id};
use honk_core::dns::upstream_pool::UpstreamPool;
use std::hint::black_box;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

fn mock_response(txid: u16) -> Vec<u8> {
    let mut v = vec![
        (txid >> 8) as u8,
        txid as u8,
        0x81,
        0x80,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    // question + answer pointing at 127.0.0.1
    v.extend_from_slice(&[
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x7f,
        0x00, 0x00, 0x01,
    ]);
    v
}

pub(super) fn bench_endpoint_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("dns_endpoint_parse");
    for (label, addr, proto) in [
        ("udp", "8.8.8.8:53", DnsProtocol::Udp),
        ("dot", "dns.google", DnsProtocol::Tls),
        ("doh", "cloudflare-dns.com/dns-query", DnsProtocol::Https),
        ("doq", "dns.adguard.com", DnsProtocol::Quic),
        ("h3", "dns.google/dns-query", DnsProtocol::H3),
    ] {
        g.bench_with_input(BenchmarkId::from_parameter(label), &addr, |b, addr| {
            b.iter(|| {
                DnsEndpoint::parse(black_box(addr), proto, None).unwrap();
            });
        });
    }
    g.finish();
}

pub(super) fn bench_cache(c: &mut Criterion) {
    let mut cache = DnsCache::new(10_000);
    let resp = mock_response(0x1234);
    for i in 0..1000 {
        cache.put(format!("host{i}.example.com:1"), resp.clone(), 300);
    }

    let mut g = c.benchmark_group("dns_cache");
    g.throughput(Throughput::Elements(1));
    g.bench_function("get_hit", |b| {
        b.iter(|| {
            black_box(cache.get("host42.example.com:1"));
        });
    });
    g.bench_function("put", |b| {
        let mut i = 0u32;
        b.iter(|| {
            i = i.wrapping_add(1);
            cache.put(
                format!("bench{i}.example.com:1"),
                black_box(resp.clone()),
                60,
            );
        });
    });
    g.finish();
}

pub(super) fn bench_framing_id(c: &mut Criterion) {
    c.bench_function("dns_force_restore_id", |b| {
        let mut msg = mock_response(0xABCD);
        b.iter(|| {
            let id = force_dns_id_zero(black_box(&mut msg));
            restore_dns_id(black_box(&mut msg), id);
        });
    });
}

pub(super) fn bench_build_query(c: &mut Criterion) {
    c.bench_function("dns_build_query_a", |b| {
        b.iter(|| build_dns_query(black_box("www.example.com"), 1));
    });
}

pub(super) fn bench_forwarder_cache_hit(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    // Spin a tiny UDP upstream once, populate cache, then bench cache hits.
    let (fw, _addr) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let txid = u16::from_be_bytes([buf[0], buf[1]]);
                let _ = sock.send_to(&mock_response(txid), src).await;
                let _ = n;
            }
        });
        let ups = [DnsUpstream {
            name: "default".into(),
            address: addr.to_string(),
            protocol: DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                rules: vec![],
                fallback: "default".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let pool = Arc::new(UpstreamPool::new(&ups, router.clone()).unwrap());
        let cache = Arc::new(Mutex::new(DnsCache::new(10_000)));
        let fw = DnsForwarder::new(pool, cache, router);
        let q = build_dns_query("example.com", 1);
        let _ = fw.resolve(&q).await.unwrap();
        (fw, addr)
    });

    let q = build_dns_query("example.com", 1);
    let mut g = c.benchmark_group("dns_forwarder");
    g.throughput(Throughput::Elements(1));
    g.bench_function("cache_hit", |b| {
        b.to_async(&rt).iter(|| async {
            let r = fw.resolve(black_box(&q)).await.unwrap();
            black_box(r);
        });
    });
    g.finish();
}

pub(super) fn bench_tcp_pool_exchange(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let pool = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                // Real DNS servers run nodelay; without it Nagle + delayed
                // ACK adds ~40ms to every benchmark exchange.
                let _ = stream.set_nodelay(true);
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).await.is_err() {
                            break;
                        }
                        let n = u16::from_be_bytes(len) as usize;
                        let mut q = vec![0u8; n];
                        if stream.read_exact(&mut q).await.is_err() {
                            break;
                        }
                        let txid = u16::from_be_bytes([q[0], q[1]]);
                        let resp = mock_response(txid);
                        if stream
                            .write_all(&(resp.len() as u16).to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if stream.write_all(&resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let ep = DnsEndpoint::parse(&addr.to_string(), DnsProtocol::Tcp, None).unwrap();
        TcpPool::new(DialContext {
            endpoint: ep,
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            proxy: None,
            socket_budget: Default::default(),
        })
    });

    let q = build_dns_query("example.com", 1);
    let mut g = c.benchmark_group("dns_tcp_pool");
    g.throughput(Throughput::Elements(1));
    g.bench_function("exchange_reused", |b| {
        b.to_async(&rt).iter(|| async {
            let r = pool.exchange(black_box(&q), None).await.unwrap();
            black_box(r);
        });
    });
    g.finish();
}

pub(super) fn bench_udp_pool_exchange(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (pool_name, pool) = rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let txid = u16::from_be_bytes([buf[0], buf[1]]);
                let _ = sock.send_to(&mock_response(txid), src).await;
                let _ = n;
            }
        });
        let ups = [DnsUpstream {
            name: "u".into(),
            address: addr.to_string(),
            protocol: DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                rules: vec![],
                fallback: "u".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        ("u", Arc::new(UpstreamPool::new(&ups, router).unwrap()))
    });

    let q = build_dns_query("example.com", 1);
    let mut g = c.benchmark_group("dns_udp_pool");
    // The production pool quarantines all 65,536 IDs for three seconds; a long
    // localhost run measures intentional exhaustion rather than exchange latency.
    g.warm_up_time(Duration::from_millis(100));
    g.measurement_time(Duration::from_millis(100));
    g.throughput(Throughput::Elements(1));
    g.bench_function("exchange", |b| {
        b.to_async(&rt).iter(|| async {
            let r = pool
                .query(black_box(pool_name), black_box(&q))
                .await
                .unwrap();
            black_box(r);
        });
    });
    g.finish();
}
