use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use honk_config::dns::DnsStrategy;
use honk_config::node::OutboundConfig;
use honk_config::types::{DnsProtocol, NodeProtocol};
use honk_outbound::bootstrap::BootstrapResolver;
use honk_outbound::proxy::{PacketRejection, packet_rejection};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::addr_cache::{ResolvedCandidates, UpstreamAddrCache};
use super::*;
use crate::dns::cache::{CacheInvalidation, DnsCache};
use crate::dns::endpoint::ResolvedEndpointAddrs;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::runtime::{
    DnsRuntime, DnsRuntimeParts, DnsServiceProvider, RoutingProjectionSnapshot, RuntimeGeneration,
};
use crate::dns::service::DnsService;
use crate::dns::transport::{DnsSocketBudget, read_length_prefixed_into, write_length_prefixed};
use crate::routing::Router;

type ReplyGate = (oneshot::Sender<()>, oneshot::Receiver<()>);
type SharedGate = Arc<parking_lot::Mutex<Option<ReplyGate>>>;
struct Gate(usize, bool, oneshot::Sender<()>, oneshot::Receiver<()>);

struct MockBootstrap {
    resolver: BootstrapResolver,
    v4: Arc<parking_lot::Mutex<Vec<[u8; 4]>>>,
    packets: Arc<AtomicUsize>,
    gate: Arc<parking_lot::Mutex<Option<Gate>>>,
    task: JoinHandle<()>,
}

impl MockBootstrap {
    async fn spawn(initial: Vec<[u8; 4]>) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let uri = format!("udp://{}", sock.local_addr().unwrap());
        let resolver = BootstrapResolver::parse(&uri).unwrap();
        let v4 = Arc::new(parking_lot::Mutex::new(initial));
        let packets = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(parking_lot::Mutex::new(None::<Gate>));
        let (tv4, tp, tg) = (Arc::clone(&v4), Arc::clone(&packets), Arc::clone(&gate));
        let task = tokio::spawn(async move {
            let (mut buf, mut held) = ([0_u8; 512], Vec::new());
            let reply = |q: &[u8], ips: &[[u8; 4]]| {
                let qt = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
                let ans = if qt == 1 { ips } else { &[] };
                let mut r = q.to_vec();
                r[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                r[6..8].copy_from_slice(&(ans.len() as u16).to_be_bytes());
                for ip in ans {
                    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    r.extend_from_slice(ip);
                }
                r
            };
            while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
                tp.fetch_add(1, Ordering::SeqCst);
                let Some(g) = tg.lock().take() else {
                    let ips = tv4.lock().clone();
                    let _ = sock.send_to(&reply(&buf[..len], &ips), peer).await;
                    continue;
                };
                held.push((buf[..len].to_vec(), peer));
                if held.len() < g.0 {
                    *tg.lock() = Some(g);
                    continue;
                }
                let _ = g.2.send(());
                if g.1 {
                    held.clear();
                    continue;
                }
                let _ = g.3.await;
                let ips = tv4.lock().clone();
                for (q, target) in held.drain(..) {
                    let _ = sock.send_to(&reply(&q, &ips), target).await;
                }
            }
        });
        Self {
            resolver,
            v4,
            packets,
            gate,
            task,
        }
    }

    fn arm(&self, hold: usize, drop_held: bool) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let ((rt, rr), (lt, lr)) = (oneshot::channel(), oneshot::channel());
        *self.gate.lock() = Some(Gate(hold, drop_held, rt, lr));
        (rr, lt)
    }
    fn set_v4(&self, ips: Vec<[u8; 4]>) {
        *self.v4.lock() = ips;
    }
    fn count(&self) -> usize {
        self.packets.load(Ordering::SeqCst)
    }
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn wait_gate<F: Future>(ready: oneshot::Receiver<()>, fut: &mut Pin<Box<F>>) {
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! { _ = ready => {}, _ = fut.as_mut() => panic!("completed before gate") }
    })
    .await
    .expect("gate timeout");
}

fn pool_for(
    proto: DnsProtocol,
    addr: &str,
    r: BootstrapResolver,
    v4_only: bool,
    proxied: bool,
) -> UpstreamPool {
    let s = [DnsStrategy::PreferIpv4, DnsStrategy::Ipv4Only][usize::from(v4_only)];
    let mut up = make_upstream("default", addr, proto);
    let (reg, nodes) = if proxied {
        let mut node = test_node("direct-proxy");
        node.outbound = OutboundConfig::from_protocol(NodeProtocol::Direct);
        up.outbound = Some(node.name.clone());
        let r = crate::proxy::ProxyRegistry::default_resolver().unwrap();
        (Some(Arc::new(r)), vec![node])
    } else {
        (None, vec![])
    };
    UpstreamPool::new_with_proxy_and_bootstrap(&[up], make_router(), reg, nodes, vec![], Some(r), s)
        .unwrap()
}

async fn query_ok(pool: &UpstreamPool, id: u16) {
    let resp = pool.query("default", &mock_dns_query(id)).await.unwrap();
    assert_eq!(resp, mock_dns_response(id));
}

fn spawn_tcp_dns(listener: TcpListener) -> (Arc<AtomicUsize>, JoinHandle<()>) {
    let served = Arc::new(AtomicUsize::new(0));
    let s = Arc::clone(&served);
    let task = tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let s = Arc::clone(&s);
            conns.spawn(async move {
                let mut q = Vec::new();
                while read_length_prefixed_into(&mut stream, &mut q, None)
                    .await
                    .is_ok()
                {
                    s.fetch_add(1, Ordering::SeqCst);
                    let resp = mock_dns_response(u16::from_be_bytes([q[0], q[1]]));
                    if write_length_prefixed(&mut stream, &resp).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (served, task)
}

fn spawn_udp_dns(sock: UdpSocket, gate: Option<SharedGate>) -> (Arc<AtomicUsize>, JoinHandle<()>) {
    let served = Arc::new(AtomicUsize::new(0));
    let s = Arc::clone(&served);
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((len, peer)) = sock.recv_from(&mut buf).await {
            if len < 2 {
                continue;
            }
            if let Some((ready, release)) = gate.as_ref().and_then(|g| g.lock().take()) {
                let _ = ready.send(());
                let _ = release.await;
            }
            s.fetch_add(1, Ordering::SeqCst);
            let resp = mock_dns_response(u16::from_be_bytes([buf[0], buf[1]]));
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    (served, task)
}

async fn resolve_cache(
    c: &UpstreamAddrCache,
    d: Duration,
    g: Option<oneshot::Receiver<()>>,
    r: anyhow::Result<(Vec<SocketAddr>, Option<u32>)>,
) -> anyhow::Result<ResolvedCandidates> {
    let mut state = Some((g, r));
    let out = c.resolve_or_wait(
        "u",
        "u.test",
        Instant::now() + d,
        || true,
        move |_| {
            let (g, r) = state.take().unwrap();
            async move {
                if let Some(rx) = g {
                    let _ = rx.await;
                }
                let ok = r.map(|(addresses, min_ttl)| ResolvedEndpointAddrs { addresses, min_ttl });
                (ok, None::<()>)
            }
        },
    );
    out.await.0
}

#[tokio::test(start_paused = true)]
async fn addr_cache_state_machine_ttl_stale_affinity_invalidation_and_waiter_rejection() {
    let cache = UpstreamAddrCache::default();
    let v4 = |b| SocketAddr::from(([192, 0, 2, b], 853));
    let v6 = |b| SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, b).into(), 853);
    let (v4_a, v4_b, v6_a, v6_b) = (v4(1), v4(2), v6(1), v6(2));
    let dual = vec![v6_a, v6_b, v4_a, v4_b];
    let sec = Duration::from_secs;
    let run = |d, g, r| resolve_cache(&cache, d, g, r);
    let ok = |a, t| resolve_cache(&cache, sec(1), None, Ok((a, t)));
    let fail = || Err(anyhow::anyhow!("servfail"));
    let hit = || cache.try_hit(Instant::now());
    let cap = |e: anyhow::Error| assert_eq!(packet_rejection(&e), Some(PacketRejection::Capacity));

    // TTL clamp [30s, 300s], default 60s, and 600s stale retention.
    for (ttl, expected) in [(Some(5), 30), (None, 60), (Some(3600), 300)] {
        let now = Instant::now();
        ok(dual.clone(), ttl).await.unwrap();
        let (refresh, stale, retry, _) = cache.cache_timestamps().unwrap();
        assert_eq!(
            (refresh - now, stale - refresh, retry),
            (sec(expected), sec(600), None)
        );
        tokio::time::advance(sec(expected + 1)).await;
    }

    // Same-family affinity promotes within its slice without overriding PreferIpv6.
    cache.record_preferred(v4_b);
    let hit_v4 = ok(dual, Some(60)).await.unwrap();
    assert_eq!(&*hit_v4.addresses, &[v6_a, v6_b, v4_b, v4_a]);
    cache.record_preferred(v6_b);
    assert_eq!(&*hit().unwrap().addresses, &[v6_b, v6_a, v4_b, v4_a]);

    // Stale fallback + 5s cooldown on ordinary error; Capacity bypasses & survives later success.
    tokio::time::advance(sec(61)).await;
    let stale = run(sec(1), None, fail()).await.unwrap();
    assert_eq!(&*stale.addresses, &[v6_b, v6_a, v4_b, v4_a]);
    assert!(hit().is_some());

    tokio::time::advance(sec(6)).await;
    let retry_before = cache.cache_timestamps().unwrap().2;
    let (tx, rx) = oneshot::channel();
    let mut leader = Box::pin(run(sec(5), Some(rx), Err(PacketRejection::Capacity.into())));
    assert!(futures::poll!(leader.as_mut()).is_pending());
    let mut waiter = Box::pin(run(sec(5), None, fail()));
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    let short = run(Duration::from_millis(20), None, fail()).await;
    assert!(short.err().unwrap().to_string().contains("timed out"));
    let _ = tx.send(());
    cap(leader.await.err().unwrap());
    assert!(cache.cache_timestamps().unwrap().2 == retry_before && hit().is_none());
    ok(vec![v4_a], Some(60)).await.unwrap();
    cap(waiter.await.err().unwrap());

    // Mid-flight invalidation prevents arming retry_after (Err) or fresh TTL (Ok).
    tokio::time::advance(sec(61)).await;
    for res in [fail(), Ok((vec![v4_a], Some(60)))] {
        let (tx, rx) = oneshot::channel();
        let mut flight = Box::pin(run(sec(5), Some(rx), res));
        assert!(futures::poll!(flight.as_mut()).is_pending());
        let epoch_after = cache.invalidate(Instant::now());
        let _ = tx.send(());
        assert!(flight.await.unwrap().invalidation_epoch < epoch_after);
        let (refresh, _, retry, _) = cache.cache_timestamps().unwrap();
        assert!(refresh <= Instant::now() && retry.is_none());
    }

    // mark_dirty_on_all_failed requires matching generation and obeys 5s forced cooldown.
    let gen1 = ok(vec![v4_a], Some(60)).await.unwrap().cache_generation;
    cache.mark_dirty_on_all_failed(gen1.map(|g| g + 99), Instant::now());
    assert!(hit().is_some());
    cache.mark_dirty_on_all_failed(gen1, Instant::now());
    assert!(hit().is_none());
    let gen2 = ok(vec![v4_b], Some(60)).await.unwrap().cache_generation;
    cache.mark_dirty_on_all_failed(gen2, Instant::now());
    assert!(hit().is_some());
    tokio::time::advance(sec(6)).await;
    cache.mark_dirty_on_all_failed(gen2, Instant::now());
    assert!(hit().is_none());
}

#[tokio::test]
async fn tcp_and_proxied_udp_cache_hits_survive_bootstrap_shutdown() {
    for (proto, proxied) in [(DnsProtocol::Tcp, false), (DnsProtocol::Udp, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (served, server_task) = spawn_tcp_dns(listener);
        let boot = MockBootstrap::spawn(vec![[127, 0, 0, 1]]).await;
        let addr = format!("c.test:{port}");
        let pool = pool_for(proto, &addr, boot.resolver, false, proxied);
        query_ok(&pool, 0x1101).await;
        let packets = Arc::clone(&boot.packets);
        boot.shutdown().await;
        query_ok(&pool, 0x1102).await;
        let p = packets.load(Ordering::SeqCst);
        let s = served.load(Ordering::SeqCst);
        assert_eq!((p, s, pool.lifecycle_stats().init_count), (2, 2, 1));
        pool.close().await;
        server_task.abort();
    }
}

#[tokio::test]
async fn singleflight_coalescing_takeover_and_close_abort() {
    let boot = MockBootstrap::spawn(vec![[127, 0, 0, 1]]).await;
    let budget = DnsSocketBudget::new(2);
    let pool = pool_for(DnsProtocol::Tcp, "sf.test:53", boot.resolver, false, false)
        .with_socket_budget(budget.clone());
    let entry = &pool.entries["default"];
    let sec = Duration::from_secs(2);
    let res = || Box::pin(pool.resolve_observed_addrs_until(entry, Instant::now() + sec));

    // 1) Concurrent cold start coalesces to one bootstrap exchange.
    let (ready, release) = boot.arm(2, false);
    let (mut leader, mut waiter) = (res(), res());
    wait_gate(ready, &mut leader).await;
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    assert_eq!((boot.count(), budget.available_sockets()), (2, 0));
    let _ = release.send(());
    let ((r1, _), (r2, _)) = tokio::join!(leader, waiter);
    assert_eq!(&*r1.unwrap().addresses, &*r2.unwrap().addresses);

    // 2) Leader cancel releases credits synchronously; surviving waiter takes over.
    entry.expire_addr_cache_for_test(Instant::now(), None);
    let (ready2, _drop2) = boot.arm(2, true);
    let (mut l2, mut w_take) = (res(), res());
    wait_gate(ready2, &mut l2).await;
    assert!(futures::poll!(w_take.as_mut()).is_pending());
    drop(l2);
    assert!(budget.available_sockets() == 2 && !entry.is_addr_in_flight());
    assert!(w_take.await.0.is_ok() && boot.count() == 6);

    // 3) close() waits for in-flight bootstrap and aborts woken waiters without new I/O.
    entry.expire_addr_cache_for_test(Instant::now(), None);
    let (ready3, _drop3) = boot.arm(2, true);
    let (mut l3, mut w_close) = (res(), res());
    wait_gate(ready3, &mut l3).await;
    assert!(futures::poll!(w_close.as_mut()).is_pending());
    let close = pool.close();
    tokio::pin!(close);
    assert!(futures::poll!(close.as_mut()).is_pending());
    drop(l3);
    let ((w_res, _), ()) = tokio::join!(w_close, close);
    assert!(w_res.err().unwrap().to_string().contains("closed"));
    assert_eq!((boot.count(), budget.available_sockets()), (8, 2));
    boot.shutdown().await;
}

#[tokio::test]
async fn rotation_all_failed_dirty_and_full_flush() {
    let (l1, l2, port) = loop {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = a.local_addr().unwrap().port();
        if let Ok(b) = TcpListener::bind(("127.0.0.2", port)).await {
            break (a, b, port);
        }
    };
    let ((served1, s1), (served2, s2)) = (spawn_tcp_dns(l1), spawn_tcp_dns(l2));
    let sc = |a: &AtomicUsize| a.load(Ordering::SeqCst);
    let boot = MockBootstrap::spawn(vec![[127, 0, 0, 1], [127, 0, 0, 2]]).await;
    let addr = format!("rr.test:{port}");
    let pool = Arc::new(pool_for(
        DnsProtocol::Tcp,
        &addr,
        boot.resolver,
        true,
        false,
    ));
    let cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(64)));
    let up = Arc::clone(&pool) as Arc<dyn DnsUpstreamPool>;
    let forwarder = Arc::new(DnsForwarder::new(up, cache, make_router()));
    let router = Arc::new(Router::new(&[], "direct").unwrap());
    let provider = Arc::new(DnsServiceProvider::new(DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        forwarder,
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(1, router)),
        outbound_runtime: None,
        transport: Arc::clone(&pool) as Arc<dyn crate::dns::runtime::RuntimeTransport>,
    })));
    let service = DnsService::with_provider(Arc::clone(&provider));

    // Same-family rotation reuses TransportKey; name invalidation keeps cache; full flush refreshes.
    query_ok(&pool, 0x4001).await;
    boot.set_v4(vec![[127, 0, 0, 2], [127, 0, 0, 1]]);
    let entry = &pool.entries["default"];
    entry.expire_addr_cache_for_test(Instant::now(), None);
    query_ok(&pool, 0x4002).await;
    assert_eq!(
        (
            pool.lifecycle_stats().init_count,
            sc(&served1),
            sc(&served2)
        ),
        (1, 2, 0)
    );
    boot.set_v4(vec![[127, 0, 0, 2]]);
    let inv = CacheInvalidation::Name {
        name: "a.test".into(),
        types: vec![],
    };
    service.invalidate_cache(inv).await.unwrap();
    query_ok(&pool, 0x4003).await;
    assert_eq!(boot.count(), 2);
    service.flush_cache().await.unwrap();
    query_ok(&pool, 0x4004).await;
    assert_eq!((boot.count(), sc(&served2)), (3, 1));

    // Exhausting candidates marks cache dirty so the next query re-resolves back to 127.0.0.1.
    s2.abort();
    let _ = s2.await;
    boot.set_v4(vec![[127, 0, 0, 1]]);
    let q5 = mock_dns_query(0x4005);
    assert!(pool.query("default", &q5).await.is_err());
    query_ok(&pool, 0x4006).await;
    assert_eq!(boot.count(), 4);

    provider.shutdown().await;
    boot.shutdown().await;
    s1.abort();
}

#[tokio::test]
async fn delayed_direct_udp_reply_fences_invalidation_and_reuses_live_shards() {
    let (udp1, udp2, port) = loop {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = a.local_addr().unwrap().port();
        if let Ok(b) = UdpSocket::bind(("127.0.0.2", port)).await {
            break (a, b, port);
        }
    };
    let gate1 = Arc::new(parking_lot::Mutex::new(None::<ReplyGate>));
    let ((_, task1), (served2, task2)) = (
        spawn_udp_dns(udp1, Some(Arc::clone(&gate1))),
        spawn_udp_dns(udp2, None),
    );
    let boot = MockBootstrap::spawn(vec![[127, 0, 0, 1]]).await;
    let addr = format!("u.test:{port}");
    let pool = pool_for(DnsProtocol::Udp, &addr, boot.resolver, true, false)
        .with_timeouts(Duration::from_millis(30), Duration::from_secs(1));

    query_ok(&pool, 0x9101).await;
    let entry = &pool.entries["default"];
    let cur = || entry.udp.lock().current;
    let shard = || {
        Arc::clone(
            entry.udp.lock().pools[0].as_ref().unwrap().shards[0]
                .as_ref()
                .unwrap(),
        )
    };
    let shard_before = shard();

    for (tx_late, tx_next, next_ip, count) in [
        (0x9102, 0x9103, [127, 0, 0, 1], 2),
        (0x9104, 0x9105, [127, 0, 0, 2], 3),
    ] {
        let ((ready, release), (hold_tx, hold_rx)) = (oneshot::channel(), oneshot::channel());
        *gate1.lock() = Some((ready, hold_rx));
        let q = mock_dns_query(tx_late);
        let mut delayed = Box::pin(pool.query("default", &q));
        wait_gate(release, &mut delayed).await;
        boot.set_v4(vec![next_ip]);
        pool.invalidate_upstream_addrs();
        let _ = hold_tx.send(());
        assert_eq!(delayed.await.unwrap(), mock_dns_response(tx_late));
        assert_eq!(cur(), None);
        query_ok(&pool, tx_next).await;
        let want = Some(SocketAddr::from((next_ip, port)));
        assert_eq!((boot.count(), cur()), (count, want));
        if next_ip == [127, 0, 0, 1] {
            assert!(Arc::ptr_eq(&shard_before, &shard()));
        }
    }
    assert_eq!(served2.load(Ordering::SeqCst), 1);

    task2.abort();
    let _ = task2.await;
    let _silent = UdpSocket::bind(("127.0.0.2", port)).await.unwrap();
    let q6 = mock_dns_query(0x9106);
    assert!(pool.query("default", &q6).await.is_err());
    assert_eq!(cur(), None);
    assert!(entry.addr_cache_timestamps().unwrap().0 <= Instant::now());

    pool.close().await;
    boot.shutdown().await;
    task1.abort();
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn flow_observation_records_bootstrap_only_for_leader() {
    use honk_outbound::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};

    let boot = MockBootstrap::spawn(vec![[127, 0, 0, 1]]).await;
    let (ready, release) = boot.arm(2, false);
    let pool = pool_for(DnsProtocol::Tcp, "obs.test:53", boot.resolver, false, false);
    let entry = &pool.entries["default"];
    let make_obs = || {
        let evs = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let sink = Arc::clone(&evs);
        let ctx = FlowContext {
            flow_id: uuid::Uuid::new_v4(),
            generation: 1,
            attempt_id: None,
            lookup_id: None,
            dns_purpose: "client_query",
        };
        let obs = FlowObserver::new(ctx, Arc::new(move |_, ev| sink.lock().push(ev)));
        (evs, obs)
    };
    let ((l_ev, l_obs), (w_ev, w_obs), (h_ev, h_obs)) = (make_obs(), make_obs(), make_obs());
    let dl = || Instant::now() + Duration::from_secs(2);
    let res = || pool.resolve_observed_addrs_until(entry, dl());
    let mut leader = Box::pin(l_obs.scope(res()));
    wait_gate(ready, &mut leader).await;
    let mut waiter = Box::pin(w_obs.scope(res()));
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    let _ = release.send(());
    let ((l, _), (w, _)) = tokio::join!(leader, waiter);
    assert!(l.is_ok() && w.is_ok() && h_obs.scope(res()).await.0.is_ok());
    let has_boot = |ev: &parking_lot::Mutex<Vec<FlowEvent>>| {
        ev.lock().iter().any(|e| matches!(e, FlowEvent::Dns(d) if d.purpose == "proxy_server" && d.status == "succeeded"))
    };
    assert!(has_boot(&l_ev) && !has_boot(&w_ev) && !has_boot(&h_ev));
    pool.close().await;
    boot.shutdown().await;
}
