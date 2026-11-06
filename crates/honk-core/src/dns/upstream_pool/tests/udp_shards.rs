use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;
use crate::dns::transport::{DnsSocketBudget, UdpPool};
use crate::test_support::run_exact_in_child;

const CHILD: &str = "HONK_DNS_EXTRA_SHARD_CHILD";

fn pool(address: SocketAddr, budget: &DnsSocketBudget) -> Arc<UpstreamPool> {
    Arc::new(
        UpstreamPool::new(
            &[make_upstream(
                "shards",
                &address.to_string(),
                DnsProtocol::Udp,
            )],
            make_router(),
        )
        .unwrap()
        .with_socket_budget(budget.clone())
        .with_timeouts(Duration::from_secs(60), Duration::from_secs(2)),
    )
}

async fn echo() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<SocketAddr>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (seen, peers) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        loop {
            let (_, peer) = socket.recv_from(&mut wire).await.unwrap();
            let response = mock_dns_response(u16::from_be_bytes([wire[0], wire[1]]));
            socket.send_to(&response, peer).await.unwrap();
            if seen.send(peer).is_err() {
                break;
            }
        }
    });
    (address, peers, task)
}

async fn peer_for(pool: &UdpPool, peers: &mut mpsc::UnboundedReceiver<SocketAddr>) -> SocketAddr {
    assert_eq!(
        pool.exchange(&mock_dns_query(0x1234), None).await.unwrap(),
        mock_dns_response(0x1234)
    );
    peers.recv().await.unwrap()
}

#[tokio::test]
async fn pending_pressure_expands_before_saturation_without_replaying_packets() {
    if run_exact_in_child(
        CHILD,
        "dns::upstream_pool::tests::udp_shards::pending_pressure_expands_before_saturation_without_replaying_packets",
    ) {
        return;
    }
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let budget = DnsSocketBudget::new(4);
    let pool = pool(address, &budget);
    let mut queries = tokio::task::JoinSet::new();
    let mut packets = Vec::new();
    for id in 0..770_u16 {
        let pool = Arc::clone(&pool);
        queries.spawn(async move {
            let response = pool.query("shards", &mock_dns_query(id)).await.unwrap();
            assert_eq!(response, mock_dns_response(id));
        });
        let mut wire = [0; 512];
        let (length, peer) = server.recv_from(&mut wire).await.unwrap();
        packets.push((wire[..length].to_vec(), peer));
    }
    let primary = packets[0].1;
    assert!(packets[..769].iter().all(|(_, peer)| *peer == primary));
    assert_ne!(packets[769].1, primary);
    assert_eq!(
        packets
            .iter()
            .map(|(_, peer)| *peer)
            .collect::<HashSet<_>>()
            .len(),
        2
    );
    assert_eq!(budget.available_sockets(), 2);
    assert_eq!(
        pool.reap_udp_shards(std::time::Instant::now() + Duration::from_secs(61)),
        0
    );
    for (wire, peer) in packets {
        let response = mock_dns_response(u16::from_be_bytes([wire[0], wire[1]]));
        server.send_to(&response, peer).await.unwrap();
        queries.join_next().await.unwrap().unwrap();
    }
    let mut wire = [0; 512];
    assert_eq!(
        server.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        pool.reap_udp_shards(std::time::Instant::now() + Duration::from_secs(61)),
        1
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while budget.available_sockets() != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pool.close().await;
    assert_eq!(pool.lifecycle_stats().tasks, 0);
    assert_eq!(budget.available_sockets(), 4);
}

#[tokio::test]
async fn cancelling_a_blocked_creator_does_not_spend_or_publish_extra_sockets() {
    let (address, mut peers, echo) = echo().await;
    let budget = DnsSocketBudget::new(1);
    let held = budget.try_acquire().unwrap();
    let pool = pool(address, &budget);
    let mut cancelled = Box::pin(pool.udp_pool(&pool.entries["shards"], address));
    assert!(futures::poll!(cancelled.as_mut()).is_pending());
    drop(cancelled);
    let mut queries = tokio::task::JoinSet::new();
    for id in 0..16_u16 {
        let pool = Arc::clone(&pool);
        queries.spawn(async move {
            assert_eq!(
                pool.query("shards", &mock_dns_query(id)).await.unwrap(),
                mock_dns_response(id)
            );
        });
    }
    drop(held);
    while let Some(result) = queries.join_next().await {
        result.unwrap();
    }
    let mut sources = HashSet::new();
    for _ in 0..16 {
        sources.insert(peers.recv().await.unwrap());
    }
    assert_eq!(sources.len(), 1);
    assert_eq!(budget.available_sockets(), 0);
    let selected = pool
        .select_udp_pool(&pool.entries["shards"], address, &[], true)
        .await
        .unwrap();
    assert!(sources.contains(&peer_for(&selected, &mut peers).await));
    drop(selected);
    pool.close().await;
    assert_eq!(budget.available_sockets(), 1);
    echo.abort();
    let _ = echo.await;
}

#[tokio::test]
async fn a_failed_shard_is_replaced_without_replacing_healthy_siblings() {
    if run_exact_in_child(
        CHILD,
        "dns::upstream_pool::tests::udp_shards::a_failed_shard_is_replaced_without_replacing_healthy_siblings",
    ) {
        return;
    }
    let (address, mut peers, echo) = echo().await;
    let budget = DnsSocketBudget::new(4);
    let pool = pool(address, &budget);
    let entry = &pool.entries["shards"];
    let mut shards = Vec::new();
    let mut sources = Vec::new();
    for _ in 0..4 {
        let shard = pool
            .select_udp_pool(entry, address, &[], true)
            .await
            .unwrap();
        sources.push(peer_for(&shard, &mut peers).await);
        shards.push(shard);
    }
    assert_eq!(sources.iter().copied().collect::<HashSet<_>>().len(), 4);
    let selected = pool
        .select_udp_pool(entry, address, &[], true)
        .await
        .unwrap();
    assert!(sources.contains(&peer_for(&selected, &mut peers).await));
    drop(selected);
    let failed = shards.remove(1);
    sources.remove(1);
    failed.close().await;
    drop(failed);
    assert_eq!(pool.reap_udp_shards(std::time::Instant::now()), 1);
    pool.join_retired_transports().await;
    let replacement = pool
        .select_udp_pool(entry, address, &[], true)
        .await
        .unwrap();
    let replacement_source = peer_for(&replacement, &mut peers).await;
    assert!(!sources.contains(&replacement_source));
    shards.push(replacement);
    sources.push(replacement_source);
    for (index, source) in sources.iter().enumerate() {
        let excluded: Vec<_> = shards
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, shard)| Some(Arc::clone(shard)))
            .collect();
        let selected = pool
            .select_udp_pool(entry, address, &excluded, false)
            .await
            .unwrap();
        assert_eq!(peer_for(&selected, &mut peers).await, *source);
    }
    assert_eq!(budget.available_sockets(), 0);
    drop(shards);
    pool.close().await;
    assert_eq!(budget.available_sockets(), 4);
    echo.abort();
    let _ = echo.await;
}

#[tokio::test]
async fn replaced_active_pool_stays_owned_until_exchange_ends_and_close_joins_it() {
    let (old_address, mut old_peers, old_echo) = echo().await;
    let (new_address, mut new_peers, new_echo) = echo().await;
    let budget = DnsSocketBudget::new(2);
    let pool = pool(old_address, &budget);
    let entry = &pool.entries["shards"];
    let old = pool.udp_pool(entry, old_address).await.unwrap();
    peer_for(&old, &mut old_peers).await;
    let in_flight = Arc::clone(&old);
    let replacement = pool.udp_pool(entry, new_address).await.unwrap();
    peer_for(&replacement, &mut new_peers).await;
    assert_eq!(pool.retiring_transports.lock().udp_pools.len(), 1);
    assert_eq!(budget.available_sockets(), 0);
    drop(old);
    pool.drain_retired_transports(false);
    assert_eq!(pool.retiring_transports.lock().udp_pools.len(), 1);
    drop(in_flight);
    drop(replacement);
    pool.close().await;
    assert!(pool.retiring_transports.lock().udp_pools.is_empty());
    assert_eq!(pool.lifecycle_stats().tasks, 0);
    assert_eq!(budget.available_sockets(), 2);
    old_echo.abort();
    new_echo.abort();
}

#[tokio::test]
async fn reaped_shards_and_cancelled_close_resume_until_tasks_and_credits_return() {
    if run_exact_in_child(
        CHILD,
        "dns::upstream_pool::tests::udp_shards::reaped_shards_and_cancelled_close_resume_until_tasks_and_credits_return",
    ) {
        return;
    }
    let (address, mut peers, echo) = echo().await;
    let budget = DnsSocketBudget::new(3);
    let pool = pool(address, &budget);
    let entry = &pool.entries["shards"];
    for _ in 0..3 {
        let shard = pool
            .select_udp_pool(entry, address, &[], true)
            .await
            .unwrap();
        peer_for(&shard, &mut peers).await;
    }
    assert_eq!(budget.available_sockets(), 0);
    assert_eq!(
        pool.reap_udp_shards(std::time::Instant::now() + Duration::from_secs(61)),
        2
    );
    let mut cancelled = Box::pin(pool.close());
    assert!(futures::poll!(cancelled.as_mut()).is_pending());
    drop(cancelled);
    pool.close().await;
    assert!(pool.retiring_transports.lock().udp_pools.is_empty());
    assert_eq!(pool.lifecycle_stats().tasks, 0);
    assert_eq!(budget.available_sockets(), 3);
    assert_eq!(
        pool.reap_udp_shards(std::time::Instant::now() + Duration::from_secs(61)),
        0
    );
    echo.abort();
}

#[tokio::test]
async fn retiring_last_exchange_wakes_replacement_without_a_maintenance_tick() {
    for cancel in [false, true] {
        let old_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_address = old_server.local_addr().unwrap();
        let new_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_address = new_server.local_addr().unwrap();
        let budget = DnsSocketBudget::new(1);
        let pool = pool(old_address, &budget);
        let query_pool = Arc::clone(&pool);
        let old_query =
            tokio::spawn(async move { query_pool.query("shards", &mock_dns_query(0x4321)).await });
        let mut old_wire = [0; 512];
        let (_, old_peer) = old_server.recv_from(&mut old_wire).await.unwrap();
        let mut creator = Box::pin(pool.udp_pool(&pool.entries["shards"], new_address));
        assert!(futures::poll!(creator.as_mut()).is_pending());
        assert_eq!(budget.available_sockets(), 0);

        if cancel {
            old_query.abort();
            assert!(old_query.await.unwrap_err().is_cancelled());
        } else {
            let response = mock_dns_response(u16::from_be_bytes([old_wire[0], old_wire[1]]));
            old_server.send_to(&response, old_peer).await.unwrap();
            assert_eq!(old_query.await.unwrap().unwrap(), mock_dns_response(0x4321));
        }

        let replacement = tokio::time::timeout(Duration::from_secs(1), creator)
            .await
            .expect("last old exchange must wake the blocked creator without maintenance")
            .unwrap();
        let mut wire = [0; 512];
        assert_eq!(
            new_server.try_recv_from(&mut wire).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let query = mock_dns_query(0x5678);
        let respond = async {
            let (_, peer) = new_server.recv_from(&mut wire).await.unwrap();
            let response = mock_dns_response(u16::from_be_bytes([wire[0], wire[1]]));
            new_server.send_to(&response, peer).await.unwrap();
        };
        let (response, ()) = tokio::join!(replacement.exchange(&query, None), respond);
        assert_eq!(response.unwrap(), mock_dns_response(0x5678));
        drop(replacement);
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
    }
}

#[tokio::test]
async fn process_extra_shards_stay_bounded_across_generations() {
    if run_exact_in_child(
        CHILD,
        "dns::upstream_pool::tests::udp_shards::process_extra_shards_stay_bounded_across_generations",
    ) {
        return;
    }
    let (address, mut peers, echo) = echo().await;
    let budget = DnsSocketBudget::new(64);
    let mut generations = Vec::new();
    let mut retained = None;
    let mut sources = HashSet::new();
    let mut last_primary = None;
    for generation in 0..17 {
        let pool = pool(address, &budget);
        let primary = pool
            .udp_pool(&pool.entries["shards"], address)
            .await
            .unwrap();
        let primary_source = peer_for(&primary, &mut peers).await;
        sources.insert(primary_source);
        let extra = pool
            .select_udp_pool(&pool.entries["shards"], address, &[], true)
            .await
            .unwrap();
        let extra_source = peer_for(&extra, &mut peers).await;
        if generation < 16 {
            assert_ne!(primary_source, extra_source);
        } else {
            assert_eq!(primary_source, extra_source);
            last_primary = Some(primary_source);
        }
        sources.insert(extra_source);
        if generation == 0 {
            retained = Some(extra);
        }
        generations.push(pool);
    }
    assert_eq!(
        sources.len(),
        17 + crate::dns::transport::MAX_EXTRA_UDP_SOCKETS
    );
    assert_eq!(budget.available_sockets(), 64 - sources.len());
    generations[0].close().await;
    let latest = generations.last().unwrap();
    let no_credit = latest
        .select_udp_pool(&latest.entries["shards"], address, &[], true)
        .await
        .unwrap();
    assert_eq!(Some(peer_for(&no_credit, &mut peers).await), last_primary);
    drop(no_credit);
    drop(retained);
    let expanded = latest
        .select_udp_pool(&latest.entries["shards"], address, &[], true)
        .await
        .unwrap();
    assert_ne!(Some(peer_for(&expanded, &mut peers).await), last_primary);
    drop(expanded);
    for generation in generations {
        generation.close().await;
    }
    assert_eq!(budget.available_sockets(), 64);
    echo.abort();
    let _ = echo.await;
}
