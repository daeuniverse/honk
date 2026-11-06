use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;
use crate::dns::transport::{
    DnsSocketBudget, IdlePressureRelease, read_length_prefixed_into, write_length_prefixed,
};

async fn stall_guard(future: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("DNS pressure test stalled");
}

fn response_for(wire: &[u8]) -> Vec<u8> {
    mock_dns_response(u16::from_be_bytes([wire[0], wire[1]]))
}

async fn spawn_udp_echo(requests: usize) -> (SocketAddr, JoinHandle<Vec<SocketAddr>>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut sources = Vec::with_capacity(requests);
        let mut wire = [0_u8; 512];
        for _ in 0..requests {
            let (len, source) = server.recv_from(&mut wire).await.unwrap();
            server
                .send_to(&response_for(&wire[..len]), source)
                .await
                .unwrap();
            sources.push(source);
        }
        sources
    });
    (address, task)
}

async fn bind_tcp_udp() -> (TcpListener, UdpSocket, SocketAddr) {
    for _ in 0..8 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        match UdpSocket::bind(address).await {
            Ok(udp) => return (tcp, udp, address),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("bind matching UDP endpoint: {error}"),
        }
    }
    panic!("bind matching TCP and UDP endpoints after bounded retries");
}

#[tokio::test]
async fn pressure_retirement_counts_one_idle_udp_pool() {
    const NAME: &str =
        "dns::upstream_pool::tests::pressure::pressure_retirement_counts_one_idle_udp_pool";
    if crate::test_support::run_exact_in_child("HONK_DNS_PRESSURE_STATS_CHILD", NAME) {
        return;
    }
    stall_guard(async {
        let (address, server) = spawn_udp_echo(1).await;
        let budget = DnsSocketBudget::new(1);
        let pool = UpstreamPool::new(
            &[make_upstream("udp", &address.to_string(), DnsProtocol::Udp)],
            make_router(),
        )
        .unwrap()
        .with_socket_budget(budget.clone());
        assert_eq!(
            pool.query("udp", &mock_dns_query(0x1000)).await.unwrap(),
            mock_dns_response(0x1000)
        );
        assert_eq!(server.await.unwrap().len(), 1);
        let before = crate::stats::dns_snapshot();

        let reclaimed = budget
            .acquire_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let delta = crate::stats::dns_snapshot().delta(before);
        assert_eq!(delta.pressure_retired_udp_pool, 1);
        assert_eq!(delta.pressure_retired_transport, 0);
        assert_eq!(delta.socket_admission_timeout, 0);
        assert_eq!(delta.socket_admission_refused, 0);

        drop(reclaimed);
        pool.close().await;
        assert_eq!(
            crate::stats::dns_snapshot()
                .delta(before)
                .pressure_retired_udp_pool,
            1
        );
        assert_eq!(budget.available_sockets(), 1);
        assert_eq!(pool.lifecycle_stats().tasks, 0);
    })
    .await;
}

#[tokio::test]
async fn budget_one_alternates_numeric_udp_upstreams() {
    stall_guard(async {
        let (a_address, a_server) = spawn_udp_echo(2).await;
        let (b_address, b_server) = spawn_udp_echo(2).await;
        let budget = DnsSocketBudget::new(1);
        let pool = UpstreamPool::new(
            &[
                make_upstream("a", &a_address.to_string(), DnsProtocol::Udp),
                make_upstream("b", &b_address.to_string(), DnsProtocol::Udp),
            ],
            make_router(),
        )
        .unwrap()
        .with_socket_budget(budget.clone());

        for (name, id) in [("a", 0x1001), ("b", 0x1002), ("a", 0x1003), ("b", 0x1004)] {
            let response = pool.query(name, &mock_dns_query(id)).await.unwrap();
            assert_eq!(response, mock_dns_response(id));
            assert_eq!(budget.available_sockets(), 0);
        }

        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
        assert_eq!(a_server.await.unwrap().len(), 2);
        assert_eq!(b_server.await.unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
async fn budget_one_reclaims_idle_tcp_for_udp_and_back() {
    stall_guard(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = listener.local_addr().unwrap();
        let tcp_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut query = Vec::new();
                read_length_prefixed_into(&mut stream, &mut query, None)
                    .await
                    .unwrap();
                write_length_prefixed(&mut stream, &response_for(&query))
                    .await
                    .unwrap();
                let mut byte = [0_u8; 1];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            }
        });
        let (udp_address, udp_server) = spawn_udp_echo(1).await;
        let budget = DnsSocketBudget::new(1);
        let pool = UpstreamPool::new(
            &[
                make_upstream("tcp", &tcp_address.to_string(), DnsProtocol::Tcp),
                make_upstream("udp", &udp_address.to_string(), DnsProtocol::Udp),
            ],
            make_router(),
        )
        .unwrap()
        .with_socket_budget(budget.clone());

        let first = pool.query("tcp", &mock_dns_query(0x2001)).await.unwrap();
        assert_eq!(first, mock_dns_response(0x2001));
        assert_eq!(budget.available_sockets(), 0);

        let udp = pool.query("udp", &mock_dns_query(0x2002)).await.unwrap();
        assert_eq!(udp, mock_dns_response(0x2002));
        assert_eq!(budget.available_sockets(), 0);
        assert_eq!(udp_server.await.unwrap().len(), 1);

        let second = pool.query("tcp", &mock_dns_query(0x2003)).await.unwrap();
        assert_eq!(second, mock_dns_response(0x2003));
        assert_eq!(budget.available_sockets(), 0);

        pool.close().await;
        tcp_server.await.unwrap();
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
    })
    .await;
}

#[tokio::test]
async fn borrowed_udp_completion_releases_blocked_query() {
    stall_guard(async {
        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_address = a_socket.local_addr().unwrap();
        let (b_address, b_server) = spawn_udp_echo(1).await;
        let budget = DnsSocketBudget::new(1);
        let pool = Arc::new(
            UpstreamPool::new(
                &[
                    make_upstream("a", &a_address.to_string(), DnsProtocol::Udp),
                    make_upstream("b", &b_address.to_string(), DnsProtocol::Udp),
                ],
                make_router(),
            )
            .unwrap()
            .with_socket_budget(budget.clone()),
        );

        let a_task = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.query("a", &mock_dns_query(0x3001)).await }
        });
        let mut a_wire = [0_u8; 512];
        let (a_len, a_source) = a_socket.recv_from(&mut a_wire).await.unwrap();

        let mut b_query = Box::pin({
            let pool = Arc::clone(&pool);
            async move { pool.query("b", &mock_dns_query(0x3002)).await }
        });
        assert!(futures::poll!(b_query.as_mut()).is_pending());
        assert_eq!(budget.available_sockets(), 0);

        a_socket
            .send_to(&response_for(&a_wire[..a_len]), a_source)
            .await
            .unwrap();
        let a_response = a_task.await.unwrap().unwrap();
        assert_eq!(a_response, mock_dns_response(0x3001));
        {
            let mut a_state = pool.entries["a"].udp.lock();
            assert_eq!(a_state.current, None);
            assert_eq!(a_state.current_address(), None);
            assert!(a_state.pools[0].as_ref().is_some_and(|family| {
                family.address == a_address && family.shards.iter().all(Option::is_none)
            }));
            a_state.current = Some(a_address);
            assert_eq!(a_state.current_address(), None);
            a_state.current = None;
        }

        let b_response = b_query.await.unwrap();
        assert_eq!(b_response, mock_dns_response(0x3002));
        assert_eq!(b_server.await.unwrap().len(), 1);

        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
    })
    .await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_task_last_arc_releases_blocked_creator() {
    stall_guard(async {
        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_address = a_socket.local_addr().unwrap();
        drop(a_socket);
        let (b_address, b_server) = spawn_udp_echo(1).await;
        let budget = DnsSocketBudget::new(1);
        let pool = Arc::new(
            UpstreamPool::new(
                &[
                    make_upstream("a", &a_address.to_string(), DnsProtocol::Udp),
                    make_upstream("b", &b_address.to_string(), DnsProtocol::Udp),
                ],
                make_router(),
            )
            .unwrap()
            .with_socket_budget(budget.clone()),
        );
        let a_pool = pool.udp_pool(&pool.entries["a"], a_address).await.unwrap();

        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let mut a_query = Box::pin({
            let a_pool = Arc::clone(&a_pool);
            let budget = budget.clone();
            async move {
                let _release = IdlePressureRelease(&budget);
                start_rx.await.unwrap();
                let a_pool = a_pool;
                a_pool.exchange(&mock_dns_query(0x7001), None).await
            }
        });
        assert!(futures::poll!(a_query.as_mut()).is_pending());

        let mut b_query = Box::pin({
            let pool = Arc::clone(&pool);
            async move { pool.query("b", &mock_dns_query(0x7002)).await }
        });
        assert!(futures::poll!(b_query.as_mut()).is_pending());
        assert_eq!(budget.available_sockets(), 0);

        let a_weak = {
            let mut state = pool.entries["a"].udp.lock();
            let removed = state.pools[0].as_mut().unwrap().shards[0].take().unwrap();
            Arc::downgrade(&removed)
        };
        drop(a_pool);
        assert_eq!(a_weak.strong_count(), 1);

        start_tx.send(()).unwrap();
        let a_task = tokio::spawn({
            let a_weak = a_weak.clone();
            async move {
                let result = a_query.await;
                let receive_references = a_weak.strong_count();
                (result, receive_references)
            }
        });
        let (a_result, receive_references) = a_task.await.unwrap();
        assert!(a_result.is_err());
        assert_eq!(receive_references, 1);

        assert_eq!(b_query.await.unwrap(), mock_dns_response(0x7002));
        assert_eq!(b_server.await.unwrap().len(), 1);
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
    })
    .await;
}

#[tokio::test]
async fn truncated_fallback_completion_releases_blocked_query() {
    stall_guard(async {
        let (tcp_listener, a_udp_socket, a_address) = bind_tcp_udp().await;
        let (b_address, b_server) = spawn_udp_echo(1).await;
        let budget = DnsSocketBudget::new(2);
        let pool = Arc::new(
            UpstreamPool::new(
                &[
                    make_upstream("a", &a_address.to_string(), DnsProtocol::Udp),
                    make_upstream("b", &b_address.to_string(), DnsProtocol::Udp),
                ],
                make_router(),
            )
            .unwrap()
            .with_socket_budget(budget.clone()),
        );

        let a_task = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.query("a", &mock_dns_query(0x6001)).await }
        });
        let mut a_wire = [0_u8; 512];
        let (a_len, a_source) = a_udp_socket.recv_from(&mut a_wire).await.unwrap();
        let a_udp = {
            let state = pool.entries["a"].udp.lock();
            Arc::clone(state.pools[0].as_ref().unwrap().shards[0].as_ref().unwrap())
        };
        let mut truncated = response_for(&a_wire[..a_len]);
        truncated[2] |= 0x02;
        a_udp_socket.send_to(&truncated, a_source).await.unwrap();

        let (mut tcp_stream, _) = tcp_listener.accept().await.unwrap();
        let mut tcp_query = Vec::new();
        read_length_prefixed_into(&mut tcp_stream, &mut tcp_query, None)
            .await
            .unwrap();
        assert_eq!(budget.available_sockets(), 0);

        let mut b_query = Box::pin({
            let pool = Arc::clone(&pool);
            async move { pool.query("b", &mock_dns_query(0x6002)).await }
        });
        assert!(futures::poll!(b_query.as_mut()).is_pending());
        assert_eq!(budget.available_sockets(), 0);

        write_length_prefixed(&mut tcp_stream, &response_for(&tcp_query))
            .await
            .unwrap();
        assert_eq!(a_task.await.unwrap().unwrap(), mock_dns_response(0x6001));
        assert_eq!(b_query.await.unwrap(), mock_dns_response(0x6002));
        assert_eq!(b_server.await.unwrap().len(), 1);

        let mut byte = [0_u8; 1];
        assert_eq!(tcp_stream.read(&mut byte).await.unwrap(), 0);
        drop(a_udp);
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 2);
    })
    .await;
}

#[tokio::test]
async fn cancelled_pressure_waiter_does_not_evict_returned_udp() {
    stall_guard(async {
        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_address = a_socket.local_addr().unwrap();
        let b_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_address = b_socket.local_addr().unwrap();
        let budget = DnsSocketBudget::new(1);
        let pool = Arc::new(
            UpstreamPool::new(
                &[
                    make_upstream("a", &a_address.to_string(), DnsProtocol::Udp),
                    make_upstream("b", &b_address.to_string(), DnsProtocol::Udp),
                ],
                make_router(),
            )
            .unwrap()
            .with_socket_budget(budget.clone()),
        );

        let a_task = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move { pool.query("a", &mock_dns_query(0x4001)).await }
        });
        let mut a_wire = [0_u8; 512];
        let (a_len, first_source) = a_socket.recv_from(&mut a_wire).await.unwrap();

        let mut b_query = Box::pin({
            let pool = Arc::clone(&pool);
            async move { pool.query("b", &mock_dns_query(0x4002)).await }
        });
        assert!(futures::poll!(b_query.as_mut()).is_pending());
        drop(b_query);

        a_socket
            .send_to(&response_for(&a_wire[..a_len]), first_source)
            .await
            .unwrap();
        assert_eq!(a_task.await.unwrap().unwrap(), mock_dns_response(0x4001));

        let second_wire = mock_dns_query(0x4003);
        let second_query = pool.query("a", &second_wire);
        let respond = async {
            let (len, source) = a_socket.recv_from(&mut a_wire).await.unwrap();
            a_socket
                .send_to(&response_for(&a_wire[..len]), source)
                .await
                .unwrap();
            source
        };
        let (second_response, second_source) = tokio::join!(second_query, respond);
        assert_eq!(second_response.unwrap(), mock_dns_response(0x4003));
        assert_eq!(second_source, first_source);
        assert_eq!(budget.available_sockets(), 0);

        let mut b_wire = [0_u8; 512];
        assert_eq!(
            b_socket.try_recv_from(&mut b_wire).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(budget.available_sockets(), 1);
    })
    .await;
}

#[tokio::test]
async fn replacement_budget_does_not_reclaim_new_registration() {
    stall_guard(async {
        let (address, server) = spawn_udp_echo(2).await;
        let old_budget = DnsSocketBudget::new(1);
        let new_budget = DnsSocketBudget::new(1);
        let pool = UpstreamPool::new(
            &[make_upstream("new", &address.to_string(), DnsProtocol::Udp)],
            make_router(),
        )
        .unwrap()
        .with_socket_budget(old_budget.clone())
        .with_socket_budget(new_budget.clone());

        let warm = pool.query("new", &mock_dns_query(0x5001)).await.unwrap();
        assert_eq!(warm, mock_dns_response(0x5001));
        assert_eq!(new_budget.available_sockets(), 0);

        let old_permit = old_budget.try_acquire().unwrap();
        let mut old_pressure = Box::pin(
            old_budget.acquire_until(tokio::time::Instant::now() + Duration::from_secs(10)),
        );
        assert!(futures::poll!(old_pressure.as_mut()).is_pending());
        drop(old_pressure);
        assert_eq!(old_budget.available_sockets(), 0);
        assert_eq!(new_budget.available_sockets(), 0);

        let retained = pool.query("new", &mock_dns_query(0x5002)).await.unwrap();
        assert_eq!(retained, mock_dns_response(0x5002));
        let sources = server.await.unwrap();
        assert_eq!(sources[0], sources[1]);

        drop(old_permit);
        assert_eq!(old_budget.available_sockets(), 1);
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        assert_eq!(new_budget.available_sockets(), 1);
    })
    .await;
}
