use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;

#[tokio::test]
async fn close_waits_for_query_admitted_before_transport_publication() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let transaction_id = u16::from_be_bytes([query[0], query[1]]);
        let response = mock_dns_response(transaction_id);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[make_upstream(
                "default",
                &address.to_string(),
                DnsProtocol::Tcp,
            )],
            make_router(),
        )
        .expect("pool"),
    );
    let pause = pool.arm_admission_pause_for_test();
    let query_pool = Arc::clone(&pool);
    let query =
        tokio::spawn(async move { query_pool.query("default", &mock_dns_query(0x1234)).await });
    pause.entered.notified().await;
    let close = pool.close();
    tokio::pin!(close);

    // When
    assert!(
        matches!(futures::poll!(close.as_mut()), std::task::Poll::Pending),
        "close returned while an admitted query could still publish a transport"
    );
    pause.release.notify_one();
    query
        .await
        .expect("query task")
        .expect("query response after release");
    close.await;
    server.await.expect("server task");

    // Then
    let slot_count = pool
        .entries
        .values()
        .map(|entry| entry.transports.lock().slots.len())
        .sum::<usize>();
    assert_eq!(slot_count, 0);
    assert_eq!(
        pool.lifecycle_stats(),
        TransportLifecycleStats {
            init_count: 1,
            close_count: 1,
            tasks: 0,
        }
    );
}

#[tokio::test]
async fn cancelled_admission_releases_concurrent_close_waiters() {
    // Given
    let pool = Arc::new(
        UpstreamPool::new(
            &[make_upstream("default", "127.0.0.1:9", DnsProtocol::Udp)],
            make_router(),
        )
        .expect("pool"),
    );
    let pause = pool.arm_admission_pause_for_test();
    let query_pool = Arc::clone(&pool);
    let query =
        tokio::spawn(async move { query_pool.query("default", &mock_dns_query(0x1234)).await });
    pause.entered.notified().await;
    let mut first_close = Box::pin(pool.close());
    let mut second_close = Box::pin(pool.close());
    assert!(matches!(
        futures::poll!(first_close.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(matches!(
        futures::poll!(second_close.as_mut()),
        std::task::Poll::Pending
    ));

    // When
    drop(first_close);
    assert!(matches!(
        futures::poll!(second_close.as_mut()),
        std::task::Poll::Pending
    ));
    query.abort();
    let cancelled = query.await.expect_err("query cancellation");

    // Then
    assert!(cancelled.is_cancelled());
    assert!(matches!(
        futures::poll!(second_close.as_mut()),
        std::task::Poll::Ready(())
    ));
    let mut idempotent_close = Box::pin(pool.close());
    assert!(matches!(
        futures::poll!(idempotent_close.as_mut()),
        std::task::Poll::Ready(())
    ));
    let error = pool
        .query("default", &mock_dns_query(0x4321))
        .await
        .expect_err("closed pool rejects new admission");
    assert!(error.to_string().contains("closed"));
    assert_eq!(pool.lifecycle_stats(), TransportLifecycleStats::default());
}

#[tokio::test]
async fn close_joins_udp_receive_task_and_removes_query_path() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP server");
    let address = server.local_addr().expect("UDP server address");
    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, peer) = server.recv_from(&mut buffer).await.expect("UDP query");
        let mut response = mock_dns_response(0);
        response[..2].copy_from_slice(&buffer[..2]);
        assert!(length >= response.len() - 16);
        server.send_to(&response, peer).await.expect("UDP response");
    });
    let pool = UpstreamPool::new(
        &[make_upstream(
            "default",
            &address.to_string(),
            DnsProtocol::Udp,
        )],
        make_router(),
    )
    .expect("pool");
    pool.query("default", &mock_dns_query(0x1234))
        .await
        .expect("UDP response");
    responder.await.expect("UDP responder");
    assert_eq!(pool.lifecycle_stats().tasks, 1);
    assert!(
        pool.entries["default"]
            .udp
            .lock()
            .pools
            .iter()
            .any(Option::is_some)
    );

    pool.close().await;
    pool.close().await;

    assert_eq!(pool.lifecycle_stats().tasks, 0);
    assert!(
        pool.entries["default"]
            .udp
            .lock()
            .pools
            .iter()
            .all(Option::is_none)
    );
    assert!(
        pool.query("default", &mock_dns_query(0x5678))
            .await
            .expect_err("closed UDP path rejects queries")
            .to_string()
            .contains("closed")
    );
}
