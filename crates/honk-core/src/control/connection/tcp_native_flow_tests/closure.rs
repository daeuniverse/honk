use super::*;

#[tokio::test]
async fn native_tcp_delete_closes_both_peers_without_recording() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"live").await?;
        let mut bytes = [0; 4];
        upstream.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"live");
        let tracker = &fixture.handle.connection_tracker;
        let catalog = fixture.handle.native.as_ref().unwrap().catalog.snapshot();
        assert_eq!(
            tracker
                .snapshot_group(&catalog.groups["outer"], Some("tcp"))
                .len(),
            1
        );
        assert!(
            tracker
                .snapshot_group(&catalog.groups["inner"], Some("udp"))
                .is_empty()
        );
        fixture
            .handle
            .group_manager
            .read()
            .set_selector_choice(
                "inner",
                "block",
                honk_outbound::group::SelectorNetworks::Both,
            )
            .unwrap();
        let connection = tracker.snapshot().pop().unwrap();
        assert_eq!(
            tracker
                .snapshot_group(&catalog.groups["inner"], Some("tcp"))
                .len(),
            1
        );
        let path = format!("{}/connections/{}", fixture.api, connection.id);
        let response = fixture
            .http
            .delete(&path)
            .header("idempotency-key", "close-once")
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(fixture.client.read(&mut bytes).await?, 0);
        assert_eq!(upstream.read(&mut bytes).await?, 0);
        (&mut fixture.task).await??;
        assert!(tracker.snapshot().is_empty());
        assert_eq!(fixture.handle.stats.snapshot()["outer"].tx_bytes, 4);
        let again = fixture
            .http
            .delete(&path)
            .header("idempotency-key", "close-once")
            .send()
            .await?;
        assert_eq!(again.status(), reqwest::StatusCode::NOT_FOUND);
        fixture.finish_removals().await?;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tcp_close_claims_share_guard_retirement() -> anyhow::Result<()> {
    use crate::connection_tracker::CloseOutcome;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        let connection = tracker.snapshot().pop().unwrap();
        let backend = fixture.handle.ebpf.write().await;
        let selected = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let disappeared = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let completion = tracker.start_close(selected);
        let mut duplicate = Box::pin(tracker.close_id(&connection.id));
        assert!(futures::poll!(&mut duplicate).is_pending());
        assert_eq!(upstream.read(&mut byte).await?, 0);
        let mut completion = Box::pin(completion.wait());
        assert!(futures::poll!(&mut completion).is_pending());
        assert_eq!(tracker.snapshot().len(), 1);
        drop(backend);
        assert_eq!(completion.await, CloseOutcome::Closed);
        assert_eq!(duplicate.await, CloseOutcome::Closed);
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        (&mut fixture.task).await??;
        assert_eq!(
            tracker.close_selected(disappeared).await,
            CloseOutcome::Gone
        );
        fixture.finish_removals().await?;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn native_bulk_oversize_counts_unowned_mapped_sources_before_any_close() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::with_recording("direct", "ip", false).await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        for index in 0..1000 {
            tracker.register(crate::connection_tracker::ConnectionEntry {
                id: uuid::Uuid::from_u128(index as u128),
                source: format!("[::ffff:127.0.0.1]:{}", index + 1).parse().unwrap(),
                destination: "192.0.2.1:443".parse().unwrap(),
                proxy: "direct".into(),
                routed_outbound: None,
                native_flow_id: None,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                start_time: std::time::Instant::now(),
                domain: None,
                network: "tcp",
                process: None,
                process_path: None,
            });
        }
        let base = format!("{}/connections", fixture.api);
        let unfiltered = fixture
            .http
            .delete(format!("{base}?type=all"))
            .send()
            .await?;
        assert_eq!(unfiltered.status(), reqwest::StatusCode::BAD_REQUEST);
        let oversized = fixture
            .http
            .delete(format!("{base}?type=tcp&src=127.0.0.1"))
            .send()
            .await?;
        assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        fixture.client.write_all(b"y").await?;
        upstream.read_exact(&mut byte).await?;
        assert_eq!(&byte, b"y");
        let unowned = fixture
            .http
            .delete(format!("{base}/{}", uuid::Uuid::nil()))
            .send()
            .await?;
        assert_eq!(unowned.status(), reqwest::StatusCode::CONFLICT);
        for index in 0..1000 {
            tracker.remove(&uuid::Uuid::from_u128(index as u128));
        }
        let closed: Value = fixture
            .http
            .delete(format!("{base}?type=tcp&src=::ffff:127.0.0.1"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(closed, serde_json::json!({"closed":1,"skipped":0}));
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        assert_eq!(upstream.read(&mut byte).await?, 0);
        (&mut fixture.task).await??;
        fixture.finish_removals().await?;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn aborted_tcp_close_does_not_acknowledge_guard_retirement() -> anyhow::Result<()> {
    use crate::connection_tracker::CloseOutcome;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = Fixture::new("direct", "ip").await?;
        let (mut upstream, _) = fixture.listener.accept().await?;
        fixture.client.write_all(b"x").await?;
        let mut byte = [0];
        upstream.read_exact(&mut byte).await?;
        let tracker = &fixture.handle.connection_tracker;
        let backend = fixture.handle.ebpf.write().await;
        let retiring = fixture.flow("active").await?;
        assert!(retiring["ended_at"].is_null());
        assert!(
            !steps(&retiring, "connection")
                .iter()
                .any(|step| step["data"]["milestone"] == "terminal")
        );
        let selected = tracker
            .snapshot_close(Some("tcp"), None, 1000)
            .unwrap()
            .pop()
            .unwrap();
        let completion = tracker.start_close(selected);
        let mut duplicate = Box::pin(
            tracker.close_selected(
                tracker
                    .snapshot_close(Some("tcp"), None, 1000)
                    .unwrap()
                    .pop()
                    .unwrap(),
            ),
        );
        assert!(futures::poll!(&mut duplicate).is_pending());
        fixture.task.abort();
        assert!((&mut fixture.task).await.unwrap_err().is_cancelled());
        assert_eq!(completion.wait().await, CloseOutcome::Failed);
        assert_eq!(duplicate.await, CloseOutcome::Failed);
        assert_eq!(upstream.read(&mut byte).await?, 0);
        assert_eq!(fixture.client.read(&mut byte).await?, 0);
        drop(backend);
        let cancelled = fixture.flow("failed").await?;
        let terminals: Vec<_> = steps(&cancelled, "connection")
            .into_iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["data"]["reason"], "cancelled");
        fixture.finish_removals().await?;
        fixture.server.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
