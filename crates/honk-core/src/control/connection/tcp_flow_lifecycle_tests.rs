use super::*;

use crate::connection_tracker::ConnectionEntry;
use crate::ebpf::mock::MockEbpfBackend;
use honk_ebpf_common::RedirectTuple;
use honk_ebpf_common::conn::{ConnState, TcpState};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::AsyncReadExt;

fn forward_tuple() -> TuplesKey {
    build_tuples_key(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        443,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        50_000,
        6,
    )
}

fn reverse_tuple() -> TuplesKey {
    build_tuples_key(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        50_000,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        443,
        6,
    )
}

fn set_padding(tuple: &mut TuplesKey, padding: [u8; 3]) {
    unsafe {
        std::ptr::copy_nonoverlapping(
            padding.as_ptr(),
            (tuple as *mut TuplesKey).cast::<u8>().add(37),
            padding.len(),
        );
    }
}

fn backend() -> Arc<RwLock<Box<dyn EbpfBackend>>> {
    Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())))
}

fn tracked_entry(id: &str) -> ConnectionEntry {
    ConnectionEntry {
        id: id.to_string(),
        source: "192.0.2.1:50000".to_string(),
        destination: "203.0.113.2:443".to_string(),
        proxy: "direct".to_string(),
        #[cfg(feature = "native-api")]
        routed_outbound: None,
        #[cfg(feature = "native-api")]
        native_flow_id: None,
        rule: "Fallback".to_string(),
        rule_payload: String::new(),
        chains: vec!["direct".to_string()],
        upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        start_time: std::time::Instant::now(),
        domain: None,
        network: "tcp".to_string(),
        process: None,
        process_path: None,
    }
}

async fn tcp_pair() -> anyhow::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect = TcpStream::connect(addr);
    let (accepted, peer) = tokio::join!(listener.accept(), connect);
    Ok((accepted?.0, peer?))
}

#[test]
fn directional_key_ignores_padding_and_refcounts_owners() {
    let mut first = forward_tuple();
    let mut second = forward_tuple();
    set_padding(&mut first, [1, 2, 3]);
    set_padding(&mut second, [4, 5, 6]);
    let key = TcpFlowKey::from_tuples(&first);

    assert_eq!(key, TcpFlowKey::from_tuples(&second));
    assert_eq!(
        key,
        TcpFlowKey::from_redirect(&RedirectTuple::from_tuples(&first))
    );
    let reverse = TcpFlowKey::from_tuples(&reverse_tuple());
    assert_ne!(key, reverse);

    let pins = TcpFlowPins::default();
    pins.retain(key);
    pins.retain(key);
    pins.retain(reverse);
    assert_eq!(pins.snapshot().len(), 2);
    assert_eq!(pins.release(key), Some(false));
    assert!(pins.snapshot().contains(&key));
    assert_eq!(pins.release(key), Some(true));
    assert!(!pins.snapshot().contains(&key));
    assert!(pins.snapshot().contains(&reverse));
    assert_eq!(pins.release(key), None);
    assert_eq!(pins.release(reverse), Some(true));
    assert!(pins.snapshot().is_empty());
}

#[tokio::test]
async fn tcp_flow_guard_abort_releases_pin_tracker_and_socket() -> anyhow::Result<()> {
    let (stream, mut peer) = tcp_pair().await?;
    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let mut flow = TcpFlowGuard::new(
        stream,
        forward_tuple(),
        Arc::clone(&pins),
        backend(),
        Arc::clone(&tracker),
    );
    flow.track(tracked_entry("abort"));
    assert_eq!(pins.snapshot().len(), 1);
    assert_eq!(tracker.snapshot().len(), 1);

    let task = tokio::spawn(async move {
        let _flow = flow;
        std::future::pending::<()>().await;
    });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(pins.snapshot().is_empty());
    assert!(tracker.snapshot().is_empty());

    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
        0
    );
    Ok(())
}

#[tokio::test]
async fn tcp_retire_waits_for_final_owner() -> anyhow::Result<()> {
    let tuple = forward_tuple();
    let backend = backend();
    backend.write().await.tcp_conn_state_store(
        &tuple,
        &ConnState {
            state: TcpState::TcpStateActive as u8,
            last_seen_ns: 0,
            ..Default::default()
        },
    )?;
    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let (first_stream, _first_peer) = tcp_pair().await?;
    let (second_stream, _second_peer) = tcp_pair().await?;
    let first = TcpFlowGuard::new(
        first_stream,
        tuple,
        Arc::clone(&pins),
        Arc::clone(&backend),
        Arc::clone(&tracker),
    );
    let second = TcpFlowGuard::new(
        second_stream,
        tuple,
        Arc::clone(&pins),
        Arc::clone(&backend),
        tracker,
    );

    first.retire().await;
    assert!(
        backend
            .read()
            .await
            .tcp_conn_state_lookup(&tuple)?
            .is_some()
    );
    assert!(pins.snapshot().contains(&TcpFlowKey::from_tuples(&tuple)));

    second.retire().await;
    assert!(
        backend
            .read()
            .await
            .tcp_conn_state_lookup(&tuple)?
            .is_none()
    );
    assert!(pins.snapshot().is_empty());
    Ok(())
}

#[tokio::test]
async fn tcp_retire_preserves_newer_incarnation() -> anyhow::Result<()> {
    let tuple = forward_tuple();
    let reverse = reverse_tuple();
    let old = ConnState {
        state: TcpState::TcpStateActive as u8,
        last_seen_ns: 0,
        ..Default::default()
    };
    let backend = backend();
    {
        let mut backend = backend.write().await;
        backend.tcp_conn_state_store(&tuple, &old)?;
        backend.tcp_conn_state_store(&reverse, &old)?;
    }

    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let (stream, mut peer) = tcp_pair().await?;
    let mut flow = TcpFlowGuard::new(
        stream,
        tuple,
        Arc::clone(&pins),
        Arc::clone(&backend),
        Arc::clone(&tracker),
    );
    flow.track(tracked_entry("replacement"));

    let mut backend_guard = backend.write().await;
    let retire = tokio::spawn(flow.retire());
    tokio::task::yield_now().await;
    assert_eq!(
        tracker.snapshot().len(),
        1,
        "retirement retains its ID until backend cleanup completes"
    );
    backend_guard.tcp_conn_state_store(
        &tuple,
        &ConnState {
            last_seen_ns: u64::MAX,
            ..old
        },
    )?;
    drop(backend_guard);
    retire.await?;

    let backend = backend.read().await;
    assert_eq!(
        backend
            .tcp_conn_state_lookup(&tuple)?
            .expect("replacement state")
            .last_seen_ns,
        u64::MAX
    );
    assert!(backend.tcp_conn_state_lookup(&reverse)?.is_some());
    drop(backend);
    assert!(pins.snapshot().is_empty());
    assert!(tracker.snapshot().is_empty());
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
        0
    );
    Ok(())
}
