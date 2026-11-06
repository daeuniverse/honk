use super::support::netns::{build_lab, pinned_map};
use crate::control::nfqueue::{HeldVerdict, NfqueueIngest, PendingUdpVerdicts, TestVerdict};
use crate::control::udp_endpoint::UdpEndpointPool;
use crate::ebpf::{EbpfBackend, RetireKind, RetireOutcome, RetireRequest, real::RealEbpfBackend};
use crate::stats::StatsManager;
use aya::maps::HashMap;
use honk_ebpf_common::{
    ConnState, ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED, RoutingMeta, TuplesKey,
    conn::RetirementFence, dae_ip::In6Addr,
};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[test]
#[ignore = "requires real maps and cgroup hooks in the disposable kernel VM gate"]
fn netns_nfqueue_reconstruction_refuses_unresolved_retirement() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        let (_client, _server) = build_lab("192.0.2.1".parse()?, "198.51.100.1".parse()?)?;
        let (_dae0, dae0_setup) = crate::daens::create_dae0_link()?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let root = Path::new("/sys/fs/bpf/nfqueue-reconstruction");
                let mut backend =
                    RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, root, 12345, &dae0_setup, 0)
                        .await?;
                let key = TuplesKey {
                    src_ip: In6Addr::from_ipv4_bytes([192, 0, 2, 10]),
                    dst_ip: In6Addr::from_ipv4_bytes([198, 51, 100, 20]),
                    src_port: 40000,
                    dst_port: 443,
                    l4proto: libc::IPPROTO_UDP as u8,
                    ..Default::default()
                };
                let token = 19;
                let incarnation = 37;
                backend.udp_conn_state_store(
                    &key,
                    &ConnState {
                        incarnation,
                        decision_token: token,
                        meta: RoutingMeta {
                            raw: ROUTING_META_FLAG_PUBLISHED
                                | ROUTING_META_FLAG_OFFLOAD
                                | (0x1200 << 8),
                        },
                        ..Default::default()
                    },
                )?;
                assert_eq!(
                    backend
                        .udp_flow_owner(token, backend.conn_state_lookup(&key)?)?
                        .incarnation(),
                    Some(incarnation)
                );
                let mut fences = HashMap::<_, TuplesKey, RetirementFence>::try_from(pinned_map(
                    root,
                    "RETIRE_FENCE",
                )?)?;
                fences.insert(
                    &key,
                    &RetirementFence {
                        owner: 900,
                        decision_token: token,
                        padding: 0,
                    },
                    1,
                )?;
                let request = RetireRequest {
                    key,
                    kind: RetireKind::Udp {
                        token,
                        incarnation: Some(incarnation),
                        pending_only: false,
                    },
                };
                assert!(
                    backend
                        .retire_batch(&[request], &mut [RetireOutcome::NotRun])
                        .is_err()
                );
                assert!(
                    backend
                        .udp_flow_owner(token, backend.conn_state_lookup(&key)?)
                        .is_err()
                );
                assert_eq!(
                    backend.conn_state_lookup(&key)?.unwrap().incarnation,
                    incarnation
                );
                assert_eq!(fences.get(&key, 0)?.owner, 900);

                let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
                    Arc::new(RwLock::new(Box::new(backend)));
                let (pending, mut fatal) = PendingUdpVerdicts::new(
                    backend,
                    Arc::new(UdpEndpointPool::new()),
                    Arc::new(StatsManager::new()),
                );
                pending.open_admission();
                let sink = Arc::new(Mutex::new(Vec::new()));
                let received_at = Instant::now();
                let packet = honk_nfqueue::QueuedPacket {
                    tuple: honk_nfqueue::UdpTuple {
                        client: "192.0.2.10:40000".parse()?,
                        destination: "198.51.100.20:443".parse()?,
                    },
                    payload: bytes::Bytes::from_static(b"held before retirement failed"),
                    mark: honk_ebpf_common::pack_nfqueue_mark(token).unwrap(),
                    priority: None,
                    received_at,
                };
                let result = pending
                    .ingest_held_wait(
                        packet,
                        HeldVerdict::test(1, received_at, Arc::clone(&sink)),
                        None,
                    )
                    .await;
                assert!(matches!(result, NfqueueIngest::Dropped));
                assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
                assert!(
                    fatal.try_recv().is_ok(),
                    "failed backend admission did not reach the critical owner"
                );
                Ok(())
            })
    })
    .join()
    .expect("isolated NFQUEUE reconstruction panicked")
}
