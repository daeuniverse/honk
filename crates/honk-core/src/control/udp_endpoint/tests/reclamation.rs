use super::*;
use crate::control::connection::build_tuples_key;
use crate::ebpf::UdpFlowOwner;
use honk_ebpf_common::TuplesKey;

fn flow(client: SocketAddr, destination: SocketAddr, proto: u8) -> TuplesKey {
    build_tuples_key(
        destination.ip(),
        destination.port(),
        client.ip(),
        client.port(),
        proto,
    )
}

#[test]
fn reclaimed_flow_retires_only_the_endpoint_of_that_incarnation() {
    let (client, destination): (SocketAddr, SocketAddr) = (
        "192.0.2.10:40000".parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
    );
    for (ready, incarnation) in [(false, Some(7)), (true, Some(7)), (false, None)] {
        let pool = Arc::new(UdpEndpointPool::new());
        let mut lease = match pool.reserve_owned_or_enqueue_at(
            honk_datapath::ScopeId::HOST,
            client,
            destination,
            Bytes::from_static(b"first"),
            UdpFlowOwner::new(22, incarnation).unwrap(),
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            Instant::now(),
            &StatsManager::new(),
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("fresh owned endpoint"),
        };
        if ready {
            let endpoint = driver_test_endpoint(
                Arc::new(ScriptedPacketTransport::new(destination, [])),
                destination,
            );
            assert!(lease.commit_ready(endpoint));
        }
        let udp = flow(client, destination, 17);
        assert!(!pool.retire_reclaimed(&udp, 6), "older incarnation");
        assert!(!pool.retire_reclaimed(&udp, 8), "newer incarnation");
        assert!(
            !pool.retire_reclaimed(&flow(client, destination, 6), 7),
            "TCP tuple with the same addresses"
        );
        let other = "192.0.2.11:40000".parse().unwrap();
        assert!(!pool.retire_reclaimed(&flow(other, destination, 17), 7));
        assert!(pool.contains(honk_datapath::ScopeId::HOST, client, destination));

        assert_eq!(pool.retire_reclaimed(&udp, 7), incarnation.is_some());
        assert_eq!(pool.is_empty(), incarnation.is_some());
        assert!(!pool.retire_reclaimed(&udp, 7));
    }
}
