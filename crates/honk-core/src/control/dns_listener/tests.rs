use super::*;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::routing::Router;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};

#[cfg(feature = "native-api")]
mod native_dns;

struct FixedAddressUpstream {
    address: [u8; 4],
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for FixedAddressUpstream {
    async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(a_response(raw, self.address))
    }
}

struct TestRuntimeTransport;

#[async_trait::async_trait]
impl crate::dns::runtime::RuntimeTransport for TestRuntimeTransport {
    async fn close(&self) {}
}

fn a_response(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, address[0], address[1], address[2], address[3],
    ]);
    response
}
fn forwarder_with_config(
    address: [u8; 4],
    config: &honk_config::dns::DnsConfig,
) -> (Arc<DnsForwarder>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream = Arc::new(FixedAddressUpstream {
        address,
        calls: Arc::clone(&calls),
    });
    let router = Arc::new(
        crate::dns::routing::DnsRouter::new_from_dns_config(config).expect("test DNS router"),
    );
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            router,
        )
        .with_cache_enabled(false),
    );
    (forwarder, calls)
}

fn forwarder(address: [u8; 4]) -> (Arc<DnsForwarder>, Arc<AtomicUsize>) {
    forwarder_with_config(address, &honk_config::dns::DnsConfig::default())
}
fn controller_with_config(
    address: [u8; 4],
    config: &honk_config::dns::DnsConfig,
    udp_query_limit: usize,
) -> (Arc<DnsController>, Arc<AtomicUsize>) {
    let (forwarder, calls) = forwarder_with_config(address, config);
    let controller = Arc::new(DnsController::new(
        forwarder,
        Arc::new(tokio::sync::RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").expect("test traffic router"),
        )),
        udp_query_limit,
    ));
    (controller, calls)
}

fn controller(address: [u8; 4]) -> (Arc<DnsController>, Arc<AtomicUsize>) {
    controller_with_config(address, &honk_config::dns::DnsConfig::default(), 256)
}
fn start_listener(
    bind: &str,
    controller: Arc<DnsController>,
) -> (DnsListener, SocketAddr, Arc<DrainTracker>) {
    start_listener_with_connection_limit(bind, controller, 16)
}

fn start_listener_with_connection_limit(
    bind: &str,
    controller: Arc<DnsController>,
    connection_permits: usize,
) -> (DnsListener, SocketAddr, Arc<DrainTracker>) {
    let endpoint = DnsBindEndpoint::parse(bind).expect("dns.bind endpoint");
    let bound = BoundDnsListener::bind(&endpoint).expect("bind standalone DNS");
    let address = bound.local_addr();
    let drain = Arc::new(DrainTracker::new().with_drain_timeout(Duration::from_millis(20)));
    let listener = bound
        .spawn(
            controller,
            Arc::new(Semaphore::new(connection_permits)),
            Arc::new(StatsManager::new()),
            Arc::clone(&drain),
            None,
            Default::default(),
        )
        .expect("spawn standalone DNS");
    (listener, address, drain)
}

async fn stop_listener(listener: &mut DnsListener, drain: &DrainTracker) {
    listener.stop_accepting();
    drain.drain().await.expect("drain standalone DNS");
    listener
        .abort_and_join()
        .await
        .expect("join standalone DNS");
    assert_eq!(
        drain.active_count(),
        0,
        "abort_and_join returned before listener children terminated"
    );
}

fn query(domain: &str, txid: u16) -> Vec<u8> {
    let mut query = crate::dns::forwarder::build_dns_query(domain, 1);
    query[..2].copy_from_slice(&txid.to_be_bytes());
    query
}

fn multi_query(first: &str, second: &str, txid: u16) -> Vec<u8> {
    let mut wire = query(first, txid);
    let second = query(second, txid);
    wire[4..6].copy_from_slice(&2u16.to_be_bytes());
    wire.extend_from_slice(&second[12..]);
    wire
}

async fn udp_exchange(address: SocketAddr, query: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP client");
    client
        .send_to(query, address)
        .await
        .expect("send UDP query");
    let mut response = [0u8; 512];
    let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut response))
        .await
        .expect("UDP response timeout")
        .expect("receive UDP response");
    response[..length].to_vec()
}

async fn read_tcp_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    crate::dns::transport::read_length_prefixed_into(
        stream,
        &mut response,
        Some(Duration::from_secs(2)),
    )
    .await
    .expect("read TCP DNS response");
    response
}

#[test]
fn selected_transports_and_dual_port_zero_are_exact() {
    let udp_endpoint = DnsBindEndpoint::parse("udp://127.0.0.1:0").unwrap();
    let udp = BoundDnsListener::bind(&udp_endpoint).unwrap();
    assert!(udp.has_udp());
    assert!(!udp.has_tcp());
    drop(udp);

    let tcp_endpoint = DnsBindEndpoint::parse("tcp://127.0.0.1:0").unwrap();
    let tcp = BoundDnsListener::bind(&tcp_endpoint).unwrap();
    assert!(tcp.has_tcp());
    assert!(!tcp.has_udp());
    drop(tcp);

    let dual_endpoint = DnsBindEndpoint::parse("tcp+udp://127.0.0.1:0").unwrap();
    let dual = BoundDnsListener::bind(&dual_endpoint).unwrap();
    assert!(dual.has_tcp());
    assert!(dual.has_udp());
    assert_eq!(dual.tcp_local_addr(), dual.udp_local_addr());
    assert_ne!(dual.local_addr().port(), 0);
}

#[test]
fn standalone_listener_capacities_and_profiles_are_exact() {
    assert_eq!(standalone_tcp_capacity(0), 0);
    assert_eq!(standalone_tcp_capacity(1), 1);
    assert_eq!(standalone_tcp_capacity(8), 2);

    let mut wire = query("large-response.example", 0x5151);
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 41, 0xff, 0xff, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        validate_exact_dns_query(&wire).unwrap().ingress(),
        crate::dns::query::IngressProfile::Udp {
            advertised_size: u16::MAX
        }
    );
    let mut undersized = wire.clone();
    let opt_class = undersized.len() - 8;
    undersized[opt_class..opt_class + 2].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        validate_exact_dns_query(&undersized).unwrap().ingress(),
        crate::dns::query::IngressProfile::Udp { advertised_size: 1 }
    );

    let mut opcode_query = query("opcode.example", 0x5252);
    opcode_query[2..4].copy_from_slice(&0x2900u16.to_be_bytes());
    let opcode_error = minimal_dns_error_response(&opcode_query, 5);
    assert_eq!(
        u16::from_be_bytes([opcode_error[2], opcode_error[3]]) & 0x7800,
        0x2800
    );
}

#[test]
fn dual_bind_failure_releases_first_transport_atomically() {
    // Another test's ephemeral UDP client can take the probed port; a leak
    // fails every attempt, a collision almost never repeats.
    for _ in 0..8 {
        let occupied_tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = occupied_tcp.local_addr().unwrap();
        let endpoint = DnsBindEndpoint::parse(&format!("tcp+udp://{address}")).unwrap();

        assert!(BoundDnsListener::bind(&endpoint).is_err());
        if std::net::UdpSocket::bind(address).is_ok() {
            return;
        }
    }
    panic!("failed dual bind must release its first UDP socket");
}

#[test]
fn wildcard_ipv6_sockets_explicitly_enable_dual_stack() {
    let endpoint = DnsBindEndpoint::parse("tcp+udp://:0").unwrap();
    let bound = BoundDnsListener::bind(&endpoint).unwrap();
    if bound.local_addr().is_ipv6() {
        assert!(
            !socket2::SockRef::from(bound.tcp.as_ref().unwrap())
                .only_v6()
                .unwrap()
        );
        assert!(
            !socket2::SockRef::from(bound.udp.as_ref().unwrap())
                .only_v6()
                .unwrap()
        );
    }
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn native_log_feed_admits_the_listener_start() {
    use futures::StreamExt;
    if crate::native_api::logs::tests::run_isolated(
        "control::dns_listener::tests::native_log_feed_admits_the_listener_start",
    ) {
        return;
    }
    use tracing_subscriber::prelude::*;
    let store = Arc::new(crate::native_api::logs::LogStore::new(
        "listener-start".into(),
        true,
        "info",
    ));
    let (layer, binding) = crate::native_api::logs::tracing_layer();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
    binding.bind(Arc::downgrade(&store));
    let mut stream = store.stream_for_test().into_body().into_data_stream();
    let mut next = async || {
        let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        String::from_utf8(frame.to_vec()).unwrap()
    };
    assert!(next().await.starts_with("event: stream.ready\n"));
    let (controller, _) = controller([192, 0, 2, 10]);
    let (mut listener, _, drain) = tracing::dispatcher::with_default(&dispatch, || {
        start_listener("udp://127.0.0.1:0", controller)
    });
    let frame = next().await;
    let record: serde_json::Value = serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(record["message"], "Standalone DNS listener started");
    assert_eq!(record["fields"]["tcp"], false);
    assert_eq!(record["fields"]["udp"], true);
    stop_listener(&mut listener, &drain).await;
    store.shutdown();
}

#[tokio::test]
async fn listener_start_is_not_logged_when_socket_adoption_fails() {
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let captured = Arc::clone(&captured);
            move || Capture(Arc::clone(&captured))
        })
        .finish();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    // epoll refuses a character device, so adopting this "socket" fails.
    let udp = std::net::UdpSocket::from(std::os::fd::OwnedFd::from(
        std::fs::File::open("/dev/null").unwrap(),
    ));
    udp.set_nonblocking(true).unwrap();
    let bound = BoundDnsListener {
        local_addr: tcp.local_addr().unwrap(),
        tcp: Some(tcp),
        udp: Some(udp),
    };
    let (controller, _) = controller([192, 0, 2, 10]);

    let result = tracing::subscriber::with_default(subscriber, || {
        bound.spawn(
            controller,
            Arc::new(Semaphore::new(16)),
            Arc::new(StatsManager::new()),
            Arc::new(DrainTracker::new()),
            None,
            Default::default(),
        )
    });

    assert!(result.is_err());
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains("Standalone DNS listener started"), "{logs}");
}

#[tokio::test]
async fn udp_listener_routes_query_and_reports_malformed_and_admission_errors() {
    let (controller, calls) = controller([192, 0, 2, 10]);
    let (mut listener, address, drain) =
        start_listener("udp://127.0.0.1:0", Arc::clone(&controller));

    let valid = query("udp.example", 0x1010);
    let response = udp_exchange(address, &valid).await;
    assert_eq!(&response[..2], &valid[..2]);
    assert!(response.windows(4).any(|window| window == [192, 0, 2, 10]));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let multi = multi_query("first.multi.example", "second.multi.example", 0x1110);
    let response = udp_exchange(address, &multi).await;
    assert_eq!(response[3] & 0x0f, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut malformed = query("malformed.example", 0x2020);
    malformed[4..6].copy_from_slice(&2u16.to_be_bytes());
    let response = udp_exchange(address, &malformed).await;
    assert_eq!(response[3] & 0x0f, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    stop_listener(&mut listener, &drain).await;

    let (saturated_controller, saturated_calls) =
        controller_with_config([192, 0, 2, 10], &honk_config::dns::DnsConfig::default(), 0);
    let (mut saturated, saturated_address, saturated_drain) =
        start_listener("udp://127.0.0.1:0", saturated_controller);
    let refused = udp_exchange(saturated_address, &query("busy.example", 0x3030)).await;
    assert_eq!(refused[3] & 0x0f, 5);
    assert_eq!(saturated_calls.load(Ordering::SeqCst), 0);
    stop_listener(&mut saturated, &saturated_drain).await;
}
#[tokio::test]
async fn standalone_listeners_route_by_exact_peer_source() {
    let mut config = honk_config::dns::DnsConfig::default();
    config.routing.request.rules = vec![honk_config::dns::DnsRequestRule {
        conditions: vec![honk_config::dns::DnsCond::Sip {
            not: false,
            cidrs: vec!["127.0.0.42/32".into()],
        }],
        action: honk_config::dns::DnsRequestAction::Upstream("default".into()),
    }];
    config.routing.request.fallback = honk_config::dns::DnsRequestAction::Reject;
    let (controller, calls) = controller_with_config([192, 0, 2, 30], &config, 256);
    let (mut listener, address, drain) = start_listener("tcp+udp://127.0.0.1:0", controller);

    let udp_client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 42), 0))
        .await
        .expect("bind source-routed UDP client");
    udp_client
        .send_to(&query("udp-source.example", 0x4040), address)
        .await
        .expect("send source-routed UDP query");
    let mut udp_response = [0u8; 512];
    let udp_length =
        tokio::time::timeout(Duration::from_secs(2), udp_client.recv(&mut udp_response))
            .await
            .expect("source-routed UDP response timeout")
            .expect("receive source-routed UDP response");
    assert!(
        udp_response[..udp_length]
            .windows(4)
            .any(|window| window == [192, 0, 2, 30])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let rejected_udp = udp_exchange(address, &query("udp-fallback.example", 0x4041)).await;
    assert_eq!(u16::from_be_bytes([rejected_udp[6], rejected_udp[7]]), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let tcp_socket = TcpSocket::new_v4().expect("create source-routed TCP socket");
    tcp_socket
        .bind(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 42).into(), 0))
        .expect("bind source-routed TCP client");
    let mut tcp_client = tcp_socket
        .connect(address)
        .await
        .expect("connect source-routed TCP client");
    let tcp_query = query("tcp-source.example", 0x4042);
    crate::dns::transport::write_length_prefixed(&mut tcp_client, &tcp_query)
        .await
        .expect("write source-routed TCP query");
    let tcp_response = read_tcp_frame(&mut tcp_client).await;
    assert!(
        tcp_response
            .windows(4)
            .any(|window| window == [192, 0, 2, 30])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(tcp_client);

    let mut rejected_tcp = TcpStream::connect(address)
        .await
        .expect("connect fallback TCP client");
    let rejected_query = query("tcp-fallback.example", 0x4043);
    crate::dns::transport::write_length_prefixed(&mut rejected_tcp, &rejected_query)
        .await
        .expect("write fallback TCP query");
    let rejected_response = read_tcp_frame(&mut rejected_tcp).await;
    assert_eq!(
        u16::from_be_bytes([rejected_response[6], rejected_response[7]]),
        0
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    stop_listener(&mut listener, &drain).await;
}

#[tokio::test]
async fn wildcard_udp_reply_uses_the_queried_local_address() {
    let (controller, _) = controller([192, 0, 2, 20]);
    let (mut listener, address, drain) = start_listener("udp://0.0.0.0:0", controller);
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP client");
    let destination = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), address.port());
    client
        .send_to(&query("reply-source.example", 0x4141), destination)
        .await
        .expect("send wildcard UDP query");

    let mut response = [0u8; 512];
    let (_, response_source) =
        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
            .await
            .expect("wildcard UDP response timeout")
            .expect("receive wildcard UDP response");
    assert_eq!(response_source.ip(), destination.ip());

    stop_listener(&mut listener, &drain).await;
}

#[tokio::test]
async fn tcp_listener_serves_persistent_frames_and_closes_malformed_connections() {
    let (controller, calls) = controller([198, 51, 100, 11]);
    let (mut listener, address, drain) = start_listener("tcp://127.0.0.1:0", controller);
    let mut client = TcpStream::connect(address).await.expect("connect TCP DNS");

    for (domain, txid) in [("first.example", 0x1111), ("second.example", 0x2222)] {
        let query = query(domain, txid);
        crate::dns::transport::write_length_prefixed(&mut client, &query)
            .await
            .expect("write TCP DNS query");
        let response = read_tcp_frame(&mut client).await;
        assert_eq!(&response[..2], &query[..2]);
        assert!(
            response
                .windows(4)
                .any(|window| window == [198, 51, 100, 11])
        );
    }

    let multi = multi_query("first.tcp.multi", "second.tcp.multi", 0x3333);
    crate::dns::transport::write_length_prefixed(&mut client, &multi)
        .await
        .expect("write multi-question TCP DNS query");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("multi-question TCP close timeout")
        .expect("read multi-question TCP close");
    assert_eq!(read, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(client);

    let mut malformed_client = TcpStream::connect(address)
        .await
        .expect("connect malformed TCP DNS");
    crate::dns::transport::write_length_prefixed(&mut malformed_client, &[0u8; 12])
        .await
        .expect("write malformed TCP DNS frame");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), malformed_client.read(&mut byte))
        .await
        .expect("malformed TCP close timeout")
        .expect("read malformed TCP close");
    assert_eq!(read, 0);

    stop_listener(&mut listener, &drain).await;
}

#[tokio::test]
async fn tcp_listener_preserves_global_connection_capacity() {
    let (controller, _) = controller([203, 0, 113, 20]);
    let (mut listener, address, drain) =
        start_listener_with_connection_limit("tcp://127.0.0.1:0", controller, 4);
    let first = TcpStream::connect(address)
        .await
        .expect("connect first idle TCP DNS client");
    tokio::time::timeout(Duration::from_secs(1), async {
        while drain.active_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first standalone TCP connection must be tracked");

    let mut second = TcpStream::connect(address)
        .await
        .expect("connect excess TCP DNS client");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), second.read(&mut byte))
        .await
        .expect("excess TCP DNS close timeout")
        .expect("read excess TCP DNS close");
    assert_eq!(read, 0);
    assert_eq!(drain.active_count(), 1);

    drop(first);
    stop_listener(&mut listener, &drain).await;
}

#[tokio::test]
async fn shutdown_releases_listener_address_for_rebind() {
    let (controller, _) = controller([203, 0, 113, 12]);
    let (mut listener, address, drain) = start_listener("tcp+udp://127.0.0.1:0", controller);
    let mut closed_client = TcpStream::connect(address)
        .await
        .expect("connect malformed TCP DNS client");
    let multi = multi_query("restart.first", "restart.second", 0x5252);
    crate::dns::transport::write_length_prefixed(&mut closed_client, &multi)
        .await
        .expect("write rejected TCP DNS query");
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), closed_client.read(&mut byte))
            .await
            .expect("rejected TCP close timeout")
            .expect("read rejected TCP close"),
        0
    );
    drop(closed_client);
    let _idle_client = TcpStream::connect(address)
        .await
        .expect("connect idle TCP DNS client");
    tokio::time::timeout(Duration::from_secs(1), async {
        while drain.active_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener must track the idle TCP connection");
    stop_listener(&mut listener, &drain).await;

    let endpoint = DnsBindEndpoint::parse(&format!("tcp+udp://{address}")).unwrap();
    let rebound = BoundDnsListener::bind(&endpoint)
        .expect("joined listener supervisors must release both sockets");
    assert_eq!(rebound.tcp_local_addr(), Some(address));
    assert_eq!(rebound.udp_local_addr(), Some(address));
}

#[tokio::test]
async fn listener_queries_acquire_the_newly_published_runtime() {
    let (controller, first_calls) = controller([192, 0, 2, 1]);
    let (mut listener, address, drain) =
        start_listener("udp://127.0.0.1:0", Arc::clone(&controller));

    let first = udp_exchange(address, &query("before.example", 0x4141)).await;
    assert!(first.windows(4).any(|window| window == [192, 0, 2, 1]));
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);

    let (replacement_forwarder, replacement_calls) = forwarder([192, 0, 2, 2]);
    let provider = controller.runtime_provider();
    let (generation, projection) = {
        let current = provider.current();
        (
            current.generation().get().saturating_add(1),
            Arc::clone(current.routing_projection()),
        )
    };
    provider.publish(crate::dns::runtime::DnsRuntime::new(
        crate::dns::runtime::DnsRuntimeParts {
            generation: crate::dns::runtime::RuntimeGeneration::new(generation),
            forwarder: replacement_forwarder,
            routing_projection: projection,
            outbound_runtime: None,
            transport: Arc::new(TestRuntimeTransport),
        },
    ));

    let second = udp_exchange(address, &query("after.example", 0x4242)).await;
    assert!(second.windows(4).any(|window| window == [192, 0, 2, 2]));
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);

    stop_listener(&mut listener, &drain).await;
}

#[tokio::test]
async fn supervisor_panic_is_a_listener_shutdown_failure() {
    let (controller, _) = controller([203, 0, 113, 12]);
    let (mut listener, address, drain) = start_listener("tcp+udp://127.0.0.1:0", controller);
    listener
        .supervisors
        .spawn(async { panic!("DNS supervisor failed") });
    assert!(listener.abort_and_join().await.is_err());
    assert_eq!(drain.active_count(), 0);
    BoundDnsListener::bind(&DnsBindEndpoint::parse(&format!("tcp+udp://{address}")).unwrap())
        .expect("failed shutdown must still join healthy supervisors");
}

#[tokio::test]
async fn query_start_spawns_only_unfinished_work_and_retains_panics() {
    let (phase_tx, phase) = watch::channel(ListenerPhase::Running);
    let mut children = JoinSet::new();
    let mut failure = None;

    start_query(&mut children, &phase, &mut failure, Box::pin(async {})).await;
    assert!(children.is_empty(), "a ready answer needs no child task");

    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let pending = Box::pin(async move {
        let _ = wait.await;
    });
    start_query(&mut children, &phase, &mut failure, pending).await;
    assert_eq!(children.len(), 1, "unfinished work must stay joined");
    release.send(()).unwrap();
    children.join_next().await.unwrap().unwrap();

    phase_tx.send(ListenerPhase::Abort).unwrap();
    let guard = Arc::new(());
    let held = Arc::clone(&guard);
    let stalled = Box::pin(async move {
        let _held = held;
        std::future::pending::<()>().await;
    });
    start_query(&mut children, &phase, &mut failure, stalled).await;
    assert!(children.is_empty());
    assert_eq!(
        Arc::strong_count(&guard),
        1,
        "aborted unfinished work must release what it owns"
    );

    assert!(failure.is_none());
    let panicking = Box::pin(async {
        panic!("standalone query failed");
    });
    start_query(&mut children, &phase, &mut failure, panicking).await;
    assert!(failure.is_some(), "a query panic must fail teardown");
}
