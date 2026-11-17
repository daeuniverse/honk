use super::*;
use crate::control::netstack::{PacketScope, capture_scope};
use honk_netstack::{Rx, wire};
use std::{net::SocketAddr, os::fd::AsFd};

async fn pending_syn(
    core: &mut RoutedCore,
    authority: &RoutingAuthority,
    ingress: Ingress,
    source: SocketAddr,
    destination: SocketAddr,
    now: Instant,
) -> (Vec<u8>, EndpointAdmission) {
    let mut bytes = vec![0; 64];
    let len = wire::tcp::emit_packet(
        &mut bytes,
        source.ip(),
        destination.ip(),
        &wire::tcp::Header {
            src_port: source.port(),
            dst_port: destination.port(),
            seq: 100,
            ack: 0,
            flags: wire::tcp::SYN,
            window: 4096,
            urgent: 0,
            options: Default::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    bytes.truncate(len);
    let packet = core.receive(ingress, now, &bytes).unwrap().unwrap();
    let Decision::Endpoint(_, admission) = core
        .decide(&authority.read_policy().await, packet, None, now)
        .unwrap()
    else {
        panic!("test policy must create a real pending Endpoint admission");
    };
    (bytes, admission)
}

fn commit_syn(
    scope: &PacketScope,
    bytes: &[u8],
    now: Instant,
    admission: &mut Option<EndpointAdmission>,
) -> io::Result<Rx> {
    let result = EndpointAdmission::commit_pending(admission, scope.scope(), |admission| {
        scope.receive_admitted_deferred_with_source(bytes, now, now, admission, false, |_, _| true)
    })?;
    scope.after_receive();
    Ok(result.0)
}

#[tokio::test]
async fn pending_reload_is_rejected_at_tcp_new_and_committed_flow_keeps_its_original_route() {
    let mut config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip }\nrouting { dport(443) -> proxy\n fallback: direct }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    config.groups.push(honk_config::group::Group {
        name: "proxy".into(),
        nodes: config
            .nodes
            .iter()
            .filter(|node| node.name == "direct")
            .map(|node| node.id)
            .collect(),
        ..Default::default()
    });
    let router = crate::routing::Router::from_config(&config.routing).unwrap();
    let plane = crate::control::tests::support::control_plane(config);
    *plane.router.write().await = router;
    let authority = plane
        .core_forward_policy(Execution::MixedEndpoints)
        .await
        .unwrap();
    let budget = MemoryBudget::new(64 << 20);
    let (scope, owner) = capture_scope(1280, 64, 16, &budget).unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let ingress = Ingress {
        scope: ScopeId::allocate().unwrap(),
        namespace: socket_namespace(socket.as_fd()).unwrap(),
        ifindex: 2,
        attachment: 1,
        mark: MarkProvenance::BeforeSkb,
    };
    let mut core = unsynchronized_core(authority.clone(), &[ingress], &budget, None);
    core.set_ingress_bindings(&[IngressBinding {
        ingress,
        role: InterfaceRole::Lan,
        facts: scope.scope(),
    }])
    .unwrap();
    let now = Instant::now();
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let next: SocketAddr = "192.0.2.10:41001".parse().unwrap();
    let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let (bytes, admitted) =
        pending_syn(&mut core, &authority, ingress, source, destination, now).await;
    let (stale_bytes, stale) =
        pending_syn(&mut core, &authority, ingress, next, destination, now).await;
    let mut admitted = Some(admitted);
    assert_eq!(
        commit_syn(&scope, &bytes, now, &mut admitted).unwrap(),
        Rx::Consumed
    );
    assert!(
        admitted.is_none(),
        "the exact TcpNew owns the accepted snapshot"
    );
    *plane.router.write().await = crate::routing::Router::new(&[], "block").unwrap();
    plane.diagnostics.write().generation += 1;
    let mut stale = Some(stale);
    assert_eq!(
        commit_syn(&scope, &stale_bytes, now, &mut stale)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(
        !scope.retains_tcp(next, destination),
        "stale handoff cannot create protocol state"
    );
    let (_, mut flow) = scope.poll_accept().unwrap();
    assert_eq!(flow.peer_addr(), source);
    assert_eq!(flow.take_routing().unwrap().decision.outbound, "proxy");
    assert!(scope.poll_accept().is_none());
    drop(flow);
    owner.shutdown().await;
}
