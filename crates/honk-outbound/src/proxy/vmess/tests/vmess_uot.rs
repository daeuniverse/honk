use super::*;
use crate::proxy::{DialFailureScope, ProxyRegistry, dial_failure_scope, node_failure};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{chain, socks5, socks5_relay};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use honk_config::group_graph::{Composed, compose};
use tokio::net::TcpListener;

const LIMIT: Duration = Duration::from_secs(5);
const FIRST: &[u8] = &[
    0, 1, 192, 0, 2, 1, 0, 53, 0, 192, 0, 2, 1, 0, 53, 0, 1, b'a',
];
const SECOND: &[u8] = &[0, 192, 0, 2, 2, 1, 187, 0, 0];
const REPLY: &[u8] = &[0, 192, 0, 2, 7, 0, 80, 0, 1, b'r'];

fn target() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], 53))
}

fn enabled_node(address: SocketAddr) -> Node {
    let mut node = chain_vmess_node();
    node.host = address.ip().to_string();
    node.address = address.to_string();
    node.port = address.port();
    node.vmess_mut().unwrap().udp_over_tcp = true;
    node.id = node.derive_id();
    node
}

async fn read_upload(wire: &mut (impl AsyncRead + Unpin), expected: &[u8]) -> Vec<u8> {
    let header = read_request_header(wire).await;
    let magic = b"sp.v2.udp-over-tcp.arpa";
    assert_eq!(&header[37..42], &[1, 0, 0, 2, magic.len() as u8]);
    assert_eq!(&header[42..42 + magic.len()], magic);
    let mut body = upload_chunks(&header);
    let mut plaintext = Vec::new();
    while plaintext.len() < expected.len() {
        plaintext.extend(read_upload_chunk(wire, &mut body).await);
    }
    assert_eq!(plaintext, expected);
    header
}

async fn receive_reply(transport: &dyn PacketTransport) {
    let mut buf = [0; 16];
    let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(
        (&buf[..n], peer),
        (&b"r"[..], SocketAddr::from(([192, 0, 2, 7], 80)))
    );
}

#[tokio::test]
async fn single_shared_chain_and_group_exit_exchange_datagrams() {
    for (chained, shared) in [(false, true), (true, true), (true, false)] {
        tokio::time::timeout(LIMIT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let exit = enabled_node(listener.local_addr().unwrap());
            let relay = socks5_relay(Vec::new(), false).await;
            let front = socks5("front", "127.0.0.1", relay.addr.port());
            let via = chain(&[&front, &exit]);
            let Composed::Routed(route) = compose(front.id, &[front.id], [exit.id]) else {
                unreachable!()
            };
            let id = if chained { via.id } else { exit.id };
            let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, via, exit]).unwrap());
            let registry = ProxyRegistry::default_resolver().unwrap();
            let server = async {
                let (mut wire, _) = listener.accept().await.unwrap();
                let expected = if shared {
                    [FIRST, SECOND, &FIRST[8..]].concat()
                } else {
                    FIRST.to_vec()
                };
                let header = read_upload(&mut wire, &expected).await;
                wire.write_all(&response_wire(&header, REPLY))
                    .await
                    .unwrap();
            };
            let client = async {
                if shared {
                    let runtime = generation.get(&id).unwrap();
                    assert!(registry.has_shared_source_for(&runtime));
                    let transport = registry
                        .prepare_shared_source(runtime, target(), None, LIMIT, false)
                        .await
                        .unwrap()
                        .commit()
                        .await
                        .unwrap();
                    transport
                        .send_to(target(), None, b"a", true, None)
                        .await
                        .unwrap();
                    transport
                        .send_to(
                            SocketAddr::from(([192, 0, 2, 2], 443)),
                            None,
                            b"",
                            true,
                            None,
                        )
                        .await
                        .unwrap();
                    transport
                        .send_to(target(), None, b"a", false, None)
                        .await
                        .unwrap();
                    receive_reply(&*transport).await;
                } else {
                    let transport = registry
                        .dial_udp_route(generation.clone(), &route, target(), None, LIMIT)
                        .await
                        .unwrap();
                    transport.send_packet_checked(b"a", &|| true).await.unwrap();
                    receive_reply(&*transport).await;
                }
            };
            tokio::join!(server, client);
            assert_eq!(relay.requests().len(), usize::from(chained));
            generation.shutdown().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn group_exit_locates_authenticated_header_and_uot_framing_faults() {
    for (response, scope) in [
        (None, DialFailureScope::Unattributed),
        (Some(false), DialFailureScope::Hop(1)),
        (Some(true), DialFailureScope::Hop(1)),
    ] {
        tokio::time::timeout(LIMIT, async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let exit = enabled_node(listener.local_addr().unwrap());
            let relay = socks5_relay(Vec::new(), false).await;
            let front = socks5("front", "127.0.0.1", relay.addr.port());
            let Composed::Routed(route) = compose(front.id, &[front.id], [exit.id]) else {
                unreachable!()
            };
            let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit]).unwrap());
            let registry = ProxyRegistry::default_resolver().unwrap();
            let peer = async {
                let (mut wire, _) = listener.accept().await.unwrap();
                let header = read_upload(&mut wire, FIRST).await;
                let mut reply = response_wire(&header, &[0xff]);
                match response {
                    None => reply.truncate(1),
                    Some(false) => reply[0] ^= 1,
                    Some(true) => {}
                }
                wire.write_all(&reply).await.unwrap();
                wire.shutdown().await.unwrap();
            };
            let client = async {
                let transport = registry
                    .dial_udp_route(generation.clone(), &route, target(), None, LIMIT)
                    .await
                    .unwrap();
                transport.send_packet_checked(b"a", &|| true).await.unwrap();
                let err = transport.recv_packet(&mut [0; 16]).await.unwrap_err();
                assert_eq!(dial_failure_scope(&err), scope);
                assert_eq!(node_failure(&err.into()), response.is_some());
            };
            tokio::join!(peer, client);
            generation.shutdown().await;
        })
        .await
        .unwrap();
    }
}

/// The outer framing may split or coalesce the VMess header and encrypted records.
async fn reply_to_frames(mut frames: impl futures_util::Stream<Item = Bytes> + Unpin) -> Bytes {
    let (mut input, mut output) = tokio::io::duplex(4096);
    tokio::select! {
        header = read_upload(&mut input, FIRST) => response_wire(&header, REPLY).into(),
        () = async {
            while let Some(frame) = frames.next().await { output.write_all(&frame).await.unwrap(); }
        } => panic!("transport closed before the VMess datagram arrived"),
    }
}

#[tokio::test]
async fn bare_ipv6_websocket_uot_exchange() {
    tokio::time::timeout(LIMIT, async {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let mut node = enabled_node(listener.local_addr().unwrap());
        let ws = node.transport_mut().unwrap();
        ws.transport = "ws".into();
        ws.ws_path = Some("uot?ed=1".into());
        node.id = node.derive_id();
        let peer = async {
            use tokio_tungstenite::tungstenite::{
                Message,
                handshake::server::{Request, Response},
            };
            let (tcp, _) = listener.accept().await.unwrap();
            #[allow(clippy::result_large_err)]
            let upgrade = |req: &Request, resp: Response| {
                assert_eq!(req.headers()["host"], "[::1]");
                assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/uot?ed=1");
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(tcp, upgrade)
                .await
                .unwrap();
            let response =
                reply_to_frames(ws.by_ref().map(|frame| frame.unwrap().into_data())).await;
            ws.send(Message::Binary(response)).await.unwrap();
            let _ = ws.next().await;
        };
        let client = async {
            let transport = VmessHandler
                .dial_udp_transport(&node, target(), None, LIMIT)
                .await
                .unwrap();
            transport.send_packet_confirmed(b"a").await.unwrap();
            receive_reply(&*transport).await;
        };
        tokio::join!(peer, client);
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct GatedWriter {
    inner: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    has_body: bool,
    blocked: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<bool>>,
}

impl AsyncWrite for GatedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf == b"setup" {
            // A lower transport may report readiness in its ambient observer.
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TransportReady,
            );
        } else {
            self.has_body = true;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.has_body {
            if let Some(blocked) = self.blocked.take() {
                let _ = blocked.send(());
            }
            if let Some(release) = &mut self.release {
                let ok = std::task::ready!(Pin::new(release).poll(cx)).unwrap();
                self.release = None;
                if !ok {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn gated_writer() -> (
    impl AsyncReadWrite,
    tokio::io::DuplexStream,
    oneshot::Receiver<()>,
    oneshot::Sender<bool>,
) {
    let (io, peer) = tokio::io::duplex(4096);
    let (reader, inner) = tokio::io::split(io);
    let (blocked, seen) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    (
        tokio::io::join(
            reader,
            GatedWriter {
                inner,
                has_body: false,
                blocked: Some(blocked),
                release: Some(gate),
            },
        ),
        peer,
        seen,
        release,
    )
}

fn fixed_transport(io: impl AsyncReadWrite + 'static) -> StreamUotTransport {
    let stream =
        VmessStream::start_uot(Box::new(io), (b"setup".to_vec(), fixed_session()), None).unwrap();
    StreamUotTransport::new(
        Box::new(stream),
        target(),
        None,
        uot::request(false, target(), None).unwrap(),
        Some(false),
        None,
    )
}

#[tokio::test]
async fn confirmed_waits_for_lower_flush_and_returns_its_error() {
    for ok in [true, false] {
        tokio::time::timeout(LIMIT, async {
            let (io, _peer, blocked, release) = gated_writer();
            let transport = fixed_transport(io);
            let mut sent = transport.send_packet_confirmed(b"a");
            assert!(futures_util::poll!(sent.as_mut()).is_pending());
            blocked.await.unwrap();
            assert!(futures_util::poll!(sent.as_mut()).is_pending());
            release.send(ok).unwrap();
            if ok {
                sent.await.unwrap();
            } else {
                assert_eq!(
                    sent.await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
            }
        })
        .await
        .unwrap();
    }
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn shared_header_and_each_flow_have_separate_observation() {
    use crate::proxy::request_observation_support::{DeferringCarrier, milestones, observed};
    use crate::runtime::flow_observation::Milestone::TargetRequestSent;
    tokio::time::timeout(LIMIT, async {
        let (io, mut peer, blocked, release) = gated_writer();
        let (io, pending) = DeferringCarrier::new(io);
        let (creator, setup_events) = observed();
        let transport = creator.sync_scope(|| fixed_transport(io));
        peer.read_exact(&mut [0; 5]).await.unwrap();
        assert!(setup_events.lock().is_empty());
        assert!(pending.lock().is_none());
        let (first, first_events) = observed();
        let (second, second_events) = observed();
        let mut send =
            std::pin::pin!(first.scope(transport.send_to(target(), None, b"a", true, None)));
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        blocked.await.unwrap();
        assert_eq!(milestones(&first_events.lock(), TargetRequestSent), 0);
        release.send(true).unwrap();
        send.await.unwrap();
        let (first_receipt, _) = pending.lock().take().unwrap();
        second
            .scope(transport.send_to_checked(
                SocketAddr::from(([192, 0, 2, 2], 443)),
                None,
                b"b",
                None,
                &|| true,
            ))
            .await
            .unwrap();
        let (second_receipt, _) = pending.lock().take().unwrap();
        assert_eq!(milestones(&second_events.lock(), TargetRequestSent), 0);
        second_receipt.confirm();
        assert_eq!(milestones(&second_events.lock(), TargetRequestSent), 1);
        assert_eq!(milestones(&first_events.lock(), TargetRequestSent), 0);
        first_receipt.confirm();
        assert_eq!(milestones(&first_events.lock(), TargetRequestSent), 1);
        assert!(setup_events.lock().is_empty());
    })
    .await
    .unwrap();
}

#[cfg(feature = "owned-tasks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_closing_during_uot_publication_cancels_commit_without_header() {
    let owner = Arc::new(crate::runtime::TaskOwner::production());
    let (carrier, mut wire) = tokio::io::duplex(64);
    let prepared = owner.task_scope().sync_scope(|| {
        PreparedUdpTransport::new(async move {
            let stream = VmessStream::commit_uot(
                Box::new(carrier),
                (b"header".to_vec(), fixed_session()),
                || {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(owner.close())
                    });
                    Ok(())
                },
            )?;
            Ok(Arc::new(stream))
        })
    });
    let error = prepared.commit().await.unwrap_err();
    assert_eq!(
        crate::proxy::packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Cancelled)
    );
    let mut sent = Vec::new();
    tokio::time::timeout(LIMIT, wire.read_to_end(&mut sent))
        .await
        .unwrap()
        .unwrap();
    assert!(sent.is_empty());
}

#[tokio::test]
async fn xhttp_speculative_winner_exchanges_data_and_losers_close_without_a_header() {
    use honk_config::node::{XhttpMode, XhttpOptions};
    #[derive(Clone, Copy, PartialEq)]
    enum Outcome {
        Drop,
        Retire,
        #[cfg(feature = "owned-tasks")]
        ClosedOwner,
        Commit,
    }
    for shared in [false, true] {
        for outcome in [
            Outcome::Drop,
            Outcome::Retire,
            #[cfg(feature = "owned-tasks")]
            Outcome::ClosedOwner,
            Outcome::Commit,
        ] {
            tokio::time::timeout(LIMIT, async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut node = enabled_node(listener.local_addr().unwrap());
                let transport = node.transport_mut().unwrap();
                transport.transport = "xhttp".into();
                transport.xhttp = Some(XhttpOptions {
                    mode: XhttpMode::StreamOne,
                    ..Default::default()
                });
                node.normalize_stream_transport().unwrap();
                node.id = node.derive_id();
                assert!(
                    crate::descriptor::descriptor(node.protocol())
                        .supports_warm(&node, WarmRequirement::Udp)
                );
                let generation =
                    OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
                let runtime = generation.get(&node.id).unwrap();
                let (tx, rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let (io, _) = listener.accept().await.unwrap();
                    let mut conn = h2::server::handshake(io).await.unwrap();
                    let (request, mut response) = conn.accept().await.unwrap().unwrap();
                    let response = response
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    tx.send((request.into_body(), response)).unwrap();
                    while let Some(Ok(_)) = conn.accept().await {}
                });
                let prepare = async {
                    if shared {
                        let p = VmessHandler
                            .prepare_shared_source(runtime.clone(), target(), None, LIMIT, true)
                            .await?;
                        Ok(PreparedUdpTransport::new(async move {
                            Ok(p.commit().await? as Arc<dyn PacketTransport>)
                        }))
                    } else {
                        VmessHandler
                            .dial_udp_transport_speculative_runtime(
                                runtime.clone(),
                                target(),
                                None,
                                LIMIT,
                            )
                            .await
                    }
                };
                #[cfg(feature = "owned-tasks")]
                let owner = Arc::new(crate::runtime::TaskOwner::production());
                #[cfg(feature = "owned-tasks")]
                let prepare = owner.scope(prepare);
                let prepared = prepare.await.unwrap();
                let (mut body, mut response) = rx.await.unwrap();
                assert_eq!(runtime.warm_counts().sessions, 0);
                match outcome {
                    Outcome::Drop => drop(prepared),
                    Outcome::Retire => {
                        generation.retire_reusable_state().await;
                        assert!(prepared.commit().await.is_err());
                    }
                    #[cfg(feature = "owned-tasks")]
                    Outcome::ClosedOwner => {
                        owner.close().await;
                        let err = prepared.commit().await.unwrap_err();
                        assert_eq!(
                            crate::proxy::packet_rejection(&err),
                            Some(crate::proxy::PacketRejection::Cancelled)
                        );
                    }
                    Outcome::Commit => {
                        let transport = prepared.commit().await.unwrap();
                        assert_eq!(runtime.warm_counts().sessions, 1);
                        let peer = async {
                            let bytes = reply_to_frames(
                                futures_util::stream::poll_fn(|cx| body.poll_data(cx))
                                    .map(Result::unwrap),
                            )
                            .await;
                            response.send_data(bytes, false).unwrap();
                        };
                        let client = async {
                            transport.send_packet_confirmed(b"a").await.unwrap();
                            receive_reply(&*transport).await;
                        };
                        tokio::join!(peer, client);
                    }
                }
                if outcome != Outcome::Commit {
                    while let Some(Ok(data)) = body.data().await {
                        assert!(data.is_empty(), "losing carrier sent VMess DATA");
                    }
                    assert_eq!(runtime.warm_counts().sessions, 0);
                }
                drop((body, response));
                generation.shutdown().await;
                server.await.unwrap();
            })
            .await
            .unwrap();
        }
    }
}
