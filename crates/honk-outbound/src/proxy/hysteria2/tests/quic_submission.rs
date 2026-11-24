use super::*;

#[tokio::test]
async fn hy2_status_confirms_one_complete_wire_datagram_at_the_selected_port() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let base = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hop = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let password = b"test-salamander".as_slice();
        for hopping in [false, true] {
            for obfs in [false, true] {
                let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let socket = Arc::new(Hy2UdpSocket::from_socket(
                    raw,
                    obfs.then(|| Arc::from(password)),
                    hopping.then(|| {
                        (
                            vec![hop.local_addr().unwrap().port()],
                            Duration::from_secs(60),
                        )
                    }),
                ));
                let mut poller = socket.clone().create_io_poller();
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                    .await
                    .unwrap();
                let submit = |contents: &[u8], segment_size| {
                    socket.try_send_with_status(&quinn::udp::Transmit {
                        destination: base.local_addr().unwrap(),
                        ecn: None,
                        contents,
                        segment_size,
                        src_ip: None,
                    })
                };
                assert!(!submit(b"invalid", Some(0)).unwrap());
                assert!(!submit(b"invalid", Some(6)).unwrap());
                #[cfg(target_os = "linux")]
                assert_eq!(
                    submit(&vec![0; 65536], None).unwrap_err().raw_os_error(),
                    Some(libc::EMSGSIZE)
                );
                let peer = if hopping { &hop } else { &base };
                for stride in [None, Some(7), Some(8)] {
                    assert!(submit(b"payload", stride).unwrap());
                    let mut wire = [0; 64];
                    let (n, source) = peer.recv_from(&mut wire).await.unwrap();
                    assert_eq!(source, socket.local_addr().unwrap());
                    let len = if obfs {
                        assert_eq!(n, 7 + SALAMANDER_SALT_LEN);
                        salamander_open(password, &mut wire[..n]).unwrap()
                    } else {
                        n
                    };
                    assert_eq!(&wire[..len], b"payload");
                }
            }
        }
    })
    .await
    .expect("strict Hy2 send did not deliver on the selected port");
}

#[cfg(feature = "flow-observation")]
mod flow {
    use super::*;
    use crate::proxy::request_observation_support::{milestones, observed};
    use crate::quic::QuicBiStream;
    use crate::runtime::flow_observation::{
        Milestone, observe_chain_request, request_write, without_target_milestones,
    };

    #[derive(Debug)]
    struct Verdict {
        socket: Arc<dyn AsyncUdpSocket>,
        positive: AtomicBool,
        status_calls: AtomicUsize,
        split_opener: AtomicBool,
        held: AtomicBool,
        ready: futures_util::task::AtomicWaker,
    }

    #[derive(Debug)]
    struct VerdictPoller(Pin<Box<dyn UdpPoller>>, Arc<Verdict>);

    impl UdpPoller for VerdictPoller {
        fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.1.ready.register(cx.waker());
            if self.1.held.load(Ordering::Relaxed) {
                Poll::Pending
            } else {
                self.0.as_mut().poll_writable(cx)
            }
        }
    }

    impl AsyncUdpSocket for Verdict {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(VerdictPoller(self.socket.clone().create_io_poller(), self))
        }
        fn try_send(&self, tx: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            self.socket.try_send(tx)
        }
        fn try_send_with_status(&self, tx: &quinn::udp::Transmit<'_>) -> io::Result<bool> {
            // The higher-priority sibling fills most of the first datagram. Let this
            // large datagram through, unconfirmed, but hold a separate final-byte datagram.
            if self.split_opener.load(Ordering::Relaxed) && tx.contents.len() < 900 {
                self.held.store(true, Ordering::Relaxed);
                return Err(io::ErrorKind::WouldBlock.into());
            }
            assert!(self.socket.try_send_with_status(tx)?);
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.positive.load(Ordering::Relaxed))
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.socket.poll_recv(cx, bufs, meta)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }
        fn max_receive_segments(&self) -> usize {
            self.socket.max_receive_segments()
        }
    }

    #[tokio::test]
    async fn hy2_header_only_boundary_and_payload_suffix_are_distinct() {
        const FINAL: &[u8] = b"END";
        let name = format!(
            "{}.{}.{}.example:443",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60)
        );
        for offset in [-1isize, 0, 1, 3] {
            tokio::time::timeout(Duration::from_secs(5), async {
                // Encode once so the random padding is identical on both sides of the credit boundary.
                let header = Bytes::from(encode_tcp_request(&name));
                let credit = header.len().checked_add_signed(offset).unwrap();
                let mut server_config = testutil::server_config(&[b"h3"], true).unwrap();
                let mut transport = quinn::TransportConfig::default();
                let split = offset == FINAL.len() as isize;
                transport.stream_receive_window((if split { 2048 } else { credit as u32 }).into());
                server_config.transport_config(Arc::new(transport));
                let server =
                    Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
                let address = server.local_addr().unwrap();
                let runtime = quinn::default_runtime().unwrap();
                let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                raw.set_nonblocking(true).unwrap();
                let socket = Arc::new(Verdict {
                    socket: runtime.wrap_udp_socket(raw).unwrap(),
                    positive: AtomicBool::new(false),
                    split_opener: AtomicBool::new(false),
                    held: AtomicBool::new(false),
                    ready: Default::default(),
                    status_calls: AtomicUsize::new(0),
                });
                let ep = Endpoint::new_with_abstract_socket(
                    EndpointConfig::default(),
                    None,
                    socket.clone(),
                    runtime,
                )
                .unwrap();
                let config = crate::quic::client_config(
                    &test_node(address.port(), TEST_PASSWORD),
                    &[b"h3"],
                    crate::quic::QuicClientOptions {
                        max_udp_payload_size: Some(1200),
                        disable_mtu_discovery: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                let connecting = ep.connect_with(config, address, "localhost").unwrap();
                let (client, peer) = tokio::join!(connecting, async {
                    server.accept().await.unwrap().await.unwrap()
                });
                let client = client.unwrap();
                let (send, recv) = client.open_bi().await.unwrap();
                let id = send.id();
                let (observer, events) = observed();
                let mut hy2 = observer
                    .scope(without_target_milestones(async {
                        Hy2TcpStream::new(QuicBiStream::new(send, recv), &name)
                    }))
                    .await;
                hy2.request = Some(header.clone());
                let dial = async {
                    let work = async {
                        assert_eq!(hy2.write(&[]).await.unwrap(), 0);
                        assert_eq!(hy2.request.as_ref(), Some(&header));
                        if split {
                            let mut sibling = client.open_uni().await.unwrap();
                            sibling.set_priority(10).unwrap();
                            socket.split_opener.store(true, Ordering::Relaxed);
                            sibling.write_all(&[b'S'; 960]).await.unwrap();
                            sibling.finish().unwrap();
                        }
                        let first = futures_util::poll!(std::pin::pin!(hy2.write(FINAL)));
                        let app = match first {
                            Poll::Pending => 0,
                            Poll::Ready(n) => n.unwrap(),
                        };
                        assert_eq!(app, offset.max(0) as usize);
                        assert_eq!(
                            hy2.request.as_deref().unwrap_or_default(),
                            &header[credit.min(header.len())..]
                        );
                        let (mut reply, mut peer_rx) = peer.accept_bi().await.unwrap();
                        assert_eq!(peer_rx.id(), id);
                        let mut wire = vec![0; credit];
                        let mut seen = 0;
                        if split {
                            assert_eq!(
                                peer.accept_uni()
                                    .await
                                    .unwrap()
                                    .read_to_end(960)
                                    .await
                                    .unwrap(),
                                [b'S'; 960]
                            );
                            let prefix = peer_rx.read_chunk(credit, true).await.unwrap().unwrap();
                            seen = prefix.bytes.len();
                            assert!(
                                seen > 0 && seen < header.len(),
                                "first datagram must contain opener only ({seen}/{})",
                                header.len()
                            );
                            assert_eq!(prefix.offset, 0);
                            wire[..seen].copy_from_slice(&prefix.bytes);
                            assert_eq!(&wire[..seen], &header[..seen]);
                            assert_eq!(
                                socket.status_calls.load(Ordering::Relaxed),
                                0,
                                "opener-only datagram was incorrectly tracked"
                            );
                            while !socket.held.load(Ordering::Relaxed) {
                                tokio::task::yield_now().await;
                            }
                            assert!(
                                futures_util::poll!(std::pin::pin!(
                                    peer_rx.read_chunk(credit, true)
                                ))
                                .is_pending(),
                                "final data reached the peer before release"
                            );
                            socket.positive.store(true, Ordering::Relaxed);
                            socket.split_opener.store(false, Ordering::Relaxed);
                            socket.held.store(false, Ordering::Relaxed);
                            socket.ready.wake();
                        }
                        peer_rx.read_exact(&mut wire[seen..]).await.unwrap();
                        assert_eq!(
                            wire.split_at(credit.min(header.len())),
                            (&header[..credit.min(header.len())], &FINAL[..app])
                        );
                        assert_eq!(socket.status_calls.load(Ordering::Relaxed) != 0, app != 0);
                        assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 0);
                        socket.positive.store(true, Ordering::Relaxed);
                        hy2.write_all(&FINAL[app..]).await.unwrap();
                        hy2.flush().await.unwrap();
                        let mut rest = vec![0; header.len() + FINAL.len() - credit];
                        peer_rx.read_exact(&mut rest).await.unwrap();
                        wire.extend(rest);
                        assert_eq!(wire.split_at(header.len()), (&header[..], FINAL));
                        let status = u8::from(offset == 1);
                        reply.write_all(&[status, 0, 0, b'R']).await.unwrap();
                        reply.finish().unwrap();
                        Ok::<_, io::Error>(())
                    };
                    request_write(std::pin::pin!(work)).await?;
                    Ok(ProxyStream {
                        stream: Box::new(hy2),
                        target_addr: address,
                        target_domain: None,
                    })
                };
                let mut tunnel = observer.scope(observe_chain_request(dial)).await.unwrap();
                let result = tunnel.stream.read_u8().await;
                if offset == 1 {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
                    assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 0);
                } else {
                    assert_eq!(result.unwrap(), b'R');
                    while milestones(&events.lock(), Milestone::TargetRequestSent) == 0 {
                        tokio::task::yield_now().await;
                    }
                    assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
                }
                assert_eq!(milestones(&events.lock(), Milestone::TargetConfirmed), 0);
            })
            .await
            .expect("Hy2 partial/scatter write stopped making progress");
        }
    }
}
