use super::*;

const QUIC_PEER_STREAM_WINDOW: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::control) enum QuicUdpMode {
    Hysteria2,
    TuicDatagram,
    TuicStream,
}

#[derive(Debug)]
pub(in crate::control) struct QuicUdpPacket {
    pub(in crate::control) connection: u64,
    pub(in crate::control) session: u32,
    pub(in crate::control) target: SocketAddr,
    pub(in crate::control) mapping: SocketAddr,
    pub(in crate::control) payload: Vec<u8>,
    pub(in crate::control) carrier: quinn::Connection,
    next_reply: Arc<std::sync::atomic::AtomicU16>,
}

#[derive(Default)]
pub(in crate::control) struct QuicStreamHold {
    pub(in crate::control) entered: tokio::sync::Notify,
    pub(in crate::control) release: tokio::sync::Notify,
    pub(in crate::control) truncated: tokio::sync::Notify,
}

pub(in crate::control) struct QuicUdpPeer {
    pub(in crate::control) node: Node,
    pub(in crate::control) packets: tokio::sync::mpsc::UnboundedReceiver<QuicUdpPacket>,
    pub(in crate::control) closed: tokio::sync::mpsc::UnboundedReceiver<u64>,
    mode: QuicUdpMode,
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl QuicUdpPeer {
    pub(in crate::control) async fn start(
        mode: QuicUdpMode,
        bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        Self::start_with_stream_hold(mode, bind, None).await
    }

    pub(in crate::control) async fn start_with_stream_hold(
        mode: QuicUdpMode,
        bind: SocketAddr,
        hold: Option<Arc<QuicStreamHold>>,
    ) -> anyhow::Result<Self> {
        use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let mut tls = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.into()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
        tls.alpn_protocols = vec![if mode == QuicUdpMode::Hysteria2 {
            b"h3".to_vec()
        } else {
            b"tuic".to_vec()
        }];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        if mode == QuicUdpMode::TuicStream {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .datagram_receive_buffer_size(None);
        }
        if hold.is_some() {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .stream_receive_window(QUIC_PEER_STREAM_WINDOW.into());
        }
        let endpoint = quinn::Endpoint::server(config, bind)?;
        let address = endpoint.local_addr()?;
        let quic = honk_config::node::QuicOptions {
            disable_mtu_discovery: mode == QuicUdpMode::Hysteria2,
            tls: honk_config::node::TlsOptions {
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut node = Node {
            name: format!("source-{mode:?}"),
            host: address.ip().to_string(),
            address: address.to_string(),
            port: address.port(),
            outbound: if mode == QuicUdpMode::Hysteria2 {
                OutboundConfig::Hysteria2(honk_config::node::Hysteria2Config {
                    auth: Some("source-test-password".into()),
                    quic,
                    ..Default::default()
                })
            } else {
                OutboundConfig::Tuic(honk_config::node::TuicConfig {
                    uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
                    password: Some("source-test-password".into()),
                    quic,
                    ..Default::default()
                })
            },
            ..Default::default()
        };
        node.id = node.derive_id();
        let (events, packets) = tokio::sync::mpsc::unbounded_channel();
        let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
        let listener = endpoint.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let mut serial = 0;
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Some(incoming) = incoming else { break; };
                        serial += 1;
                        let events = events.clone();
                        let hold = hold.clone();
                        let closed_tx = closed_tx.clone();
                        connections.spawn(async move {
                            let connection = incoming.await?;
                            run_quic_udp_peer(mode, serial, connection, address.ip(), events, hold).await?;
                            let _ = closed_tx.send(serial);
                            Ok::<_, anyhow::Error>(())
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap()??;
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                result??;
            }
            Ok(())
        });
        Ok(Self {
            node,
            packets,
            closed,
            mode,
            endpoint,
            task,
        })
    }

    pub(in crate::control) async fn reply(
        &self,
        packet: &QuicUdpPacket,
        source: SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let id = packet
            .next_reply
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        send_quic_udp_reply(
            self.mode,
            &packet.carrier,
            packet.session,
            id,
            source,
            payload,
        )
        .await
    }

    pub(in crate::control) async fn close(self) -> anyhow::Result<()> {
        self.endpoint.close(0u32.into(), b"test finished");
        self.task.await??;
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

// These bytes are independent of the outbound codecs: RFC 9000 varints,
// Hysteria2's textual address and TUIC v5's sing address discriminants.
fn quic_peer_varint(input: &mut &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(!input.is_empty(), "missing QUIC varint");
    let width = 1usize << (input[0] >> 6);
    anyhow::ensure!(input.len() >= width, "short QUIC varint");
    let value = input[..width].iter().enumerate().fold(0usize, |n, (i, b)| {
        (n << 8) | usize::from(if i == 0 { b & 63 } else { *b })
    });
    *input = &input[width..];
    Ok(value)
}

fn decode_quic_udp_request(
    mode: QuicUdpMode,
    wire: &[u8],
) -> anyhow::Result<(u32, SocketAddr, Vec<u8>)> {
    if mode == QuicUdpMode::Hysteria2 {
        anyhow::ensure!(
            wire.len() >= 9 && wire[6..8] == [0, 1],
            "fragmented/short Hy2 fixture packet"
        );
        let session = u32::from_be_bytes(wire[..4].try_into()?);
        let mut rest = &wire[8..];
        let size = quic_peer_varint(&mut rest)?;
        anyhow::ensure!(rest.len() >= size, "short Hy2 address");
        let target = std::str::from_utf8(&rest[..size])?.parse()?;
        return Ok((session, target, rest[size..].to_vec()));
    }
    anyhow::ensure!(
        wire.len() >= 11 && wire[..2] == [5, 2] && wire[6..8] == [1, 0],
        "invalid TUIC fixture packet"
    );
    let session = u32::from(u16::from_be_bytes(wire[2..4].try_into()?));
    let size = usize::from(u16::from_be_bytes(wire[8..10].try_into()?));
    let (ip, offset) = match wire[10] {
        1 => {
            anyhow::ensure!(wire.len() >= 17, "short TUIC IPv4 address");
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(
                    &wire[11..15],
                )?)),
                15,
            )
        }
        2 => {
            anyhow::ensure!(wire.len() >= 29, "short TUIC IPv6 address");
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(
                    &wire[11..27],
                )?)),
                27,
            )
        }
        _ => anyhow::bail!("fixture expects numeric TUIC target"),
    };
    let port = u16::from_be_bytes(wire[offset..offset + 2].try_into()?);
    if wire.len() < offset + 2 + size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "TUIC fixture payload truncated",
        )
        .into());
    }
    anyhow::ensure!(wire.len() == offset + 2 + size, "TUIC payload length");
    Ok((
        session,
        SocketAddr::new(ip, port),
        wire[offset + 2..].to_vec(),
    ))
}

async fn send_quic_udp_reply(
    mode: QuicUdpMode,
    conn: &quinn::Connection,
    session: u32,
    packet: u16,
    source: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut wire = Vec::new();
    if mode == QuicUdpMode::Hysteria2 {
        wire.extend_from_slice(&session.to_be_bytes());
        wire.extend_from_slice(&packet.to_be_bytes());
        wire.extend_from_slice(&[0, 1]);
        let address = source.to_string();
        anyhow::ensure!(address.len() < 64, "fixture address varint");
        wire.push(address.len() as u8);
        wire.extend_from_slice(address.as_bytes());
    } else {
        wire.extend_from_slice(&[5, 2]);
        wire.extend_from_slice(&(session as u16).to_be_bytes());
        wire.extend_from_slice(&packet.to_be_bytes());
        wire.extend_from_slice(&[1, 0]);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        match source.ip() {
            std::net::IpAddr::V4(ip) => {
                wire.push(1);
                wire.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                wire.push(2);
                wire.extend_from_slice(&ip.octets());
            }
        }
        wire.extend_from_slice(&source.port().to_be_bytes());
    }
    wire.extend_from_slice(payload);
    if mode == QuicUdpMode::TuicStream {
        let mut stream = conn.open_uni().await?;
        stream.write_all(&wire).await?;
        stream.finish()?;
    } else {
        conn.send_datagram(wire.into())?;
    }
    Ok(())
}

async fn run_quic_udp_peer(
    mode: QuicUdpMode,
    serial: u64,
    conn: quinn::Connection,
    bind: std::net::IpAddr,
    events: tokio::sync::mpsc::UnboundedSender<QuicUdpPacket>,
    hold: Option<Arc<QuicStreamHold>>,
) -> anyhow::Result<()> {
    let mut sockets =
        std::collections::HashMap::<u32, (Arc<UdpSocket>, Arc<std::sync::atomic::AtomicU16>)>::new(
        );
    let mut tasks = tokio::task::JoinSet::<anyhow::Result<()>>::new();
    let (wire_tx, mut wire_rx) = tokio::sync::mpsc::unbounded_channel();
    loop {
        let wire = tokio::select! {
            biased;
            _ = conn.closed() => break,
            result = tasks.join_next(), if !tasks.is_empty() => { result.unwrap()??; continue; }
            request = conn.accept_bi(), if mode == QuicUdpMode::Hysteria2 => {
                let (mut send, mut recv) = request?;
                tasks.spawn(async move {
                    let request = recv.read_to_end(8192).await?;
                    anyhow::ensure!(request.windows(20).any(|v| v == b"source-test-password"), "Hy2 auth credential");
                    // QPACK literal :status=233, hysteria-udp=true, hysteria-cc-rx=0.
                    let headers = b"\x00\x00\x5f\x09\x03233\x27\x05hysteria-udp\x04true\x27\x07hysteria-cc-rx\x010";
                    send.write_all(&[1, headers.len() as u8]).await?;
                    send.write_all(headers).await?;
                    send.finish()?;
                    Ok(())
                });
                continue;
            }
            request = conn.accept_uni() => {
                let mut recv = request?;
                let sender = wire_tx.clone();
                let carrier = conn.clone();
                let hold = hold.clone();
                tasks.spawn(async move {
                    if mode == QuicUdpMode::Hysteria2 {
                        let mut buffer = [0; 1024];
                        while recv.read(&mut buffer).await?.is_some() {}
                    } else {
                        let mut head = [0; 2];
                        recv.read_exact(&mut head).await?;
                        match head {
                            [5, 0] => {
                                let mut auth = [0; 48];
                                recv.read_exact(&mut auth).await?;
                                let mut expected = [0; 32];
                                carrier.export_keying_material(&mut expected, &auth[..16], b"source-test-password")
                                    .map_err(|e| anyhow::anyhow!("TLS exporter: {e:?}"))?;
                                anyhow::ensure!(auth[16..] == expected, "TUIC auth token");
                            }
                            [5, 2] => {
                                if let Some(hold) = hold {
                                    hold.entered.notify_one();
                                    hold.release.notified().await;
                                }
                                let body = match recv.read_to_end(65536).await {
                                    Ok(body) => body,
                                    Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_))) => return Ok(()),
                                    Err(error) => return Err(error.into()),
                                };
                                let mut wire = head.to_vec();
                                wire.extend_from_slice(&body);
                                sender.send(wire)?;
                            }
                            [5, 3] | [5, 4] => {}
                            _ => anyhow::bail!("unexpected TUIC command"),
                        }
                    }
                    Ok(())
                });
                continue;
            }
            wire = conn.read_datagram(), if mode != QuicUdpMode::TuicStream => {
                let wire = wire?;
                if mode != QuicUdpMode::Hysteria2 && wire.first() == Some(&5) && wire.get(1) == Some(&4) { continue; }
                wire.to_vec()
            }
            wire = wire_rx.recv() => wire.expect("peer stream sender retained"),
        };
        let (session, target, payload) = match decode_quic_udp_request(mode, &wire) {
            Ok(packet) => packet,
            Err(error) => {
                if let Some(hold) = &hold
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
                {
                    hold.truncated.notify_one();
                    continue;
                }
                return Err(error);
            }
        };
        let (socket, next_reply) = if let Some((socket, counter)) = sockets.get(&session) {
            (Arc::clone(socket), Arc::clone(counter))
        } else {
            let socket =
                Arc::new(honk_outbound::util::udp_marked_bind(SocketAddr::new(bind, 0)).await?);
            let counter = Arc::new(std::sync::atomic::AtomicU16::new(0));
            sockets.insert(session, (Arc::clone(&socket), Arc::clone(&counter)));
            let next_reply = Arc::clone(&counter);
            let receiver = Arc::clone(&socket);
            let carrier = conn.clone();
            tasks.spawn(async move {
                let mut buffer = [0; 65536];
                loop {
                    let (size, source) = receiver.recv_from(&mut buffer).await?;
                    let id = next_reply.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    send_quic_udp_reply(mode, &carrier, session, id, source, &buffer[..size])
                        .await?;
                }
            });
            (socket, counter)
        };
        socket.send_to(&payload, target).await?;
        events.send(QuicUdpPacket {
            connection: serial,
            session,
            target,
            mapping: socket.local_addr()?,
            payload,
            carrier: conn.clone(),
            next_reply,
        })?;
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            Ok(Err(_)) if conn.close_reason().is_some() => {}
            result => result??,
        }
    }
    Ok(())
}
