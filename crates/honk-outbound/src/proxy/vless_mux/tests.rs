use super::*;
use crate::session::SpeculativeCheckout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn receive_windows_cover_every_maximum_udp_frame() {
    let maximum_response_frame = 1 + 2 + super::super::uot::MAX_PACKET_SIZE;
    assert!(H2_STREAM_RECV_WINDOW as usize >= maximum_response_frame);
    assert!(H2_CONNECTION_RECV_WINDOW as usize >= maximum_response_frame * MAX_STREAMS_PER_SESSION);
}

#[test]
fn physical_preface_matches_sing_mux() {
    assert_eq!(&mux_preface(false)[..], &[0, H2MUX_BACKEND]);
    let padded = mux_preface(true);
    assert_eq!(&padded[..3], &[1, H2MUX_BACKEND, 1]);
    let length = u16::from_be_bytes([padded[3], padded[4]]) as usize;
    assert!((256..768).contains(&length));
    assert_eq!(padded.len(), 5 + length);
}

#[test]
fn stream_request_rejects_overlong_domains() {
    let domain = "x".repeat(256);
    assert_eq!(
        stream_request(0, "127.0.0.1:443".parse().unwrap(), Some(&domain))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn padding_frames_first_sixteen_records_per_direction() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let mut padded = PaddingStream::new(client, true);
    for value in 0..PADDED_RECORDS {
        padded.write_all(&[value]).await.unwrap();
        padded.flush().await.unwrap();
        let mut header = [0; 4];
        wire.read_exact(&mut header).await.unwrap();
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 1);
        let padding = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut body = vec![0; 1 + padding];
        wire.read_exact(&mut body).await.unwrap();
        assert_eq!(body[0], value);
    }
    padded.write_all(b"raw").await.unwrap();
    padded.flush().await.unwrap();
    let mut raw = [0; 3];
    wire.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw, b"raw");

    for value in 0..PADDED_RECORDS {
        let padding = 256usize;
        wire.write_all(&[0, 1, 1, 0, value]).await.unwrap();
        wire.write_all(&vec![0; padding]).await.unwrap();
        let mut output = [0];
        padded.read_exact(&mut output).await.unwrap();
        assert_eq!(output[0], value);
    }
    wire.write_all(b"raw").await.unwrap();
    let mut raw = [0; 3];
    padded.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw, b"raw");
}

async fn receive_at_least(recv: &mut h2::RecvStream, body: &mut BytesMut, minimum: usize) -> bool {
    while body.len() < minimum {
        let Some(Ok(data)) = recv.data().await else {
            return false;
        };
        let size = data.len();
        body.extend_from_slice(&data);
        if recv.flow_control().release_capacity(size).is_err() {
            return false;
        }
    }
    true
}

async fn serve_logical_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
    let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
        return;
    };
    let mut recv = request.into_body();
    let mut body = BytesMut::new();
    if !receive_at_least(&mut recv, &mut body, 9).await {
        return;
    }
    match u16::from_be_bytes([body[0], body[1]]) {
        0 => {
            assert_eq!(&body[2..9], &[1, 93, 184, 216, 34, 1, 187]);
            if send
                .send_data(Bytes::from_static(b"\0hello"), false)
                .is_err()
                || !receive_at_least(&mut recv, &mut body, 13).await
            {
                return;
            }
            assert_eq!(&body[9..13], b"ping");
            if send.send_data(Bytes::from_static(b"pong"), false).is_err() {
                return;
            }
            while let Some(Ok(data)) = recv.data().await {
                let size = data.len();
                let _ = recv.flow_control().release_capacity(size);
            }
            let _ = send.send_data(Bytes::new(), true);
        }
        FLAG_UDP => {
            let target = &body[2..9];
            assert!(matches!(
                target,
                [1, 8, 8, 8, 8, 0, 53] | [1, 1, 1, 1, 1, 0, 53]
            ));
            let maximum = target[1] == 1;
            if !receive_at_least(&mut recv, &mut body, 14).await {
                return;
            }
            assert_eq!(&body[9..14], b"\0\x03dns");
            let answer = if maximum {
                vec![0x5a; super::super::uot::MAX_PACKET_SIZE]
            } else {
                b"answer".to_vec()
            };
            let packet =
                super::super::uot::encode_packet(&answer, super::super::uot::MAX_PACKET_SIZE)
                    .unwrap();
            let mut response = BytesMut::with_capacity(1 + packet.len());
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&packet);
            let _ = send.send_data(response.freeze(), true);
        }
        flags => panic!("unexpected mux flags {flags}"),
    }
}
async fn server_carrier(
    mut wire: tokio::io::DuplexStream,
    padded: bool,
) -> PaddingStream<tokio::io::DuplexStream> {
    if padded {
        let mut request = [0; 5];
        wire.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[1, H2MUX_BACKEND, 1]);
        let padding = u16::from_be_bytes([request[3], request[4]]) as usize;
        let mut ignored = vec![0; padding];
        wire.read_exact(&mut ignored).await.unwrap();
    } else {
        let mut request = [0; 2];
        wire.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0, H2MUX_BACKEND]);
    }
    PaddingStream::new(wire, padded)
}

async fn serve_h2mux(
    wire: tokio::io::DuplexStream,
    padded: bool,
    goaway_after_first: bool,
) -> usize {
    let io = server_carrier(wire, padded).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut requests = 0;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request.unwrap();
        requests += 1;
        tokio::spawn(serve_logical_stream(request, respond));
        if goaway_after_first && requests == 1 {
            connection.graceful_shutdown();
        }
    }
    requests
}

async fn exercise_h2mux(padded: bool) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_h2mux(server, padded, false));
    let session = connect(Box::new(client), padded).await.unwrap();

    let tcp_permit = session.try_reserve().unwrap();
    let mut tcp = Arc::clone(&session)
        .open_stream(tcp_permit, "93.184.216.34:443".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("TCP logical stream must open"));
    let mut greeting = [0; 5];
    tcp.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    tcp.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    tcp.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    let udp_permit = session.try_reserve().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(udp_permit, "8.8.8.8:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("UDP logical stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();
    assert_eq!(session.active_streams(), 2);
    assert_eq!(
        udp.recv_packet(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut answer = [0; 16];
    assert_eq!(
        udp.recv_packet(&mut answer).await.unwrap(),
        (6, "8.8.8.8:53".parse().unwrap())
    );
    assert_eq!(&answer[..6], b"answer");

    drop(udp);
    tcp.shutdown().await.unwrap();
    drop(tcp);
    assert_eq!(session.active_streams(), 0);
    session.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn tcp_and_udp_share_plain_and_padded_h2mux_carriers() {
    exercise_h2mux(false).await;
    exercise_h2mux(true).await;
}

#[tokio::test]
async fn maximum_udp_frame_cannot_exhaust_the_h2_receive_window() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_h2mux(server, false, false));
    let session = connect(Box::new(client), false).await.unwrap();
    let permit = session.try_reserve().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(permit, "1.1.1.1:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("maximum-frame UDP stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();

    let mut packet = vec![0; super::super::uot::MAX_PACKET_SIZE];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        udp.recv_packet(&mut packet),
    )
    .await
    .expect("maximum UoT frame deadlocked HTTP/2 flow control")
    .unwrap();
    assert_eq!(size, super::super::uot::MAX_PACKET_SIZE);
    assert_eq!(peer, "1.1.1.1:53".parse().unwrap());
    assert!(packet.iter().all(|byte| *byte == 0x5a));

    drop(udp);
    session.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn tcp_receive_window_admits_one_megabyte_before_reads() {
    const PAYLOAD_SIZE: usize = 1024 * 1024;

    let (client, server) = tokio::io::duplex(2 * PAYLOAD_SIZE);
    let (sent, sent_done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let writer = tokio::spawn(async move {
            let mut response = BytesMut::with_capacity(PAYLOAD_SIZE + 1);
            response.extend_from_slice(&[0]);
            response.resize(PAYLOAD_SIZE + 1, 0x5a);
            send_owned(&mut send, response.freeze()).await.unwrap();
            send.send_data(Bytes::new(), true).unwrap();
            let _ = sent.send(());
        });
        while connection.accept().await.is_some() {}
        writer.await.unwrap();
    });

    let session = connect(Box::new(client), false).await.unwrap();
    let permit = session.try_reserve().unwrap();
    let mut tcp = Arc::clone(&session)
        .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("large-response TCP stream must open"));
    tokio::time::timeout(std::time::Duration::from_secs(2), sent_done)
        .await
        .expect("one-megabyte response stalled behind the initial H2 stream window")
        .unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert_eq!(response.len(), PAYLOAD_SIZE);
    assert!(response.iter().all(|byte| *byte == 0x5a));

    drop(tcp);
    session.close();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_tcp_stream_leaves_connection_credit_for_udp() {
    let capacity = H2_CONNECTION_RECV_WINDOW as usize + 1024 * 1024;
    let (client, server) = tokio::io::duplex(capacity);
    let (filled, filled_done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut filled = Some(filled);
        let mut writers = Vec::new();
        while let Some(request) = connection.accept().await {
            let (request, mut respond) = request.unwrap();
            if let Some(filled) = filled.take() {
                writers.push(tokio::spawn(async move {
                    let mut recv = request.into_body();
                    let mut request_body = BytesMut::new();
                    assert!(receive_at_least(&mut recv, &mut request_body, 9).await);
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    let mut response = BytesMut::with_capacity(H2_STREAM_RECV_WINDOW as usize);
                    response.extend_from_slice(&[0]);
                    response.resize(H2_STREAM_RECV_WINDOW as usize, 0x5a);
                    send_owned(&mut send, response.freeze()).await.unwrap();
                    send.send_data(Bytes::new(), true).unwrap();
                    let _ = filled.send(());
                }));
            } else {
                writers.push(tokio::spawn(serve_logical_stream(request, respond)));
            }
        }
        for writer in writers {
            writer.await.unwrap();
        }
    });

    let session = connect(Box::new(client), false).await.unwrap();
    let tcp = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|error| match error {
            OpenError::Session(error) | OpenError::Draining(error) | OpenError::Refused(error) => {
                panic!("stalled TCP stream must open: {error:#}")
            }
        });
    tokio::time::timeout(std::time::Duration::from_secs(2), filled_done)
        .await
        .expect("peer could not fill one TCP stream window")
        .unwrap();

    let udp_target = "8.8.8.8:53".parse().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(session.try_reserve().unwrap(), udp_target, None)
        .await
        .unwrap_or_else(|_| panic!("sibling UDP stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();
    let mut answer = [0; 16];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        udp.recv_packet(&mut answer),
    )
    .await
    .expect("stalled TCP stream consumed all H2 connection credit")
    .unwrap();
    assert_eq!(peer, udp_target);
    assert_eq!(&answer[..size], b"answer");

    drop(udp);
    drop(tcp);
    session.close();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn goaway_rolls_over_without_cutting_the_live_stream() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let servers = Arc::new(Mutex::new(Vec::new()));
    let dial = {
        let dials = Arc::clone(&dials);
        let sessions = Arc::clone(&sessions);
        let servers = Arc::clone(&servers);
        move || {
            let dials = Arc::clone(&dials);
            let sessions = Arc::clone(&sessions);
            let servers = Arc::clone(&servers);
            async move {
                let index = dials.fetch_add(1, Ordering::AcqRel);
                let (client, server) = tokio::io::duplex(1 << 20);
                servers
                    .lock()
                    .push(tokio::spawn(serve_h2mux(server, false, index == 0)));
                let session = connect(Box::new(client), false).await?;
                sessions.lock().push(Arc::clone(&session));
                Ok(session)
            }
        }
    };
    let open = |session: Arc<VlessMuxSession>, permit: SessionPermit<VlessMuxSession>| async move {
        session
            .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
            .await
    };

    let mut first = pool.open_with(dial.clone(), open).await.unwrap();
    let mut greeting = [0; 5];
    first.read_exact(&mut greeting).await.unwrap();
    first.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    first.read_exact(&mut pong).await.unwrap();

    let first_session = Arc::clone(&sessions.lock()[0]);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if matches!(
                Arc::clone(&first_session).check_ready().await,
                Err(OpenError::Draining(_))
            ) {
                first_session.begin_drain();
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut second = pool.open_with(dial, open).await.unwrap();
    second.read_exact(&mut greeting).await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(first_session.state(), SessionState::Draining);
    assert!(!first_session.is_closed());

    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    drop(first);
    drop(second);
    assert!(first_session.is_closed());
    pool.shutdown();
    let servers = std::mem::take(&mut *servers.lock());
    for server in servers {
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            1
        );
    }
}
async fn serve_idle_h2mux(wire: tokio::io::DuplexStream) -> usize {
    let io = server_carrier(wire, false).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut streams = Vec::new();
    while let Some(stream) = connection.accept().await {
        streams.push(stream.unwrap());
    }
    streams.len()
}

#[tokio::test]
async fn saturated_carrier_opens_the_second_pool_slot() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (first_client, first_server) = tokio::io::duplex(1 << 20);
    let first_server = tokio::spawn(serve_idle_h2mux(first_server));
    let first = connect(Box::new(first_client), false).await.unwrap();
    pool.insert(&first);
    let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
        .map(|_| first.try_reserve().unwrap())
        .collect();
    assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);

    let (second_client, second_server) = tokio::io::duplex(1 << 20);
    let second_server = tokio::spawn(serve_idle_h2mux(second_server));
    let second = pool
        .offer(move || async move { connect(Box::new(second_client), false).await })
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(pool.metrics().sessions, 2);

    drop(permits);
    pool.shutdown();
    assert_eq!(first_server.await.unwrap(), 0);
    assert_eq!(second_server.await.unwrap(), 0);
}

async fn prepare_detached(
    pool: &Arc<VlessMuxPool>,
) -> (
    super::super::PreparedUdpTransport,
    Arc<VlessMuxSession>,
    tokio::task::JoinHandle<usize>,
) {
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_idle_h2mux(server));
    let session = connect(Box::new(client), false).await.unwrap();
    reservation.attach(&session).unwrap();
    let permit = session.try_reserve().unwrap();
    let transport = Arc::clone(&session)
        .open_packet(permit, "8.8.8.8:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("detached UDP stream must open"));
    let transport: Arc<dyn PacketTransport> = transport;
    (
        super::super::PreparedUdpTransport::new(async move {
            reservation.commit()?;
            Ok(transport)
        }),
        session,
        server,
    )
}

#[tokio::test]
async fn detached_session_publishes_only_on_commit() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (loser, loser_session, loser_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    drop(loser);
    assert!(loser_session.is_closed());
    assert!(loser_server.await.unwrap() <= 1);

    let (winner, winner_session, winner_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    let transport = winner.commit().await.unwrap();
    assert_eq!(pool.live_session_count(), 1);
    assert!(!winner_session.is_closed());
    drop(transport);
    pool.shutdown();
    assert!(winner_session.is_closed());
    assert!(winner_server.await.unwrap() <= 1);
}

#[tokio::test]
async fn carrier_failure_fans_out_and_stream_capacity_is_bounded() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut streams = Vec::new();
        for _ in 0..2 {
            streams.push(connection.accept().await.unwrap().unwrap());
        }
        accepted_tx.send(()).unwrap();
        drop_rx.await.unwrap();
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
        .map(|_| session.try_reserve().unwrap())
        .collect();
    assert!(session.try_reserve().is_none());
    drop(permits);

    let mut first = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("first stream must open"));
    let mut second = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("second stream must open"));
    accepted_rx.await.unwrap();
    drop_tx.send(()).unwrap();
    server.await.unwrap();
    let mut byte = [0];
    assert!(first.read_exact(&mut byte).await.is_err());
    assert!(second.read_exact(&mut byte).await.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_logical_stream_sends_cancel_reset() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        ready_tx.send(()).unwrap();
        tokio::select! {
            reset = std::future::poll_fn(|cx| send.poll_reset(cx)) => reset.unwrap(),
            request = connection.accept() => {
                panic!("unexpected H2 event while awaiting reset: {request:?}");
            }
        }
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("logical stream must open"));
    ready_rx.await.unwrap();
    drop(stream);
    let reset = tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reset, h2::Reason::CANCEL);
    session.close();
}

#[tokio::test]
async fn remote_no_error_reset_is_clean_eof_after_payload() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(b"\0payload"), false)
            .unwrap();
        tokio::select! {
            result = reset_rx => result.unwrap(),
            request = connection.accept() => {
                panic!("unexpected H2 event while awaiting reset: {request:?}");
            }
        }
        send.send_reset(h2::Reason::NO_ERROR);
        while connection.accept().await.is_some() {}
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let mut stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("logical stream must open"));
    let mut payload = [0; 7];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"payload");
    reset_tx.send(()).unwrap();
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    drop(stream);
    session.close();
    server.await.unwrap();
}

#[tokio::test]
async fn mux_body_error_is_reported_lazily() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(&[1, 3, b'b', b'a', b'd']), true)
            .unwrap();
        while connection.accept().await.is_some() {}
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let mut stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("logical stream must open before lazy rejection"));
    let error = stream.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("bad"));
    drop(stream);
    session.close();
    server.await.unwrap();
}

#[tokio::test]
async fn logical_writes_wait_for_h2_flow_control() {
    const PAYLOAD_SIZE: usize = 4 * 1024 * 1024;
    let (client, server) = tokio::io::duplex(1 << 20);
    let release = Arc::new(tokio::sync::Notify::new());
    let server_release = Arc::clone(&release);
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(&[0]), false).unwrap();
        accepted_tx.send(()).unwrap();
        let handler = tokio::spawn(async move {
            let mut recv = request.into_body();
            server_release.notified().await;
            let mut received = 0;
            while let Some(data) = recv.data().await {
                let data = data.unwrap();
                received += data.len();
                recv.flow_control().release_capacity(data.len()).unwrap();
            }
            let _ = send.send_data(Bytes::new(), true);
            drained_tx.send(received).unwrap();
        });
        while connection.accept().await.is_some() {}
        handler.await.unwrap();
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("flow-control stream must open"));
    accepted_rx.await.unwrap();
    let mut writer = tokio::spawn(async move {
        let mut stream = stream;
        stream.write_all(&vec![0x5a; PAYLOAD_SIZE]).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(stream)
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut writer)
            .await
            .is_err(),
        "writer must stop at the peer's H2 receive window"
    );
    release.notify_one();
    let stream = writer.await.unwrap().unwrap();
    drop(stream);
    assert!(drained_rx.await.unwrap() >= PAYLOAD_SIZE);
    session.close();
    server.await.unwrap();
}
