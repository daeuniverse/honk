use super::*;
use crate::proxy::transport;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{BufReader, DuplexStream, WriteHalf};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::protocol::{
    CloseFrame,
    frame::{
        Frame,
        coding::{CloseCode, Data, OpCode},
    },
};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

fn ws_node() -> Node {
    let mut node = crate::test_support::node(
        "vmess-ws",
        "127.0.0.1",
        80,
        honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
    );
    node.transport_mut().unwrap().transport = "ws".into();
    node
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn losing_socks_dial_drops_its_blocked_vmess_websocket_frame() {
    use crate::proxy::request_observation_support::{gated_ws_frame, milestones, observed};
    use crate::proxy::socks5::Socks5Handler;
    use crate::runtime::flow_observation::Milestone;

    const CONNECT: &[u8] = &[5, 1, 0, 1, 192, 0, 2, 1, 0, 80];
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let generation = Arc::new(crate::runtime::TaskOwner::production());
    let tasks = generation.task_scope();
    tokio::time::timeout(TIMEOUT, tasks.scope(async {
        let node = crate::test_support::socks5("exit", "127.0.0.1", 1080);
        let exit = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
        let ws_node = ws_node();
        let (observer, events) = observed();
        let mut losing = None;
        for cancel in [true, false] {
            let session = fixed_session();
            let mut upload = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
            let hello_wire = upload.seal_chunk(&[5, 1, 0]);
            let connect_wire = upload.seal_chunk(CONNECT);
            let (physical, peer, blocked, open) = gated_ws_frame(connect_wire.clone());
            let (stream, peer) = tokio::join!(
                transport::wrap_tunnel(&ws_node, physical, TunnelDialOptions::new(TIMEOUT)),
                tokio_tungstenite::accept_async(peer),
            );
            let vmess = VmessStream::start(stream.unwrap(), hex(HEADER_WIRE), fixed_session()).unwrap();
            let mut peer = peer.unwrap();
            assert_eq!(peer.next().await.unwrap().unwrap().into_data().as_ref(), hex(HEADER_WIRE));
            let mut reply = BodyChunks::new(&session.resp_key, &session.resp_iv).unwrap();
            let mut dial = Box::pin(observer.scope(Socks5Handler.dial_over(exit.clone(), Box::new(vmess),
                "192.0.2.1:80".parse().unwrap(), None, TunnelDialOptions::new(TIMEOUT))));
            let greet = async {
                let hello = peer.next().await.unwrap().unwrap().into_data();
                assert_eq!(hello.as_ref(), hello_wire);
                let mut response = hex(RESP_HEADER_WIRE);
                response.extend(reply.seal_chunk(&[5, 0]));
                peer.send(Message::Binary(response.into())).await.unwrap();
                blocked.await.unwrap();
            };
            tokio::select! { () = greet => (), result = &mut dial => panic!("premature SOCKS dial: {result:?}") }
            if cancel {
                losing = Some((dial, open, peer));
            } else {
                let (loser, release_loser, mut losing_peer) = losing.take().unwrap();
                drop(loser);
                let writer_dropped = release_loser.send(()).is_err();
                let mut late = Vec::new();
                losing_peer.get_mut().read_to_end(&mut late).await.unwrap();
                assert!(late.is_empty());
                assert!(writer_dropped, "nested WS writer still alive");
                assert!(events.lock().is_empty());
                open.send(()).unwrap();
                assert_eq!(peer.next().await.unwrap().unwrap().into_data().as_ref(), connect_wire);
                peer.send(Message::Binary(reply.seal_chunk(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).into())).await.unwrap();
                let _live = dial.await.unwrap();
                assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
                assert_eq!(milestones(&events.lock(), Milestone::TargetConfirmed), 1);
            }
        }
    })).await.unwrap();
    generation.close().await;
}

#[tokio::test(start_paused = true)]
async fn vmess_half_close_waits_for_the_ws_terminator_and_keeps_download_open() {
    use tokio::io::AsyncBufReadExt;
    tokio::time::timeout(Duration::from_secs(3), async {
        for route in [Route::Physical, Route::Supplied] {
            let (wire, peer) = tokio::io::duplex(8);
            let (mut app, mut peer) = one_byte_request(Box::new(wire), peer, route).await;
            let session = fixed_session();
            let mut upload = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
            drop(upload.seal_chunk(b"q"));
            let term = upload.seal_chunk(&[]);
            {
                let mut closing = std::pin::pin!(app.shutdown());
                tokio::select! {
                    result = closing.as_mut() => panic!("upload ended before its terminator: {result:?}"),
                    prefix = peer.get_mut().fill_buf() => assert_eq!(prefix.unwrap()[0], 0x82),
                }
                assert!(tokio::time::timeout(Duration::from_millis(1), closing.as_mut()).await.is_err());
                let (done, frame) = tokio::join!(closing, peer.next());
                done.unwrap();
                assert_eq!(frame.unwrap().unwrap().into_data().as_ref(), term);
            }
            peer.send(Message::Binary(response(b"reply").0.into())).await.unwrap();
            let mut reply = [0; 5];
            app.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        }
    }).await.unwrap();
}

type Peer = WebSocketStream<BufReader<DuplexStream>>;

#[derive(Clone, Copy)]
enum Route {
    Physical,
    Supplied,
    Buffered,
}

async fn one_byte_request(
    physical: Box<dyn AsyncReadWrite>,
    peer: DuplexStream,
    route: Route,
) -> (VmessStream, Peer) {
    let node = ws_node();
    let open = async {
        if matches!(route, Route::Supplied) {
            transport::wrap_tunnel(
                &node,
                physical,
                TunnelDialOptions::new(Duration::from_secs(3)),
            )
            .await
        } else {
            transport::wrap_after_tls(&node, physical).await
        }
    };
    let (lower, peer) = tokio::join!(open, tokio_tungstenite::accept_async(BufReader::new(peer)));
    let lower = lower.unwrap();
    let lower: Box<dyn AsyncReadWrite> = if matches!(route, Route::Buffered) {
        Box::new(tokio::io::BufStream::new(lower))
    } else {
        lower
    };
    let mut app = VmessStream::start(lower, hex(HEADER_WIRE), fixed_session()).unwrap();
    let mut peer = peer.unwrap();
    assert_eq!(
        peer.next().await.unwrap().unwrap().into_data().as_ref(),
        hex(HEADER_WIRE)
    );
    app.write_all(b"q").await.unwrap();
    let session = fixed_session();
    let request = BodyChunks::new(&session.req_key, &session.req_iv)
        .unwrap()
        .seal_chunk(b"q");
    assert_eq!(
        peer.next().await.unwrap().unwrap().into_data().as_ref(),
        request
    );
    (app, peer)
}

fn response(payload: &[u8]) -> (Vec<u8>, BodyChunks) {
    let session = fixed_session();
    let mut body = BodyChunks::new(&session.resp_key, &session.resp_iv).unwrap();
    let mut wire = hex(RESP_HEADER_WIRE);
    for chunk in payload.chunks(CHUNK_MAX_LEN) {
        wire.extend(body.seal_chunk(chunk));
    }
    (wire, body)
}

fn replace_command(wire: &mut [u8], id: u8, declared_len: u8) {
    let s = fixed_session();
    let header = VmessHandler::seal_aad(
        &kdf16(&s.resp_key, KDF_SALT_RESP_KEY, &[]),
        &kdf12(&s.resp_iv, KDF_SALT_RESP_IV, &[]),
        &[s.resp_header, 0, id, declared_len],
        &[],
    );
    let start = 2 + GCM_TAG_LEN;
    wire[start..start + header.len()].copy_from_slice(&header);
}

fn close_frame(code: CloseCode) -> CloseFrame {
    CloseFrame {
        code,
        reason: Default::default(),
    }
}

#[tokio::test(start_paused = true)]
async fn peer_first_ws_close_finishes_vmess_and_preserves_the_unread_response() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for marker in [false, true] {
            let (lower, peer) = tokio::io::duplex(256 * 1024);
            let (mut app, mut peer) =
                one_byte_request(Box::new(lower), peer, Route::Physical).await;
            let payload = if marker {
                (0..72 * 1024).map(|n| (n % 251) as u8).collect()
            } else {
                1u64.to_be_bytes().to_vec()
            };
            let (mut wire, mut body) = response(&payload);
            if marker {
                replace_command(&mut wire, 0, 9);
                wire.extend(body.seal_chunk(&[]));
            }
            let mut wire = bytes::Bytes::from(wire);
            let first = wire.split_to(wire.len() / 2);
            peer.send(Message::Frame(Frame::message(
                first,
                OpCode::Data(Data::Binary),
                false,
            )))
            .await
            .unwrap();
            peer.send(Message::Frame(Frame::message(
                wire,
                OpCode::Data(Data::Continue),
                true,
            )))
            .await
            .unwrap();
            let close = Message::Close((!marker).then(|| close_frame(CloseCode::Normal)));
            peer.send(close.clone()).await.unwrap();
            peer.get_mut().shutdown().await.unwrap();
            assert_eq!(peer.next().await.unwrap().unwrap(), close);
            assert_eq!(peer.get_mut().read(&mut [0]).await.unwrap(), 0);
            if !marker {
                let mut ack = [0; 8];
                app.read_exact(&mut ack).await.unwrap();
                assert_eq!(u64::from_be_bytes(ack), 1);
            }
            // The other ordering waits for upload shutdown before reading more than one duplex holds.
            app.shutdown().await.unwrap();
            app.shutdown().await.unwrap();
            let mut remaining = Vec::new();
            app.read_to_end(&mut remaining).await.unwrap();
            assert_eq!(
                remaining.as_slice(),
                if marker { &payload[..] } else { &[] }
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn peer_close_sends_local_fin_before_waiting_for_the_peer_fin() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (wire, peer) = tokio::io::duplex(4096);
        let (mut app, mut peer) = one_byte_request(Box::new(wire), peer, Route::Physical).await;
        peer.send(Message::Binary(response(b"reply").0.into())).await.unwrap();
        peer.send(Message::Close(None)).await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
        {
            let mut shutdown = std::pin::pin!(app.shutdown());
            let mut byte = [0];
            tokio::select! {
                first = peer.get_mut().read(&mut byte) => assert_eq!(first.unwrap(), 0, "data after reciprocal Close"),
                done = shutdown.as_mut() => panic!("unsettled peer close reported {done:?}"),
            }
            assert!(shutdown.as_mut().now_or_never().is_none());
            peer.get_mut().shutdown().await.unwrap();
            shutdown.await.unwrap();
        }
        app.shutdown().await.unwrap();
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn vmess_does_not_certify_an_incomplete_response_or_an_unproved_ws_close() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for case in [
            "header",
            "command extent",
            "length",
            "ciphertext",
            "bad tag",
            "terminal length",
            "short terminal tag",
            "bad terminal tag",
            "bad tag after ordinary eof",
            "unfinished fragment",
            "abnormal close",
            "raw eof",
            "reset after close",
            "zero close write",
            "supplied tunnel",
            "buffered carrier",
        ] {
            let (lower, peer) = tokio::io::duplex(256 * 1024);
            let reset = (case == "reset after close")
                .then(|| io::Error::from_raw_os_error(libc::ECONNRESET));
            let route = match case {
                "supplied tunnel" => Route::Supplied,
                "buffered carrier" => Route::Buffered,
                _ => Route::Physical,
            };
            let mut zero_hit = None;
            let physical: Box<dyn AsyncReadWrite> = if case == "zero close write" {
                let (rd, wire) = tokio::io::split(lower);
                let (seen, hit) = oneshot::channel();
                zero_hit = Some(hit);
                Box::new(tokio::io::join(
                    rd,
                    CloseWriter {
                        wire,
                        fault: CloseFault::Zero(Some(seen)),
                    },
                ))
            } else {
                Box::new(ErrorOnEof(lower, reset))
            };
            let (mut app, mut peer) = one_byte_request(physical, peer, route).await;
            let payload = if case == "bad terminal tag" {
                (0..72 * 1024).map(|n| (n % 251) as u8).collect()
            } else {
                b"reply".to_vec()
            };
            let (mut wire, mut body) = response(&payload);
            match case {
                "header" => wire.truncate(3),
                "command extent" => replace_command(&mut wire, 1, 9),
                "length" => wire.push(body.seal_chunk(b"next")[0]),
                "ciphertext" | "bad tag" => {
                    let mut bad = body.seal_chunk(b"next");
                    if case == "ciphertext" {
                        bad.pop();
                    } else {
                        *bad.last_mut().unwrap() ^= 1;
                    }
                    wire.extend(bad);
                }
                "terminal length"
                | "short terminal tag"
                | "bad terminal tag"
                | "bad tag after ordinary eof" => {
                    let mut bad = body.seal_chunk(&[]);
                    match case {
                        "terminal length" => bad.truncate(2),
                        "short terminal tag" => bad.truncate(7),
                        _ => *bad.last_mut().unwrap() ^= 1,
                    }
                    wire.extend(bad);
                }
                _ => {}
            }
            let mut received = Vec::new();
            if case == "bad tag after ordinary eof" {
                let tag = wire.split_off(wire.len() - GCM_TAG_LEN);
                peer.send(Message::Binary(wire.into())).await.unwrap();
                app.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
                wire = tag;
            }
            peer.send(Message::Binary(wire.into())).await.unwrap();
            if case == "unfinished fragment" {
                peer.send(Message::Frame(Frame::message(
                    vec![0x42],
                    OpCode::Data(Data::Binary),
                    false,
                )))
                .await
                .unwrap();
            }
            if case != "raw eof" {
                let code = if case == "abnormal close" {
                    CloseCode::Policy
                } else {
                    CloseCode::Normal
                };
                peer.send(Message::Close(Some(close_frame(code))))
                    .await
                    .unwrap();
            }
            peer.get_mut().shutdown().await.unwrap();
            peer.get_mut().read_to_end(&mut Vec::new()).await.unwrap();
            let error = app.shutdown().await.expect_err(case);
            let kind = error.kind();
            if let Some(mut hit) = zero_hit {
                hit.try_recv().unwrap();
                assert_eq!(kind, io::ErrorKind::ConnectionReset);
            }
            if case == "reset after close" {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                let error = anyhow::Error::new(error);
                assert_eq!(
                    error
                        .root_cause()
                        .downcast_ref::<io::Error>()
                        .and_then(io::Error::raw_os_error),
                    Some(libc::ECONNRESET)
                );
            }
            let read_error = app.read_to_end(&mut received).await.expect_err(case);
            assert_eq!(read_error.kind(), kind, "{case}");
            if matches!(
                case,
                "command extent" | "bad tag" | "bad terminal tag" | "bad tag after ordinary eof"
            ) {
                assert!(
                    crate::group::ScoreOutcome::from_io_error(&read_error).is_node_failure(),
                    "{case}: {read_error}"
                );
            }
            assert_eq!(
                received.as_slice(),
                if case == "header" { &[] } else { &payload[..] },
                "{case}"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn peer_close_does_not_acknowledge_an_interrupted_binary_send() {
    use tokio::io::{AsyncBufReadExt, ReadHalf};

    #[derive(Debug)]
    struct EofRead(ReadHalf<DuplexStream>, Option<oneshot::Sender<()>>);
    impl AsyncRead for EofRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.remaining();
            let result = Pin::new(&mut self.0).poll_read(cx, buf);
            if before != 0
                && buf.remaining() == before
                && matches!(result, Poll::Ready(Ok(())))
                && let Some(seen) = self.1.take()
            {
                let _ = seen.send(());
            }
            result
        }
    }

    tokio::time::timeout(Duration::from_secs(3), async {
        for pending_data in [false, true] {
            let (lower, peer) = tokio::io::duplex(8);
            let (rd, wr) = tokio::io::split(lower);
            let (seen, saw_eof) = oneshot::channel();
            let carrier = Box::new(tokio::io::join(EofRead(rd, Some(seen)), wr));
            let (mut app, mut peer) = one_byte_request(carrier, peer, Route::Physical).await;
            if pending_data {
                app.write_all(&[0xa5; 256]).await.unwrap();
            }
            let (mut down, mut up) = tokio::io::split(app);
            let (ack, acknowledged) = oneshot::channel();
            let application = async {
                let mut reply = [0; 5];
                down.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
                ack.send(()).unwrap();
            };
            let other = async {
                // Even the 18-byte terminator can't fit in the eight-byte wire.
                assert_eq!(peer.get_mut().fill_buf().await.unwrap()[0], 0x82);
                peer.send(Message::Binary(response(b"reply").0.into()))
                    .await
                    .unwrap();
                acknowledged.await.unwrap();
                peer.send(Message::Close(None)).await.unwrap();
                peer.get_mut().shutdown().await.unwrap();
                let _ = saw_eof.await;
                peer.get_mut().read_to_end(&mut Vec::new()).await.unwrap();
            };
            let (closed, (), ()) = tokio::join!(up.shutdown(), application, other);
            assert!(
                closed.is_err(),
                "a partial physical frame was credited; pending_data={pending_data}"
            );
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
enum CloseFault {
    Zero(Option<oneshot::Sender<()>>),
    Hold {
        reached: Option<oneshot::Sender<()>>,
        release: oneshot::Receiver<()>,
    },
}

#[derive(Debug)]
struct CloseWriter {
    wire: WriteHalf<DuplexStream>,
    fault: CloseFault,
}

impl AsyncWrite for CloseWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let CloseFault::Zero(seen) = &mut self.fault
            && data.first() == Some(&0x88)
        {
            if let Some(seen) = seen.take() {
                let _ = seen.send(());
            }
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.wire).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let CloseFault::Hold { reached, release } = &mut self.fault {
            if let Some(reached) = reached.take() {
                reached.send(()).unwrap();
            }
            if !release.is_terminated() {
                std::task::ready!(Pin::new(release).poll(cx)).unwrap();
            }
        }
        Pin::new(&mut self.wire).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn peer_close_does_not_discard_business_bytes_queued_behind_its_reply() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (wire, peer) = tokio::io::duplex(4096);
        let (rd, wr) = tokio::io::split(wire);
        let (reached, closing) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        let physical = tokio::io::join(
            rd,
            CloseWriter {
                wire: wr,
                fault: CloseFault::Hold {
                    reached: Some(reached),
                    release: gate,
                },
            },
        );
        let (mut app, mut peer) = one_byte_request(Box::new(physical), peer, Route::Physical).await;
        peer.send(Message::Binary(response(b"reply").0.into()))
            .await
            .unwrap();
        peer.send(Message::Close(None)).await.unwrap();
        peer.get_mut().shutdown().await.unwrap();
        closing.await.unwrap();
        let mut reply = [0; 5];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        app.write_all(b"never forwarded").await.unwrap();
        let mut shutdown = std::pin::pin!(app.shutdown());
        let early = tokio::time::timeout(Duration::from_millis(1), shutdown.as_mut())
            .await
            .ok();
        release.send(()).unwrap();
        let result = match early {
            Some(result) => result,
            None => shutdown.await,
        };
        assert!(result.is_err());
        assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
        assert_eq!(peer.get_mut().read(&mut [0]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}
