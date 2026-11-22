use super::{connected, stream};
use crate::proxy::ProxyStream;
use crate::proxy::request_observation_support::{milestones, observed};
use crate::proxy::transport::grpc::wrap_grpc;
use crate::runtime::flow_observation::{Milestone, observe_chain_request, request_write};
use bytes::Bytes;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST: &[u8] = b"0123456789abcdef";
const WIRE: &[u8] = b"\0\0\0\0\x12\x0a\x100123456789abcdef";
const MARKER: Bytes = Bytes::from_static(b"\0\0\0\0\x03\x0a\x01X");

async fn split_reader(first_data_ok: bool, interleaved_ping_ok: bool) {
    let (client, server, gate) = connected().await;
    let node = super::super::tls_node(Default::default());
    let io = stream(&client).await;
    let (grpc, (mut h2, mut body, mut reply)) =
        tokio::join!(wrap_grpc(&node, Box::new(io)), async {
            let (send, recv) = server.accept_bi().await.unwrap();
            let mut h2 = h2::server::Builder::new()
                .initial_window_size(16)
                .handshake::<_, Bytes>(crate::quic::QuicBiStream::new(send, recv))
                .await
                .unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/GunService/Tun");
            let mut reply = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            reply.send_data(MARKER, false).unwrap();
            (h2, request.into_body(), reply)
        });
    let mut grpc = grpc.unwrap();
    let mut ping = h2.ping_pong().unwrap();
    let exchange = async {
        let mut marker = [0];
        grpc.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, *b"X");
        let (observer, events) = observed();
        let sent = || milestones(&events.lock(), Milestone::TargetRequestSent);
        let returned = observer
            .scope(observe_chain_request(async {
                request_write(std::pin::pin!(grpc.write_all(REQUEST))).await?;
                Ok(ProxyStream {
                    stream: grpc,
                    target_addr: client.remote_address(),
                    target_domain: None,
                })
            }))
            .await
            .unwrap();
        assert_eq!(sent(), 0);
        let (mut reader, _writer) = tokio::io::split(returned.stream);
        let peer = async {
            gate.held().await;
            assert_eq!(sent(), 0);
            gate.release(Some(first_data_ok));
            let first = body.data().await.unwrap().unwrap();
            assert_eq!(&first[..], &WIRE[..16]);
            assert_eq!(sent(), 0, "a prefix cannot prove the application write");

            // No DATA credit: the only H2 output solicited here is the PING ACK.
            let tracked_ping = {
                let mut pong = std::pin::pin!(ping.ping(h2::Ping::opaque()));
                tokio::select! {
                    result = &mut pong => { result.unwrap(); false }
                    () = gate.held() => {
                        gate.release(Some(interleaved_ping_ok));
                        pong.await.unwrap();
                        true
                    }
                }
            };
            assert_eq!(sent(), 0);
            body.flow_control().release_capacity(first.len()).unwrap();
            let expected = usize::from(first_data_ok && (interleaved_ping_ok || !tracked_ping));
            if expected != 0 {
                gate.held().await;
                assert_eq!(sent(), 0, "DATA queued to QUIC but not yet submitted");
                assert!(futures_util::poll!(std::pin::pin!(body.data())).is_pending());
            }
            // After an uncertain prefix the root may already use ordinary writes.
            gate.release(None);
            let last = body.data().await.unwrap().unwrap();
            assert_eq!(&last[..], &WIRE[16..]);
            if expected != 0 {
                while sent() == 0 {
                    tokio::task::yield_now().await;
                }
            }
            let status_sends = gate.strict.load(Relaxed);
            ping.ping(h2::Ping::opaque()).await.unwrap();
            assert_eq!(
                gate.strict.load(Relaxed),
                status_sends,
                "a later PING used the request receipt"
            );
            reply.send_data(MARKER, false).unwrap();
            expected
        };
        let (expected, read) = tokio::join!(peer, reader.read_exact(&mut marker));
        read.unwrap();
        assert_eq!(marker, *b"X");
        assert_eq!(sent(), expected);
    };
    tokio::select! {
        () = exchange => {}
        _ = h2.accept() => panic!("gRPC peer stopped or received a second request"),
    }
}

#[tokio::test]
async fn grpc_split_reader_requires_every_native_data_submission() {
    for (data, ping) in [(true, true), (false, true), (true, false)] {
        tokio::time::timeout(super::super::TIMEOUT, split_reader(data, ping))
            .await
            .unwrap();
    }
}
