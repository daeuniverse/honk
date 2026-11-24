use std::io;
use std::pin::{Pin, pin};
use std::sync::atomic::Ordering::Relaxed;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

use super::super::{TIMEOUT, tls_node};
use super::{SplitWrite, connected, sent, wait_sent};
use crate::proxy::TunnelDialOptions;
use crate::proxy::request_observation_support::observed;
use crate::proxy::transport::wrap_tunnel;
use crate::proxy::vmess::test_support::UploadPeer;
use crate::quic::QuicBiStream;
use crate::runtime::flow_observation::{request_write, without};

struct Peer {
    ws: WebSocketStream<QuicBiStream>,
    buffered: Bytes,
}

// VMess sees a byte stream. A WebSocket message can cover part of a chunk or several chunks.
impl AsyncRead for Peer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() != 0 {
            while self.buffered.is_empty() {
                self.buffered = match ready!(self.ws.poll_next_unpin(cx)).unwrap().unwrap() {
                    Message::Binary(bytes) => bytes,
                    _ => panic!("expected a WebSocket binary message"),
                };
            }
            let n = buf.remaining().min(self.buffered.len());
            buf.put_slice(&self.buffered[..n]);
            self.buffered.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

async fn nested_request(prefix_confirmed: bool) {
    const BEFORE: &[u8] = b"before";
    const B: &[u8] = b"second root";
    const A_END: &[u8] = b"end of first root";
    const AFTER: &[u8] = b"after";
    let chunk = UploadPeer::CHUNK_LEN;
    let a = vec![b'A'; 2 * chunk + 3 - BEFORE.len()];
    let b_start = BEFORE.len() + a.len();
    let expected = [BEFORE, a.as_slice(), B, A_END, AFTER].concat();

    let (client, server, gate) = connected().await;
    let mut node = tls_node(Default::default());
    node.transport_mut().unwrap().transport = "ws".into();
    let (tx, rx) = client.open_bi().await.unwrap();
    let id = tx.id();
    let (ws, peer_ws) = tokio::join!(
        wrap_tunnel(
            &node,
            Box::new(QuicBiStream::new(tx, rx)),
            TunnelDialOptions::new(TIMEOUT),
        ),
        async {
            let (tx, rx) = server.accept_bi().await.unwrap();
            assert_eq!(rx.id(), id);
            tokio_tungstenite::accept_async(QuicBiStream::new(tx, rx))
                .await
                .unwrap()
        }
    );
    let header = UploadPeer::header();
    let (lower, release_suffix) =
        SplitWrite::new(ws.unwrap(), header.len() + UploadPeer::FULL_WIRE_LEN);
    let (mut vmess, mut upload) = UploadPeer::start(Box::new(lower));
    let mut peer = Peer {
        ws: peer_ws,
        buffered: Bytes::new(),
    };
    let mut received = vec![0; header.len()];
    peer.read_exact(&mut received).await.unwrap();
    assert_eq!(received, header);
    assert_eq!(gate.strict.load(Relaxed), 0);

    let (observer_a, events_a) = observed();
    let (observer_b, events_b) = observed();
    {
        let (seal_a, open_a) = oneshot::channel();
        let (seal_b, open_b) = oneshot::channel();
        let writes = async {
            vmess.write_all(BEFORE).await?;
            let write_a = async {
                vmess.write_all(&a).await?;
                let write_b = async {
                    vmess.write_all(B).await?;
                    open_b.await.unwrap();
                    Ok::<(), io::Error>(())
                };
                observer_b.scope(request_write(pin!(write_b))).await?;
                vmess.write_all(A_END).await?;
                without(vmess.write_all(AFTER)).await?;
                open_a.await.unwrap();
                Ok::<(), io::Error>(())
            };
            observer_a.scope(request_write(pin!(write_a))).await
        };
        // Queue both roots before the current-thread VMess relay reads either one.
        let mut writes = pin!(tokio::task::unconstrained(writes));
        assert!(futures_util::poll!(writes.as_mut()).is_pending());
        seal_b.send(()).unwrap();
        assert!(futures_util::poll!(writes.as_mut()).is_pending());
        tokio::select! {
            biased;
            _ = peer.read_u8() => panic!("the first VMess chunk bypassed the native gate"),
            () = gate.held() => {}
        }
        seal_a.send(()).unwrap();
        writes.await.unwrap();
    }
    assert_eq!((sent(&events_a), sent(&events_b)), (0, 0));

    // This socket call owns bytes of the first VMess chunk. No later chunk can
    // reach WS until its decoded prefix arrives at the peer.
    gate.release(Some(prefix_confirmed));
    while gate.strict.load(Relaxed) == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(gate.strict.load(Relaxed), 1);
    gate.release(None);
    assert_eq!(upload.read_chunk(&mut peer).await, expected[..chunk]);
    assert_eq!((sent(&events_a), sent(&events_b)), (0, 0));

    let prefix_sends = gate.strict.load(Relaxed);
    gate.hold();
    release_suffix.send(()).unwrap();
    {
        let mut suffix = pin!(async {
            let mut offset = chunk;
            let mut shared_chunk = false;
            while offset < expected.len() {
                let plain = upload.read_chunk(&mut peer).await;
                assert!(!plain.is_empty(), "premature VMess terminal chunk");
                let end = offset + plain.len();
                assert_eq!(plain, expected[offset..end]);
                shared_chunk |= offset < b_start && end > b_start + B.len();
                offset = end;
            }
            assert!(shared_chunk, "a VMess drain must carry A+B+A");
        });
        tokio::select! {
            biased;
            () = suffix.as_mut() => panic!("the entire suffix bypassed the native gate"),
            () = gate.held() => {}
        }
        assert_eq!((sent(&events_a), sent(&events_b)), (0, 0));
        gate.release(None);
        suffix.await;
    }
    assert!(gate.strict.load(Relaxed) > prefix_sends);
    wait_sent(&events_b).await;
    if prefix_confirmed {
        wait_sent(&events_a).await;
    }

    vmess.shutdown().await.unwrap();
    assert!(upload.read_chunk(&mut peer).await.is_empty());
    assert!(peer.buffered.is_empty());
    assert_eq!(sent(&events_a), usize::from(prefix_confirmed));
    assert_eq!(sent(&events_b), 1);
}

#[tokio::test]
async fn nested_vmess_ws_requires_every_request_range() {
    for prefix_confirmed in [true, false] {
        tokio::time::timeout(TIMEOUT, nested_request(prefix_confirmed))
            .await
            .expect("timed out stepping the nested VMess request");
    }
}
