use super::*;
use std::sync::atomic::AtomicBool;
use std::task::Waker;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn response_frame(
    id: u16,
    status: u8,
    options: u8,
    peer: Option<SocketAddr>,
    payload: Option<&[u8]>,
) -> Bytes {
    let mut metadata = base_metadata(id, status, options);
    if let Some(peer) = peer {
        metadata.extend_from_slice(&[NETWORK_UDP]);
        encode_address(&mut metadata, peer, None).unwrap();
    }
    metadata_frame(metadata, payload).unwrap()
}

async fn read_wire_frame<R: AsyncRead + Unpin>(wire: &mut R) -> IncomingFrame {
    read_frame(wire).await.unwrap()
}

fn udp_target() -> SocketAddr {
    "1.2.3.4:53".parse().unwrap()
}

async fn open_udp(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Result<Arc<VlessXudpTransport>, OpenError> {
    open_xudp(session, permit, target, target_domain, [0; 8]).await
}

mod cancellation;
mod codec_tests;
mod session;
