use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};

pub(crate) const PASSWORD: &str = "udp-recovery";
// Lowercase SHA-224 hex of PASSWORD, as required by the Trojan request.
const PASSWORD_HEX: &[u8; 56] = b"781967c547c1befc120b00b4e65311fd671613ed3d62a965b1753c28";

/// One listener owns all its carrier tasks and stops only after honk has drained.
pub(crate) struct Peer {
    accepted: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Peer {
    pub(crate) fn start<F, Fut>(listener: TcpListener, serve: F) -> Self
    where
        F: Fn(TcpStream, usize) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    Some(done) = workers.join_next(), if !workers.is_empty() => done.unwrap(),
                    connection = listener.accept() => {
                        let (stream, _) = connection.unwrap();
                        stream.set_nodelay(true).unwrap();
                        let id = count.fetch_add(1, Ordering::Relaxed);
                        workers.spawn(serve(stream, id));
                    }
                    _ = &mut stopped => break,
                }
            }
            while let Some(done) = workers.join_next().await {
                done.unwrap();
            }
        });
        Self {
            accepted,
            stop,
            task,
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    pub(crate) async fn finish(self, expected: usize) {
        self.stop.send(()).unwrap();
        let mut task = self.task;
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            result.unwrap();
        } else {
            task.abort();
            let _ = task.await;
            panic!("UDP recovery wire peer did not drain");
        }
        assert_eq!(self.accepted.load(Ordering::Relaxed), expected);
    }
}

fn address(raw: &[u8]) -> SocketAddr {
    SocketAddr::from((
        [raw[0], raw[1], raw[2], raw[3]],
        u16::from_be_bytes([raw[4], raw[5]]),
    ))
}

pub(crate) async fn front(mut stream: TcpStream, exit: SocketAddr, refuse: bool) {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 10];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request[..4], [5, 1, 0, 1]);
    assert_eq!(address(&request[4..]), exit);
    if refuse {
        // Refuse CONNECT to the exit after accepting the SOCKS connection.
        stream
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        return;
    }
    let mut relay = TcpStream::connect(exit).await.unwrap();
    relay.set_nodelay(true).unwrap();
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    tokio::io::copy_bidirectional(&mut stream, &mut relay)
        .await
        .unwrap();
}

async fn read_trojan_request(reader: &mut (impl AsyncReadExt + Unpin)) -> SocketAddr {
    let mut request = [0; 68];
    reader.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..56], PASSWORD_HEX);
    assert_eq!(request[56..60], *b"\r\n\x03\x01");
    assert_eq!(request[66..], *b"\r\n");
    address(&request[60..66])
}

pub(crate) async fn trojan_peer(mut stream: TcpStream, targets: &[SocketAddr], dns: SocketAddr) {
    let target = read_trojan_request(&mut stream).await;
    assert!(targets.contains(&target), "unexpected target {target}");
    let mut frame = [0; 11];
    stream.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame[0], 1);
    assert_eq!(address(&frame[1..7]), target);
    assert_eq!(frame[9..], *b"\r\n");
    let length = usize::from(u16::from_be_bytes([frame[7], frame[8]]));
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(
        relay.send_to(&payload, target).await.unwrap(),
        payload.len()
    );
    let mut reply = [0; 512];
    let (len, source) = tokio::select! {
        biased;
        // Cancellation can close the owner while the DNS authority holds a reply.
        read = stream.read_u8() => {
            assert_eq!(target, dns);
            assert_eq!(read.unwrap_err().kind(), ErrorKind::UnexpectedEof);
            return;
        }
        reply = relay.recv_from(&mut reply) => reply.unwrap(),
    };
    let SocketAddr::V4(source) = source else {
        panic!("IPv4 fixture peer");
    };
    frame[1..5].copy_from_slice(&source.ip().octets());
    frame[5..7].copy_from_slice(&source.port().to_be_bytes());
    frame[7..9].copy_from_slice(&(len as u16).to_be_bytes());
    let mut response = Vec::with_capacity(frame.len() + len);
    response.extend_from_slice(&frame);
    response.extend_from_slice(&reply[..len]);
    stream.write_all(&response).await.unwrap();
    // The byte after the only request must be EOF, including for recovery misses.
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
}

/// Relay a QUIC connection over one plaintext Trojan UDP association.
pub(crate) async fn trojan_quic_peer(stream: TcpStream, target: SocketAddr) {
    let (mut reader, mut writer) = stream.into_split();
    assert_eq!(read_trojan_request(&mut reader).await, target);
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.connect(target).await.unwrap();
    let upload = async {
        let mut payload = vec![0; usize::from(u16::MAX)];
        let mut frame = [0; 11];
        while reader.read(&mut frame[..1]).await.unwrap() != 0 {
            reader.read_exact(&mut frame[1..]).await.unwrap();
            assert_eq!(frame[0], 1);
            assert_eq!(address(&frame[1..7]), target);
            assert_eq!(frame[9..], *b"\r\n");
            let length = u16::from_be_bytes([frame[7], frame[8]]) as usize;
            let payload = &mut payload[..length];
            reader.read_exact(payload).await.unwrap();
            assert_eq!(relay.send(payload).await.unwrap(), length);
        }
    };
    let download = async {
        let SocketAddr::V4(peer) = target else {
            panic!("IPv4 fixture peer")
        };
        let mut frame = [1, 0, 0, 0, 0, 0, 0, 0, 0, b'\r', b'\n'];
        frame[1..5].copy_from_slice(&peer.ip().octets());
        frame[5..7].copy_from_slice(&peer.port().to_be_bytes());
        let mut reply = vec![0; usize::from(u16::MAX)];
        loop {
            let length = relay.recv(&mut reply).await.unwrap();
            frame[7..9].copy_from_slice(&(length as u16).to_be_bytes());
            if let Err(error) = writer.write_all(&frame).await {
                break error;
            }
            if let Err(error) = writer.write_all(&reply[..length]).await {
                break error;
            }
        }
    };
    tokio::select! {
        biased;
        () = upload => {}
        error = download => {
            assert!(matches!(error.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset));
        }
    }
}

pub(crate) fn dns_reply(query: &[u8]) -> Vec<u8> {
    assert_eq!(
        crate::dns::forwarder::parse_dns_question(query),
        Some(("google.com".into(), 1))
    );
    let mut reply = query.to_vec();
    reply[2..4].copy_from_slice(&[0x81, 0x80]);
    reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
    crate::dns::forwarder::validate_dns_probe_response(query, &reply).unwrap();
    reply
}
