use super::*;
use crate::proxy::direct::DirectHandler;
use crate::proxy::{DirectMark, ProxyStream, TcpOutbound};
use crate::util::{bypass_mark, connect_outbound, init_bypass_mark, marked_udp_socket};
use honk_config::node::Node;
use honk_ebpf_common::DAE_BYPASS_MARK;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const TIMEOUT: Duration = Duration::from_secs(2);

fn tcp_mark(stream: &ProxyStream) -> u32 {
    let socket = stream
        .stream
        .as_ref()
        .as_any()
        .downcast_ref::<TcpStream>()
        .unwrap();
    socket2::SockRef::from(socket).mark().unwrap()
}

#[test]
#[ignore = "requires Linux CAP_NET_ADMIN or CAP_NET_RAW for real SO_MARK"]
fn socket_marks_preserve_global_and_direct_flow_isolation() {
    const CHILD: &str = "HONK_SOCKET_MARK_CHILD";
    let Some(mark) = std::env::var_os(CHILD) else {
        for mark in [0x200, 0x300] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "proxy::packet::socket_mark_tests::socket_marks_preserve_global_and_direct_flow_isolation",
                    "--ignored",
                    "--nocapture",
                ])
                .env(CHILD, mark.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let mark: u32 = mark.to_str().unwrap().parse().unwrap();
    assert_eq!(bypass_mark(), DAE_BYPASS_MARK);
    let default = marked_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_eq!(
        socket2::SockRef::from(&default).mark().unwrap(),
        DAE_BYPASS_MARK
    );
    init_bypass_mark(mark).unwrap();
    init_bypass_mark(mark).unwrap();
    assert_eq!(
        init_bypass_mark(mark + 1).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(bypass_mark(), mark);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(TIMEOUT, async {
                for ip in ["127.0.0.1", "::1"] {
                    exercise_marks(ip.parse().unwrap(), mark).await;
                }
            })
            .await
            .expect("marked loopback traffic must complete");
        });
}

async fn exercise_marks(ip: std::net::IpAddr, global: u32) {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    let (first, second) = tokio::join!(
        DirectHandler::dial_marked(target, DirectMark::new(0x321), TIMEOUT),
        DirectHandler::dial_marked(target, DirectMark::new(0x456), TIMEOUT),
    );
    let mut first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(tcp_mark(&first), 0x4000_0321);
    assert_eq!(tcp_mark(&second), 0x4000_0456);
    let (mut peer, first_addr) = listener.accept().await.unwrap();
    let (other, _) = listener.accept().await.unwrap();
    let first_socket = first
        .stream
        .as_ref()
        .as_any()
        .downcast_ref::<TcpStream>()
        .unwrap();
    if first_addr != first_socket.local_addr().unwrap() {
        peer = other;
    }
    first.stream.write_all(b"direct tcp").await.unwrap();
    let mut payload = [0; 10];
    peer.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"direct tcp");
    peer.write_all(b"tcp reply!").await.unwrap();
    first.stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"tcp reply!");

    // A direct probe and a proxy carrier created while marked flows live stay global.
    let probe = DirectHandler::new()
        .dial(&Node::default(), target, None, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(tcp_mark(&probe), global);
    let carrier = connect_outbound(&target.to_string(), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(socket2::SockRef::from(&carrier).mark().unwrap(), global);
    assert_eq!(tcp_mark(&first), 0x4000_0321);

    let server = UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap();
    let target = server.local_addr().unwrap();
    let first = DirectHandler::dial_udp_marked(target, DirectMark::new(0x321)).unwrap();
    let second = DirectHandler::dial_udp_marked(target, DirectMark::new(0x456)).unwrap();
    let ordinary = DirectHandler::dial_udp_marked(target, None).unwrap();
    assert_eq!(
        socket2::SockRef::from(first.socket.as_ref())
            .mark()
            .unwrap(),
        0x4000_0321
    );
    assert_eq!(
        socket2::SockRef::from(second.socket.as_ref())
            .mark()
            .unwrap(),
        0x4000_0456
    );
    assert_eq!(
        socket2::SockRef::from(ordinary.socket.as_ref())
            .mark()
            .unwrap(),
        global
    );
    let carrier = marked_udp_socket(SocketAddr::new(ip, 0)).unwrap();
    assert_eq!(socket2::SockRef::from(&carrier).mark().unwrap(), global);
    for (transport, payload) in [
        (&first, b"first".as_slice()),
        (&second, b"second".as_slice()),
    ] {
        transport.send_packet(payload).await.unwrap();
        let mut packet = [0; 64];
        let (len, client) = server.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..len], payload);
        server.send_to(b"udp reply", client).await.unwrap();
        let (len, source) = transport.recv_packet(&mut packet).await.unwrap();
        assert_eq!(&packet[..len], b"udp reply");
        assert_eq!(source, target);
    }
    assert_eq!(
        socket2::SockRef::from(first.socket.as_ref())
            .mark()
            .unwrap(),
        0x4000_0321
    );
}
