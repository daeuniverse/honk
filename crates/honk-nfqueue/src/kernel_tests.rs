//! Root-only real-kernel coverage for the complete minimal NFQUEUE mechanism.
//! The test owns a newly unshared network namespace, so neither its queue nor
//! its nftables table can affect the host namespace.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::{
    FatalReceiver, NFQUEUE_SIGNATURE_MARK, NfqueueService, PacketCallback, QUEUE_NUM, StartError,
    TABLE_NAME, UdpTuple, VerdictError, netlink,
};

const INPUT_TOKEN: u32 = 0x0012_3456;
const INPUT_MARK: u32 = NFQUEUE_SIGNATURE_MARK | INPUT_TOKEN;
const FINAL_MARK: u32 = 0x0042_0000;
const RTM_NEWLINK: u16 = 16;
const IFF_UP: u32 = 1;
const NETLINK_ROUTE: libc::c_int = 0;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFTA_TABLE_NAME: u16 = 1;
const SKF_AD_OFF: i32 = -0x1000;
const SKF_AD_MARK: i32 = 20;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackDecision {
    Accept,
    ExplicitDrop,
    DefaultDrop,
}

#[derive(Debug)]
struct CallbackEvent {
    tuple: UdpTuple,
    payload: Bytes,
    mark: u32,
    decision: CallbackDecision,
    verdict_error: Option<String>,
    retry_rejected: bool,
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn nfqueue_service_isolated_netns_kernel_contract() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: requires root");
        return;
    }

    std::thread::Builder::new()
        .name("honk-nfq-netns-test".into())
        .spawn(|| {
            let result = unsafe { libc::unshare(libc::CLONE_NEWNET) };
            assert_eq!(
                result,
                0,
                "unshare(CLONE_NEWNET): {}",
                io::Error::last_os_error()
            );
            configure_loopback();
            exercise_kernel_contract();
        })
        .expect("spawn isolated netns test")
        .join()
        .expect("isolated netns test panicked");
}

fn exercise_kernel_contract() {
    assert!(
        !owned_table_exists(),
        "fresh netns must have no owned table"
    );

    let (event_tx, events) = mpsc::channel();
    let callback: PacketCallback = Arc::new(move |packet, mut guard| {
        let decision = if packet.payload.starts_with(b"accept-") {
            CallbackDecision::Accept
        } else if packet.payload.as_ref() == b"explicit-drop" {
            CallbackDecision::ExplicitDrop
        } else {
            CallbackDecision::DefaultDrop
        };

        let mut verdict_error = None;
        let mut retry_rejected = false;
        match decision {
            CallbackDecision::Accept => {
                if let Err(error) = guard.accept(FINAL_MARK) {
                    verdict_error = Some(error.to_string());
                }
                retry_rejected = matches!(guard.drop_packet(), Err(VerdictError::AlreadyCommitted));
                drop(guard);
            }
            CallbackDecision::ExplicitDrop => {
                if let Err(error) = guard.drop_packet() {
                    verdict_error = Some(error.to_string());
                }
                retry_rejected = matches!(
                    guard.accept(FINAL_MARK),
                    Err(VerdictError::AlreadyCommitted)
                );
                drop(guard);
            }
            CallbackDecision::DefaultDrop => drop(guard),
        }

        event_tx
            .send(CallbackEvent {
                tuple: packet.tuple,
                payload: packet.payload,
                mark: packet.mark,
                decision,
                verdict_error,
                retry_rejected,
            })
            .expect("kernel test event receiver");
    });
    let (mut service, _) =
        NfqueueService::start(Arc::clone(&callback)).expect("start production NFQUEUE");

    assert!(owned_table_exists(), "service must publish its owned table");
    assert_queue_configuration_in_proc();
    match NfqueueService::start(Arc::new(|_, _| {})) {
        Err(StartError::Queue(error)) => {
            assert!(
                error.contains("already bound") || error.contains("busy") || error.contains("Busy"),
                "unexpected second-bind error: {error}"
            );
        }
        Err(error) => panic!("second queue bind failed at the wrong stage: {error}"),
        Ok((second, _)) => {
            let _ = second.shutdown();
            panic!("a second service bound fixed queue {QUEUE_NUM}");
        }
    }

    // An unwinding service closes the queue but intentionally leaves its
    // fail-closed table; the next owner must reclaim that stale table.
    drop(service);
    assert!(
        owned_table_exists(),
        "unwinding must retain the owned table"
    );
    assert!(
        !queue_is_listed_in_proc(),
        "dropping the service must release the fixed queue"
    );
    assert!(
        crate::preflight().is_ok(),
        "a stale table must not block queue preflight"
    );
    let (new_service, mut fatal) = NfqueueService::start(Arc::clone(&callback))
        .expect("restart must reclaim a stale owned table");
    service = new_service;
    assert!(owned_table_exists(), "restart must publish the owned table");

    let ipv4_receiver = marked_receiver("127.0.0.1:0".parse().unwrap());
    let ipv6_receiver = marked_receiver("[::1]:0".parse().unwrap());
    let ipv4_client = marked_client("127.0.0.1:0".parse().unwrap());
    let ipv6_client = marked_client("[::1]:0".parse().unwrap());
    ipv4_client
        .connect(ipv4_receiver.local_addr().unwrap())
        .expect("connect IPv4 client");
    ipv6_client
        .connect(ipv6_receiver.local_addr().unwrap())
        .expect("connect IPv6 client");

    exercise_datagram(
        &ipv4_client,
        &ipv4_receiver,
        &events,
        &mut fatal,
        b"accept-ipv4",
        CallbackDecision::Accept,
    );
    exercise_datagram(
        &ipv6_client,
        &ipv6_receiver,
        &events,
        &mut fatal,
        b"accept-ipv6",
        CallbackDecision::Accept,
    );
    exercise_datagram(
        &ipv4_client,
        &ipv4_receiver,
        &events,
        &mut fatal,
        b"explicit-drop",
        CallbackDecision::ExplicitDrop,
    );
    exercise_datagram(
        &ipv6_client,
        &ipv6_receiver,
        &events,
        &mut fatal,
        b"uncommitted-drop",
        CallbackDecision::DefaultDrop,
    );

    let rebound = service.rebind().expect("hard rebind production NFQUEUE");
    service = rebound.0;
    fatal = rebound.1;
    assert!(
        owned_table_exists(),
        "hard rebind must retain the owned nftables table"
    );
    assert_queue_configuration_in_proc();
    exercise_datagram(
        &ipv4_client,
        &ipv4_receiver,
        &events,
        &mut fatal,
        b"accept-rebound",
        CallbackDecision::Accept,
    );

    assert!(
        matches!(
            fatal.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "the exercised kernel path must not report a fatal listener or verdict error"
    );
    service.shutdown().expect("clean NFQUEUE shutdown");
    assert!(
        !owned_table_exists(),
        "shutdown must remove the wholly owned nftables table"
    );
    assert!(
        !queue_is_listed_in_proc(),
        "shutdown must release the fixed queue binding"
    );
}

fn exercise_datagram(
    client: &UdpSocket,
    receiver: &UdpSocket,
    events: &Receiver<CallbackEvent>,
    fatal: &mut FatalReceiver,
    payload: &[u8],
    expected_decision: CallbackDecision,
) {
    client.send(payload).expect("send marked UDP datagram");
    let event = receive_event_or_fatal(events, fatal);
    assert_eq!(event.mark, INPUT_MARK, "NFQA_MARK is an exact carrier");
    assert_eq!(event.payload.as_ref(), payload);
    assert_eq!(event.tuple.destination, receiver.local_addr().unwrap());
    assert_eq!(event.decision, expected_decision);
    assert!(
        event.verdict_error.is_none(),
        "kernel verdict failed: {:?}",
        event.verdict_error
    );
    assert_eq!(
        event.retry_rejected,
        expected_decision != CallbackDecision::DefaultDrop,
        "explicit verdicts must commit exactly once"
    );

    if expected_decision == CallbackDecision::Accept {
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut received = vec![0u8; payload.len() + 1];
        let size = receiver
            .recv(&mut received)
            .expect("marked ACCEPT must deliver with the final mark");
        assert_eq!(&received[..size], payload);
        assert_no_delivery(receiver, Duration::from_millis(100));
    } else {
        assert_no_delivery(receiver, Duration::from_millis(250));
    }
}

fn receive_event_or_fatal(
    events: &Receiver<CallbackEvent>,
    fatal: &mut FatalReceiver,
) -> CallbackEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match fatal.try_recv() {
            Ok(error) => panic!("NFQUEUE listener failed before callback: {error:?} ({error})"),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                panic!("NFQUEUE fatal channel closed before callback")
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for NFQUEUE callback"
        );
        match events.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(event) => return event,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
}

fn marked_receiver(address: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(address).expect("bind UDP receiver");
    attach_exact_mark_filter(&socket, FINAL_MARK);
    socket
}

fn marked_client(address: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(address).expect("bind marked UDP client");
    set_socket_u32(
        socket.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_MARK,
        INPUT_MARK,
        "SO_MARK",
    );
    socket
}

fn attach_exact_mark_filter(socket: &UdpSocket, mark: u32) {
    let mut instructions = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: (SKF_AD_OFF + SKF_AD_MARK) as u32,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: mark,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: u32::MAX,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&program as *const libc::sock_fprog).cast::<libc::c_void>(),
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    assert_eq!(
        result,
        0,
        "SO_ATTACH_FILTER(mark == {mark:#x}): {}",
        io::Error::last_os_error()
    );
}

fn assert_no_delivery(socket: &UdpSocket, timeout: Duration) {
    socket.set_read_timeout(Some(timeout)).unwrap();
    let mut byte = [0u8; 1];
    let error = socket
        .recv(&mut byte)
        .expect_err("packet must be delivered at most once");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        "unexpected receive error: {error}"
    );
}

fn configure_loopback() {
    let interface = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(
        interface,
        0,
        "if_nametoindex(lo): {}",
        io::Error::last_os_error()
    );
    let socket = open_netlink_socket(NETLINK_ROUTE);
    let mut request = Vec::with_capacity(48);
    request.extend_from_slice(&[0; 4]);
    request.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
    request.extend_from_slice(&(netlink::NLM_F_REQUEST | netlink::NLM_F_ACK).to_ne_bytes());
    request.extend_from_slice(&1u32.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(&[0, 0]);
    request.extend_from_slice(&0u16.to_ne_bytes());
    request.extend_from_slice(&(interface as i32).to_ne_bytes());
    request.extend_from_slice(&IFF_UP.to_ne_bytes());
    request.extend_from_slice(&IFF_UP.to_ne_bytes());
    let request_length = request.len() as u32;
    request[..4].copy_from_slice(&request_length.to_ne_bytes());
    netlink::send(socket.as_raw_fd(), &request).expect("RTM_NEWLINK request");
    expect_ack(socket.as_raw_fd(), 1, "bring loopback up");
}

fn expect_ack(fd: RawFd, sequence: u32, operation: &str) {
    let reply = netlink::recv_datagram(fd, 4096).expect("netlink ACK");
    for message in netlink::messages(reply) {
        let message = message.expect("valid netlink ACK");
        if message.message_type != netlink::NLMSG_ERROR || message.sequence != sequence {
            continue;
        }
        assert!(message.body.len() >= 4, "truncated netlink ACK");
        let code = i32::from_ne_bytes(message.body[..4].try_into().unwrap());
        assert_eq!(
            code,
            0,
            "{operation}: {}",
            io::Error::from_raw_os_error(-code)
        );
        return;
    }
    panic!("missing netlink ACK for {operation}");
}

fn owned_table_exists() -> bool {
    let socket = netlink::open_socket(false).expect("nft query socket");
    set_receive_timeout(socket.as_raw_fd(), Duration::from_secs(2));
    let sequence = 0x4e46_5101;
    let mut request = Vec::with_capacity(64);
    let start = netlink::put_message_header(
        &mut request,
        (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE,
        netlink::NLM_F_REQUEST,
        sequence,
        netlink::NFPROTO_INET,
        netlink::NFNL_SUBSYS_NFTABLES,
    );
    netlink::put_attribute_string(&mut request, NFTA_TABLE_NAME, TABLE_NAME);
    netlink::seal_message(&mut request, start);
    netlink::send(socket.as_raw_fd(), &request).expect("nft GETTABLE request");

    loop {
        let reply = netlink::recv_datagram(socket.as_raw_fd(), 4096).expect("nft GETTABLE reply");
        for message in netlink::messages(reply) {
            let message = message.expect("valid nft GETTABLE reply");
            if message.sequence != sequence {
                continue;
            }
            if message.message_type == (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE {
                return true;
            }
            if message.message_type == netlink::NLMSG_ERROR {
                assert!(message.body.len() >= 4, "truncated nft GETTABLE error");
                let code = i32::from_ne_bytes(message.body[..4].try_into().unwrap());
                if code == -libc::ENOENT {
                    return false;
                }
                panic!(
                    "nft GETTABLE failed: {}",
                    io::Error::from_raw_os_error(-code)
                );
            }
        }
    }
}

fn assert_queue_configuration_in_proc() {
    let contents = std::fs::read_to_string("/proc/thread-self/net/netfilter/nfnetlink_queue")
        .expect("read thread-netns nfnetlink_queue proc state");
    let rows = contents
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.first().copied() == Some("320"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "exactly one fixed NFQUEUE must be bound");
    assert!(
        rows[0].len() >= 5,
        "unexpected nfnetlink_queue row: {:?}",
        rows[0]
    );
    assert_eq!(rows[0][3], "2", "queue must use COPY_PACKET mode");
    assert_eq!(
        rows[0][4], "65531",
        "kernel must clamp the requested 65535-byte copy range only by the attribute header"
    );
}

fn queue_is_listed_in_proc() -> bool {
    std::fs::read_to_string("/proc/thread-self/net/netfilter/nfnetlink_queue")
        .expect("read thread-netns nfnetlink_queue proc state")
        .lines()
        .any(|line| line.split_whitespace().next() == Some("320"))
}

fn open_netlink_socket(protocol: libc::c_int) -> OwnedFd {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    assert!(raw >= 0, "netlink socket: {}", io::Error::last_os_error());
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "netlink bind: {}", io::Error::last_os_error());
    socket
}

fn set_receive_timeout(fd: RawFd, timeout: Duration) {
    let value = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&value as *const libc::timeval).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "SO_RCVTIMEO: {}", io::Error::last_os_error());
}

fn set_socket_u32(fd: RawFd, level: libc::c_int, option: libc::c_int, value: u32, name: &str) {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const u32).cast::<libc::c_void>(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{name}: {}", io::Error::last_os_error());
}
