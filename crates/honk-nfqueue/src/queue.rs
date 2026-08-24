use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

use bytes::{Bytes, BytesMut};

use crate::netlink;
use crate::packet;
use crate::verdict::{GuardTracker, VerdictGuard};
use crate::{
    COPY_RANGE, FatalError, FatalNotifier, MAX_DATAGRAM_SIZE, PacketCallback, QUEUE_MAXLEN,
    QUEUE_NUM, SO_RCVBUF_SIZE,
};

const NFQA_MSG_PACKET: u16 = 0;
const NFQA_MSG_CONFIG: u16 = 2;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
const NFQNL_COPY_PACKET: u8 = 2;
const POLL_TIMEOUT_MS: libc::c_int = 100;

#[derive(Debug, thiserror::Error)]
pub(crate) enum QueueError {
    #[error("NFQUEUE preflight: {0}")]
    Io(#[from] io::Error),
    #[error("NFQUEUE 320 is already bound")]
    Busy,
}

pub(crate) fn preflight() -> Result<(), QueueError> {
    let _socket = netlink::open_socket(false)?;
    match std::fs::read_to_string("/proc/thread-self/net/netfilter/nfnetlink_queue") {
        Ok(contents) if queue_row(&contents).is_some() => Err(QueueError::Busy),
        Ok(_) => Ok(()),
        Err(error) => Err(QueueError::Io(error)),
    }
}

fn queue_row(contents: &str) -> Option<(u64, u64, u64)> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let queue = fields.next()?.parse::<u16>().ok()?;
        let _peer_port = fields.next()?;
        let depth = fields.next()?.parse().ok()?;
        let _copy_mode = fields.next()?;
        let _copy_range = fields.next()?;
        let dropped = fields.next()?.parse().ok()?;
        let user_dropped = fields.next()?.parse().ok()?;
        (queue == QUEUE_NUM).then_some((depth, dropped, user_dropped))
    })
}

pub(crate) struct QueueSocket {
    fd: OwnedFd,
    sequence: AtomicU32,
    alive: AtomicBool,
    receive_buffer_bytes: usize,
    fatal: Arc<FatalNotifier>,
}

impl QueueSocket {
    pub(crate) fn bind(fatal: Arc<FatalNotifier>) -> Result<Arc<Self>, QueueError> {
        let fd = netlink::open_socket(false)?;
        set_receive_buffer(fd.as_raw_fd())?;
        let receive_buffer_bytes = receive_buffer_size(fd.as_raw_fd())?;
        let socket = Arc::new(Self {
            fd,
            sequence: AtomicU32::new(1),
            alive: AtomicBool::new(true),
            receive_buffer_bytes,
            fatal,
        });
        socket.configure()?;
        set_nonblocking(socket.fd.as_raw_fd())?;
        Ok(socket)
    }
    fn configure(&self) -> Result<(), QueueError> {
        self.send_config_command(NFQNL_CFG_CMD_PF_BIND, libc::AF_INET as u16, 0)?;
        self.send_config_command(NFQNL_CFG_CMD_PF_BIND, libc::AF_INET6 as u16, 0)?;
        self.send_config_command(NFQNL_CFG_CMD_BIND, 0, QUEUE_NUM)
            .map_err(|error| {
                // The kernel returns EPERM before its EBUSY branch when another
                // netlink port owns the queue instance.
                if matches!(error.raw_os_error(), Some(libc::EBUSY) | Some(libc::EPERM)) {
                    QueueError::Busy
                } else {
                    QueueError::Io(error)
                }
            })?;

        let mut params = [0u8; 5];
        params[..4].copy_from_slice(&COPY_RANGE.to_be_bytes());
        params[4] = NFQNL_COPY_PACKET;
        self.send_config_attribute(NFQA_CFG_PARAMS, &params)?;
        self.send_config_attribute(NFQA_CFG_QUEUE_MAXLEN, &QUEUE_MAXLEN.to_be_bytes())?;
        Ok(())
    }

    fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn send_config_attribute(&self, kind: u16, payload: &[u8]) -> io::Result<()> {
        let sequence = self.next_sequence();
        let mut request = Vec::with_capacity(64);
        let start = netlink::put_message_header(
            &mut request,
            (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_CONFIG,
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
            sequence,
            0,
            QUEUE_NUM,
        );
        netlink::put_attribute(&mut request, kind, payload);
        netlink::seal_message(&mut request, start);
        netlink::send_and_ack(self.fd.as_raw_fd(), &request, sequence)
    }

    fn send_config_command(&self, command: u8, protocol_family: u16, queue: u16) -> io::Result<()> {
        let mut payload = [0u8; 4];
        payload[0] = command;
        payload[2..].copy_from_slice(&protocol_family.to_be_bytes());
        let sequence = self.next_sequence();
        let mut request = Vec::with_capacity(48);
        let start = netlink::put_message_header(
            &mut request,
            (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_CONFIG,
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
            sequence,
            0,
            queue,
        );
        netlink::put_attribute(&mut request, NFQA_CFG_CMD, &payload);
        netlink::seal_message(&mut request, start);
        netlink::send_and_ack(self.fd.as_raw_fd(), &request, sequence)
    }

    pub(crate) fn send_verdict(
        &self,
        packet_id: u32,
        verdict: u32,
        mark: Option<u32>,
    ) -> io::Result<()> {
        let result = if self.alive.load(Ordering::Acquire) {
            let sequence = self.next_sequence();
            let message = crate::verdict::build_verdict_message(packet_id, verdict, mark, sequence);
            netlink::send(self.fd.as_raw_fd(), &message)
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "NFQUEUE verdict socket is closed",
            ))
        };
        if let Err(error) = &result {
            self.fatal.notify(FatalError::VerdictSocket {
                error: error.to_string(),
            });
        }
        result
    }

    pub(crate) fn mark_closed(&self) {
        self.alive.store(false, Ordering::Release);
    }

    pub(crate) fn receive_buffer_bytes(&self) -> usize {
        self.receive_buffer_bytes
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> (Arc<Self>, OwnedFd, crate::FatalReceiver) {
        use std::os::fd::FromRawFd;

        let mut descriptors = [0; 2];
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                descriptors.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        let (fatal, receiver) = crate::fatal_channel();
        let receive_buffer_bytes = receive_buffer_size(descriptors[0]).unwrap();
        let socket = Arc::new(Self {
            fd: unsafe { OwnedFd::from_raw_fd(descriptors[0]) },
            sequence: AtomicU32::new(1),
            alive: AtomicBool::new(true),
            receive_buffer_bytes,
            fatal,
        });
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        (socket, reader, receiver)
    }
}

pub(crate) fn listen(
    socket: Arc<QueueSocket>,
    stop: Arc<AtomicBool>,
    callback: PacketCallback,
    tracker: Arc<GuardTracker>,
) -> Result<(), FatalError> {
    let mut poll_fd = libc::pollfd {
        fd: socket.fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    while !stop.load(Ordering::Acquire) {
        poll_fd.revents = 0;
        let ready = unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MS) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(listener_io("poll", error));
        }
        if ready == 0 || stop.load(Ordering::Acquire) {
            continue;
        }

        let mut received_any = false;
        loop {
            match receive_exact(socket.fd.as_raw_fd()) {
                Ok(Some(datagram)) => {
                    received_any = true;
                    dispatch_datagram(datagram, Instant::now(), &socket, &callback, &tracker)?;
                }
                Ok(None) => break,
                Err(error) => return Err(error),
            }
        }
        if !received_any && poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
        {
            return Err(FatalError::ListenerExited);
        }
    }
    Ok(())
}

fn dispatch_datagram(
    datagram: Bytes,
    received_at: Instant,
    socket: &Arc<QueueSocket>,
    callback: &PacketCallback,
    tracker: &Arc<GuardTracker>,
) -> Result<(), FatalError> {
    let mut message_count = 0usize;
    for message in netlink::messages(datagram) {
        message_count += 1;
        let message = message.map_err(|error| FatalError::MalformedMessage {
            error: error.to_string(),
        })?;
        let expected_type = (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_PACKET;
        if message.message_type != expected_type {
            return Err(FatalError::UnexpectedMessage {
                message_type: message.message_type,
            });
        }
        if message.body.len() < netlink::NFGENMSG_LEN || message.body[1] != 0 {
            return Err(FatalError::MalformedMessage {
                error: "invalid NFQUEUE nfgenmsg".into(),
            });
        }
        let queue = u16::from_be_bytes([message.body[2], message.body[3]]);
        if queue != QUEUE_NUM {
            return Err(FatalError::UnexpectedQueue { queue });
        }
        let parsed = packet::parse_packet_message(message.body, received_at).map_err(|error| {
            FatalError::MalformedMessage {
                error: error.to_string(),
            }
        })?;
        let guard = VerdictGuard::new(Arc::clone(socket), parsed.packet_id, Arc::clone(tracker));
        if catch_unwind(AssertUnwindSafe(|| (callback)(parsed.packet, guard))).is_err() {
            return Err(FatalError::CallbackPanicked);
        }
    }
    if message_count == 0 {
        return Err(FatalError::MalformedMessage {
            error: "empty netlink datagram".into(),
        });
    }
    Ok(())
}

fn receive_exact(fd: RawFd) -> Result<Option<Bytes>, FatalError> {
    let mut probe = [0u8; 1];
    let (expected, _) = match recvmsg(
        fd,
        &mut probe,
        libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT,
    ) {
        Ok(received) => received,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
            return Err(FatalError::Enobufs);
        }
        Err(error) => return Err(listener_io("peek recvmsg", error)),
    };
    if expected == 0 {
        return Err(FatalError::ListenerExited);
    }
    if expected > MAX_DATAGRAM_SIZE {
        return Err(FatalError::DatagramTooLarge {
            length: expected,
            limit: MAX_DATAGRAM_SIZE,
        });
    }

    let mut buffer = BytesMut::zeroed(expected);
    let (actual, flags) = match recvmsg(fd, &mut buffer, libc::MSG_DONTWAIT) {
        Ok(received) => received,
        Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
            return Err(FatalError::Enobufs);
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(FatalError::DatagramLengthChanged {
                expected,
                actual: 0,
            });
        }
        Err(error) => return Err(listener_io("consume recvmsg", error)),
    };
    if flags & libc::MSG_TRUNC != 0 {
        return Err(FatalError::DatagramTruncated);
    }
    if actual != expected {
        return Err(FatalError::DatagramLengthChanged { expected, actual });
    }
    Ok(Some(buffer.freeze()))
}

fn recvmsg(fd: RawFd, buffer: &mut [u8], flags: libc::c_int) -> io::Result<(usize, libc::c_int)> {
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    let received = unsafe { libc::recvmsg(fd, &mut message, flags) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((received as usize, message.msg_flags))
}

fn set_receive_buffer(fd: RawFd) -> io::Result<()> {
    let requested = SO_RCVBUF_SIZE as libc::c_int;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&requested as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn receive_buffer_size(fd: RawFd) -> io::Result<usize> {
    let mut value = 0 as libc::c_int;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value.max(0) as usize)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if current < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, current | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn listener_io(operation: &'static str, error: io::Error) -> FatalError {
    FatalError::ListenerIo {
        operation,
        error: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn queue_row_finds_owned_queue() {
        let input = "319 10 1 2 65535 3 4 8\n320 20 17 2 65535 5 6 9\n";
        assert_eq!(queue_row(input), Some((17, 5, 6)));
    }

    const NFQA_CFG_MASK: u16 = 4;
    const NFQA_CFG_FLAGS: u16 = 5;

    #[test]
    fn configure_emits_only_bind_copy_packet_and_maxlen_without_flags() {
        let (socket, peer, _fatal) = QueueSocket::for_test();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::with_capacity(5);
            for _ in 0..5 {
                let request =
                    netlink::recv_datagram(peer.as_raw_fd(), 256).expect("config request");
                let message = netlink::messages(request.clone())
                    .next()
                    .expect("one config message")
                    .expect("valid config message");
                let mut acknowledgement = Vec::with_capacity(20);
                let start = netlink::put_message_header(
                    &mut acknowledgement,
                    netlink::NLMSG_ERROR,
                    0,
                    message.sequence,
                    0,
                    0,
                );
                netlink::seal_message(&mut acknowledgement, start);
                netlink::send(peer.as_raw_fd(), &acknowledgement).expect("config ACK");
                requests.push(request);
            }
            requests
        });

        socket.configure().expect("queue configuration");
        let requests = responder.join().expect("config responder");
        let decoded = requests
            .into_iter()
            .map(|request| {
                let message = netlink::messages(request)
                    .next()
                    .unwrap()
                    .expect("valid config message");
                assert_eq!(
                    message.message_type,
                    (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_CONFIG
                );
                assert_eq!(message.flags, netlink::NLM_F_REQUEST | netlink::NLM_F_ACK);
                let queue = u16::from_be_bytes(message.body[2..4].try_into().unwrap());
                let attributes = netlink::attributes(message.body.slice(netlink::NFGENMSG_LEN..))
                    .collect::<Result<Vec<_>, _>>()
                    .expect("valid config attributes");
                assert_eq!(attributes.len(), 1);
                (queue, attributes[0].kind, attributes[0].payload.clone())
            })
            .collect::<Vec<_>>();

        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded[0].0, 0);
        assert_eq!(decoded[0].1, NFQA_CFG_CMD);
        assert_eq!(decoded[0].2[0], NFQNL_CFG_CMD_PF_BIND);
        assert_eq!(
            u16::from_be_bytes(decoded[0].2[2..4].try_into().unwrap()),
            libc::AF_INET as u16
        );
        assert_eq!(decoded[1].0, 0);
        assert_eq!(decoded[1].1, NFQA_CFG_CMD);
        assert_eq!(decoded[1].2[0], NFQNL_CFG_CMD_PF_BIND);
        assert_eq!(
            u16::from_be_bytes(decoded[1].2[2..4].try_into().unwrap()),
            libc::AF_INET6 as u16
        );
        assert_eq!(decoded[2].0, QUEUE_NUM);
        assert_eq!(decoded[2].1, NFQA_CFG_CMD);
        assert_eq!(decoded[2].2.as_ref(), &[NFQNL_CFG_CMD_BIND, 0, 0, 0]);
        assert_eq!(decoded[3].0, QUEUE_NUM);
        assert_eq!(decoded[3].1, NFQA_CFG_PARAMS);
        assert_eq!(decoded[3].2[..4], COPY_RANGE.to_be_bytes());
        assert_eq!(decoded[3].2[4], NFQNL_COPY_PACKET);
        assert_eq!(decoded[4].0, QUEUE_NUM);
        assert_eq!(decoded[4].1, NFQA_CFG_QUEUE_MAXLEN);
        assert_eq!(decoded[4].2.as_ref(), &QUEUE_MAXLEN.to_be_bytes());
        assert!(
            decoded
                .iter()
                .all(|(_, kind, _)| !matches!(*kind, NFQA_CFG_MASK | NFQA_CFG_FLAGS)),
            "fail-open and GSO flags must not be configured"
        );
    }

    #[test]
    fn malformed_netlink_length_is_listener_fatal() {
        let (socket, _peer, _fatal) = QueueSocket::for_test();
        let tracker = GuardTracker::new();
        let callback: PacketCallback = Arc::new(|_, _| panic!("malformed input dispatched"));
        let mut datagram = vec![0u8; netlink::NLMSG_HDRLEN];
        datagram[..4].copy_from_slice(&((netlink::NLMSG_HDRLEN + 1) as u32).to_ne_bytes());

        let error = dispatch_datagram(
            Bytes::from(datagram),
            Instant::now(),
            &socket,
            &callback,
            &tracker,
        )
        .expect_err("malformed netlink length must stop the listener");
        assert!(matches!(
            error,
            FatalError::MalformedMessage { error }
                if error == format!("invalid netlink message length {}", netlink::NLMSG_HDRLEN + 1)
        ));
    }
}
