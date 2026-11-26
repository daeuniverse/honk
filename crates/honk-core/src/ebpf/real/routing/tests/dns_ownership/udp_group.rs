//! Four distinct transparent UDP sockets per family, so a test can tell which
//! listener a datagram was steered to; `TproxyListeners` publishes one socket
//! four times and cannot.

use super::*;
use aya::programs::SkLookup;
use aya_ebpf_bindings::bindings::bpf_sk_lookup;
use std::os::fd::AsFd;

pub(super) const LISTENERS: usize = 4;
const BPF_PROG_TEST_RUN: libc::c_long = 10;
const SK_PASS: u32 = 1;

pub(super) struct UdpGroup {
    pub(super) v4: Vec<UdpSocket>,
    pub(super) v6: Vec<UdpSocket>,
}

#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    padding: u32,
}

impl UdpGroup {
    /// Replaces the listener sockets published to `LISTEN_SOCKET_MAP`.
    pub(super) fn publish(backend: &mut RealEbpfBackend, listeners: &TproxyListeners) -> Self {
        let group = Self {
            v4: (0..LISTENERS)
                .map(|_| TproxyListeners::udp(false))
                .collect(),
            v6: (0..LISTENERS).map(|_| TproxyListeners::udp(true)).collect(),
        };
        for socket in group.v4.iter().chain(&group.v6) {
            socket.set_nonblocking(true).unwrap();
        }
        let fds = |sockets: &[UdpSocket]| sockets.iter().map(|s| s.as_raw_fd()).collect::<Vec<_>>();
        backend
            .publish_listener_socket_maps(
                listeners.tcp4.as_raw_fd(),
                Some(listeners.tcp6.as_raw_fd()),
                &fds(&group.v4),
                &fds(&group.v6),
            )
            .unwrap();
        group
    }

    pub(super) fn sockets(&self, ipv6: bool) -> &[UdpSocket] {
        if ipv6 { &self.v6 } else { &self.v4 }
    }

    /// Index of the listener whose queue holds a datagram, waiting briefly.
    #[track_caller]
    pub(super) fn receiver(&self, ipv6: bool) -> (usize, SocketAddr) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            for (index, socket) in self.sockets(ipv6).iter().enumerate() {
                if let Ok((_, source)) = socket.recv_from(&mut [0; 64]) {
                    return (index, source);
                }
            }
            assert!(std::time::Instant::now() < deadline, "no listener received");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(super) fn cookie(&self, ipv6: bool, index: usize) -> u64 {
        socket_cookie(&self.sockets(ipv6)[index])
    }
}

fn ip6_words(address: Ipv6Addr) -> [u32; 4] {
    let octets = address.octets();
    std::array::from_fn(|i| u32::from_ne_bytes(octets[i * 4..i * 4 + 4].try_into().unwrap()))
}

fn socket_cookie(socket: &UdpSocket) -> u64 {
    let mut cookie = 0u64;
    let mut length = mem::size_of_val(&cookie) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&raw mut cookie).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "SO_COOKIE: {}", std::io::Error::last_os_error());
    cookie
}

/// Cookie of the listener `tproxy_sk_lookup` selects for a UDP datagram, via
/// BPF_PROG_TEST_RUN (aya has no `TestRun` for `SkLookup`).
pub(super) fn lookup_cookie(
    backend: &RealEbpfBackend,
    source: SocketAddr,
    destination: SocketAddr,
) -> u64 {
    let object = backend.bpf().unwrap();
    let program: &SkLookup = object
        .program("tproxy_sk_lookup")
        .unwrap()
        .try_into()
        .unwrap();
    let mut context: bpf_sk_lookup = unsafe { mem::zeroed() };
    context.protocol = IPPROTO_UDP as u32;
    context.remote_port = source.port().to_be();
    context.local_port = u32::from(destination.port());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            context.family = libc::AF_INET as u32;
            context.remote_ip4 = u32::from_ne_bytes(source.octets());
            context.local_ip4 = u32::from_ne_bytes(destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            context.family = libc::AF_INET6 as u32;
            context.remote_ip6 = ip6_words(source);
            context.local_ip6 = ip6_words(destination);
        }
        _ => panic!("mixed address families"),
    }
    let mut context_out: bpf_sk_lookup = unsafe { mem::zeroed() };
    let size = mem::size_of::<bpf_sk_lookup>() as u32;
    let mut attr = TestRunAttr {
        prog_fd: program.fd().unwrap().as_fd().as_raw_fd() as u32,
        ctx_size_in: size,
        ctx_size_out: size,
        ctx_in: (&raw const context) as u64,
        ctx_out: (&raw mut context_out) as u64,
        ..Default::default()
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &raw mut attr,
            mem::size_of::<TestRunAttr>(),
        )
    };
    assert_eq!(
        result,
        0,
        "BPF_PROG_TEST_RUN tproxy_sk_lookup: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(attr.retval, SK_PASS, "sk_lookup {source} -> {destination}");
    let cookie = unsafe { context_out.__bindgen_anon_1.cookie };
    assert_ne!(cookie, 0, "sk_lookup selected no socket");
    cookie
}
