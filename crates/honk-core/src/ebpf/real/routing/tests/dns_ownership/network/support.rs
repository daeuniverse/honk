use super::*;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

pub(super) struct NetworkFixture {
    pub(super) backend: RealEbpfBackend,
    pub(super) listeners: TproxyListeners,
    pub(super) client_ns: OwnedFd,
    pub(super) resolver_ns: OwnedFd,
    _router_ns: OwnedFd,
    _daens_ns: OwnedFd,
}

impl NetworkFixture {
    pub(super) fn new(use_redirect_peer: u8) -> Self {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/default/forwarding", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv6/conf/default/accept_dad", "0").unwrap();
        let router_ns = OwnedFd::from(std::fs::File::open("/proc/thread-self/ns/net").unwrap());
        let client_ns = fresh_netns();
        let resolver_ns = fresh_netns();
        let daens_ns = fresh_netns();
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        netlink.add_veth_pair("hrlan0", "hrclient0").unwrap();
        netlink.add_veth_pair("hrwan0", "hrresolver0").unwrap();
        let daemon_link = netlink.add_link_pair("hrdae0", "hrpeer0").unwrap();
        eprintln!(
            "DNS native/redirect topology: {daemon_link:?}, redirect_peer={use_redirect_peer}"
        );
        let (wan, _) = netlink.get_link("hrwan0").unwrap();
        let (client, _) = netlink.get_link("hrclient0").unwrap();
        let (resolver, _) = netlink.get_link("hrresolver0").unwrap();
        let (dae0, dae0_mac) = netlink.get_link("hrdae0").unwrap();
        let (peer, peer_mac) = netlink.get_link("hrpeer0").unwrap();
        netlink.set_link_netns_fd(client, &client_ns).unwrap();
        netlink.set_link_netns_fd(resolver, &resolver_ns).unwrap();
        netlink.set_link_netns_fd(peer, &daens_ns).unwrap();
        for (namespace, name, v4, v6) in [
            (&router_ns, "hrlan0", [10, 81, 0, 1], "fd81::1"),
            (&router_ns, "hrwan0", [198, 51, 100, 1], "2001:db8:81::1"),
            (&router_ns, "hrdae0", [169, 254, 81, 1], "fd82::1"),
            (&client_ns, "hrclient0", [10, 81, 0, 2], "fd81::2"),
            (
                &resolver_ns,
                "hrresolver0",
                [198, 51, 100, 53],
                "2001:db8:81::53",
            ),
            (&daens_ns, "hrpeer0", [169, 254, 81, 2], "fd82::2"),
        ] {
            configure_link(
                namespace,
                name,
                v4,
                v6.parse::<Ipv6Addr>().unwrap().octets(),
            );
        }
        add_default_routes(
            &client_ns,
            "hrclient0",
            [10, 81, 0, 1],
            "fd81::1".parse::<Ipv6Addr>().unwrap().octets(),
        );
        add_default_routes(
            &resolver_ns,
            "hrresolver0",
            [198, 51, 100, 1],
            "2001:db8:81::1".parse::<Ipv6Addr>().unwrap().octets(),
        );
        add_default_routes(
            &daens_ns,
            "hrpeer0",
            [169, 254, 81, 1],
            "fd82::1".parse::<Ipv6Addr>().unwrap().octets(),
        );
        in_netns(&daens_ns, || {
            // Mark-aware reverse lookups must work with the production transparent-source setup.
            std::fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", "1").unwrap();
            for scope in ["all", "hrpeer0"] {
                std::fs::write(format!("/proc/sys/net/ipv4/conf/{scope}/rp_filter"), "0").unwrap();
                std::fs::write(format!("/proc/sys/net/ipv4/conf/{scope}/accept_local"), "1")
                    .unwrap();
            }
            let mut routes = crate::netlink::NlSock::new().unwrap();
            let (lo, _) = routes.get_link("lo").unwrap();
            let (peer, _) = routes.get_link("hrpeer0").unwrap();
            routes
                .neigh_replace(peer, crate::netlink::FAM_V4, &[169, 254, 81, 1], &dae0_mac)
                .unwrap();
            routes
                .neigh_replace(
                    peer,
                    crate::netlink::FAM_V6,
                    &"fd82::1".parse::<Ipv6Addr>().unwrap().octets(),
                    &dae0_mac,
                )
                .unwrap();
            for family in [crate::netlink::FAM_V4, crate::netlink::FAM_V6] {
                routes
                    .add_rule_fwmark(family, TPROXY_MARK, !DNS_ROUTE_MARK_MASK, 100)
                    .unwrap();
                routes
                    .add_route(
                        family,
                        100,
                        crate::netlink::ROUTE_LOCAL,
                        crate::netlink::SCOPE_HOST,
                        crate::netlink::PROTO_STATIC,
                        None,
                        None,
                        Some(lo),
                    )
                    .unwrap();
            }
        });
        let param = DaeParam {
            tproxy_port: 12345u16.to_be() as u32,
            dae0_ifindex: dae0,
            wan_ifindex: wan,
            dae0peer_mac: peer_mac,
            use_redirect_peer,
            dae_socket_mark: DAE_BYPASS_MARK,
            ..Default::default()
        };
        let mut rules = vec![rule(
            "native-dns",
            RoutingCondition {
                port: vec!["53".into()],
                dscp: vec![DSCP_DIRECT_MUST.to_string()],
                ..Default::default()
            },
            "direct",
            0,
            true,
        )];
        rules.push(rule(
            "block-must",
            RoutingCondition {
                dscp: vec![DSCP_BLOCK_MUST.to_string()],
                ..Default::default()
            },
            "block",
            0,
            true,
        ));
        rules.extend(dns_ordering_rules());
        let plan = compile(&rules);
        let mut backend = RealEbpfBackend::load_routing_test_fixture(&object(), param).unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        let listeners = in_netns(&daens_ns, TproxyListeners::new);
        listeners.publish(&mut backend).unwrap();
        load_classifier(&mut backend, "lan_ingress_l2");
        load_classifier(&mut backend, "dae0peer_ingress");
        load_classifier(&mut backend, "dae0_ingress");
        aya::programs::tc::qdisc_add_clsact("hrlan0").unwrap();
        let program: &mut SchedClassifier = backend
            .bpf_mut()
            .unwrap()
            .program_mut("lan_ingress_l2")
            .unwrap()
            .try_into()
            .unwrap();
        program.attach("hrlan0", TcAttachType::Ingress).unwrap();
        aya::programs::tc::qdisc_add_clsact("hrdae0").unwrap();
        let program: &mut SchedClassifier = backend
            .bpf_mut()
            .unwrap()
            .program_mut("dae0_ingress")
            .unwrap()
            .try_into()
            .unwrap();
        program.attach("hrdae0", TcAttachType::Ingress).unwrap();
        in_netns(&daens_ns, || {
            aya::programs::tc::qdisc_add_clsact("hrpeer0").unwrap();
            let program: &mut SchedClassifier = backend
                .bpf_mut()
                .unwrap()
                .program_mut("dae0peer_ingress")
                .unwrap()
                .try_into()
                .unwrap();
            program.attach("hrpeer0", TcAttachType::Ingress).unwrap();
        });
        backend.set_datapath_ready(true).unwrap();
        Self {
            backend,
            listeners,
            client_ns,
            resolver_ns,
            _router_ns: router_ns,
            _daens_ns: daens_ns,
        }
    }

    pub(super) fn udp_client(&self, destination: SocketAddr, dscp: u8) -> UdpSocket {
        in_netns(&self.client_ns, || {
            let address = if destination.is_ipv4() {
                "10.81.0.2:0"
            } else {
                "[fd81::2]:0"
            };
            let client = udp_socket(address.parse().unwrap());
            set_dscp(&client, destination.is_ipv6(), dscp);
            client
        })
    }

    pub(super) fn dns_mark(&self, outbound: u8) -> u32 {
        UdpDnsRoute::new(outbound, self.backend.routing_policy_generation())
            .unwrap()
            .to_mark()
    }

    pub(super) fn l3_tun(&mut self) -> std::fs::File {
        let tun = tun("hrtun0");
        load_classifier(&mut self.backend, "lan_ingress_l3");
        aya::programs::tc::qdisc_add_clsact("hrtun0").unwrap();
        let program: &mut SchedClassifier = self
            .backend
            .bpf_mut()
            .unwrap()
            .program_mut("lan_ingress_l3")
            .unwrap()
            .try_into()
            .unwrap();
        program.attach("hrtun0", TcAttachType::Ingress).unwrap();
        tun
    }

    pub(super) fn assert_no_redirects(&self) {
        assert_udp_empty(&self.listeners.udp4);
        assert_udp_empty(&self.listeners.udp6);
        assert_tcp_empty(&self.listeners.tcp4);
        assert_tcp_empty(&self.listeners.tcp6);
    }
}

fn fresh_netns() -> OwnedFd {
    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        std::fs::File::open("/proc/thread-self/ns/net")
            .map(OwnedFd::from)
            .unwrap()
    })
    .join()
    .unwrap()
}

pub(super) fn in_netns<T>(netns: &OwnedFd, f: impl FnOnce() -> T) -> T {
    let current = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    nix::sched::setns(netns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    nix::sched::setns(&current, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn configure_link(netns: &OwnedFd, name: &str, v4: [u8; 4], v6: [u8; 16]) {
    in_netns(netns, || {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (loopback, _) = netlink.get_link("lo").unwrap();
        let (ifindex, _) = netlink.get_link(name).unwrap();
        netlink.set_link_up(loopback, true).unwrap();
        netlink.set_link_up(ifindex, true).unwrap();
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0").unwrap();
        netlink
            .addr_op(true, ifindex, libc::AF_INET as u8, &v4, 24)
            .unwrap();
        netlink
            .addr_op(true, ifindex, libc::AF_INET6 as u8, &v6, 64)
            .unwrap();
    });
}

pub(super) fn udp_socket(address: SocketAddr) -> UdpSocket {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None).unwrap();
    if address.is_ipv6() {
        socket.set_only_v6(true).unwrap();
    }
    socket.bind(&address.into()).unwrap();
    let socket: UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

pub(super) fn tcp_listener(address: SocketAddr) -> TcpListener {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
    socket.set_reuse_address(true).unwrap();
    if address.is_ipv6() {
        socket.set_only_v6(true).unwrap();
    }
    socket.bind(&address.into()).unwrap();
    socket.listen(128).unwrap();
    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true).unwrap();
    listener
}

pub(super) fn tcp_connect(address: SocketAddr, dscp: u8, mark: u32) -> std::io::Result<TcpStream> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &mark).unwrap();
    set_dscp(&socket, address.is_ipv6(), dscp);
    socket.connect_timeout(&address.into(), Duration::from_secs(2))?;
    let stream: TcpStream = socket.into();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    Ok(stream)
}

pub(super) fn accept_connection(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, source)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return (stream, source);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < deadline, "TCP accept timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("TCP accept: {error}"),
        }
    }
}

pub(super) fn set_dscp(socket: &impl AsRawFd, ipv6: bool, dscp: u8) {
    let value: libc::c_int = i32::from(dscp) << 2;
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS)
    };
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&value as *const libc::c_int).cast(),
                mem::size_of_val(&value) as libc::socklen_t,
            )
        },
        0,
        "set DSCP: {}",
        std::io::Error::last_os_error()
    );
}

pub(super) fn exchange_tcp(
    client: &mut TcpStream,
    server: &mut TcpStream,
    query: &[u8],
    answer: &[u8],
) {
    let mut wire = (query.len() as u16).to_be_bytes().to_vec();
    wire.extend_from_slice(query);
    client.write_all(&wire).unwrap();
    let mut received = vec![0; wire.len()];
    server.read_exact(&mut received).unwrap();
    assert_eq!(received, wire);
    wire[2..].copy_from_slice(answer);
    server.write_all(&wire).unwrap();
    client.read_exact(&mut received).unwrap();
    assert_eq!(received, wire);
}

#[track_caller]
pub(super) fn recv_marked(socket: &UdpSocket) -> (Vec<u8>, SocketAddr, u32) {
    let mut payload = [0u8; 64];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = [0usize; 8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = mem::size_of_val(&source) as libc::socklen_t;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control) as _;
    let size = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    assert!(size >= 0, "recvmsg: {}", std::io::Error::last_os_error());
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    let first = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!first.is_null(), "missing SO_MARK cmsg");
    assert_eq!(unsafe { (*first).cmsg_level }, libc::SOL_SOCKET);
    assert_eq!(unsafe { (*first).cmsg_type }, libc::SO_MARK);
    assert_eq!(unsafe { (*first).cmsg_len } as usize, unsafe {
        libc::CMSG_LEN(mem::size_of::<u32>() as u32)
    } as usize);
    let mark = unsafe { ptr::read_unaligned(libc::CMSG_DATA(first).cast::<u32>()) };
    assert!(unsafe { libc::CMSG_NXTHDR(&message, first) }.is_null());
    let source = unsafe {
        match source.ss_family as libc::c_int {
            libc::AF_INET => {
                let address = ptr::read_unaligned(
                    (&source as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                );
                SocketAddr::from((
                    Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let address = ptr::read_unaligned(
                    (&source as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                );
                SocketAddr::from((
                    Ipv6Addr::from(address.sin6_addr.s6_addr),
                    u16::from_be(address.sin6_port),
                ))
            }
            family => panic!("unexpected source family {family}"),
        }
    };
    (payload[..size as usize].to_vec(), source, mark)
}

fn add_default_routes(netns: &OwnedFd, name: &str, v4_gateway: [u8; 4], v6_gateway: [u8; 16]) {
    in_netns(netns, || {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (ifindex, _) = netlink.get_link(name).unwrap();
        netlink
            .add_route(
                libc::AF_INET as u8,
                254,
                1,
                0,
                4,
                None,
                Some(&v4_gateway),
                Some(ifindex),
            )
            .unwrap();
        netlink
            .add_route(
                libc::AF_INET6 as u8,
                254,
                1,
                0,
                4,
                None,
                Some(&v6_gateway),
                Some(ifindex),
            )
            .unwrap();
    });
}

fn tun(name: &str) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/net/tun")
        .unwrap();
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (byte, value) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *byte = value as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) },
        0,
        "create TUN: {}",
        std::io::Error::last_os_error()
    );
    let mut netlink = crate::netlink::NlSock::new().unwrap();
    let ifindex = nix::net::if_::if_nametoindex(name).unwrap();
    netlink.set_link_up(ifindex, true).unwrap();
    file
}

#[track_caller]
pub(super) fn exchange_udp(client: &UdpSocket, server: &UdpSocket, destination: SocketAddr) {
    client.send_to(DNS_QUERY, destination).unwrap();
    let mut bytes = [0; 64];
    let (size, source) = server.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..size], DNS_QUERY);
    assert_eq!(source, client.local_addr().unwrap());
    let answer = dns_answer();
    server.send_to(&answer, source).unwrap();
    let (size, source) = client.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..size], answer);
    assert_eq!(source, destination);
}

#[track_caller]
pub(super) fn assert_udp_empty(socket: &UdpSocket) {
    let timeout = socket.read_timeout().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 64]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    socket.set_read_timeout(timeout).unwrap();
}

#[track_caller]
pub(super) fn assert_tcp_empty(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
