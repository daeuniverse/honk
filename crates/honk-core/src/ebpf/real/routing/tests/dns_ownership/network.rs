use super::*;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

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

fn in_netns<T>(netns: &OwnedFd, f: impl FnOnce() -> T) -> T {
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

fn udp_socket(address: SocketAddr, receive_mark: bool) -> UdpSocket {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None).unwrap();
    if address.is_ipv6() {
        socket.set_only_v6(true).unwrap();
    }
    if receive_mark {
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVMARK,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0,
            "SO_RCVMARK: {}",
            std::io::Error::last_os_error()
        );
    }
    socket.bind(&address.into()).unwrap();
    let socket: UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn tcp_listener(address: SocketAddr) -> TcpListener {
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

fn tcp_connect(address: SocketAddr, dscp: u8) -> TcpStream {
    tcp_connect_marked(address, dscp, 0)
}

fn tcp_connect_marked(address: SocketAddr, dscp: u8, mark: u32) -> TcpStream {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &mark).unwrap();
    set_dscp(&socket, address.is_ipv6(), dscp);
    socket
        .connect_timeout(&address.into(), Duration::from_secs(2))
        .unwrap();
    let stream: TcpStream = socket.into();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn accept_connection(listener: &TcpListener) -> (TcpStream, SocketAddr) {
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

fn set_dscp(socket: &impl AsRawFd, ipv6: bool, dscp: u8) {
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

fn exchange_tcp(client: &mut TcpStream, server: &mut TcpStream, query: &[u8], answer: &[u8]) {
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
fn recv_marked(socket: &UdpSocket) -> (Vec<u8>, SocketAddr, u32) {
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

fn run_dns_network(use_redirect_peer: u8, verify_l3: bool) {
    isolated(move || {
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
        let client4 = in_netns(&client_ns, || {
            udp_socket("10.81.0.2:0".parse().unwrap(), false)
        });
        let client6 = in_netns(&client_ns, || {
            udp_socket("[fd81::2]:0".parse().unwrap(), false)
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
                dscp: vec!["8".into()],
                ..Default::default()
            },
            "direct",
            0,
            true,
        )];
        rules.push(rule(
            "blocked-local-service",
            RoutingCondition {
                dscp: vec!["16".into()],
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
        let mut l3_tun = verify_l3.then(|| tun("hrtun0"));
        if verify_l3 {
            load_classifier(&mut backend, "lan_ingress_l3");
            aya::programs::tc::qdisc_add_clsact("hrtun0").unwrap();
            let program: &mut SchedClassifier = backend
                .bpf_mut()
                .unwrap()
                .program_mut("lan_ingress_l3")
                .unwrap()
                .try_into()
                .unwrap();
            program.attach("hrtun0", TcAttachType::Ingress).unwrap();
        }
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
        let generation = backend.routing_policy_generation();
        let mut buffer = [0u8; 64];
        let raw_mark = UdpDnsRoute::new(2, generation).unwrap().to_mark();
        let controller_mark =
            UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation)
                .unwrap()
                .to_mark();
        let query =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x03com\x00\x00\x01\x00\x01";
        let mut answer = query.to_vec();
        answer[2] = 0x81;
        answer[3] = 0x80;
        if let Some(tun) = l3_tun.as_mut() {
            for (source, destination, source_port, dscp, receiver, expected_mark) in [
                (
                    IpAddr::V4(Ipv4Addr::new(10, 82, 0, 2)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
                    44000,
                    46,
                    &listeners.udp4,
                    raw_mark,
                ),
                (
                    IpAddr::V4(Ipv4Addr::new(10, 82, 0, 2)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
                    44001,
                    0,
                    &listeners.udp4,
                    controller_mark,
                ),
                (
                    IpAddr::V6("fd83::2".parse().unwrap()),
                    IpAddr::V6("2001:db8:81::53".parse().unwrap()),
                    44002,
                    46,
                    &listeners.udp6,
                    raw_mark,
                ),
                (
                    IpAddr::V6("fd83::2".parse().unwrap()),
                    IpAddr::V6("2001:db8:81::53".parse().unwrap()),
                    44003,
                    0,
                    &listeners.udp6,
                    controller_mark,
                ),
            ] {
                let packet = packet(source, destination, IPPROTO_UDP, source_port, 53, dscp, 0);
                tun.write_all(&packet[14..]).unwrap();
                let (payload, observed_source, observed_mark) = recv_marked(receiver);
                assert_eq!(payload.as_slice(), &[0xa5]);
                assert_eq!(observed_source, SocketAddr::new(source, source_port));
                assert_eq!(observed_mark, expected_mark);
            }
        }

        let exact4 = udp_socket("10.81.0.1:53".parse().unwrap(), false);
        let exact6 = udp_socket("[fd81::1]:53".parse().unwrap(), false);
        if let Some(tun) = l3_tun.as_mut() {
            for (source, destination, receiver) in [
                ("10.82.0.2", "10.81.0.1", &listeners.udp4),
                ("fd83::2", "fd81::1", &listeners.udp6),
            ] {
                let source: IpAddr = source.parse().unwrap();
                let packet = packet(
                    source,
                    destination.parse().unwrap(),
                    IPPROTO_UDP,
                    44004,
                    53,
                    0,
                    0,
                );
                tun.write_all(&packet[14..]).unwrap();
                let (payload, observed_source, mark) = recv_marked(receiver);
                assert_eq!(payload, [0xa5]);
                assert_eq!(observed_source, SocketAddr::new(source, 44004));
                assert_eq!(mark, controller_mark);
            }
        }
        for (client, local, receiver, destination, payload) in [
            (
                &client4,
                &exact4,
                &listeners.udp4,
                "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
                b"exact4".as_slice(),
            ),
            (
                &client6,
                &exact6,
                &listeners.udp6,
                "[fd81::1]:53".parse().unwrap(),
                b"exact6".as_slice(),
            ),
        ] {
            client.send_to(payload, destination).unwrap();
            let (observed, source, mark) = recv_marked(receiver);
            assert_eq!(observed, payload);
            assert_eq!(source, client.local_addr().unwrap());
            assert_eq!(mark, controller_mark);
            local.set_nonblocking(true).unwrap();
            assert_eq!(
                local.recv_from(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        drop((exact4, exact6));
        let tcp_exact4 = tcp_listener("10.81.0.1:53".parse().unwrap());
        let tcp_exact6 = tcp_listener("[fd81::1]:53".parse().unwrap());
        for (local, receiver, destination) in [
            (
                &tcp_exact4,
                &listeners.tcp4,
                "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
            ),
            (
                &tcp_exact6,
                &listeners.tcp6,
                "[fd81::1]:53".parse().unwrap(),
            ),
        ] {
            let mut client = in_netns(&client_ns, || tcp_connect(destination, 0));
            let (mut server, source) = accept_connection(receiver);
            assert_eq!(source, client.local_addr().unwrap());
            for _ in 0..2 {
                exchange_tcp(&mut client, &mut server, query, &answer);
            }
            assert_eq!(
                local.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        drop((tcp_exact4, tcp_exact6));

        let wildcard4 = udp_socket("0.0.0.0:53".parse().unwrap(), false);
        let wildcard6 = udp_socket("[::]:53".parse().unwrap(), false);
        let tcp_wildcard4 = tcp_listener("0.0.0.0:53".parse().unwrap());
        let tcp_wildcard6 = tcp_listener("[::]:53".parse().unwrap());
        for (client, local, tcp, receiver, tcp_receiver, destination) in [
            (
                &client4,
                &wildcard4,
                &tcp_wildcard4,
                &listeners.udp4,
                &listeners.tcp4,
                "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
            ),
            (
                &client6,
                &wildcard6,
                &tcp_wildcard6,
                &listeners.udp6,
                &listeners.tcp6,
                "[fd81::1]:53".parse().unwrap(),
            ),
        ] {
            set_dscp(client, destination.is_ipv6(), 16);
            client.send_to(b"block-must", destination).unwrap();
            for (dscp, expected_mark) in [(0, controller_mark), (46, raw_mark)] {
                set_dscp(client, destination.is_ipv6(), dscp);
                client.send_to(b"wild", destination).unwrap();
                let (payload, source, mark) = recv_marked(receiver);
                assert_eq!(payload, b"wild");
                assert_eq!(source, client.local_addr().unwrap());
                assert_eq!(mark, expected_mark);
                let mut stream = in_netns(&client_ns, || tcp_connect(destination, dscp));
                let (mut server, source) = accept_connection(tcp_receiver);
                assert_eq!(source, stream.local_addr().unwrap());
                exchange_tcp(&mut stream, &mut server, query, &answer);
            }
            in_netns(&client_ns, || {
                let domain = if destination.is_ipv4() {
                    socket2::Domain::IPV4
                } else {
                    socket2::Domain::IPV6
                };
                let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
                set_dscp(&socket, destination.is_ipv6(), 16);
                assert_eq!(
                    socket
                        .connect_timeout(&destination.into(), Duration::from_secs(2))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::TimedOut
                );
            });
            assert_eq!(
                tcp.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            set_dscp(client, destination.is_ipv6(), 8);
            client.send_to(query, destination).unwrap();
            let (size, source) = local.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], query);
            assert_eq!(source, client.local_addr().unwrap());
            local.send_to(&answer, source).unwrap();
            let (size, source) = client.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], answer);
            assert_eq!(source, destination);
            set_dscp(client, destination.is_ipv6(), 0);
            let mut stream = in_netns(&client_ns, || tcp_connect(destination, 8));
            let (mut server, source) = accept_connection(tcp);
            assert_eq!(source, stream.local_addr().unwrap());
            exchange_tcp(&mut stream, &mut server, query, &answer);

            let loopback = if destination.is_ipv4() {
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
            } else {
                SocketAddr::from((Ipv6Addr::LOCALHOST, 53))
            };
            let backend_client = udp_socket(SocketAddr::new(loopback.ip(), 0), false);
            backend_client.send_to(query, loopback).unwrap();
            let (size, source) = local.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], query);
            assert_eq!(source, backend_client.local_addr().unwrap());
            local.send_to(&answer, source).unwrap();
            let (size, source) = backend_client.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], answer);
            assert_eq!(source, loopback);
            let mut stream = tcp_connect(loopback, 0);
            let (mut server, source) = accept_connection(tcp);
            assert_eq!(source, stream.local_addr().unwrap());
            exchange_tcp(&mut stream, &mut server, query, &answer);
        }

        for (client, destination) in [
            (&client4, "10.81.0.1:5353".parse::<SocketAddr>().unwrap()),
            (&client6, "[fd81::1]:5353".parse().unwrap()),
        ] {
            let local = udp_socket(destination, false);
            set_dscp(client, destination.is_ipv6(), 16);
            client.send_to(b"local-udp", destination).unwrap();
            let (size, source) = local.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], b"local-udp");
            assert_eq!(source, client.local_addr().unwrap());
            set_dscp(client, destination.is_ipv6(), 0);
        }

        let resolver4 = in_netns(&resolver_ns, || {
            udp_socket("198.51.100.53:53".parse().unwrap(), false)
        });
        let resolver6 = in_netns(&resolver_ns, || {
            udp_socket("[2001:db8:81::53]:53".parse().unwrap(), false)
        });
        let resolver_tcp4 = in_netns(&resolver_ns, || {
            tcp_listener("198.51.100.53:53".parse().unwrap())
        });
        let resolver_tcp6 = in_netns(&resolver_ns, || {
            tcp_listener("[2001:db8:81::53]:53".parse().unwrap())
        });
        for (client, receiver, destination) in [
            (
                &client4,
                &listeners.udp4,
                "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
            ),
            (
                &client6,
                &listeners.udp6,
                "[2001:db8:81::53]:53".parse().unwrap(),
            ),
        ] {
            set_dscp(client, destination.is_ipv6(), 46);
            client.send_to(b"raw-must", destination).unwrap();
            set_dscp(client, destination.is_ipv6(), 0);
            client.send_to(b"nonmust-dns", destination).unwrap();
            for (expected, mark) in [
                (b"raw-must".as_slice(), raw_mark),
                (b"nonmust-dns".as_slice(), controller_mark),
            ] {
                let (payload, source, observed_mark) = recv_marked(receiver);
                assert_eq!(payload, expected);
                assert_eq!(source, client.local_addr().unwrap());
                assert_eq!(observed_mark, mark);
            }
        }

        for (receiver, destination) in [
            (&listeners.tcp4, resolver4.local_addr().unwrap()),
            (&listeners.tcp6, resolver6.local_addr().unwrap()),
        ] {
            let mut client = in_netns(&client_ns, || tcp_connect(destination, 0));
            let (mut server, source) = accept_connection(receiver);
            assert_eq!(source, client.local_addr().unwrap());
            exchange_tcp(&mut client, &mut server, query, &answer);
        }
        for (client, resolver) in [(&client4, &resolver4), (&client6, &resolver6)] {
            let destination = resolver.local_addr().unwrap();
            set_dscp(client, destination.is_ipv6(), 8);
            client.send_to(query, destination).unwrap();
            let (size, source) = resolver.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], query);
            assert_eq!(source, client.local_addr().unwrap());
            resolver.send_to(&answer, source).unwrap();
            let (size, source) = client.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..size], answer);
            assert_eq!(source, destination);
        }
        for resolver in [&resolver_tcp4, &resolver_tcp6] {
            let destination = resolver.local_addr().unwrap();
            let mut client = in_netns(&client_ns, || tcp_connect(destination, 8));
            let (mut server, source) = accept_connection(resolver);
            assert_eq!(source, client.local_addr().unwrap());
            exchange_tcp(&mut client, &mut server, query, &answer);
        }
        for socket in [&wildcard4, &wildcard6, &listeners.udp4, &listeners.udp6] {
            socket.set_nonblocking(true).unwrap();
            assert_eq!(
                socket.recv_from(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        for socket in [
            &tcp_wildcard4,
            &tcp_wildcard6,
            &listeners.tcp4,
            &listeners.tcp6,
        ] {
            assert_eq!(
                socket.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        backend.set_datapath_ready(false).unwrap();
    });
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn dns_local_fib_and_v4_v6_carriers_reach_resolvers_without_snat() {
    run_dns_network(0, false);
}

#[test]
#[ignore = "requires root, Linux with TUN, SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, redirect_peer, veth/netkit, and isolated netns support"]
fn dns_l3_tun_v4_v6_controller_and_raw_marks_reach_redirect_peer_listeners() {
    run_dns_network(1, true);
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn dns_marked_loopback_backend_survives_lan_hook_without_exempting_other_marks() {
    for bypass_mark in [DAE_BYPASS_MARK, 0] {
        isolated(move || {
            let mut netlink = crate::netlink::NlSock::new().unwrap();
            let (lo, _) = netlink.get_link("lo").unwrap();
            netlink.set_link_up(lo, true).unwrap();
            let param = DaeParam {
                dae_socket_mark: bypass_mark,
                ..fixture_param()
            };
            let plan = compile(&[rule(
                "block-dns",
                RoutingCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                "block",
                0,
                true,
            )]);
            let mut backend = RealEbpfBackend::load_routing_test_fixture(&object(), param).unwrap();
            backend.publish_routing_plan(&plan, &[]).unwrap();
            let listeners = TproxyListeners::new();
            listeners.publish(&mut backend).unwrap();
            load_classifier(&mut backend, "lan_ingress_l2");
            aya::programs::tc::qdisc_add_clsact("lo").unwrap();
            let program: &mut SchedClassifier = backend
                .bpf_mut()
                .unwrap()
                .program_mut("lan_ingress_l2")
                .unwrap()
                .try_into()
                .unwrap();
            program.attach("lo", TcAttachType::Ingress).unwrap();
            backend
                .set_datapath_flags(honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)
                .unwrap();
            backend.set_datapath_ready(true).unwrap();

            for destination in [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
            ] {
                let server = udp_socket(destination, false);
                let tcp_server = tcp_listener(destination);
                let client = udp_socket(SocketAddr::new(destination.ip(), 0), false);
                if bypass_mark != 0 {
                    nix::sys::socket::setsockopt(
                        &client,
                        nix::sys::socket::sockopt::Mark,
                        &bypass_mark,
                    )
                    .unwrap();
                    client.send_to(b"backend-query", destination).unwrap();
                    let mut bytes = [0; 64];
                    let (size, source) = server.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], b"backend-query");
                    assert_eq!(source, client.local_addr().unwrap());
                    server.send_to(b"backend-answer", source).unwrap();
                    let (size, source) = client.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], b"backend-answer");
                    assert_eq!(source, destination);
                    let mut stream = tcp_connect_marked(destination, 0, bypass_mark);
                    let (mut accepted, source) = accept_connection(&tcp_server);
                    assert_eq!(source, stream.local_addr().unwrap());
                    for _ in 0..2 {
                        exchange_tcp(&mut stream, &mut accepted, b"query", b"reply");
                    }
                }
                server
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                for mark in [0, DAE_BYPASS_MARK | 0x200] {
                    nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::Mark, &mark)
                        .unwrap();
                    client.send_to(b"must-drop", destination).unwrap();
                    let mut bytes = [0; 64];
                    assert_eq!(
                        server.recv_from(&mut bytes).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    let domain = if destination.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    };
                    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
                    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &mark)
                        .unwrap();
                    socket
                        .connect_timeout(&destination.into(), Duration::from_millis(200))
                        .expect_err("a non-exact mark must not bypass the DNS block");
                }
                assert_eq!(
                    tcp_server.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            backend.set_datapath_ready(false).unwrap();
        });
    }
}
