use super::*;
use crate::control::sockets;
use crate::control::tests::support::{addr, bytes_of};

#[cfg(target_os = "linux")]
#[test]
fn udp_listener_enables_reuse_port_before_bind() {
    use std::os::fd::AsRawFd;

    let first = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    let mut enabled = 0i32;
    let mut enabled_len = std::mem::size_of_val(&enabled) as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            first.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&mut enabled as *mut i32).cast(),
            &mut enabled_len,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(enabled, 1);

    first
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let addr = first.local_addr().unwrap();
    let second = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    second.bind(&addr).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_receive_batch_preserves_order_metadata_and_cancellation() {
    let socket = sockets::bind_tproxy_udp_listeners(SocketAddr::from(([127, 0, 0, 1], 0)), 1)
        .unwrap()
        .pop()
        .unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)
        .unwrap();
    let local_addr = socket.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    for sequence in 0..9u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sender.send_to(&[], local_addr).await.unwrap();

    let mut batch = sockets::UdpRecvBatch::new().unwrap();
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 8);
    for index in 0..batch.len() {
        let (data, source, meta) = batch.packet(index).unwrap();
        assert_eq!(data, &[index as u8]);
        assert_eq!(source, sender_addr);
        assert_eq!(meta.original_dst_cmsg, Some(local_addr));
        assert_eq!(meta.packet_dst_ip, Some(local_addr.ip()));
        assert!(meta.packet_ifindex.is_some());
        assert_eq!(meta.local_addr, local_addr);
        assert_eq!(meta.packet_mark, None);
    }

    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch.packet(0).unwrap().0, &[8]);
    assert!(batch.packet(1).unwrap().0.is_empty());

    for sequence in 10..13u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 3);

    for sequence in 13..16u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 3);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch),
        )
        .await
        .is_err()
    );
    for sequence in 16..25u8 {
        sender.send_to(&[sequence], local_addr).await.unwrap();
    }
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.packet(0).unwrap().0, &[16]);
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();
    assert_eq!(batch.len(), 8);
    for index in 0..batch.len() {
        assert_eq!(batch.packet(index).unwrap().0, &[index as u8 + 17]);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_receive_batch_rejects_truncated_slot_without_losing_next_packet() {
    let socket = sockets::bind_tproxy_udp_listeners(SocketAddr::from(([127, 0, 0, 1], 0)), 1)
        .unwrap()
        .pop()
        .unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)
        .unwrap();
    let local_addr = socket.local_addr().unwrap();
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(&[1, 2], local_addr).await.unwrap();
    sender.send_to(&[3], local_addr).await.unwrap();

    let mut batch = sockets::UdpRecvBatch::new_for_test(1).unwrap();
    sockets::recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch)
        .await
        .unwrap();

    assert_eq!(batch.len(), 2);
    assert_eq!(
        batch.packet(0).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(batch.packet(1).unwrap().0, &[3]);
}
/// Test storage has the same `cmsghdr` alignment required by `recvmsg`.
#[repr(C)]
struct AlignedTestCmsgStorage {
    _alignment: [libc::cmsghdr; 0],
    bytes: [u8; 256],
}

impl AlignedTestCmsgStorage {
    fn new() -> Self {
        // SAFETY: all-zero bytes are a valid initial representation for this
        // test-only raw control-message storage.
        unsafe { std::mem::zeroed() }
    }
}

fn cmsg_len(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_LEN as the platform ABI macro wrapper.
    unsafe { libc::CMSG_LEN(data_len as _) as usize }
}

fn cmsg_space(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_SPACE as the platform ABI macro wrapper.
    unsafe { libc::CMSG_SPACE(data_len as _) as usize }
}

fn append_cmsg(
    storage: &mut AlignedTestCmsgStorage,
    used: &mut usize,
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: &[u8],
) {
    let space = cmsg_space(data.len());
    assert!(*used + space <= storage.bytes.len());
    // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
    let mut header: libc::cmsghdr = unsafe { std::mem::zeroed::<libc::cmsghdr>() };
    header.cmsg_len = cmsg_len(data.len()) as _;
    header.cmsg_level = cmsg_level;
    header.cmsg_type = cmsg_type;
    // SAFETY: `AlignedTestCmsgStorage` is explicitly cmsghdr-aligned, the
    // checked range fits storage, and the header is initialized before use.
    unsafe {
        let ptr = storage
            .bytes
            .as_mut_ptr()
            .add(*used)
            .cast::<libc::cmsghdr>();
        assert_eq!(
            ptr as usize % std::mem::align_of::<libc::cmsghdr>(),
            0,
            "test cmsg header must be naturally aligned"
        );
        std::ptr::write(ptr, header);
    }
    let data_start = *used + cmsg_len(0);
    storage.bytes[data_start..data_start + data.len()].copy_from_slice(data);
    *used += space;
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv4_multi_cmsg() {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = 4444u16.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(203, 0, 113, 10)).to_be(),
    };
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let packet_mark = 0x1234_5678u32;
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::SOL_SOCKET,
        libc::SO_MARK,
        bytes_of(&packet_mark),
    );

    let metadata = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap();
    assert_eq!(metadata.original_dst_cmsg, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        metadata.packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(metadata.packet_ifindex, Some(0));
    assert_eq!(metadata.packet_mark, Some(packet_mark));
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv6_multi_cmsg() {
    let expected_original: std::net::Ipv6Addr = "2001:db8::4444".parse().unwrap();
    let expected_packet: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let mut original: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    original.sin6_family = libc::AF_INET6 as _;
    original.sin6_port = 4444u16.to_be();
    original.sin6_addr = libc::in6_addr {
        s6_addr: expected_original.octets(),
    };
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_packet.octets(),
        },
        ipi6_ifindex: 7,
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_PKTINFO,
        bytes_of(&pktinfo),
    );

    let metadata = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap();
    assert_eq!(
        metadata.original_dst_cmsg,
        Some(addr("[2001:db8::4444]:4444"))
    );
    assert_eq!(
        metadata.packet_dst_ip,
        Some(std::net::IpAddr::V6(expected_packet))
    );
    assert_eq!(metadata.packet_ifindex, Some(7));
    assert_eq!(metadata.packet_mark, None);
}

#[test]
fn udp_original_dst_cmsg_parser_uses_only_returned_control_length() {
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let returned_control_len = used;
    // Bytes beyond msg_controllen are not kernel-returned control data; make
    // them malformed to prove they cannot influence the parser.
    unsafe {
        // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
        let mut malformed_header: libc::cmsghdr = std::mem::zeroed::<libc::cmsghdr>();
        malformed_header.cmsg_len = 0;
        malformed_header.cmsg_level = libc::IPPROTO_IP;
        malformed_header.cmsg_type = libc::IP_PKTINFO;
        std::ptr::write(
            storage.bytes.as_mut_ptr().add(used).cast::<libc::cmsghdr>(),
            malformed_header,
        );
    }
    let malformed_len = used + cmsg_len(0);

    let metadata =
        parse_cmsg_control(&storage.bytes[..returned_control_len], 0, addr("0.0.0.0:0")).unwrap();
    assert_eq!(
        metadata.packet_dst_ip,
        Some("198.51.100.53".parse().unwrap())
    );
    let error =
        parse_cmsg_control(&storage.bytes[..malformed_len], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_fails_closed_on_truncation_or_ctrunc() {
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &[0; 1],
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let error = parse_cmsg_control(&storage.bytes[..used], libc::MSG_CTRUNC, addr("0.0.0.0:0"))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

fn ipv4_origdst(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = port.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
    };
    original
}

fn ipv4_pktinfo(ip: [u8; 4]) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
        },
    }
}

#[test]
fn udp_original_dst_cmsg_parser_requires_exact_recognized_payload_length() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut oversized = bytes_of(&original).to_vec();
    oversized.push(0xab);

    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &oversized,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut oversized_pkt = bytes_of(&pktinfo).to_vec();
    oversized_pkt.extend_from_slice(&[0xde, 0xad]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &oversized_pkt,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_rejects_duplicate_recognized_records() {
    // Equal ORIGDST values are still ambiguous provenance.
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Conflicting ORIGDST values fail closed.
    let other = ipv4_origdst([198, 51, 100, 10], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&other),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Unspecified followed by a valid ORIGDST is still a duplicate.
    let unspecified = ipv4_origdst([0, 0, 0, 0], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&unspecified),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Duplicate PKTINFO (equal values) is also rejected.
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_packet_mark_cmsg_requires_one_native_u32() {
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::SOL_SOCKET,
        libc::SO_MARK,
        &[1, 2, 3],
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::SOL_SOCKET,
        libc::SO_MARK,
        &[1, 2, 3, 4, 5],
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let packet_mark = 0x1234_5678u32;
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    for _ in 0..2 {
        append_cmsg(
            &mut storage,
            &mut used,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            bytes_of(&packet_mark),
        );
    }
    let error = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_skips_unknown_cmsg_with_padding() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    // Unknown record with a non-aligned-looking payload still consumes CMSG_SPACE.
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7fff, // not a recognized ORIGDST/PKTINFO type
        &[0x11, 0x22, 0x33],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7ffe,
        &[0xaa, 0xbb],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );

    let metadata = parse_cmsg_control(&storage.bytes[..used], 0, addr("0.0.0.0:0")).unwrap();
    assert_eq!(metadata.original_dst_cmsg, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        metadata.packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(metadata.packet_ifindex, Some(0));
    assert_eq!(metadata.packet_mark, None);
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
#[test]
#[ignore = "requires an isolated root network namespace; run via just test-netns"]
fn netns_transparent_udp_batches_preserve_queued_packet_marks() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
        let mut netlink = crate::netlink::NlSock::new()?;
        let (loopback, _) = netlink.get_link("lo")?;
        netlink.set_link_up(loopback, true)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                for address in [
                    SocketAddr::from(([127, 0, 0, 1], 0)),
                    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
                ] {
                    let receiver = build_tproxy_udp(address, false, true)?;
                    let local = receiver.local_addr()?;
                    let sender = std::net::UdpSocket::bind(address)?;
                    let source = sender.local_addr()?;
                    let marks = [
                        UdpDnsRoute::new(OutboundIndex::UserBase as u8, 1)
                            .unwrap()
                            .to_mark(),
                        UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, 1)
                            .unwrap()
                            .to_mark(),
                        0,
                    ];
                    let mut batch = UdpRecvBatch::new()?;
                    for (first, count) in [(0u8, 10u8), (10, 3)] {
                        for sequence in first..first + count {
                            set_so_mark(&sender, marks[usize::from(sequence) % marks.len()])?;
                            sender.send_to(&[sequence], local)?;
                        }
                        let mut received = 0;
                        while received < count {
                            tokio::time::timeout(
                                Duration::from_secs(2),
                                recv_batch_from_with_orig_dst(&receiver, local, &mut batch),
                            )
                            .await??;
                            for index in 0..batch.len() {
                                let (data, peer, metadata) =
                                    batch.packet(index).expect("valid marked datagram");
                                let sequence = first + received;
                                assert_eq!(data, &[sequence]);
                                assert_eq!(peer, source);
                                assert_eq!(metadata.original_dst_cmsg, Some(local));
                                assert_eq!(metadata.packet_dst_ip, Some(local.ip()));
                                assert_eq!(
                                    metadata.packet_mark,
                                    Some(marks[usize::from(sequence) % marks.len()])
                                );
                                received += 1;
                            }
                        }
                    }
                }
                Ok(())
            })
    })
    .join()
    .expect("UDP mark namespace thread")
}

#[test]
fn reply_send_errors_about_the_destination_keep_the_socket() {
    for code in [libc::EHOSTUNREACH, libc::ECONNREFUSED, libc::EMSGSIZE] {
        assert!(send_error_is_destination_specific(
            &io::Error::from_raw_os_error(code)
        ));
    }
    for code in [libc::EBADF, libc::ENOTSOCK, libc::EIO] {
        assert!(!send_error_is_destination_specific(
            &io::Error::from_raw_os_error(code)
        ));
    }
    assert!(!send_error_is_destination_specific(&io::Error::other(
        "no os code"
    )));
}
