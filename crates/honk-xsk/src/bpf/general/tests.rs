//! Real BPF execution proves the emitted policy and counter ABI, not driver metadata support.
use super::*;
use honk_ebpf_common::xdp::CaptureAuthority;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::MetadataExt;

fn capture() -> GeneralCapture {
    GeneralCapture {
        authority: CaptureAuthority {
            namespace_cookie: 1,
            attachment_generation: 2,
            scope: 3,
            config_generation: 4,
            ifindex: 1,
            reserved: 0,
        },
        bypass_mark: 128,
        vlan_metadata: false,
    }
}

fn require_vm() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "requires guest root");
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .contains("virtme.")
    );
    assert_ne!(
        std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
        std::fs::metadata("/proc/1/ns/net").unwrap().ino(),
        "requires the disposable guest's private network namespace"
    );
}

#[repr(C)]
#[derive(Default)]
struct TestRun {
    program: u32,
    action: u32,
    input_len: u32,
    output_len: u32,
    input: u64,
    output: u64,
    repeat: u32,
    duration: u32,
    context_len: u32,
    result_len: u32,
    context: u64,
    result: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    reserved: u32,
}

fn run(program: &OwnedFd, frame: &[u8], metadata_len: usize) -> (u32, Vec<u8>, Vec<u8>) {
    let mut input = vec![0; metadata_len];
    input.extend_from_slice(frame);
    let context = [metadata_len as u32, input.len() as u32, 0, 1, 0, 0];
    let mut result = [0u32; 6];
    let mut output = vec![0; input.len() + 256];
    let mut attr = TestRun {
        program: program.as_raw_fd() as u32,
        input_len: input.len() as u32,
        output_len: output.len() as u32,
        input: input.as_ptr() as u64,
        output: output.as_mut_ptr() as u64,
        repeat: 1,
        context_len: size_of::<[u32; 6]>() as u32,
        result_len: size_of::<[u32; 6]>() as u32,
        context: context.as_ptr() as u64,
        result: result.as_mut_ptr() as u64,
        ..TestRun::default()
    };
    bpf(10, &mut attr).unwrap();
    assert_eq!(result[2], 0);
    assert_eq!(result[1], attr.output_len);
    let metadata = output[..result[0] as usize].to_vec();
    let packet = output[result[0] as usize..result[1] as usize].to_vec();
    (attr.action, metadata, packet)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u32::from(word[0]) << 8 | u32::from(*word.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(source: SocketAddr, destination: SocketAddr, mac: [u8; 6], tags: usize) -> Vec<u8> {
    let offset = 14 + 4 * tags;
    let ipv6 = source.is_ipv6();
    assert_eq!(ipv6, destination.is_ipv6());
    let ip_len = if ipv6 { 48 } else { 28 };
    let mut bytes = vec![0; (offset + ip_len).max(60 + 4 * tags)];
    bytes[..6].copy_from_slice(&mac);
    bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    for tag in 0..tags {
        bytes[12 + 4 * tag..14 + 4 * tag].copy_from_slice(&0x8100u16.to_be_bytes());
        bytes[14 + 4 * tag..16 + 4 * tag].copy_from_slice(&(tag as u16 + 42).to_be_bytes());
    }
    bytes[offset - 2..offset]
        .copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
    let transport = offset + if ipv6 { 40 } else { 20 };
    bytes[transport..transport + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());
    bytes[transport + 4..transport + 6].copy_from_slice(&8u16.to_be_bytes());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            bytes[offset] = 0x45;
            bytes[offset + 2..offset + 4].copy_from_slice(&28u16.to_be_bytes());
            bytes[offset + 8] = 64;
            bytes[offset + 9] = 17;
            bytes[offset + 12..offset + 16].copy_from_slice(&source.octets());
            bytes[offset + 16..offset + 20].copy_from_slice(&destination.octets());
            let sum = checksum(&bytes[offset..offset + 20]);
            bytes[offset + 10..offset + 12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            bytes[offset] = 0x60;
            bytes[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
            bytes[offset + 6] = 17;
            bytes[offset + 7] = 64;
            bytes[offset + 8..offset + 24].copy_from_slice(&source.octets());
            bytes[offset + 24..offset + 40].copy_from_slice(&destination.octets());
            let mut pseudo = bytes[offset + 8..offset + 40].to_vec();
            pseudo.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 17]);
            pseudo.extend_from_slice(&bytes[transport..transport + 8]);
            let sum = checksum(&pseudo);
            bytes[transport + 6..transport + 8].copy_from_slice(&sum.to_be_bytes());
        }
        _ => unreachable!(),
    }
    bytes
}

#[test]
fn capture_rejects_missing_authority_without_loading() {
    let mut capture = capture();
    for queues in [0, 257] {
        assert!(build(&capture, &[], queues, 9, 10, true, None).is_err());
    }
    assert!(build(&capture, &[Ipv4Addr::BROADCAST; 65], 1, 9, 10, true, None).is_err());
    capture.vlan_metadata = true;
    assert!(build(&capture, &[], 1, 9, 10, true, None).is_err());
    assert!(build(&capture, &[], 1, 9, 10, true, Some(0)).is_err());
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_group_unicast_cannot_borrow_connected_socket_exemption() {
    require_vm();
    let capture = capture();
    let programs = Programs::load_general(&capture, 1, &[]).unwrap();
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind).unwrap();
        let peer = UdpSocket::bind(bind).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mark = capture.bypass_mark;
        // SAFETY: SO_MARK consumes this live u32 and does not retain its pointer.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    std::ptr::from_ref(&mark).cast(),
                    size_of::<u32>() as libc::socklen_t,
                )
            },
            0
        );
        for program in [&programs.discover, &programs.data] {
            for tags in 0..=2 {
                let unicast = packet(
                    peer.local_addr().unwrap(),
                    socket.local_addr().unwrap(),
                    [2, 0, 0, 0, 0, 1],
                    tags,
                );
                assert_eq!(run(program, &unicast, 0).0, XDP_PASS as u32);
                for mac in [[0xff; 6], [1, 0, 0x5e, 0, 0, 1]] {
                    let group = packet(
                        peer.local_addr().unwrap(),
                        socket.local_addr().unwrap(),
                        mac,
                        tags,
                    );
                    let before = programs.counters().unwrap().per_queue[0];
                    assert_eq!(run(program, &group, 0).0, XDP_DROP as u32);
                    assert_eq!(programs.counters().unwrap().per_queue[0], before + 1);
                }
            }
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_destinations_and_metadata_counter_are_distinct() {
    require_vm();
    let capture = capture();
    let broadcast = Ipv4Addr::new(192, 0, 2, 255);
    let programs = Programs::load_general(&capture, 1, &[broadcast]).unwrap();
    for program in [&programs.discover, &programs.data] {
        for (source, destination) in [
            ("0.0.0.0:68", "255.255.255.255:67"),
            ("192.0.2.1:68", "192.0.2.255:67"),
            ("192.0.2.1:5353", "224.0.0.251:5353"),
            ("192.0.2.1:1900", "239.255.255.250:1900"),
            ("[2001:db8::1]:5353", "[ff02::fb]:5353"),
        ] {
            for tags in 0..=2 {
                let frame = packet(
                    source.parse().unwrap(),
                    destination.parse().unwrap(),
                    [0xff; 6],
                    tags,
                );
                assert_eq!(run(program, &frame, 0).0, XDP_PASS as u32);
            }
        }
    }
    assert_eq!(programs.counters().unwrap().per_queue, [0]);
    assert_eq!(programs.metadata_failures().unwrap(), 0);
    let frame = packet(
        "192.0.2.1:41000".parse().unwrap(),
        "198.51.100.1:42000".parse().unwrap(),
        [0xff; 6],
        2,
    );
    for (index, prefix) in [0, METADATA_LEN].into_iter().enumerate() {
        let (action, untouched, received) = run(&programs.data, &frame, prefix);
        assert_eq!(action, XDP_DROP as u32); // No XSK exists: redirect fallback stays closed.
        assert_eq!(untouched.len(), prefix);
        assert_eq!(programs.counters().unwrap().per_queue, [index as u64 + 1]);
        assert_eq!(programs.metadata_failures().unwrap(), 0);
        let decoded = capture.decode(&[&received], &[], 0).unwrap();
        assert_eq!((decoded.l3_offset, decoded.l3_len), (22, 28));
        assert_eq!(decoded.vlan_count, 2);
        assert_eq!(
            &received[decoded.l3_offset..decoded.l3_offset + decoded.l3_len],
            &frame[22..50]
        );
        if prefix != 0 {
            assert_eq!(
                capture.decode(&[&received], &untouched, 0),
                Err(crate::DecodeError::Metadata)
            );
        }
    }
    // Device-bound VLAN programs cannot TEST_RUN. Exercise their shared selected
    // packet emitter with real helpers, without pretending to prove a driver/kfunc.
    let mut b = Builder::new();
    b.program.flags = 1 << 5;
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 8, 9, 16, 0));
    b.jump(Insn::new(JEQ32_K, 8, 0, 0, -1), Label::Pass);
    for offset in (-64..-32).step_by(4) {
        b.emit(Insn::new(ST_W, 10, 0, offset, 0));
    }
    // Newer TEST_RUN reserves xdp_frame headroom before executing the program.
    // Reach exhaustion through the real helper, not an invalid input context.
    b.emit(Insn::new(LDX_W, 0, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 1, 9, 8, 0));
    let exhaust = forward(&mut b, JNE_X, 0, 1, 0);
    let ready = forward(&mut b, JA, 0, 0, 0);
    patch(&mut b, exhaust);
    for _ in 0..(256 / METADATA_LEN) {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_K, 2, 0, 0, -(METADATA_LEN as i32)));
        b.emit(Insn::new(CALL, 0, 0, 0, 54));
    }
    patch(&mut b, ready);
    selected(
        &mut b,
        1,
        programs.counters.as_raw_fd(),
        programs.xsks.as_raw_fd(),
        true,
        true,
    );
    let mut log = vec![0; 1 << 20];
    let (metadata_program, _) =
        load_program(&b.finish().unwrap(), b"honk_meta_test", &mut log).unwrap();
    assert_eq!(
        run(&metadata_program, &frame, METADATA_LEN).0,
        XDP_DROP as u32
    );
    assert_eq!(programs.counters().unwrap().per_queue, [2]);
    assert_eq!(programs.metadata_failures().unwrap(), 1);
    let (action, metadata, _) = run(&metadata_program, &frame, 0);
    assert_eq!(action, XDP_DROP as u32);
    assert_eq!(metadata.len(), METADATA_LEN);
    assert_eq!(programs.counters().unwrap().per_queue, [3]);
    assert_eq!(programs.metadata_failures().unwrap(), 1);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_legacy_capture_keeps_rejection_counters_and_xsk_miss_closed() {
    require_vm();
    let capture = Capture {
        protocol: Protocol::Udp,
        client: "192.0.2.1:41000".parse().unwrap(),
        service: "198.51.100.1:42000".parse().unwrap(),
        own_mac: [2, 0, 0, 0, 0, 1],
        peer_mac: [2, 0, 0, 0, 0, 2],
    };
    let programs = Programs::load(&capture, 1).unwrap();
    for program in [&programs.discover, &programs.data] {
        let frame = packet(
            capture.client.into(),
            capture.service.into(),
            capture.own_mac,
            0,
        );
        let before = programs.counters().unwrap();
        assert_eq!(run(program, &frame, 0).0, XDP_DROP as u32);
        assert_eq!(
            programs.counters().unwrap().per_queue[0],
            before.per_queue[0] + 1
        );
        for (offset, value) in [(20, 0x20), (14, 0x46), (0, 3)] {
            let mut bad = frame.clone();
            bad[offset] = value;
            assert_eq!(run(program, &bad, 0).0, XDP_DROP as u32);
        }
        let after = programs.counters().unwrap();
        assert_eq!(after.fragments, before.fragments + 1);
        assert_eq!(after.options, before.options + 1);
        assert_eq!(after.malformed, before.malformed + 1);
        assert_eq!(programs.metadata_failures().unwrap(), 0);
    }
}
