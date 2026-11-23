use super::*;
use crate::{control::ControlPlane, netlink::NlSock, routing::Router};
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
    xdp::CaptureAuthority,
    xdp_gateway::{CaptureRealmKey, GatewayKey, GatewayReason},
};
use honk_xsk::{ConntrackKfuncs, GatewayLoad, GatewayMaps, GeneralCapture, Programs};
use std::os::{fd::BorrowedFd, unix::fs::MetadataExt};

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

fn run(program: BorrowedFd<'_>, ifindex: u32, frame: &[u8], action: u32) -> io::Result<()> {
    let context = [0, frame.len() as u32, 0, ifindex, 0, 0];
    let mut result = [0u32; 6];
    let mut output = vec![0; frame.len() + 256];
    let mut attr = TestRun {
        program: program.as_raw_fd() as u32,
        input_len: frame.len() as u32,
        output_len: output.len() as u32,
        input: frame.as_ptr() as u64,
        output: output.as_mut_ptr() as u64,
        repeat: 1,
        context_len: size_of::<[u32; 6]>() as u32,
        result_len: size_of::<[u32; 6]>() as u32,
        context: context.as_ptr() as u64,
        result: result.as_mut_ptr() as u64,
        ..TestRun::default()
    };
    syscall(10, &mut attr)?;
    assert_eq!(attr.action, action);
    assert_eq!(result[2], 0);
    assert_eq!(result[0], 0, "nonmetadata program added metadata");
    // TEST_RUN flattens SG output; ctx.data_end covers only the linear head.
    assert!(result[0] <= result[1] && result[1] <= attr.output_len);
    assert!(attr.output_len as usize <= output.len());
    assert_eq!(attr.output_len as usize, frame.len());
    assert_eq!(&output[..attr.output_len as usize], frame);
    Ok(())
}

fn stat(maps: &GatewayMaps, reason: GatewayReason) -> io::Result<u64> {
    // Per-CPU BPF values use eight-byte slots even on offline possible CPUs.
    let possible = std::fs::read_to_string("/sys/devices/system/cpu/possible")?;
    let cpus: usize = possible
        .trim()
        .split(',')
        .map(|range| match range.split_once('-') {
            Some((first, last)) => {
                last.parse::<usize>().unwrap() - first.parse::<usize>().unwrap() + 1
            }
            None => 1,
        })
        .sum();
    let mut values = vec![0u64; cpus];
    let key = reason as u32;
    syscall(
        1,
        &mut MapElement {
            fd: maps.stats_fd().as_raw_fd() as u32,
            reserved: 0,
            key: &key as *const u32 as u64,
            value: values.as_mut_ptr() as u64,
            flags: 0,
        },
    )?;
    Ok(values.into_iter().sum())
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|word| u32::from(word[0]) << 8 | u32::from(*word.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_checksum(frame: &mut [u8]) {
    let length = usize::from(frame[14] & 15) * 4;
    frame[24..26].fill(0);
    let sum = checksum(&frame[14..14 + length]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

fn udp(ipv6: bool, sport: u16, dport: u16) -> (GatewayKey, Vec<u8>) {
    let src = if ipv6 {
        "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    } else {
        std::net::Ipv4Addr::new(192, 0, 2, 1)
            .to_ipv6_mapped()
            .octets()
    };
    let dst = if ipv6 {
        "2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    } else {
        std::net::Ipv4Addr::new(198, 51, 100, 1)
            .to_ipv6_mapped()
            .octets()
    };
    let key = GatewayKey {
        realm_id: 1,
        family: if ipv6 { 6 } else { 4 },
        src,
        dst,
        sport: sport.to_be(),
        dport: dport.to_be(),
        proto: 17,
        reserved: [0; 3],
    };
    let transport = if ipv6 { 54 } else { 34 };
    let mut frame = vec![0; (transport + 8).max(60)];
    frame[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
    frame[transport..transport + 2].copy_from_slice(&sport.to_be_bytes());
    frame[transport + 2..transport + 4].copy_from_slice(&dport.to_be_bytes());
    frame[transport + 4..transport + 6].copy_from_slice(&8u16.to_be_bytes());
    if ipv6 {
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&8u16.to_be_bytes());
        frame[20] = 17;
        frame[21] = 64;
        frame[22..38].copy_from_slice(&src);
        frame[38..54].copy_from_slice(&dst);
        let mut pseudo = frame[22..54].to_vec();
        pseudo.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 17]);
        pseudo.extend_from_slice(&frame[54..]);
        let sum = checksum(&pseudo);
        frame[60..62].copy_from_slice(&sum.to_be_bytes());
    } else {
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&28u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&src[12..]);
        frame[30..34].copy_from_slice(&dst[12..]);
        ipv4_checksum(&mut frame);
    }
    (key, frame)
}

fn extensions(sport: u16, protocols: &[u8], lengths: &[usize]) -> (GatewayKey, Vec<u8>) {
    assert_eq!(protocols.len(), lengths.len());
    let (key, base) = udp(true, sport, 18084);
    let payload = lengths.iter().sum::<usize>() + 8;
    // Start with zeroed payload: old UDP bytes must never become fragment offset bits.
    let mut frame = vec![0; 54 + payload];
    frame[..54].copy_from_slice(&base[..54]);
    frame[18..20].copy_from_slice(&(payload as u16).to_be_bytes());
    frame[20] = protocols.first().copied().unwrap_or(17);
    let mut offset = 54;
    for (index, protocol) in protocols.iter().enumerate() {
        frame[offset] = protocols.get(index + 1).copied().unwrap_or(17);
        if *protocol == 44 {
            assert_eq!(lengths[index], 8);
            frame[offset + 3] = 1;
            frame[offset + 4..offset + 8].copy_from_slice(&105u32.to_be_bytes());
        } else {
            frame[offset + 1] = if *protocol == 51 {
                (lengths[index] / 4 - 2) as u8
            } else {
                (lengths[index] / 8 - 1) as u8
            };
        }
        offset += lengths[index];
    }
    frame[offset..].copy_from_slice(&base[54..]);
    (key, frame)
}

fn quoted_ipv6(frame: &[u8]) -> Vec<u8> {
    let (_, mut quote) = udp(true, 44000, 443);
    quote.truncate(54);
    quote[18..20].copy_from_slice(&((frame.len() - 14 + 8) as u16).to_be_bytes());
    quote[20] = 58;
    quote.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    let start = quote.len();
    quote.extend_from_slice(&frame[14..]);
    // The ICMP error quotes the reverse flow; the gateway reverses its inner tuple.
    quote[start + 8..start + 24].copy_from_slice(&frame[38..54]);
    quote[start + 24..start + 40].copy_from_slice(&frame[22..38]);
    let transport = quote.len() - 8;
    quote[transport..transport + 2].copy_from_slice(&frame[frame.len() - 6..frame.len() - 4]);
    quote[transport + 2..transport + 4].copy_from_slice(&frame[frame.len() - 8..frame.len() - 6]);
    let mut pseudo = quote[22..54].to_vec();
    pseudo.extend_from_slice(&((quote.len() - 54) as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&quote[54..]);
    let sum = checksum(&pseudo);
    quote[56..58].copy_from_slice(&sum.to_be_bytes());
    quote
}

fn tcp(ipv6: bool, sport: u16, dport: u16) -> (GatewayKey, Vec<u8>) {
    let (mut key, mut frame) = udp(ipv6, sport, dport);
    key.proto = 6;
    let transport = if ipv6 { 54 } else { 34 };
    frame.truncate(transport);
    frame.resize((transport + 20).max(60), 0);
    frame[transport..transport + 2].copy_from_slice(&sport.to_be_bytes());
    frame[transport + 2..transport + 4].copy_from_slice(&dport.to_be_bytes());
    frame[transport + 12] = 0x50;
    frame[transport + 13] = 2;
    let mut pseudo = if ipv6 {
        frame[18..20].copy_from_slice(&20u16.to_be_bytes());
        frame[20] = 6;
        let mut pseudo = frame[22..54].to_vec();
        pseudo.extend_from_slice(&[0, 0, 0, 20, 0, 0, 0, 6]);
        pseudo
    } else {
        frame[16..18].copy_from_slice(&40u16.to_be_bytes());
        frame[23] = 6;
        ipv4_checksum(&mut frame);
        let mut pseudo = frame[26..34].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo
    };
    pseudo.extend_from_slice(&frame[transport..transport + 20]);
    let sum = checksum(&pseudo);
    frame[transport + 16..transport + 18].copy_from_slice(&sum.to_be_bytes());
    (key, frame)
}

#[test]
#[ignore = "requires root in the disposable kernel VM gate and a private network namespace"]
fn kernel_gateway_full_program_adaptive_endpoint_verifies_and_preserves_packets()
-> anyhow::Result<()> {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "NOT_EXERCISED: guest root required"
    );
    assert!(std::fs::read_to_string("/proc/cmdline")?.contains("virtme."));
    assert!(std::env::var_os("HONK_CI_VM_LANE").is_some());
    let expected = std::env::var("HONK_CI_EXPECTED_KERNEL")?;
    assert!(!expected.is_empty());
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        expected
    );
    let current = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
    assert_ne!(current, std::fs::metadata("/proc/1/ns/net")?.ino());
    assert_ne!(current.to_string(), std::env::var("HONK_XDP_PARENT_NETNS")?);
    std::thread::spawn(move || -> anyhow::Result<()> {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
        assert_ne!(current, std::fs::metadata("/proc/thread-self/ns/net")?.ino());
        let mut netlink = NlSock::new()?;
        netlink.add_veth_pair("gwfull0", "gwfull1")?;
        // /sys/class/net reflects the netns sysfs was mounted in, not this unshared thread's.
        let ifindex = nix::net::if_::if_nametoindex("gwfull0")?;
        let peer = nix::net::if_::if_nametoindex("gwfull1")?;
        netlink.set_link_mtu(ifindex, 9000)?;
        netlink.set_link_mtu(peer, 9000)?;
        netlink.set_link_up(ifindex, true)?;
        netlink.set_link_up(peer, true)?;

        // Exact Router/plan used by adaptive::configuration(false, XskMode::Copy).
        // On floor 6.12 the old full honk_gw_boot exceeds 1,000,000 processed insns
        // in its quoted IPv6 EH walk, before any packet is submitted.
        let mut config = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }\n\
             dns { bind: '' }\n\
             datapath { backend: xdp\n direct: endpoint\n interface { dut2: lan } }\n\
             routing { dport(18084) -> packet-proof\n dport(18086) -> packet-proof\n fallback: direct }",
        )?;
        config.ensure_builtin_nodes();
        config.groups.push(honk_config::group::Group {
            name: "packet-proof".into(),
            nodes: vec![honk_config::config::DIRECT_NODE_ID],
            ..Default::default()
        });
        let router = Router::from_config(&config.routing)?;
        let plan = ControlPlane::compile_routing_plan(&config, &router)?;
        assert_eq!(plan.rules.len(), 2);
        assert!(plan.rules.iter().all(|rule| rule.action.outbound == 2));
        assert_eq!(plan.fallback.outbound, 0);
        let policy = GatewayPolicy::prepare(&plan, false)?;
        let conntrack = ConntrackKfuncs::read()?;
        let maps = GatewayMaps::new(
            &[(
                CaptureRealmKey {
                    physical_ifindex: ifindex,
                    ..Default::default()
                },
                1,
            )],
            &[],
        )?;
        maps.set_mode_flags(DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)?;
        let mut capture = GeneralCapture {
            authority: CaptureAuthority {
                namespace_cookie: 1,
                attachment_generation: 2,
                scope: 5,
                config_generation: 2,
                ifindex,
                reserved: 0,
            },
            bypass_mark: 0x100,
            vlan_metadata: true,
        };
        // Match the failing Endpoint's veth RX VLAN kfunc path first. This API
        // must verify both honk_gw_boot and honk_gw_data, with real CT kfuncs/FDs.
        let metadata = Programs::load_general_gateway(
            &capture,
            2,
            &[],
            GatewayLoad {
                routing: &policy.bytecode.insns,
                maps: &maps,
                conntrack: &conntrack,
                dns: None,
                arbitration: None,
            },
        )?;
        assert_ne!(metadata.discover_prog_id(), 0);
        assert_ne!(metadata.data_prog_id(), 0);
        assert_ne!(metadata.discover_prog_id(), metadata.data_prog_id());
        drop(metadata);

        // Device-bound metadata programs are load coverage; use the same full
        // policy without driver metadata for portable BPF_PROG_TEST_RUN packets.
        capture.vlan_metadata = false;
        let programs = Programs::load_general_gateway(
            &capture,
            2,
            &[],
            GatewayLoad {
                routing: &policy.bytecode.insns,
                maps: &maps,
                conntrack: &conntrack,
                dns: None,
                arbitration: None,
            },
        )?;
        for (index, program) in [programs.discover_fd(), programs.data_fd()]
            .into_iter()
            .enumerate()
        {
            let base = 45000 + index as u16 * 100;
            for ipv6 in [false, true] {
                for dport in [18084, 18086, 443] {
                    for (key, frame) in [
                        udp(ipv6, base + dport % 100, dport),
                        tcp(ipv6, base + dport % 100, dport),
                    ] {
                        run(program, ifindex, &frame, if dport == 443 { 2 } else { 1 })?;
                        assert_eq!(maps.lookup_hold(&key)?.is_some(), index == 1 && dport != 443);
                    }
                }
            }
        }
        let program = programs.data_fd();
        let (options_key, mut options) = udp(false, 46000, 18084);
        options.splice(34..34, [1u8; 40]);
        options[14] = 0x4f;
        options[16..18].copy_from_slice(&68u16.to_be_bytes());
        ipv4_checksum(&mut options);
        run(program, ifindex, &options, 1)?;
        assert!(maps.lookup_hold(&options_key)?.is_some());
        for ipv6 in [false, true] {
            let (key, mut jumbo) = udp(ipv6, 46001, 18084);
            jumbo.resize(9014, 0);
            if ipv6 {
                jumbo[18..20].copy_from_slice(&8960u16.to_be_bytes());
                jumbo[58..60].copy_from_slice(&8960u16.to_be_bytes());
                jumbo[60..62].fill(0);
                let mut pseudo = jumbo[22..54].to_vec();
                pseudo.extend_from_slice(&8960u32.to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 17]);
                pseudo.extend_from_slice(&jumbo[54..]);
                let sum = checksum(&pseudo);
                jumbo[60..62].copy_from_slice(&sum.to_be_bytes());
            } else {
                jumbo[16..18].copy_from_slice(&9000u16.to_be_bytes());
                jumbo[38..40].copy_from_slice(&8980u16.to_be_bytes());
                ipv4_checksum(&mut jumbo);
            }
            run(program, ifindex, &jumbo, 1)?;
            assert!(maps.lookup_hold(&key)?.is_some());
        }
        for (port, protocols, lengths) in [
            (46002, vec![44, 60], vec![8, 8]),
            (46003, vec![0, 43, 60, 51], vec![8, 8, 8, 16]),
            (46004, vec![60; 8], vec![32; 8]),
        ] {
            let (key, frame) = extensions(port, &protocols, &lengths);
            run(program, ifindex, &frame, 1)?;
            assert!(maps.lookup_hold(&key)?.is_some());
            if port == 46002 {
                assert_eq!(&frame[54..62], &[60, 0, 0, 1, 0, 0, 0, 105]);
                let mut later = frame[..62].to_vec();
                later[18..20].copy_from_slice(&8u16.to_be_bytes());
                later[56..58].copy_from_slice(&8u16.to_be_bytes());
                let before = stat(&maps, GatewayReason::XskFragment)?;
                run(program, ifindex, &later, 1)?;
                assert_eq!(stat(&maps, GatewayReason::XskFragment)?, before + 1);
            }
            if port == 46004 {
                let before = stat(&maps, GatewayReason::XskEndpointHold)?;
                run(program, ifindex, &quoted_ipv6(&frame), 1)?;
                assert_eq!(stat(&maps, GatewayReason::XskEndpointHold)?, before + 1);
            }
        }
        let (key, mut first) = udp(false, 46007, 18084);
        first[18..20].copy_from_slice(&107u16.to_be_bytes());
        first[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        ipv4_checksum(&mut first);
        run(program, ifindex, &first, 1)?;
        assert!(maps.lookup_hold(&key)?.is_some());
        let mut later = first;
        later[20..22].copy_from_slice(&1u16.to_be_bytes());
        later[34..42].fill(0xff);
        ipv4_checksum(&mut later);
        let before = stat(&maps, GatewayReason::XskFragment)?;
        run(program, ifindex, &later, 1)?;
        assert_eq!(stat(&maps, GatewayReason::XskFragment)?, before + 1);

        let (key, mut atomic) = extensions(46008, &[44, 60], &[8, 8]);
        atomic[57] = 0;
        atomic[58..62].copy_from_slice(&106u32.to_be_bytes());
        run(program, ifindex, &atomic, 1)?;
        assert!(maps.lookup_hold(&key)?.is_some());
        let mut later = atomic[..62].to_vec();
        later[18..20].copy_from_slice(&8u16.to_be_bytes());
        later[56..58].copy_from_slice(&8u16.to_be_bytes());
        let before = stat(&maps, GatewayReason::FragmentMiss)?;
        run(program, ifindex, &later, 1)?;
        assert_eq!(stat(&maps, GatewayReason::FragmentMiss)?, before + 1);

        assert_eq!(stat(&maps, GatewayReason::UnclassifiableHeader)?, 0);
        let before = stat(&maps, GatewayReason::UnclassifiableHeader)?;
        for (port, protocols, lengths) in [
            (46005, vec![60; 9], vec![8; 9]),
            (46006, vec![60; 2], vec![256, 8]),
        ] {
            let (key, frame) = extensions(port, &protocols, &lengths);
            run(program, ifindex, &frame, 1)?;
            assert_eq!(maps.lookup_hold(&key)?, None);
        }
        assert_eq!(stat(&maps, GatewayReason::UnclassifiableHeader)?, before + 2);
        assert_eq!(maps.lookup_errors()?, 0);
        Ok(())
    })
    .join()
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}
