use super::*;

#[test]
fn batch_lock_flag_matches_kernel_abi() {
    assert_eq!(BPF_F_LOCK, 4);
}

#[test]
fn batch_errors_never_return_partial_or_fallback_success() {
    for elem_flags in [0, BPF_F_LOCK] {
        for errno in [
            libc::EINVAL,
            libc::ENOSYS,
            libc::EOPNOTSUPP,
            libc::EFAULT,
            libc::EPERM,
            libc::EIO,
            libc::ENOSPC,
        ] {
            for after_progress in [false, true] {
                let error = batch_error(
                    BatchError::Errno {
                        errno,
                        after_progress,
                    },
                    elem_flags,
                );
                if matches!(errno, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) {
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                } else {
                    assert_eq!(error.raw_os_error(), Some(errno));
                }
            }
        }
    }
    let error = batch_error(
        BatchError::InvalidCount {
            count: BPF_BATCH_CHUNK + 1,
            terminal: false,
        },
        BPF_F_LOCK,
    );
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn flow_wrapper_layouts_reject_old_payload_only_maps() {
    for (name, key_size, payload_size, wrapper_size, expected_size, offset) in [
        (
            "CONN_STATE_MAP",
            std::mem::size_of::<TuplesKey>(),
            std::mem::size_of::<ConnState>(),
            std::mem::size_of::<FlowMapValue<ConnState>>(),
            80,
            std::mem::offset_of!(FlowMapValue<ConnState>, value),
        ),
        (
            "REDIRECT_TRACK",
            std::mem::size_of::<RedirectTuple>(),
            std::mem::size_of::<RedirectEntry>(),
            std::mem::size_of::<FlowMapValue<RedirectEntry>>(),
            48,
            std::mem::offset_of!(FlowMapValue<RedirectEntry>, value),
        ),
        (
            "ROUTING_HANDOFF_MAP",
            std::mem::size_of::<TuplesKey>(),
            std::mem::size_of::<RoutingHandoffEntry>(),
            std::mem::size_of::<FlowMapValue<RoutingHandoffEntry>>(),
            80,
            std::mem::offset_of!(FlowMapValue<RoutingHandoffEntry>, value),
        ),
    ] {
        assert_eq!(offset, 8);
        assert_eq!(wrapper_size, payload_size + 8);
        assert_eq!(wrapper_size, expected_size);
        let info = [1, 0, key_size as u32, wrapper_size as u32, 0, 0];
        check_map_layout(name, info, 1, key_size as u32, wrapper_size as u32).unwrap();
        for (field, value) in [(0, 2), (2, key_size as u32 + 1), (3, payload_size as u32)] {
            let mut old = info;
            old[field] = value;
            assert!(check_map_layout(name, old, 1, key_size as u32, wrapper_size as u32).is_err());
        }
    }
}

#[test]
fn flow_payload_decodes_fixed_wire_offsets_without_lock_header() {
    let mut aligned = [0u64; 11];
    let bytes = unsafe { std::slice::from_raw_parts_mut(aligned.as_mut_ptr() as *mut u8, 88) };
    let bytes = &mut bytes[1..81];
    bytes[..8].fill(0xa5);
    bytes[9] = 6;
    bytes[10..12].copy_from_slice(&1u16.to_ne_bytes());
    bytes[12..16].copy_from_slice(&42u32.to_ne_bytes());
    bytes[16..24].copy_from_slice(&456u64.to_ne_bytes());
    bytes[60..64].copy_from_slice(&123u32.to_ne_bytes());
    bytes[64..72].copy_from_slice(&789u64.to_ne_bytes());
    bytes[72..76].copy_from_slice(&u32::MAX.to_ne_bytes());
    bytes[76..80].copy_from_slice(&2u32.to_ne_bytes());
    let conn: ConnState = flow_payload(bytes);
    assert_eq!(conn.state, 6);
    assert_eq!(conn.decision_token, 42);
    assert_eq!(conn.last_seen_ns, 456);
    assert_eq!(conn.trace_id, 123);
    assert_eq!(conn.incarnation, 789);
    assert_eq!(conn.tcp_syn_flags, 1);
    assert_eq!(conn.tcp_syn_isn, u32::MAX);
    assert_eq!(conn.reserved, 2);

    bytes[8..].fill(0);
    bytes[8..16].copy_from_slice(&321u64.to_ne_bytes());
    bytes[28] = 1;
    bytes[29] = 7;
    bytes[32..36].copy_from_slice(&12u32.to_ne_bytes());
    bytes[36..40].copy_from_slice(&43u32.to_ne_bytes());
    bytes[40..48].copy_from_slice(&790u64.to_ne_bytes());
    let redirect: RedirectEntry = flow_payload(&bytes[..48]);
    assert_eq!(redirect.last_seen_ns, 321);
    assert_eq!(redirect.from_wan, 1);
    assert_eq!(redirect.outbound, 7);
    assert_eq!(redirect.ifindex, 12);
    assert_eq!(redirect.decision_token, 43);
    assert_eq!(redirect.incarnation, 790);

    bytes[8..].fill(0);
    bytes[8..16].copy_from_slice(&654u64.to_ne_bytes());
    bytes[56..64].copy_from_slice(&44u64.to_ne_bytes());
    bytes[64..68].copy_from_slice(&124u32.to_ne_bytes());
    bytes[72..80].copy_from_slice(&791u64.to_ne_bytes());
    let handoff: RoutingHandoffEntry = flow_payload(bytes);
    assert_eq!(handoff.last_seen_ns, 654);
    assert_eq!(handoff.routing_generation, 44);
    assert_eq!(handoff.trace_id, 124);
    assert_eq!(handoff.incarnation, 791);
}

#[test]
fn ordinary_stats_print_all_canonical_keys_and_zero_missing_counters() {
    let mut reads = 0;
    let mut output = Vec::new();
    print_ordinary_stats_with(
        stats_cardinality_info(BpfStatsKey::COUNT),
        |key| {
            let index = u32::from_ne_bytes(key.try_into().unwrap());
            assert_eq!(index, reads);
            reads += 1;
            Ok((index != 4).then_some(u64::from(index) + 10))
        },
        &mut output,
    )
    .unwrap();
    assert_eq!(reads, BpfStatsKey::COUNT);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "udp_conn_overflow: 10\n",
            "tcp_conn_overflow: 11\n",
            "redirect_track_insert_failure: 12\n",
            "routing_handoff_insert_failure: 13\n",
            "socket_identity_capture_failure: 0\n",
            "tcp_child_proof_storage_failure: 15\n",
            "tcp_publisher_claim_failure: 16\n",
            "new_flow_rate_limited: 17\n",
            "udp_reverse_learning_suspended: 18\n",
        )
    );
}

fn stats_cardinality_info(max_entries: u32) -> [u32; 6] {
    let mut info = [0; 6];
    info[4] = max_entries;
    info
}

#[test]
fn ordinary_stats_refuse_other_cardinality_before_any_read() {
    for found in [BpfStatsKey::COUNT - 1, BpfStatsKey::COUNT + 1] {
        let mut reads = 0;
        let mut output = Vec::new();
        print_ordinary_stats_with(
            stats_cardinality_info(found),
            |_| {
                reads += 1;
                Ok(Some(1))
            },
            &mut output,
        )
        .expect_err("mismatched statistics map was accepted");
        assert_eq!(reads, 0);
        assert!(output.is_empty());
    }
}

struct SysfsFixture(tempfile::TempDir);

impl SysfsFixture {
    fn new(possible: Option<&str>, present: &[u32]) -> Self {
        let fixture = Self(tempfile::tempdir().unwrap());
        if let Some(possible) = possible {
            std::fs::write(fixture.root().join("possible"), possible).unwrap();
        }
        for cpu in present {
            std::fs::create_dir(fixture.root().join(format!("cpu{cpu}"))).unwrap();
        }
        fixture
    }

    fn root(&self) -> &Path {
        self.0.path()
    }
}

fn stats_metadata_fixture(name: &str) -> [u32; 6] {
    let mut info = [0; 6];
    info[0] = 6;
    info[2] = 4;
    info[3] = match name {
        "CONN_STATE_OCCUPANCY" => 8,
        "OUTBOUND_STATS" => 32,
        _ => panic!("unexpected statistics map {name}"),
    };
    info
}

fn open_stats_fixture(name: &str) -> anyhow::Result<(OwnedFd, [u32; 6])> {
    Ok((
        std::fs::File::open("/dev/null")?.into(),
        stats_metadata_fixture(name),
    ))
}

fn prepared(root: &Path) -> PerCpuStats {
    prepare_percpu_stats(root, || Ok(()), open_stats_fixture).unwrap()
}

fn assert_source_error(fixture: &SysfsFixture) {
    let mut opened = 0;
    let result = prepare_percpu_stats(
        fixture.root(),
        || Ok(()),
        |name| {
            opened += 1;
            open_stats_fixture(name)
        },
    );
    let error = result.err().expect("invalid CPU source was accepted");
    assert!(
        error
            .to_string()
            .contains(&fixture.root().join("possible").display().to_string())
    );
    assert_eq!(opened, 0, "CPU source failure must precede map opening");
}

#[test]
fn prepare_percpu_stats_uses_possible_population_not_present_directories() {
    let fixture = SysfsFixture::new(Some("0-63\n"), &(0..32).collect::<Vec<_>>());
    let stats = prepared(fixture.root());
    assert_eq!((stats.occupancy.len(), stats.outbound.len()), (512, 2048));
}

#[test]
fn prepare_percpu_stats_counts_sparse_possible_members() {
    for (mask, present, lengths) in [
        ("0,2-3\n", &[0, 2, 3][..], (24, 96)),
        ("0,2-3,8\n", &[0, 2, 3, 8][..], (32, 128)),
        ("7\n", &[7][..], (8, 32)),
    ] {
        let fixture = SysfsFixture::new(Some(mask), present);
        let stats = prepared(fixture.root());
        assert_eq!(
            (stats.occupancy.len(), stats.outbound.len()),
            lengths,
            "{mask}"
        );
    }
}

#[test]
fn prepare_percpu_stats_rejects_missing_or_unreadable_possible_before_opening() {
    for possible_is_directory in [false, true] {
        let fixture = SysfsFixture::new(None, &[0, 1, 2]);
        if possible_is_directory {
            std::fs::create_dir(fixture.root().join("possible")).unwrap();
        }
        assert_source_error(&fixture);
    }
}

#[test]
fn prepare_percpu_stats_rejects_noncanonical_possible_lists() {
    for input in [
        "", ",", "0,", ",0", "x", "+1", "01", "-1", "2-1", "0,0", "0-2,2-3", "1,0", "0-1-2",
    ] {
        let fixture = SysfsFixture::new(Some(input), &[0]);
        assert_source_error(&fixture);
    }
}

#[test]
fn checked_possible_parser_and_percpu_size_reject_overflow_without_allocating() {
    let half = usize::MAX / 2;
    for input in [
        format!("{}0", usize::MAX),
        format!("0-{}", usize::MAX),
        format!("0-{half},{}-{}", half + 1, usize::MAX),
    ] {
        assert!(parse_possible_cpus(&input).is_err(), "{input}");
    }
    assert_eq!(percpu_buffer_len(1, 9).unwrap(), 16);
    for (count, value_size) in [
        ((usize::MAX / 8) + 1, 8),
        (1, usize::MAX),
        ((isize::MAX as usize / 8) + 1, 8),
    ] {
        assert!(
            percpu_buffer_len(count, value_size).is_err(),
            "{count} x {value_size}"
        );
    }
}

#[test]
fn prepare_percpu_stats_rejects_each_percpu_map_layout_field() {
    let fixture = SysfsFixture::new(Some("0\n"), &[0]);
    for map in ["CONN_STATE_OCCUPANCY", "OUTBOUND_STATS"] {
        for (field, value) in [(0, 1), (2, 8), (3, 16)] {
            let expected = stats_metadata_fixture(map);
            let mut actual = expected;
            actual[field] = value;
            let result = prepare_percpu_stats(
                fixture.root(),
                || Ok(()),
                |name| {
                    let (fd, info) = open_stats_fixture(name)?;
                    Ok((fd, if name == map { actual } else { info }))
                },
            );
            let error = result
                .err()
                .expect("invalid per-CPU layout was accepted")
                .to_string();
            assert!(error.contains(map), "{error}");
            for (label, info) in [("expected", expected), ("actual", actual)] {
                assert!(
                    error.contains(&format!(
                        "{label} type={} key={} value={}",
                        info[0], info[2], info[3]
                    )),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn prepare_percpu_stats_propagates_metadata_query_errors_for_each_map() {
    let fixture = SysfsFixture::new(Some("0\n"), &[0]);
    for failed_map in ["CONN_STATE_OCCUPANCY", "OUTBOUND_STATS"] {
        let result = prepare_percpu_stats(
            fixture.root(),
            || Ok(()),
            |name| {
                anyhow::ensure!(name != failed_map, "synthetic metadata query failure");
                open_stats_fixture(name)
            },
        );
        let error = result.err().expect("metadata query failure was ignored");
        let text = format!("{error:#}");
        assert!(text.contains(failed_map), "{text}");
        assert!(text.contains("synthetic metadata query failure"), "{text}");
    }
}

fn encode(counters: OutboundStatsCounters) -> Vec<u8> {
    [
        counters.tx_packets.to_ne_bytes(),
        counters.tx_bytes.to_ne_bytes(),
        counters.rx_packets.to_ne_bytes(),
        counters.rx_bytes.to_ne_bytes(),
    ]
    .concat()
}

#[test]
fn sums_packed_outbound_counters_across_cpus() {
    let mut values = encode(OutboundStatsCounters {
        tx_packets: 1,
        tx_bytes: 20,
        rx_packets: 3,
        rx_bytes: 40,
    });
    values.extend(encode(OutboundStatsCounters {
        tx_packets: 5,
        tx_bytes: 60,
        rx_packets: 7,
        rx_bytes: 80,
    }));

    let total = sum_percpu_outbound(&values);
    assert_eq!(total.tx_packets, 6);
    assert_eq!(total.tx_bytes, 80);
    assert_eq!(total.rx_packets, 10);
    assert_eq!(total.rx_bytes, 120);
}

fn tuple_wire(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, l4proto: u8) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0..16].copy_from_slice(&lookup::encode_ip_key(src));
    out[16..32].copy_from_slice(&lookup::encode_ip_key(dst));
    out[32..34].copy_from_slice(&sport.to_ne_bytes());
    out[34..36].copy_from_slice(&dport.to_ne_bytes());
    out[36] = l4proto;
    out
}

#[allow(clippy::too_many_arguments)]
fn conn_wire(
    wan_ingress: u8,
    state: u8,
    syn_flags: u16,
    token: u32,
    meta_flags: u64,
    outbound: u8,
    mark: u32,
    must: u8,
    dscp: u8,
    pname: &[u8],
    pid: u32,
    trace_id: u32,
    incarnation: u64,
) -> [u8; 80] {
    let mut wire = [0u8; 80];
    wire[0..8].fill(0xa5);
    let p = &mut wire[8..80];
    p[0] = wan_ingress;
    p[1] = state;
    p[2..4].copy_from_slice(&syn_flags.to_ne_bytes());
    p[4..8].copy_from_slice(&token.to_ne_bytes());
    p[8..16].copy_from_slice(&9000u64.to_ne_bytes());
    let mut meta_bytes = meta_flags.to_ne_bytes();
    meta_bytes[0] = outbound;
    meta_bytes[1..5].copy_from_slice(&mark.to_ne_bytes());
    meta_bytes[5] = must;
    meta_bytes[6] = dscp;
    p[16..24].copy_from_slice(&meta_bytes);
    let copy_len = pname.len().min(16);
    p[32..32 + copy_len].copy_from_slice(&pname[..copy_len]);
    p[48..52].copy_from_slice(&pid.to_ne_bytes());
    p[52..56].copy_from_slice(&trace_id.to_ne_bytes());
    p[56..64].copy_from_slice(&incarnation.to_ne_bytes());
    wire
}

fn redirect_wire(
    from_wan: u8,
    outbound: u8,
    ifindex: u32,
    token: u32,
    incarnation: u64,
) -> [u8; 48] {
    let mut wire = [0u8; 48];
    wire[0..8].fill(0x5a);
    let p = &mut wire[8..48];
    p[0..8].copy_from_slice(&9100u64.to_ne_bytes());
    p[20] = from_wan;
    p[21] = outbound;
    p[24..28].copy_from_slice(&ifindex.to_ne_bytes());
    p[28..32].copy_from_slice(&token.to_ne_bytes());
    p[32..40].copy_from_slice(&incarnation.to_ne_bytes());
    wire
}

#[allow(clippy::too_many_arguments)]
fn handoff_wire(
    outbound: u8,
    mark: u32,
    must: u8,
    dscp: u8,
    pname: &[u8],
    pid: u32,
    token: u32,
    generation: u64,
    trace_id: u32,
    incarnation: u64,
) -> [u8; 80] {
    let mut wire = [0u8; 80];
    wire[0..8].fill(0x3c);
    let p = &mut wire[8..80];
    p[0..8].copy_from_slice(&9200u64.to_ne_bytes());
    p[8..12].copy_from_slice(&mark.to_ne_bytes());
    p[12] = must;
    p[19] = outbound;
    let copy_len = pname.len().min(16);
    p[20..20 + copy_len].copy_from_slice(&pname[..copy_len]);
    p[36..40].copy_from_slice(&pid.to_ne_bytes());
    p[40] = dscp;
    p[44..48].copy_from_slice(&token.to_ne_bytes());
    p[48..56].copy_from_slice(&generation.to_ne_bytes());
    p[56..60].copy_from_slice(&trace_id.to_ne_bytes());
    p[64..72].copy_from_slice(&incarnation.to_ne_bytes());
    wire
}

fn domain_bitmap_wire(bits: &[u32]) -> [u8; 32] {
    let mut words = [0u32; 8];
    for &b in bits {
        words[(b / 32) as usize] |= 1u32 << (b % 32);
    }
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    out
}

#[test]
fn correlates_native_direct_offload_and_multiword_domain_predicates_ignoring_lock_bytes() {
    use honk_ebpf_common::{ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED};

    let src: IpAddr = "192.168.1.10".parse().unwrap();
    let dst: IpAddr = "172.217.75.94".parse().unwrap();
    let key = tuple_wire(src, 51234, dst, 443, libc::IPPROTO_TCP as u8);
    let conn = conn_wire(
        0,
        0,
        0,
        0,
        ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD,
        0,
        0x200,
        0,
        0,
        b"curl\0trailing",
        4242,
        0,
        11,
    );
    let domain_entries = [(
        lookup::encode_ip_key(dst),
        domain_bitmap_wire(&[0, 65, 255]),
    )];
    let descriptor = RoutingPolicyDescriptor {
        slot: 1,
        features: 3,
        generation: 19,
        domain_map_id: 77,
        trace_policy: 0,
    };

    let filter = lookup::FlowFilter {
        ip: Some(dst),
        ..Default::default()
    };
    let report = lookup::correlate_wire_records(
        &filter,
        lookup::DomainSnapshot::Published {
            descriptor,
            entries: &domain_entries,
        },
        &[(key, conn)],
        &[],
        &[],
    );

    assert!(report.policy_published);
    assert_eq!(report.policy_generation, Some(19));
    assert_eq!(
        report.domain_lookups,
        vec![lookup::DomainIpCorrelation {
            ip: dst,
            state: lookup::DomainEntryState::Matched(vec![0, 65, 255]),
        }]
    );
    assert_eq!(report.flows.len(), 1);
    let flow = &report.flows[0];
    assert_eq!(flow.disposition, "native_direct_offload");
    assert!(flow.anomalies.is_empty());
    assert_eq!(flow.conn_state.as_ref().unwrap().pname, "curl");
    assert_eq!(flow.conn_state.as_ref().unwrap().mark, 0x200);

    let json = lookup::render_json(&report);
    assert!(
        json.contains(r#""disposition":"native_direct_offload""#),
        "{json}"
    );
    assert!(json.contains(r#""predicates":[0,65,255]"#), "{json}");
}

#[test]
fn distinguishes_known_zero_absent_and_unpublished_domain_states_and_sip_dst_lookup() {
    use honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED;
    use honk_ebpf_common::conn::TCP_SYN_ORIGINAL_INTERCEPT;

    let sip: IpAddr = "192.168.1.10".parse().unwrap();
    let dst_zero: IpAddr = "172.217.75.94".parse().unwrap();
    let dst_absent: IpAddr = "2001:db8::9".parse().unwrap();

    let key1 = tuple_wire(sip, 50001, dst_zero, 443, libc::IPPROTO_TCP as u8);
    let key2 = tuple_wire(sip, 50002, dst_absent, 443, libc::IPPROTO_TCP as u8);
    let conn1 = conn_wire(
        0,
        0,
        TCP_SYN_ORIGINAL_INTERCEPT,
        0,
        ROUTING_META_FLAG_PUBLISHED,
        2,
        0,
        0,
        0,
        b"",
        0,
        7,
        55,
    );
    let redir1 = redirect_wire(0, 2, 4, 0, 55);
    let handoff1 = handoff_wire(2, 0, 0, 0, b"", 0, 0, 12, 7, 55);

    let domain_entries = [(lookup::encode_ip_key(dst_zero), [0u8; 32])];
    let descriptor = RoutingPolicyDescriptor {
        slot: 0,
        features: 1,
        generation: 12,
        domain_map_id: 9,
        trace_policy: 0,
    };

    let report = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            sip: Some(sip),
            ..Default::default()
        },
        lookup::DomainSnapshot::Published {
            descriptor,
            entries: &domain_entries,
        },
        &[(key1, conn1), (key2, conn1)],
        &[(key1, redir1), (key2, redir1)],
        &[(key1, handoff1), (key2, handoff1)],
    );
    assert_eq!(report.flows.len(), 2);
    assert_eq!(report.flows[0].disposition, "userspace_proxy");
    assert!(report.flows[0].anomalies.is_empty());
    assert_eq!(
        report.domain_lookups,
        vec![
            lookup::DomainIpCorrelation {
                ip: dst_zero,
                state: lookup::DomainEntryState::KnownZero,
            },
            lookup::DomainIpCorrelation {
                ip: dst_absent,
                state: lookup::DomainEntryState::Absent,
            },
        ]
    );

    let unpublished = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dst_zero),
            ..Default::default()
        },
        lookup::DomainSnapshot::Unpublished,
        &[(key1, conn1)],
        &[(key1, redir1)],
        &[(key1, handoff1)],
    );
    assert!(!unpublished.policy_published);
    assert_eq!(
        unpublished.domain_lookups[0].state,
        lookup::DomainEntryState::Unpublished
    );
    assert_eq!(unpublished.flows[0].disposition, "userspace_proxy");

    let empty_flows = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dst_zero),
            dport: Some(8443),
            ..Default::default()
        },
        lookup::DomainSnapshot::Published {
            descriptor,
            entries: &domain_entries,
        },
        &[(key1, conn1)],
        &[],
        &[],
    );
    assert!(empty_flows.flows.is_empty());
    assert_eq!(
        empty_flows.domain_lookups[0].state,
        lookup::DomainEntryState::KnownZero
    );
    assert!(lookup::render_json(&empty_flows).contains(r#""disposition":"no_flow_state""#));
}

#[test]
fn detects_nfqueue_pending_token_mismatch_and_tcp_intercept_anomalies() {
    use honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED;
    use honk_ebpf_common::conn::{TCP_SYN_ORIGINAL_INTERCEPT, UdpDecisionState};

    let sip: IpAddr = "10.0.0.2".parse().unwrap();
    let dip: IpAddr = "1.1.1.1".parse().unwrap();
    let udp_key = tuple_wire(sip, 53001, dip, 443, libc::IPPROTO_UDP as u8);
    let token = 0x1000_002a;
    let udp_conn = conn_wire(
        0,
        UdpDecisionState::Pending as u8,
        0,
        token,
        ROUTING_META_FLAG_PUBLISHED,
        0xfd,
        0,
        0,
        0,
        b"",
        0,
        3,
        99,
    );
    let udp_redir = redirect_wire(0, 0xfd, 2, token, 99);
    let udp_handoff_ok = handoff_wire(0xfd, 0, 0, 0, b"", 0, token, 5, 3, 99);

    let ok_report = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dip),
            ..Default::default()
        },
        lookup::DomainSnapshot::Unpublished,
        &[(udp_key, udp_conn)],
        &[(udp_key, udp_redir)],
        &[(udp_key, udp_handoff_ok)],
    );
    assert_eq!(ok_report.flows[0].disposition, "nfqueue_pending");
    assert!(ok_report.flows[0].anomalies.is_empty());

    let bad_handoff = handoff_wire(0xfd, 0, 0, 0, b"", 0, token + 1, 5, 3, 99);
    let bad_udp = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dip),
            ..Default::default()
        },
        lookup::DomainSnapshot::Unpublished,
        &[(udp_key, udp_conn)],
        &[],
        &[(udp_key, bad_handoff)],
    );
    assert_eq!(
        bad_udp.flows[0].anomalies,
        vec!["token_mismatch", "missing_redirect_track"]
    );

    let tcp_key = tuple_wire(sip, 53002, dip, 443, libc::IPPROTO_TCP as u8);
    let tcp_conn = conn_wire(
        0,
        0,
        TCP_SYN_ORIGINAL_INTERCEPT,
        0,
        ROUTING_META_FLAG_PUBLISHED,
        0xfd,
        0,
        0,
        0,
        b"",
        0,
        4,
        8,
    );
    let stale_redir = redirect_wire(0, 0xfd, 2, 0, 7);
    let bad_tcp = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dip),
            proto: Some(lookup::BpfProto::Tcp),
            ..Default::default()
        },
        lookup::DomainSnapshot::Unpublished,
        &[(tcp_key, tcp_conn)],
        &[(tcp_key, stale_redir)],
        &[],
    );
    assert_eq!(
        bad_tcp.flows[0].disposition,
        "userspace_control_plane_routing"
    );
    assert_eq!(
        bad_tcp.flows[0].anomalies,
        vec!["incarnation_mismatch", "missing_routing_handoff"]
    );
}

#[test]
fn classifies_reverse_bypass_drop_marked_direct_and_stateless_udp() {
    use honk_ebpf_common::conn::UdpDecisionState;
    use honk_ebpf_common::{ROUTING_META_FLAG_PUBLISHED, ROUTING_META_FLAG_WAN_USERSPACE};

    let sip: IpAddr = "10.0.0.2".parse().unwrap();
    let dip: IpAddr = "8.8.4.4".parse().unwrap();

    let k_rev = tuple_wire(sip, 40000, dip, 443, libc::IPPROTO_UDP as u8);
    let c_rev = conn_wire(
        1,
        0,
        0,
        0,
        ROUTING_META_FLAG_PUBLISHED,
        2,
        0,
        0,
        0,
        b"",
        0,
        0,
        1,
    );

    let k_abort = tuple_wire(sip, 40001, dip, 443, libc::IPPROTO_UDP as u8);
    let c_abort = conn_wire(
        0,
        UdpDecisionState::Aborted as u8,
        0,
        5,
        0,
        0,
        0,
        0,
        0,
        b"",
        0,
        0,
        2,
    );

    let k_wan_mark = tuple_wire(sip, 40002, dip, 443, libc::IPPROTO_UDP as u8);
    let c_wan_mark = conn_wire(
        0,
        UdpDecisionState::None as u8,
        0,
        0,
        ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_WAN_USERSPACE,
        0,
        0x10,
        1,
        0,
        b"",
        0,
        0,
        3,
    );

    let k_drop = tuple_wire(sip, 40003, dip, 443, libc::IPPROTO_TCP as u8);
    let c_drop = conn_wire(
        0,
        0,
        0,
        0,
        ROUTING_META_FLAG_PUBLISHED,
        1,
        0,
        0,
        0,
        b"",
        0,
        0,
        4,
    );

    let k_dns = tuple_wire(sip, 40004, dip, 53, libc::IPPROTO_UDP as u8);
    let h_dns = handoff_wire(0xfd, 0, 0, 0, b"", 0, 0, 9, 0, 0);

    let report = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            dip: Some(dip),
            ..Default::default()
        },
        lookup::DomainSnapshot::Unpublished,
        &[
            (k_rev, c_rev),
            (k_abort, c_abort),
            (k_wan_mark, c_wan_mark),
            (k_drop, c_drop),
        ],
        &[],
        &[(k_dns, h_dns)],
    );
    let by_sport: std::collections::BTreeMap<u16, &str> = report
        .flows
        .iter()
        .map(|f| (f.tuple.src_port, f.disposition))
        .collect();
    assert_eq!(by_sport[&40000], "reverse_bypass");
    assert_eq!(by_sport[&40001], "udp_aborted");
    assert_eq!(by_sport[&40002], "userspace_marked_direct");
    assert_eq!(by_sport[&40003], "kernel_drop_block");
    assert_eq!(by_sport[&40004], "stateless_userspace_udp");
}

#[test]
fn canonicalizes_ipv4_mapped_ipv6_selectors_across_flows_and_domain_routing() {
    use honk_ebpf_common::{ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED};

    let sip_v4: IpAddr = "192.168.1.10".parse().unwrap();
    let dip_v4: IpAddr = "172.217.75.94".parse().unwrap();
    let sip_mapped: IpAddr = "::ffff:192.168.1.10".parse().unwrap();
    let dip_mapped: IpAddr = "::ffff:172.217.75.94".parse().unwrap();

    let key = tuple_wire(sip_v4, 51234, dip_v4, 443, libc::IPPROTO_TCP as u8);
    let conn = conn_wire(
        0,
        0,
        0,
        0,
        ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD,
        0,
        0,
        0,
        0,
        b"",
        0,
        1,
        11,
    );
    let mut bitmap = [0u8; 32];
    bitmap[0] = 1;
    let domain_entries = [(lookup::encode_ip_key(dip_v4), bitmap)];
    let descriptor = RoutingPolicyDescriptor {
        slot: 0,
        features: 1,
        generation: 3,
        domain_map_id: 7,
        trace_policy: 0,
    };

    let by_ip = lookup::correlate_wire_records(
        &lookup::FlowFilter {
            ip: Some(dip_mapped),
            ..Default::default()
        },
        lookup::DomainSnapshot::Published {
            descriptor,
            entries: &domain_entries,
        },
        &[(key, conn)],
        &[],
        &[],
    );
    assert_eq!(by_ip.flows.len(), 1);
    assert_eq!(by_ip.flows[0].disposition, "native_direct_offload");
    assert_eq!(
        by_ip.domain_lookups,
        vec![lookup::DomainIpCorrelation {
            ip: dip_v4,
            state: lookup::DomainEntryState::Matched(vec![0]),
        }]
    );

    let args = lookup::LookupArgs {
        ip: None,
        sip: Some(sip_mapped),
        dip: Some(dip_mapped),
        sport: None,
        dport: Some(443),
        proto: Some(lookup::BpfProto::Tcp),
        limit: 50,
        pin_root: std::path::PathBuf::from("/sys/fs/bpf"),
        json: false,
    };
    let parsed_filter = lookup::FlowFilter::from_args(&args).unwrap();
    assert_eq!(parsed_filter.sip, Some(sip_v4));
    assert_eq!(parsed_filter.dip, Some(dip_v4));
    let by_sip_dip = lookup::correlate_wire_records(
        &parsed_filter,
        lookup::DomainSnapshot::Published {
            descriptor,
            entries: &domain_entries,
        },
        &[(key, conn)],
        &[],
        &[],
    );
    assert_eq!(by_sip_dip.flows.len(), 1);
    assert_eq!(by_sip_dip.domain_lookups.len(), 1);
    assert_eq!(by_sip_dip.domain_lookups[0].ip, dip_v4);
}
