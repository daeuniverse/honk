use std::alloc::System;
use std::process::Command;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

use super::{DnsRequestMeta, IngressProfile, QueryContext};

mod allocation;

#[global_allocator]
pub(super) static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const QDCOUNT_ALLOCATION_CHILD: &str = "HONK_QDCOUNT_ALLOCATION_CHILD";

fn query(flags: u16, questions: &[(&[u8], u16, u16)], opt: Option<&[u8]>) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34];
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&u16::from(opt.is_some()).to_be_bytes());
    for (name, qtype, qclass) in questions {
        wire.extend_from_slice(name);
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&qclass.to_be_bytes());
    }
    if let Some(opt) = opt {
        wire.extend_from_slice(opt);
    }
    wire
}

fn example_name(case: bool) -> Vec<u8> {
    let first = if case { b"ExAmPlE" } else { b"example" };
    let mut name = vec![7];
    name.extend_from_slice(first);
    name.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    name
}

fn opt(size: u16, version: u8, flags: u16, options: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 0, 41];
    wire.extend_from_slice(&size.to_be_bytes());
    wire.extend_from_slice(&[0, version]);
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.extend_from_slice(&(options.len() as u16).to_be_bytes());
    wire.extend_from_slice(options);
    wire
}

#[test]
fn rejects_impossible_qdcount_before_large_allocation() {
    if std::env::var_os(QDCOUNT_ALLOCATION_CHILD).is_some() {
        // Given
        let raw = [0, 1, 1, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
        let region = Region::new(GLOBAL);

        // When
        let result = QueryContext::parse(&raw);
        let allocated = region.change().bytes_allocated;

        // Then
        assert!(result.is_err());
        assert!(
            allocated <= 1_024,
            "impossible QDCOUNT allocated {allocated} bytes before rejection"
        );
        return;
    }

    // Given
    let current_test = std::env::current_exe().expect("current test executable");

    // When
    let output = Command::new(current_test)
        .args([
            "--exact",
            "dns::query::tests::rejects_impossible_qdcount_before_large_allocation",
            "--nocapture",
        ])
        .env(QDCOUNT_ALLOCATION_CHILD, "1")
        .output()
        .expect("isolated allocation test");

    // Then
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn accepts_questions_at_the_minimum_wire_size_boundary() {
    // Given
    let raw = query(0x0100, &[(&[0], 1, 1), (&[0], 28, 1)], None);

    // When
    let context = QueryContext::parse(&raw).expect("two minimum-size questions");

    // Then
    assert_eq!(context.all_question_offsets().len(), 2);
    assert!(!context.is_cacheable());
}

#[test]
fn canonical_domain_keeps_root_and_rejects_malformed_wire() {
    for (wire, expected) in [(vec![0], "."), (example_name(true), "example.com")] {
        let raw = query(0x0100, &[(&wire, 2, 1)], None);
        let context = QueryContext::parse(&raw).unwrap();
        assert_eq!(
            context.qname().unwrap().to_domain_name().as_deref(),
            Some(expected)
        );
        assert!(super::validate_exact_dns_query(&raw).is_some());
        assert_eq!(
            crate::dns::forwarder::parse_dns_question(&raw),
            Some((expected.to_owned(), 2)),
        );
    }
    for wire in [
        vec![],
        vec![0, 0],
        vec![1, b'a', 0, 0],
        vec![2, b'a'],
        vec![1, 0xff, 0],
    ] {
        assert!(super::DnsName(wire.into()).to_domain_name().is_none());
    }
}

#[test]
fn preserves_exact_question_identity_when_parsed() {
    // Given
    let name = example_name(true);
    let raw = query(0x0130, &[(&name, 28, 3)], Some(&opt(1232, 0, 0x8000, &[])));

    // When
    let context = QueryContext::parse_with_profile(
        &raw,
        IngressProfile::Udp {
            advertised_size: 1232,
        },
    )
    .expect("valid query");

    // Then
    assert_eq!(context.txid().get(), 0x1234);
    assert_eq!(context.qname().expect("question").as_wire(), name);
    assert_eq!(context.qtype().expect("question").get(), 28);
    assert_eq!(context.qclass().expect("question").get(), 3);
    assert_eq!(context.question_offsets().expect("question").start(), 12);
    assert_eq!(context.question_offsets().expect("question").end(), 29);
    assert_eq!(context.edns().expect("OPT").advertised_size(), 1232);
    assert!(context.edns().expect("OPT").dnssec_ok());
    assert_eq!(
        context.ingress(),
        IngressProfile::Udp {
            advertised_size: 1232
        }
    );
    assert_eq!(&context.canonical_wire()[0..2], &[0, 0]);
    assert!(context.is_cacheable());
    assert!(context.is_coalescable());
}

#[test]
fn bypasses_optimization_but_forwards_semantically_unusual_queries() {
    let name = example_name(false);
    let mut cases = vec![
        query(0x8100, &[(&name, 1, 1)], None),
        query(0x0900, &[(&name, 1, 1)], None),
        query(0x0140, &[(&name, 1, 1)], None),
        query(0x0100, &[(&name, 1, 1), (&name, 28, 1)], None),
        query(0x0100, &[(&name, 1, 1)], Some(&opt(1232, 1, 0, &[]))),
        query(
            0x0100,
            &[(&name, 1, 1)],
            Some(&opt(1232, 0, 0, &[0, 8, 0, 0])),
        ),
        query(
            0x0100,
            &[(&name, 1, 1)],
            Some(&opt(1232, 0, 0, &[0, 10, 0, 0])),
        ),
        query(
            0x0100,
            &[(&name, 1, 1)],
            Some(&opt(1232, 0, 0, &[65, 0, 0, 0])),
        ),
    ];
    let mut answer = query(0x0100, &[(&name, 1, 1)], None);
    answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    cases.push(answer);
    let mut authority = query(0x0100, &[(&name, 1, 1)], None);
    authority[8..10].copy_from_slice(&1_u16.to_be_bytes());
    authority.extend_from_slice(&[0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
    cases.push(authority);

    for raw in cases {
        // When
        let context = QueryContext::parse(&raw).expect("valid query must forward");

        // Then
        assert!(!context.is_cacheable());
        assert!(!context.is_coalescable());
    }
}

#[test]
fn canonical_identity_distinguishes_response_affecting_query_fields() {
    let lower = example_name(false);
    let mixed = example_name(true);
    let base = query(0x0100, &[(&lower, 1, 1)], None);
    let variants = [
        query(0x0100, &[(&mixed, 1, 1)], None),
        query(0x0100, &[(&lower, 1, 3)], None),
        query(0x0000, &[(&lower, 1, 1)], None),
        query(0x0120, &[(&lower, 1, 1)], None),
        query(0x0110, &[(&lower, 1, 1)], None),
        query(0x0100, &[(&lower, 1, 1)], Some(&opt(1232, 0, 0, &[]))),
        query(0x0100, &[(&lower, 1, 1)], Some(&opt(1400, 0, 0, &[]))),
        query(0x0100, &[(&lower, 1, 1)], Some(&opt(1232, 0, 0x8000, &[]))),
    ];
    let base = QueryContext::parse(&base).expect("base");

    for raw in variants {
        // When
        let variant = QueryContext::parse(&raw).expect("variant");

        // Then
        assert!(variant.is_cacheable());
        assert_ne!(variant.canonical_wire(), base.canonical_wire());
    }
    let mut other_txid = base.canonical_wire().to_vec();
    other_txid[0..2].copy_from_slice(&0xffff_u16.to_be_bytes());
    assert_eq!(
        QueryContext::parse(&other_txid)
            .expect("other ID")
            .canonical_wire(),
        base.canonical_wire()
    );
}

#[test]
fn request_metadata_normalizes_ipv4_mapped_source() {
    let original_dst = "[2001:db8::53]:53".parse().expect("destination");
    let metadata = DnsRequestMeta::new(
        Some("::ffff:192.0.2.10".parse().expect("mapped source")),
        Some(original_dst),
    );

    assert_eq!(metadata.source_ip(), Some("192.0.2.10".parse().unwrap()));
    assert_eq!(metadata.original_dst(), Some(original_dst));
}

#[test]
fn rejects_malformed_name_compression_without_panicking() {
    let malformed = [
        vec![],
        vec![0; 11],
        vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0],
        vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1],
        vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64, 0],
    ];

    for raw in malformed {
        // When
        let parsed = QueryContext::parse(&raw);

        // Then
        assert!(parsed.is_err());
    }
}

fn full_parse_verdict(raw: &[u8]) -> Option<u16> {
    let query = QueryContext::parse(raw).ok()?;
    query.qname()?.to_domain_name()?;
    Some(query.edns().map_or(512, |edns| edns.advertised_size()))
}

#[test]
fn allocation_free_scan_matches_full_parse() {
    let name = example_name(false);
    let plain = query(0x0100, &[(&name, 1, 1)], None);
    let with_opt = |opt: &[u8]| query(0x0100, &[(&name, 1, 1)], Some(opt));
    let mut two_opts = with_opt(&[opt(1232, 0, 0x8000, &[]), opt(4096, 0, 0, &[])].concat());
    two_opts[11] = 2;
    let mut foreign_owner = vec![1, b'a'];
    foreign_owner.extend_from_slice(&opt(512, 0, 0, &[]));
    assert_eq!(full_parse_verdict(&with_opt(&foreign_owner)), None);
    let mut with_answer = plain.clone();
    with_answer[7] = 1;
    with_answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    let seeds = [
        plain.clone(),
        with_opt(&opt(1232, 0, 0x8000, &[])),
        with_opt(&opt(1, 0, 0, &[0, 10, 0, 2, 1, 2])),
        with_opt(&opt(1232, 0, 0, &[0, 10, 0, 5, 1])),
        with_opt(&foreign_owner),
        two_opts,
        with_answer,
        query(0x0100, &[(&[2, 0xff, 0xfe, 0], 1, 1)], None),
    ];

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as usize
    };
    let (mut accepted, mut rejected) = (0, 0);
    for seed in &seeds {
        for _ in 0..5000 {
            let mut raw = seed.clone();
            for _ in 0..=next() % 3 {
                let at = next() % raw.len();
                raw[at] = next() as u8;
            }
            if next() % 4 == 0 {
                raw.truncate(next() % (raw.len() + 1));
            }
            if raw.len() < 12 || u16::from_be_bytes([raw[4], raw[5]]) != 1 {
                continue;
            }
            let scanned = super::parser::scan_single_question_query(&raw)
                .ok()
                .map(|size| size.unwrap_or(512));
            assert_eq!(scanned, full_parse_verdict(&raw), "{raw:?}");
            if scanned.is_some() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert!(accepted > 1000 && rejected > 1000, "{accepted}/{rejected}");
}

#[test]
fn validation_follows_compression_through_labels_past_the_pointer_range() {
    let rr = |owner: &[u8], rdata: &[u8]| {
        let mut wire = owner.to_vec();
        wire.extend_from_slice(&[0, 10, 0, 1, 0, 0, 0, 0]);
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(rdata);
        wire
    };
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 10, 0, 1];
    wire.extend(rr(&[0], &vec![0; 16352]));
    assert_eq!(wire.len(), 16380);
    // The `abc` owner starts inside the 14-bit range but its terminator does not.
    wire.extend(rr(&[3, b'a', b'b', b'c', 0], &[]));
    wire.extend(rr(&[0xff, 0xfc], &[]));

    assert!(super::validate_exact_dns_query(&wire).is_some());
}
