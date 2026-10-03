use std::process::Command;

use stats_alloc::Region;

use super::GLOBAL;
use crate::dns::query::{QueryContext, QueryError};
use crate::dns::response::ResponseTemplate;

const LINEAR_ALLOCATION_CHILD: &str = "HONK_LINEAR_NAME_ALLOCATION_CHILD";

fn minimum_questions(count: u16) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0];
    wire.extend_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&[0; 6]);
    for _ in 0..count {
        wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    }
    wire
}

fn minimum_rr_response(request: &QueryContext, count: u16) -> Vec<u8> {
    let mut wire = request.canonical_wire().to_vec();
    wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    wire[6..8].copy_from_slice(&count.to_be_bytes());
    for _ in 0..count {
        wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    wire
}

#[test]
fn many_names_allocate_linearly() {
    if std::env::var_os(LINEAR_ALLOCATION_CHILD).is_some() {
        let query_wire = minimum_questions(13_104);
        assert_eq!(query_wire.len(), 65_532);
        let query_region = Region::new(GLOBAL);
        QueryContext::parse(&query_wire).expect("maximum minimum-size query");
        let query_allocated = query_region.change().bytes_allocated;
        assert!(
            query_allocated <= query_wire.len() * 16,
            "query allocated {query_allocated} bytes for {} wire bytes",
            query_wire.len()
        );

        let request = QueryContext::parse(&minimum_questions(1)).expect("request");
        let response_wire = minimum_rr_response(&request, 5_956);
        assert_eq!(response_wire.len(), 65_533);
        let response_region = Region::new(GLOBAL);
        ResponseTemplate::validate(&request, &response_wire).expect("near-limit response");
        let response_allocated = response_region.change().bytes_allocated;
        assert!(
            response_allocated <= response_wire.len() * 16,
            "response allocated {response_allocated} bytes for {} wire bytes",
            response_wire.len()
        );
        println!(
            "query={query_allocated}/{} response={response_allocated}/{}",
            query_wire.len() * 16,
            response_wire.len() * 16
        );
        return;
    }

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "dns::query::tests::allocation::many_names_allocate_linearly",
            "--nocapture",
        ])
        .env(LINEAR_ALLOCATION_CHILD, "1")
        .output()
        .expect("isolated allocation test");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn rejects_compression_beyond_hop_budget() {
    let valid = pointer_chain_query(128);
    QueryContext::parse(&valid).expect("128 backward compression pointers");

    let excessive = pointer_chain_query(129);
    assert!(matches!(
        QueryContext::parse(&excessive),
        Err(QueryError::MalformedName)
    ));
}

fn pointer_chain_query(hops: u16) -> Vec<u8> {
    let question_count = hops + 1;
    let mut wire = vec![0, 1, 1, 0];
    wire.extend_from_slice(&question_count.to_be_bytes());
    wire.extend_from_slice(&[0; 6]);
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut previous_name = 12_usize;
    for _ in 0..hops {
        let name = wire.len();
        let target = u16::try_from(previous_name).expect("test pointer fits");
        wire.extend_from_slice(&[(target >> 8) as u8 | 0xc0, target as u8, 0, 1, 0, 1]);
        previous_name = name;
    }
    wire
}

const VALIDATE_ALLOCATION_CHILD: &str = "HONK_VALIDATE_ALLOCATION_CHILD";

#[test]
fn udp_query_validation_allocates_at_most_the_pointer_table() {
    if std::env::var_os(VALIDATE_ALLOCATION_CHILD).is_some() {
        let wire = crate::dns::forwarder::build_dns_query("www.example.com", 1);
        let region = Region::new(GLOBAL);
        crate::dns::query::validate_exact_dns_query(&wire).expect("valid query");
        let allocations = region.change().allocations;
        assert!(allocations <= 1, "validation allocated {allocations} times");
        return;
    }

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "dns::query::tests::allocation::udp_query_validation_allocates_at_most_the_pointer_table",
            "--nocapture",
        ])
        .env(VALIDATE_ALLOCATION_CHILD, "1")
        .output()
        .expect("isolated allocation test");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
