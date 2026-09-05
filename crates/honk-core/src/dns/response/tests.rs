use super::{
    ResponseError, ResponseTemplate, build_dns_error_response, build_dns_refused,
    build_dns_servfail,
};
use crate::dns::query::{IngressProfile, QueryContext};

fn query(txid: u16, profile: IngressProfile) -> QueryContext {
    let mut wire = txid.to_be_bytes().to_vec();
    wire.extend_from_slice(&[
        0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
        b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    QueryContext::parse_with_profile(&wire, profile).expect("query")
}

fn answer(request: &QueryContext, answer_count: u16) -> Vec<u8> {
    let mut wire = request.canonical_wire().to_vec();
    wire[0..2].copy_from_slice(&0xaaaa_u16.to_be_bytes());
    wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    wire[6..8].copy_from_slice(&answer_count.to_be_bytes());
    for index in 0..answer_count {
        wire.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        wire.extend_from_slice(&[192, 0, 2, u8::try_from(index + 1).expect("small index")]);
    }
    wire
}

#[test]
fn checks_upstream_transaction_id_without_changing_template_validation() {
    let request = query(0x1234, IngressProfile::Internal);
    let response = answer(&request, 0);

    assert!(super::check_transaction_id(0xaaaa, &response).is_ok());
    assert!(matches!(
        super::check_transaction_id(0x1234, &response),
        Err(ResponseError::TransactionIdMismatch {
            expected: 0x1234,
            actual: 0xaaaa
        })
    ));
    assert!(ResponseTemplate::validate(&request, &response).is_ok());
}
#[test]
fn restores_each_callers_txid_for_full_profiles() {
    // Given
    let original = query(1, IngressProfile::Internal);
    let template = ResponseTemplate::validate(&original, &answer(&original, 1)).expect("response");

    for profile in [
        IngressProfile::Tcp,
        IngressProfile::Api,
        IngressProfile::Internal,
    ] {
        let caller = query(0xbeef, profile);

        // When
        let rendered = template.render(&caller).expect("render");

        // Then
        assert_eq!(&rendered[0..2], &[0xbe, 0xef]);
        assert_eq!(u16::from_be_bytes([rendered[6], rendered[7]]), 1);
    }
}

#[test]
fn truncates_udp_only_between_complete_records() {
    // Given
    let original = query(1, IngressProfile::Internal);
    let template = ResponseTemplate::validate(&original, &answer(&original, 3)).expect("response");
    let caller = query(
        0x7788,
        IngressProfile::Udp {
            advertised_size: 61,
        },
    );

    // When
    let rendered = template.render(&caller).expect("render");

    // Then
    assert_eq!(rendered.len(), 61);
    assert_eq!(&rendered[0..2], &[0x77, 0x88]);
    assert_ne!(rendered[2] & 0x02, 0);
    assert_eq!(u16::from_be_bytes([rendered[6], rendered[7]]), 2);
    assert_eq!(u16::from_be_bytes([rendered[8], rendered[9]]), 0);
    assert_eq!(u16::from_be_bytes([rendered[10], rendered[11]]), 0);
}

#[test]
fn rejects_stale_identity_and_malformed_responses() {
    let request = query(1, IngressProfile::Internal);
    let mut wrong_question = answer(&request, 0);
    wrong_question[13] = b'x';
    let mut wrong_opcode = answer(&request, 0);
    wrong_opcode[2] |= 0x08;
    let mut not_response = answer(&request, 0);
    not_response[2] &= 0x7f;
    let mut truncated_rr = answer(&request, 1);
    truncated_rr.pop();
    let mut compression_loop = answer(&request, 1);
    compression_loop[29..31].copy_from_slice(&[0xc0, 0x1d]);
    let mut trailing = answer(&request, 0);
    trailing.push(0);

    for raw in [
        wrong_question,
        wrong_opcode,
        not_response,
        truncated_rr,
        compression_loop,
        trailing,
    ] {
        // When
        let result = ResponseTemplate::validate(&request, &raw);

        // Then
        assert!(result.is_err());
    }

    let template = ResponseTemplate::validate(&request, &answer(&request, 0)).expect("response");
    let mut different = query(2, IngressProfile::Internal);
    let mut raw = different.canonical_wire().to_vec();
    raw[13] = b'x';
    different = QueryContext::parse(&raw).expect("different query");
    assert!(matches!(
        template.render(&different),
        Err(ResponseError::RequestIdentityMismatch)
    ));
}

#[test]
fn builds_error_responses_in_the_dns_response_layer() {
    let request = query(0x1234, IngressProfile::Internal);
    let mut wire = request.canonical_wire().to_vec();
    wire[..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    let servfail = build_dns_servfail(&wire);
    let refused = build_dns_refused(&wire);

    assert_eq!(&servfail[..2], &[0x12, 0x34]);
    assert_eq!(servfail[2], 0x81);
    assert_eq!(servfail[3], 0x82);
    assert_eq!(refused[3], 0x85);

    wire[2..4].copy_from_slice(&0x2930_u16.to_be_bytes());
    let opcode_refused = build_dns_refused(&wire);
    assert_eq!(
        u16::from_be_bytes([opcode_refused[2], opcode_refused[3]]) & 0x7800,
        0x2800
    );
    let opcode_flags = u16::from_be_bytes([opcode_refused[2], opcode_refused[3]]);
    assert_eq!(opcode_flags & 0x0020, 0, "AD must not be asserted locally");
    assert_ne!(opcode_flags & 0x0010, 0, "CD is echoed from the request");
    assert_eq!(build_dns_error_response(&[1, 2], 15), vec![0; 12]);
}
