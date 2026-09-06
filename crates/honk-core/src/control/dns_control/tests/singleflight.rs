use super::*;

#[test]
fn udp_profile_uses_exact_edns_advertised_size() {
    let mut query = query_with_txid("example.com", 1);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(
        crate::dns::query::udp_ingress_profile(&query),
        crate::dns::query::IngressProfile::Udp {
            advertised_size: 1232,
        }
    );
    assert_eq!(
        crate::dns::query::udp_ingress_profile(&query_with_txid("example.com", 2)),
        crate::dns::query::IngressProfile::Udp {
            advertised_size: 512,
        }
    );
}

#[tokio::test]
async fn singleflight_dedups_and_restores_txid() {
    let (controller, upstream) = test_controller(
        response_with_txid("example.com", 0x1111),
        Duration::from_millis(100),
    );
    let first = query_with_txid("example.com", 0xaaaa);
    let second = query_with_txid("example.com", 0xbbbb);

    let (first_response, second_response) = tokio::join!(
        controller.answer_query_for_test(
            &first,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
        controller.answer_query_for_test(
            &second,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
    );

    assert_eq!(&first_response[0..2], &first[0..2]);
    assert_eq!(&second_response[0..2], &second[0..2]);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
}

fn query_with_edns_option(txid: u16) -> Vec<u8> {
    let mut query = query_with_txid("example.com", txid);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 5, 0, 12, 0, 1, 0]);
    query
}

#[tokio::test]
async fn ineligible_queries_bypass_singleflight() {
    let (controller, upstream) = test_controller(
        response_with_txid("example.com", 0x1111),
        Duration::from_millis(100),
    );
    let first = query_with_edns_option(0xaaaa);
    let second = query_with_edns_option(0xbbbb);

    let _ = tokio::join!(
        controller.answer_query_for_test(
            &first,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
        controller.answer_query_for_test(
            &second,
            crate::dns::query::DnsRequestMeta::EMPTY,
            crate::dns::query::IngressProfile::Internal,
        ),
    );

    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}
