mod query;
mod routing_dial;
mod routing_leaf;
mod shutdown;

use std::sync::Arc;

use honk_config::dns::DnsUpstream;
use honk_config::node::{Group, Node};
use honk_config::types::DnsProtocol;

use super::*;
use crate::dns::routing::DnsRouter;

fn make_router() -> Arc<DnsRouter> {
    Arc::new(
        DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    )
}

fn make_upstream(name: &str, address: &str, protocol: DnsProtocol) -> DnsUpstream {
    DnsUpstream {
        name: name.to_string(),
        address: address.to_string(),
        protocol,
        tls_server_name: None,
        outbound: None,
    }
}

fn mock_dns_response(transaction_id: u16) -> Vec<u8> {
    vec![
        (transaction_id >> 8) as u8,
        transaction_id as u8,
        0x81,
        0x80,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x07,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        0x03,
        b'c',
        b'o',
        b'm',
        0x00,
        0x00,
        0x01,
        0x00,
        0x01,
        0xc0,
        0x0c,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x3c,
        0x00,
        0x04,
        0x7f,
        0x00,
        0x00,
        0x01,
    ]
}

fn mock_dns_query(transaction_id: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    query.push(0x07);
    query.extend_from_slice(b"example");
    query.push(0x03);
    query.extend_from_slice(b"com");
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

fn test_node(name: &str) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        ..Default::default()
    }
}

fn test_group(
    name: &str,
    policy: honk_config::group::GroupPolicy,
    node_ids: Vec<uuid::Uuid>,
) -> Group {
    Group {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        icon: None,
        policy,
        nodes: node_ids,
        filters: vec![],
        groups: vec![],
        default: None,
        final_outbound: None,
        check_url: None,
        check_interval: None,
        tolerance: 50,
        idle_timeout: None,
        interrupt_connections: false,
        own: Default::default(),
        created_at: chrono::Utc::now(),
    }
}
