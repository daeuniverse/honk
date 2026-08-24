use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::netlink;
use crate::{NFQUEUE_SIGNATURE_MARK, QUEUE_NUM};

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_MARK: u32 = 3;
const NFT_META_L4PROTO: u32 = 16;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
const NFTA_QUEUE_NUM: u16 = 1;
const NFT_REG_1: u32 = 1;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_ACCEPT: u32 = 1;
const IPPROTO_UDP: u8 = 17;

pub const TABLE_NAME: &str = "honk_nfqueue";
pub const CHAIN_NAME: &str = "udp_decision";
pub const CHAIN_PRIORITY: i32 = -250;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RulesError {
    #[error("nftables netlink: {0}")]
    Io(#[from] io::Error),
}
pub(crate) struct NftRuleset {
    socket: OwnedFd,
    sequence: u32,
    installed: bool,
}

impl NftRuleset {
    pub(crate) fn install() -> Result<Self, RulesError> {
        let socket = netlink::open_socket(false)?;
        let mut ruleset = Self {
            socket,
            sequence: 1,
            installed: false,
        };
        // The singleton process lock reserves these names; reclaim a stale
        // table before publishing the replacement transaction.
        ruleset.remove_owned_table()?;
        let sequence = ruleset.next_sequence();
        let request = build_install_batch(sequence);
        netlink::send_and_acks(ruleset.socket.as_raw_fd(), &request, sequence, 4)?;
        ruleset.installed = true;
        Ok(ruleset)
    }

    pub(crate) fn uninstall(&mut self) -> Result<(), RulesError> {
        if !self.installed {
            return Ok(());
        }
        let result = self.remove_owned_table();
        if result.is_ok() {
            self.installed = false;
        }
        result
    }

    fn remove_owned_table(&mut self) -> Result<(), RulesError> {
        let sequence = self.next_sequence();
        let request = build_delete_batch(sequence);
        match netlink::send_and_acks(self.socket.as_raw_fd(), &request, sequence, 2) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        sequence
    }
}

fn build_install_batch(sequence: u32) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(1024);
    put_batch_begin(&mut buffer, sequence);

    let table = put_nft_header(
        &mut buffer,
        NFT_MSG_NEWTABLE,
        netlink::NLM_F_CREATE,
        sequence,
    );
    netlink::put_attribute_string(&mut buffer, NFTA_TABLE_NAME, TABLE_NAME);
    netlink::put_attribute_be32(&mut buffer, NFTA_TABLE_FLAGS, 0);
    netlink::seal_message(&mut buffer, table);

    let chain = put_nft_header(
        &mut buffer,
        NFT_MSG_NEWCHAIN,
        netlink::NLM_F_CREATE,
        sequence,
    );
    netlink::put_attribute_string(&mut buffer, NFTA_CHAIN_TABLE, TABLE_NAME);
    netlink::put_attribute_string(&mut buffer, NFTA_CHAIN_NAME, CHAIN_NAME);
    let hook = netlink::begin_nested(&mut buffer, NFTA_CHAIN_HOOK);
    netlink::put_attribute_be32(&mut buffer, NFTA_HOOK_HNUM, NF_INET_PRE_ROUTING);
    netlink::put_attribute_be32(&mut buffer, NFTA_HOOK_PRIORITY, CHAIN_PRIORITY as u32);
    netlink::seal_nested(&mut buffer, hook);
    netlink::put_attribute_string(&mut buffer, NFTA_CHAIN_TYPE, "filter");
    netlink::put_attribute_be32(&mut buffer, NFTA_CHAIN_POLICY, NF_ACCEPT);
    netlink::seal_message(&mut buffer, chain);

    let rule = put_nft_header(
        &mut buffer,
        NFT_MSG_NEWRULE,
        netlink::NLM_F_CREATE,
        sequence,
    );
    netlink::put_attribute_string(&mut buffer, NFTA_RULE_TABLE, TABLE_NAME);
    netlink::put_attribute_string(&mut buffer, NFTA_RULE_CHAIN, CHAIN_NAME);
    let expressions = netlink::begin_nested(&mut buffer, NFTA_RULE_EXPRESSIONS);
    put_queue_rule_expressions(&mut buffer);
    netlink::seal_nested(&mut buffer, expressions);
    netlink::seal_message(&mut buffer, rule);

    put_batch_end(&mut buffer, sequence);
    buffer
}

fn build_delete_batch(sequence: u32) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(128);
    put_batch_begin(&mut buffer, sequence);
    let table = put_nft_header(&mut buffer, NFT_MSG_DELTABLE, 0, sequence);
    netlink::put_attribute_string(&mut buffer, NFTA_TABLE_NAME, TABLE_NAME);
    netlink::seal_message(&mut buffer, table);
    put_batch_end(&mut buffer, sequence);
    buffer
}

fn put_batch_begin(buffer: &mut Vec<u8>, sequence: u32) {
    let start = netlink::put_message_header(
        buffer,
        netlink::NFNL_MSG_BATCH_BEGIN,
        netlink::NLM_F_REQUEST,
        sequence,
        0,
        netlink::NFNL_BATCH_RES_ID,
    );
    netlink::seal_message(buffer, start);
}

fn put_batch_end(buffer: &mut Vec<u8>, sequence: u32) {
    let start = netlink::put_message_header(
        buffer,
        netlink::NFNL_MSG_BATCH_END,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
        sequence,
        0,
        netlink::NFNL_BATCH_RES_ID,
    );
    netlink::seal_message(buffer, start);
}

fn put_nft_header(buffer: &mut Vec<u8>, message_type: u16, flags: u16, sequence: u32) -> usize {
    netlink::put_message_header(
        buffer,
        (netlink::NFNL_SUBSYS_NFTABLES << 8) | message_type,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | flags,
        sequence,
        netlink::NFPROTO_INET,
        netlink::NFNL_SUBSYS_NFTABLES,
    )
}

fn put_queue_rule_expressions(buffer: &mut Vec<u8>) {
    put_meta_load(buffer, NFT_META_L4PROTO);
    put_compare_u8(buffer, NFT_CMP_EQ, IPPROTO_UDP);
    put_meta_load(buffer, NFT_META_MARK);
    put_bitwise_signature_mark(buffer);
    put_compare_u32(buffer, NFT_CMP_EQ, NFQUEUE_SIGNATURE_MARK);
    // The value is intentionally unused: this expression keeps inet
    // conntrack/defrag registered while the chain itself stays pre-conntrack.
    put_ct_state_load(buffer);
    put_queue(buffer);
}

fn put_expression(buffer: &mut Vec<u8>, name: &str, data: impl FnOnce(&mut Vec<u8>)) {
    let element = netlink::begin_nested(buffer, NFTA_LIST_ELEM);
    netlink::put_attribute_string(buffer, NFTA_EXPR_NAME, name);
    let expression_data = netlink::begin_nested(buffer, NFTA_EXPR_DATA);
    data(buffer);
    netlink::seal_nested(buffer, expression_data);
    netlink::seal_nested(buffer, element);
}

fn put_meta_load(buffer: &mut Vec<u8>, key: u32) {
    put_expression(buffer, "meta", |buffer| {
        netlink::put_attribute_be32(buffer, NFTA_META_DREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_META_KEY, key);
    });
}

fn put_compare_u8(buffer: &mut Vec<u8>, operation: u32, value: u8) {
    put_expression(buffer, "cmp", |buffer| {
        netlink::put_attribute_be32(buffer, NFTA_CMP_SREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_CMP_OP, operation);
        let data = netlink::begin_nested(buffer, NFTA_CMP_DATA);
        netlink::put_attribute(buffer, NFTA_DATA_VALUE, &[value]);
        netlink::seal_nested(buffer, data);
    });
}

fn put_compare_u32(buffer: &mut Vec<u8>, operation: u32, value: u32) {
    put_expression(buffer, "cmp", |buffer| {
        netlink::put_attribute_be32(buffer, NFTA_CMP_SREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_CMP_OP, operation);
        let data = netlink::begin_nested(buffer, NFTA_CMP_DATA);
        netlink::put_attribute(buffer, NFTA_DATA_VALUE, &value.to_ne_bytes());
        netlink::seal_nested(buffer, data);
    });
}

fn put_bitwise_signature_mark(buffer: &mut Vec<u8>) {
    put_expression(buffer, "bitwise", |buffer| {
        netlink::put_attribute_be32(buffer, NFTA_BITWISE_SREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_BITWISE_DREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_BITWISE_LEN, 4);
        let mask = netlink::begin_nested(buffer, NFTA_BITWISE_MASK);
        netlink::put_attribute(
            buffer,
            NFTA_DATA_VALUE,
            &NFQUEUE_SIGNATURE_MARK.to_ne_bytes(),
        );
        netlink::seal_nested(buffer, mask);
        let xor = netlink::begin_nested(buffer, NFTA_BITWISE_XOR);
        netlink::put_attribute(buffer, NFTA_DATA_VALUE, &0u32.to_ne_bytes());
        netlink::seal_nested(buffer, xor);
    });
}

fn put_ct_state_load(buffer: &mut Vec<u8>) {
    put_expression(buffer, "ct", |buffer| {
        netlink::put_attribute_be32(buffer, NFTA_CT_DREG, NFT_REG_1);
        netlink::put_attribute_be32(buffer, NFTA_CT_KEY, NFT_CT_STATE);
    });
}

fn put_queue(buffer: &mut Vec<u8>) {
    put_expression(buffer, "queue", |buffer| {
        netlink::put_attribute_be16(buffer, NFTA_QUEUE_NUM, QUEUE_NUM);
    });
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[derive(Debug)]
    struct Expression {
        name: String,
        data: Bytes,
    }

    fn decoded_expressions() -> Vec<Expression> {
        let messages = netlink::messages(Bytes::from(build_install_batch(19)))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(messages.len(), 5);
        assert_eq!(
            messages
                .iter()
                .skip(1)
                .filter(|message| message.flags & netlink::NLM_F_ACK != 0)
                .count(),
            4,
            "every transactional operation and the batch end requests an ACK"
        );
        let rule = messages
            .iter()
            .find(|message| {
                message.message_type == (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE
            })
            .expect("rule message");
        let rule_attributes = netlink::attributes(rule.body.slice(netlink::NFGENMSG_LEN..))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let expressions = rule_attributes
            .into_iter()
            .find(|attribute| attribute.kind == NFTA_RULE_EXPRESSIONS)
            .expect("expressions");
        netlink::attributes(expressions.payload)
            .map(|element| {
                let element = element.unwrap();
                assert_eq!(element.kind, NFTA_LIST_ELEM);
                let attributes = netlink::attributes(element.payload)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let name = attributes
                    .iter()
                    .find(|attribute| attribute.kind == NFTA_EXPR_NAME)
                    .unwrap()
                    .payload
                    .split_last()
                    .map(|(_, bytes)| String::from_utf8(bytes.to_vec()).unwrap())
                    .unwrap();
                let data = attributes
                    .into_iter()
                    .find(|attribute| attribute.kind == NFTA_EXPR_DATA)
                    .unwrap()
                    .payload;
                Expression { name, data }
            })
            .collect()
    }

    #[test]
    fn install_batch_owns_accept_prerouting_chain() {
        let messages = netlink::messages(Bytes::from(build_install_batch(23)))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let table = messages
            .iter()
            .find(|message| {
                message.message_type == (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE
            })
            .unwrap();
        let table_attributes = netlink::attributes(table.body.slice(netlink::NFGENMSG_LEN..))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(table_attributes[0].payload.as_ref(), b"honk_nfqueue\0");

        let chain = messages
            .iter()
            .find(|message| {
                message.message_type == (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN
            })
            .unwrap();
        let chain_attributes = netlink::attributes(chain.body.slice(netlink::NFGENMSG_LEN..))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(chain_attributes[0].payload.as_ref(), b"honk_nfqueue\0");
        assert_eq!(chain_attributes[1].payload.as_ref(), b"udp_decision\0");
        let hook = netlink::attributes(chain_attributes[2].payload.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(hook[0].payload[..4].try_into().unwrap()),
            NF_INET_PRE_ROUTING
        );
        assert_eq!(
            u32::from_be_bytes(hook[1].payload[..4].try_into().unwrap()) as i32,
            CHAIN_PRIORITY
        );
        assert_eq!(chain_attributes[3].payload.as_ref(), b"filter\0");
        assert_eq!(
            u32::from_be_bytes(chain_attributes[4].payload[..4].try_into().unwrap()),
            NF_ACCEPT
        );
    }

    #[test]
    fn every_nft_transaction_operation_requests_an_ack() {
        for (batch, expected_types) in [
            (
                build_install_batch(31),
                vec![
                    netlink::NFNL_MSG_BATCH_BEGIN,
                    (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
                    (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
                    (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
                    netlink::NFNL_MSG_BATCH_END,
                ],
            ),
            (
                build_delete_batch(32),
                vec![
                    netlink::NFNL_MSG_BATCH_BEGIN,
                    (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
                    netlink::NFNL_MSG_BATCH_END,
                ],
            ),
        ] {
            let messages = netlink::messages(Bytes::from(batch))
                .collect::<Result<Vec<_>, _>>()
                .expect("valid nft batch");
            assert_eq!(
                messages
                    .iter()
                    .map(|message| message.message_type)
                    .collect::<Vec<_>>(),
                expected_types
            );
            assert_eq!(messages[0].flags & netlink::NLM_F_ACK, 0);
            assert!(
                messages[1..]
                    .iter()
                    .all(|message| message.flags & netlink::NLM_F_ACK != 0),
                "every transactional operation and batch end must request an ACK"
            );
        }
    }

    #[test]
    fn rule_expression_order_keeps_ct_after_cheap_selectors() {
        let expressions = decoded_expressions();
        assert_eq!(
            expressions
                .iter()
                .map(|expression| expression.name.as_str())
                .collect::<Vec<_>>(),
            vec!["meta", "cmp", "meta", "bitwise", "cmp", "ct", "queue"]
        );

        let first_meta = netlink::attributes(expressions[0].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(first_meta[1].payload[..4].try_into().unwrap()),
            NFT_META_L4PROTO
        );
        let second_meta = netlink::attributes(expressions[2].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(second_meta[1].payload[..4].try_into().unwrap()),
            NFT_META_MARK
        );

        let bitwise = netlink::attributes(expressions[3].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(bitwise.len(), 5);
        assert_eq!(bitwise[3].kind, NFTA_BITWISE_MASK);
        let mask = netlink::attributes(bitwise[3].payload.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(mask.len(), 1);
        assert_eq!(mask[0].kind, NFTA_DATA_VALUE);
        assert_eq!(
            mask[0].payload.as_ref(),
            &NFQUEUE_SIGNATURE_MARK.to_ne_bytes()
        );
        assert_eq!(bitwise[4].kind, NFTA_BITWISE_XOR);
        let xor = netlink::attributes(bitwise[4].payload.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(xor[0].payload.as_ref(), &0u32.to_ne_bytes());

        let mark_comparison = netlink::attributes(expressions[4].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(mark_comparison[1].payload[..4].try_into().unwrap()),
            NFT_CMP_EQ
        );
        let comparison_data = netlink::attributes(mark_comparison[2].payload.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            comparison_data[0].payload.as_ref(),
            &NFQUEUE_SIGNATURE_MARK.to_ne_bytes()
        );

        let ct = netlink::attributes(expressions[5].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(ct.len(), 2);
        assert_eq!(
            u32::from_be_bytes(ct[1].payload[..4].try_into().unwrap()),
            NFT_CT_STATE
        );
    }

    #[test]
    fn queue_is_fixed_and_has_no_bypass_or_fanout_flags() {
        let expressions = decoded_expressions();
        let queue = netlink::attributes(expressions[6].data.clone())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].kind, NFTA_QUEUE_NUM);
        assert_eq!(
            u16::from_be_bytes(queue[0].payload[..2].try_into().unwrap()),
            QUEUE_NUM
        );
    }
}
