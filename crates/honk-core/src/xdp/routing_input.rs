pub(crate) fn mac_string(mac: [u8; 6]) -> String {
    let mut text = String::with_capacity(17);
    for byte in super::mac_text(mac) {
        text.push(char::from(byte));
    }
    text
}

#[cfg(test)]
pub(crate) fn test_peer(
    realm: u32,
    device: usize,
    mac: [u8; 6],
    vid: u16,
) -> super::worker::PeerHold {
    super::worker::PeerHold::for_test(
        "192.0.2.1".parse().unwrap(),
        super::ReturnPath {
            realm,
            device,
            mac,
            vlan_tci: [vid, 0],
            vlan_proto: [0x8100, 0],
            vlan_count: 1,
        },
    )
}

#[cfg(test)]
pub(crate) fn test_fragments() -> [Vec<u8>; 3] {
    use honk_netstack::wire::{checksum::checksum, udp};
    let mut packet = [0; 100];
    let len = udp::emit_packet(
        &mut packet,
        "192.0.2.1:40000".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
        &[7; 32],
    )
    .unwrap();
    std::array::from_fn(|index| {
        let (offset, end) = [(0usize, 16usize), (16, 32), (32, len - 20)][index];
        let mut fragment = packet[..20].to_vec();
        fragment.extend_from_slice(&packet[20 + offset..20 + end]);
        let total = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&total.to_be_bytes());
        let field = (offset / 8) as u16 | if index < 2 { 0x2000 } else { 0 };
        fragment[6..8].copy_from_slice(&field.to_be_bytes());
        fragment[10..12].fill(0);
        let sum = checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&sum.to_be_bytes());
        fragment
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn plain_process_name_retains_canonical_missing_semantics() {
        for (predicate, expected) in [("pname(curl)", "direct"), ("!pname(curl)", "block")] {
            let config = honk_config::parser::parse_dae_config(&format!(
                "routing {{ {predicate} -> block\n fallback: direct }}"
            ))
            .unwrap();
            let router = crate::routing::Router::from_config(&config.routing).unwrap();
            let input = crate::routing::ConnectionInfo {
                domain: None,
                dst_ip: "198.51.100.1".parse().unwrap(),
                dst_port: 443,
                src_ip: "192.0.2.1".parse().unwrap(),
                src_port: 40000,
                protocol: "tcp",
                process_name: None,
                mac: None,
                dscp: Some(0),
            };
            assert_eq!(router.route(&input), expected);
        }
    }
    use super::mac_string;

    #[test]
    fn mac_routing_text_preserves_all_octets() {
        assert_eq!(
            mac_string([0x02, 0xab, 0, 0x10, 0xfe, 0xff]),
            "02:ab:00:10:fe:ff"
        );
    }
}
