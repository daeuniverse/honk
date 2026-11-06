use std::net::SocketAddrV4;

use honk_ebpf_common::xdp::{CaptureAuthority, HIDDEN_VLAN, PacketMetadata, RX_VLAN_CHECKED};

/// Authority is pinned to the attachment, not reconstructed from received bytes.
#[derive(Clone, Debug)]
pub struct GeneralCapture {
    pub authority: CaptureAuthority,
    pub bypass_mark: u32,
    /// True requires device-bound VLAN metadata; false requires verified RX stripping off.
    pub vlan_metadata: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Authority,
    Metadata,
    Truncated,
    Ethernet,
    Ip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedPacket {
    /// Offset in received bytes; recovered VLAN metadata never adds inline bytes.
    pub l3_offset: usize,
    pub l3_len: usize,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub ether_type: u16,
    pub vlan_tci: [u16; 2],
    pub vlan_proto: [u16; 2],
    pub vlan_count: u8,
}

impl GeneralCapture {
    /// Checks the envelope only. The canonical packet engine owns IP/transport
    /// checksums, extension headers and reassembly, including non-first fragments.
    /// Wire-only input has no producer metadata and must come from the owned XSK/queue.
    pub fn decode(
        &self,
        segments: &[&[u8]],
        metadata: &[u8],
        queue: u32,
    ) -> Result<DecodedPacket, DecodeError> {
        if !self.authority.is_valid() {
            return Err(DecodeError::Authority);
        }
        let meta = if self.vlan_metadata {
            let meta = PacketMetadata::decode(metadata).ok_or(DecodeError::Metadata)?;
            if meta.ingress_ifindex != self.authority.ifindex || meta.rx_queue != queue {
                return Err(DecodeError::Authority);
            }
            if meta.flags & RX_VLAN_CHECKED == 0 {
                return Err(DecodeError::Metadata);
            }
            Some(meta)
        } else {
            if !metadata.is_empty() {
                return Err(DecodeError::Metadata);
            }
            None
        };
        // Only the maximum Ethernet + fixed IP header is copied; packet storage
        // remains scatter/gather through the device and forwarding engine.
        let mut header = [0u8; 62];
        let mut copied = 0;
        let mut length = 0usize;
        for segment in segments {
            length = length.checked_add(segment.len()).ok_or(DecodeError::Ip)?;
            let n = segment.len().min(header.len() - copied);
            header[copied..copied + n].copy_from_slice(&segment[..n]);
            copied += n;
        }
        if copied < 14 {
            return Err(DecodeError::Truncated);
        }
        if header[6..12] == [0; 6] || header[6] & 1 != 0 {
            return Err(DecodeError::Ethernet);
        }
        let be16 = |i| u16::from_be_bytes([header[i], header[i + 1]]);
        let mut ether_type = be16(12);
        let mut offset = 14;
        let mut vlan_tci = [0; 2];
        let mut vlan_proto = [0; 2];
        let hidden = usize::from(meta.is_some_and(|meta| meta.flags & HIDDEN_VLAN != 0));
        let mut vlan_count = hidden;
        if let Some(meta) = meta.filter(|_| hidden != 0) {
            if !matches!(meta.vlan_proto[0], 0x8100 | 0x88a8) {
                return Err(DecodeError::Metadata);
            }
            vlan_tci[0] = meta.vlan_tci[0];
            vlan_proto[0] = meta.vlan_proto[0];
        }
        while matches!(ether_type, 0x8100 | 0x88a8) {
            if vlan_count == 2 || copied < offset + 4 {
                return Err(DecodeError::Ethernet);
            }
            vlan_proto[vlan_count] = ether_type;
            vlan_tci[vlan_count] = be16(offset);
            ether_type = be16(offset + 2);
            offset += 4;
            vlan_count += 1;
        }
        if let Some(meta) = meta
            && (meta.l2_len as usize != offset
                || meta.ether_type != ether_type
                || meta.vlan_tci != vlan_tci
                || meta.vlan_proto != vlan_proto
                || usize::from(meta.vlan_count) != vlan_count
                || usize::from(meta.inline_vlan_count) != vlan_count - hidden)
        {
            return Err(DecodeError::Metadata);
        }
        let ip_length = match ether_type {
            0x0800 if copied >= offset + 20 => {
                let ihl = usize::from(header[offset] & 15) * 4;
                let total = usize::from(be16(offset + 2));
                if header[offset] >> 4 != 4 || ihl < 20 || total < ihl {
                    return Err(DecodeError::Ip);
                }
                total
            }
            0x86dd if copied >= offset + 40 => {
                if header[offset] >> 4 != 6 || be16(offset + 4) == 0 {
                    // IPv6 jumbograms require a distinct supported frame contract.
                    return Err(DecodeError::Ip);
                }
                usize::from(be16(offset + 4)) + 40
            }
            0x0800 | 0x86dd => return Err(DecodeError::Truncated),
            _ => return Err(DecodeError::Ethernet),
        };
        if ip_length > length - offset {
            return Err(DecodeError::Truncated);
        }
        if length > offset + ip_length && length > 60 + 4 * (vlan_count - hidden) {
            return Err(DecodeError::Ip);
        }
        Ok(DecodedPacket {
            l3_offset: offset,
            l3_len: ip_length,
            source_mac: header[6..12].try_into().unwrap(),
            destination_mac: header[..6].try_into().unwrap(),
            ether_type,
            vlan_tci,
            vlan_proto,
            vlan_count: vlan_count as u8,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Capture {
    pub protocol: Protocol,
    pub client: SocketAddrV4,
    pub service: SocketAddrV4,
    pub own_mac: [u8; 6],
    pub peer_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Reject {
    ShortEthernet,
    DestinationMac,
    SourceMac,
    EtherType,
    ShortIpv4,
    Version,
    Options,
    Fragment,
    Protocol,
    Tuple,
    Length,
    Padding,
}

impl Reject {
    pub const ALL: &'static [Self] = &[
        Self::ShortEthernet,
        Self::DestinationMac,
        Self::SourceMac,
        Self::EtherType,
        Self::ShortIpv4,
        Self::Version,
        Self::Options,
        Self::Fragment,
        Self::Protocol,
        Self::Tuple,
        Self::Length,
        Self::Padding,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShortEthernet => "short_ethernet",
            Self::DestinationMac => "destination_mac",
            Self::SourceMac => "source_mac",
            Self::EtherType => "ethertype",
            Self::ShortIpv4 => "short_ipv4",
            Self::Version => "version",
            Self::Options => "options",
            Self::Fragment => "fragment",
            Self::Protocol => "protocol",
            Self::Tuple => "tuple",
            Self::Length => "length",
            Self::Padding => "padding",
        }
    }
}

impl Capture {
    pub fn rx_ip<'a>(&self, frame: &'a [u8]) -> Result<&'a [u8], Reject> {
        if frame.len() < 14 {
            return Err(Reject::ShortEthernet);
        }
        if frame[..6] != self.own_mac {
            return Err(Reject::DestinationMac);
        }
        if frame[6..12] != self.peer_mac {
            return Err(Reject::SourceMac);
        }
        if frame[12..14] != [0x08, 0x00] {
            return Err(Reject::EtherType);
        }
        let ip = &frame[14..];
        if ip.len() < 20 {
            return Err(Reject::ShortIpv4);
        }
        if ip[0] >> 4 != 4 {
            return Err(Reject::Version);
        }
        if ip[0] & 0x0f != 5 {
            return Err(Reject::Options);
        }
        if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
            return Err(Reject::Fragment);
        }
        if ip[9] != self.protocol.number() {
            return Err(Reject::Protocol);
        }
        let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        let l4_min = match self.protocol {
            Protocol::Tcp => 20,
            Protocol::Udp => 8,
        };
        if total_len < 20 + l4_min || total_len > 1500 || total_len > ip.len() {
            return Err(Reject::Length);
        }
        if frame.len() != 14 + total_len && frame.len() > 60 {
            return Err(Reject::Padding);
        }
        let l4 = &ip[20..total_len];
        match self.protocol {
            Protocol::Tcp => {
                let header_len = usize::from(l4[12] >> 4) * 4;
                if header_len < 20 || header_len > l4.len() {
                    return Err(Reject::Length);
                }
            }
            Protocol::Udp => {
                if usize::from(u16::from_be_bytes([l4[4], l4[5]])) != l4.len() {
                    return Err(Reject::Length);
                }
            }
        }
        if ip[12..16] != self.client.ip().octets()
            || ip[16..20] != self.service.ip().octets()
            || u16::from_be_bytes([l4[0], l4[1]]) != self.client.port()
            || u16::from_be_bytes([l4[2], l4[3]]) != self.service.port()
        {
            return Err(Reject::Tuple);
        }
        Ok(&ip[..total_len])
    }

    pub fn eth_header(&self) -> [u8; 14] {
        let mut header = [0; 14];
        header[..6].copy_from_slice(&self.peer_mac);
        header[6..12].copy_from_slice(&self.own_mac);
        header[12..].copy_from_slice(&[0x08, 0x00]);
        header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::xdp::{INLINE_VLAN, METADATA_LEN, METADATA_VERSION};

    #[test]
    fn general_decoder_keeps_vlan_and_fragmented_scatter_gather() {
        let capture = GeneralCapture {
            authority: CaptureAuthority {
                namespace_cookie: 1,
                attachment_generation: 2,
                scope: 3,
                config_generation: 4,
                ifindex: 5,
                reserved: 0,
            },
            bypass_mark: 128,
            vlan_metadata: true,
        };
        for ipv6 in [false, true] {
            let ip_len = if ipv6 { 48 } else { 28 };
            let mut bytes = vec![0; 18 + ip_len];
            bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
            bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
            bytes[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            bytes[14..16].copy_from_slice(&123u16.to_be_bytes());
            let ether_type: u16 = if ipv6 { 0x86dd } else { 0x0800 };
            bytes[16..18].copy_from_slice(&ether_type.to_be_bytes());
            bytes[18] = if ipv6 { 0x60 } else { 0x45 };
            if ipv6 {
                bytes[22..24].copy_from_slice(&8u16.to_be_bytes());
                bytes[24] = 44;
                bytes[58] = 17;
                bytes[60..62].copy_from_slice(&8u16.to_be_bytes());
            } else {
                bytes[20..22].copy_from_slice(&(ip_len as u16).to_be_bytes());
                bytes[24..26].copy_from_slice(&1u16.to_be_bytes());
                bytes[27] = 17;
            }
            let mut meta = [0u8; METADATA_LEN];
            meta[..2].copy_from_slice(&METADATA_VERSION.to_ne_bytes());
            meta[2..4].copy_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
            meta[4..8].copy_from_slice(&(INLINE_VLAN | RX_VLAN_CHECKED).to_ne_bytes());
            meta[8..12].copy_from_slice(&7u32.to_ne_bytes());
            meta[12..16].copy_from_slice(&5u32.to_ne_bytes());
            meta[16..18].copy_from_slice(&18u16.to_ne_bytes());
            meta[18..20].copy_from_slice(&ether_type.to_ne_bytes());
            meta[20..22].copy_from_slice(&123u16.to_ne_bytes());
            meta[24..26].copy_from_slice(&0x8100u16.to_ne_bytes());
            meta[28..30].copy_from_slice(&1u16.to_ne_bytes());
            meta[30..32].copy_from_slice(&1u16.to_ne_bytes());
            let wire_only = GeneralCapture {
                vlan_metadata: false,
                ..capture.clone()
            };
            for length in 0..METADATA_LEN {
                assert_eq!(
                    capture.decode(&[&bytes], &meta[..length], 7),
                    Err(DecodeError::Metadata)
                );
            }
            for bad in [&meta[..], &meta[..1], &[0xff; METADATA_LEN][..]] {
                assert_eq!(
                    wire_only.decode(&[&bytes], bad, 7),
                    Err(DecodeError::Metadata)
                );
            }
            let invalid = GeneralCapture {
                authority: CaptureAuthority {
                    namespace_cookie: 0,
                    ..wire_only.authority
                },
                ..wire_only.clone()
            };
            assert_eq!(
                invalid.decode(&[&bytes], &[], 7),
                Err(DecodeError::Authority)
            );
            for split in 0..bytes.len() {
                let packet = capture
                    .decode(&[&bytes[..split], &bytes[split..]], &meta, 7)
                    .unwrap();
                assert_eq!((packet.l3_offset, packet.l3_len), (18, ip_len));
                assert_eq!(packet.vlan_tci, [123, 0]);
                let wire = wire_only
                    .decode(&[&bytes[..split], &bytes[split..]], &[], 7)
                    .unwrap();
                assert_eq!(wire, packet);
            }
            bytes[6] = 3;
            assert_eq!(
                capture.decode(&[&bytes], &meta, 7),
                Err(DecodeError::Ethernet)
            );
            bytes[6] = 2;
            assert_eq!(
                capture.decode(&[&bytes], &meta, 8),
                Err(DecodeError::Authority)
            );
            meta[20] ^= 1;
            assert_eq!(
                capture.decode(&[&bytes], &meta, 7),
                Err(DecodeError::Metadata)
            );
        }
    }

    #[test]
    fn recovered_outer_vlan_keeps_logical_identity_separate_from_inline_offset() {
        let capture = GeneralCapture {
            authority: CaptureAuthority {
                namespace_cookie: 1,
                attachment_generation: 2,
                scope: 3,
                config_generation: 4,
                ifindex: 5,
                reserved: 0,
            },
            bypass_mark: 128,
            vlan_metadata: true,
        };
        let protocols = [0x88a8u16, 0x8100, 0x8100];
        let tags = [0xb02cu16, 0x602d, 46];
        for hidden in 0..=1usize {
            for inline in 0..=3usize - hidden {
                let count = inline + hidden;
                let offset = 14 + inline * 4;
                let mut bytes = vec![0; offset + 28];
                bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
                bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
                for index in 0..inline {
                    let start = 12 + index * 4;
                    bytes[start..start + 2]
                        .copy_from_slice(&protocols[hidden + index].to_be_bytes());
                    bytes[start + 2..start + 4]
                        .copy_from_slice(&tags[hidden + index].to_be_bytes());
                }
                bytes[offset - 2..offset].copy_from_slice(&0x0800u16.to_be_bytes());
                bytes[offset] = 0x45;
                bytes[offset + 2..offset + 4].copy_from_slice(&28u16.to_be_bytes());
                let flags = RX_VLAN_CHECKED
                    | if hidden != 0 { HIDDEN_VLAN } else { 0 }
                    | if inline != 0 { INLINE_VLAN } else { 0 };
                let mut meta = [0u8; METADATA_LEN];
                meta[..2].copy_from_slice(&METADATA_VERSION.to_ne_bytes());
                meta[2..4].copy_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
                meta[4..8].copy_from_slice(&flags.to_ne_bytes());
                meta[8..12].copy_from_slice(&7u32.to_ne_bytes());
                meta[12..16].copy_from_slice(&5u32.to_ne_bytes());
                meta[16..18].copy_from_slice(&(offset as u16).to_ne_bytes());
                meta[18..20].copy_from_slice(&0x0800u16.to_ne_bytes());
                for index in 0..count.min(2) {
                    meta[20 + index * 2..22 + index * 2]
                        .copy_from_slice(&tags[index].to_ne_bytes());
                    meta[24 + index * 2..26 + index * 2]
                        .copy_from_slice(&protocols[index].to_ne_bytes());
                }
                meta[28..30].copy_from_slice(&(count as u16).to_ne_bytes());
                meta[30..32].copy_from_slice(&(inline as u16).to_ne_bytes());
                if count > 2 {
                    assert!(capture.decode(&[&bytes], &meta, 7).is_err());
                    meta[28..30].copy_from_slice(&2u16.to_ne_bytes());
                    meta[30..32].copy_from_slice(&((2 - hidden) as u16).to_ne_bytes());
                    assert_eq!(
                        capture.decode(&[&bytes], &meta, 7),
                        Err(DecodeError::Ethernet)
                    );
                    continue;
                }
                for split in 0..=bytes.len() {
                    let packet = capture
                        .decode(&[&bytes[..split], &bytes[split..]], &meta, 7)
                        .unwrap();
                    assert_eq!(packet.l3_offset, offset);
                    assert_eq!(usize::from(packet.vlan_count), count);
                    assert_eq!(&packet.vlan_tci[..count], &tags[..count]);
                    assert_eq!(&packet.vlan_proto[..count], &protocols[..count]);
                }
                let ip_end = bytes.len();
                for ip_length in [28usize, 40] {
                    bytes.resize(offset + ip_length, 0);
                    bytes[offset + 2..offset + 4]
                        .copy_from_slice(&(ip_length as u16).to_be_bytes());
                    bytes[offset + 9] = if ip_length == 40 { 6 } else { 17 };
                    if ip_length == 40 {
                        bytes[offset + 32] = 0x50;
                        bytes[offset + 33] = 0x10;
                    }
                    bytes.resize(60 + 4 * inline, 0xa5);
                    for split in 0..=bytes.len() {
                        let packet = capture
                            .decode(&[&bytes[..split], &bytes[split..]], &meta, 7)
                            .unwrap();
                        assert_eq!((packet.l3_offset, packet.l3_len), (offset, ip_length));
                        assert_eq!(usize::from(packet.vlan_count), count);
                    }
                    bytes.push(0);
                    assert_eq!(capture.decode(&[&bytes], &meta, 7), Err(DecodeError::Ip));
                }
                bytes.truncate(ip_end);
                bytes[offset + 2..offset + 4].copy_from_slice(&28u16.to_be_bytes());
                let mut no_proof = capture.clone();
                no_proof.vlan_metadata = false;
                assert_eq!(
                    no_proof.decode(&[&bytes], &meta, 7),
                    Err(DecodeError::Metadata)
                );
                for wrong_flags in [
                    flags ^ RX_VLAN_CHECKED,
                    flags ^ INLINE_VLAN,
                    flags ^ HIDDEN_VLAN,
                    flags | 8,
                ] {
                    let mut bad = meta;
                    bad[4..8].copy_from_slice(&wrong_flags.to_ne_bytes());
                    assert_eq!(
                        capture.decode(&[&bytes], &bad, 7),
                        Err(DecodeError::Metadata)
                    );
                }
                if hidden != 0 {
                    let mut bad = meta;
                    bad[24..26].copy_from_slice(&0x9100u16.to_ne_bytes());
                    assert_eq!(
                        capture.decode(&[&bytes], &bad, 7),
                        Err(DecodeError::Metadata)
                    );
                    bad = meta;
                    bad[16..18].copy_from_slice(&((offset + 4) as u16).to_ne_bytes());
                    assert_eq!(
                        capture.decode(&[&bytes], &bad, 7),
                        Err(DecodeError::Metadata)
                    );
                }
                if hidden == 0 || inline != 0 {
                    let mut bad = meta;
                    bad[20 + hidden * 2] ^= 1;
                    assert_eq!(
                        capture.decode(&[&bytes], &bad, 7),
                        Err(DecodeError::Metadata)
                    );
                }
            }
        }
    }

    fn capture(protocol: Protocol) -> Capture {
        Capture {
            protocol,
            client: "10.10.10.251:41000".parse().unwrap(),
            service: "10.10.10.252:42000".parse().unwrap(),
            own_mac: [0x58, 0x47, 0xca, 0x74, 0xec, 0x9d],
            peer_mac: [0xba, 0xda, 0x2e, 0x00, 0x76, 0xa0],
        }
    }

    fn frame(capture: &Capture, payload: usize) -> Vec<u8> {
        let l4_len = match capture.protocol {
            Protocol::Tcp => 20,
            Protocol::Udp => 8,
        } + payload;
        let mut frame = vec![0; 34 + l4_len];
        frame[..6].copy_from_slice(&capture.own_mac);
        frame[6..12].copy_from_slice(&capture.peer_mac);
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((20 + l4_len) as u16).to_be_bytes());
        frame[23] = capture.protocol.number();
        frame[26..30].copy_from_slice(&capture.client.ip().octets());
        frame[30..34].copy_from_slice(&capture.service.ip().octets());
        frame[34..36].copy_from_slice(&capture.client.port().to_be_bytes());
        frame[36..38].copy_from_slice(&capture.service.port().to_be_bytes());
        match capture.protocol {
            Protocol::Tcp => frame[46] = 0x50,
            Protocol::Udp => frame[38..40].copy_from_slice(&(l4_len as u16).to_be_bytes()),
        }
        frame
    }

    #[test]
    fn empty_udp_trims_only_minimum_ethernet_padding() {
        let capture = capture(Protocol::Udp);
        let mut frame = frame(&capture, 0);
        assert_eq!(frame.len(), 42);
        assert_eq!(capture.rx_ip(&frame).unwrap().len(), 28);
        frame.resize(60, 0xa5);
        assert_eq!(capture.rx_ip(&frame).unwrap(), &frame[14..42]);
        frame.push(0);
        assert_eq!(capture.rx_ip(&frame), Err(Reject::Padding));
        let mut large = self::frame(&capture, 32);
        assert!(capture.rx_ip(&large).is_ok());
        large.push(0);
        assert_eq!(capture.rx_ip(&large), Err(Reject::Padding));
    }

    #[test]
    fn exact_tuple_options_fragments_and_l4_extents() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let capture = capture(protocol);
            let valid = frame(&capture, 0);
            assert!(capture.rx_ip(&valid).is_ok());
            for offset in [26, 30, 34, 36] {
                let mut altered = valid.clone();
                altered[offset] ^= 1;
                assert_eq!(capture.rx_ip(&altered), Err(Reject::Tuple));
            }
            let mut altered = valid.clone();
            altered[14] = 0x46;
            assert_eq!(capture.rx_ip(&altered), Err(Reject::Options));
            for fragment in [0x2000u16, 1, 0x2001] {
                altered = valid.clone();
                altered[20..22].copy_from_slice(&fragment.to_be_bytes());
                assert_eq!(capture.rx_ip(&altered), Err(Reject::Fragment));
            }
            altered = valid.clone();
            altered[20] = 0x40;
            assert!(capture.rx_ip(&altered).is_ok());
            altered = valid.clone();
            altered[23] ^= 1;
            assert_eq!(capture.rx_ip(&altered), Err(Reject::Protocol));
            altered = valid.clone();
            altered.pop();
            assert_eq!(capture.rx_ip(&altered), Err(Reject::Length));
            altered = valid.clone();
            match protocol {
                Protocol::Tcp => altered[46] = 0x40,
                Protocol::Udp => altered[39] = 7,
            }
            assert_eq!(capture.rx_ip(&altered), Err(Reject::Length));
        }
    }

    #[test]
    fn ethernet_context_and_rejection_indices_are_exact() {
        let capture = capture(Protocol::Udp);
        let header = capture.eth_header();
        assert_eq!(&header[..6], &capture.peer_mac);
        assert_eq!(&header[6..12], &capture.own_mac);
        assert_eq!(&header[12..], &[8, 0]);
        let valid = frame(&capture, 0);
        for (offset, reason) in [
            (0, Reject::DestinationMac),
            (6, Reject::SourceMac),
            (12, Reject::EtherType),
        ] {
            let mut altered = valid.clone();
            altered[offset] ^= 1;
            assert_eq!(capture.rx_ip(&altered), Err(reason));
        }
        for length in 0..14 {
            assert_eq!(capture.rx_ip(&valid[..length]), Err(Reject::ShortEthernet));
        }
        for length in 14..34 {
            assert_eq!(capture.rx_ip(&valid[..length]), Err(Reject::ShortIpv4));
        }
        for (index, reason) in Reject::ALL.iter().enumerate() {
            assert_eq!(reason.index(), index);
            assert!(!reason.as_str().is_empty());
        }
    }
}
