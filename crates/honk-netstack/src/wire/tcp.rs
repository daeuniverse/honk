use std::net::IpAddr;

use super::checksum::Checksum;
use super::{PROTO_TCP, ParseError, emit_ip_header};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

const FIXED_LEN: usize = 20;
const MAX_OPTIONS: usize = 40;
const MAX_SACK_BLOCKS: usize = 4;
const MAX_WSCALE: u8 = 14;

const KIND_EOL: u8 = 0;
const KIND_NOP: u8 = 1;
const KIND_MSS: u8 = 2;
const KIND_WS: u8 = 3;
const KIND_SACK_PERMITTED: u8 = 4;
const KIND_SACK: u8 = 5;
const KIND_TS: u8 = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SackBlocks {
    n: u8,
    blocks: [(u32, u32); MAX_SACK_BLOCKS],
}

impl SackBlocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns false when all four slots are taken.
    pub fn push(&mut self, left: u32, right: u32) -> bool {
        if usize::from(self.n) == MAX_SACK_BLOCKS {
            return false;
        }
        self.blocks[usize::from(self.n)] = (left, right);
        self.n += 1;
        true
    }

    pub fn as_slice(&self) -> &[(u32, u32)] {
        &self.blocks[..usize::from(self.n)]
    }

    pub fn len(&self) -> usize {
        usize::from(self.n)
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    /// `(tsval, tsecr)`.
    pub timestamps: Option<(u32, u32)>,
    pub sack: SackBlocks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub urgent: u16,
    pub options: Options,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Returns the header and the payload offset (the data offset in bytes).
pub fn parse(seg: &[u8]) -> Result<(Header, usize), ParseError> {
    if seg.len() < FIXED_LEN {
        return Err(ParseError::Malformed);
    }
    let data_off = usize::from(seg[12] >> 4) * 4;
    if data_off < FIXED_LEN || data_off > seg.len() {
        return Err(ParseError::Malformed);
    }
    let hdr = Header {
        src_port: u16::from_be_bytes([seg[0], seg[1]]),
        dst_port: u16::from_be_bytes([seg[2], seg[3]]),
        seq: be32(&seg[4..8]),
        ack: be32(&seg[8..12]),
        flags: seg[13],
        window: u16::from_be_bytes([seg[14], seg[15]]),
        urgent: u16::from_be_bytes([seg[18], seg[19]]),
        options: parse_options(&seg[FIXED_LEN..data_off]),
    };
    Ok((hdr, data_off))
}

/// Lenient per RFC 9293 §3.1: a broken option ends parsing but keeps what was already read.
fn parse_options(mut opts: &[u8]) -> Options {
    let mut o = Options::default();
    let mut seen_sack = false;
    while let Some((&kind, rest)) = opts.split_first() {
        match kind {
            KIND_EOL => break,
            KIND_NOP => {
                opts = rest;
                continue;
            }
            _ => {}
        }
        let Some(&len) = rest.first() else { break };
        let len = usize::from(len);
        if len < 2 || len > opts.len() {
            break;
        }
        let body = &opts[2..len];
        match (kind, len) {
            (KIND_MSS, 4) if o.mss.is_none() => {
                o.mss = Some(u16::from_be_bytes([body[0], body[1]]))
            }
            (KIND_WS, 3) if o.wscale.is_none() => o.wscale = Some(body[0].min(MAX_WSCALE)),
            (KIND_SACK_PERMITTED, 2) => o.sack_permitted = true,
            (KIND_TS, 10) if o.timestamps.is_none() => {
                o.timestamps = Some((be32(&body[..4]), be32(&body[4..])));
            }
            (KIND_SACK, 10 | 18 | 26 | 34) if !seen_sack => {
                seen_sack = true;
                for b in body.as_chunks::<8>().0 {
                    o.sack.push(be32(&b[..4]), be32(&b[4..]));
                }
            }
            _ => {}
        }
        opts = &opts[len..];
    }
    o
}

pub fn verify_checksum(src: IpAddr, dst: IpAddr, seg: &[u8]) -> bool {
    if src.is_ipv4() != dst.is_ipv4() || (src.is_ipv4() && seg.len() > usize::from(u16::MAX)) {
        return false;
    }
    let mut c = Checksum::pseudo(src, dst, PROTO_TCP, seg.len());
    c.add(seg);
    c.finish() == 0
}

/// Writes the options area, zero (EOL) padded to a multiple of four, and returns its length.
///
/// SYN segments carry MSS, SACK-permitted, timestamps and NOP+window scale in that order,
/// emitting only what is set. Established segments carry `NOP NOP TS` followed by
/// `NOP NOP SACK` with as many blocks as the 40-byte budget leaves room for.
fn write_options(o: &Options, syn: bool, buf: &mut [u8]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8]| {
        buf[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    if syn {
        if let Some(mss) = o.mss {
            put(&[KIND_MSS, 4]);
            put(&mss.to_be_bytes());
        }
        if o.sack_permitted {
            put(&[KIND_SACK_PERMITTED, 2]);
        }
        if let Some((val, ecr)) = o.timestamps {
            put(&[KIND_TS, 10]);
            put(&val.to_be_bytes());
            put(&ecr.to_be_bytes());
        }
        if let Some(ws) = o.wscale {
            put(&[KIND_NOP, KIND_WS, 3, ws]);
        }
    } else {
        let mut room = MAX_OPTIONS - 4;
        if let Some((val, ecr)) = o.timestamps {
            put(&[KIND_NOP, KIND_NOP, KIND_TS, 10]);
            put(&val.to_be_bytes());
            put(&ecr.to_be_bytes());
            room -= 12;
        }
        let k = o.sack.len().min(room / 8);
        if k > 0 {
            put(&[KIND_NOP, KIND_NOP, KIND_SACK, (2 + 8 * k) as u8]);
            for &(l, r) in &o.sack.as_slice()[..k] {
                put(&l.to_be_bytes());
                put(&r.to_be_bytes());
            }
        }
    }
    n.next_multiple_of(4)
}

pub fn header_len(opts: &Options, syn: bool) -> usize {
    let len = if syn {
        usize::from(opts.mss.is_some()) * 4
            + usize::from(opts.sack_permitted) * 2
            + usize::from(opts.timestamps.is_some()) * 10
            + usize::from(opts.wscale.is_some()) * 4
    } else {
        let tslen = usize::from(opts.timestamps.is_some()) * 12;
        let blocks = opts.sack.len().min((MAX_OPTIONS - tslen - 4) / 8);
        tslen + if blocks == 0 { 0 } else { 4 + 8 * blocks }
    };
    FIXED_LEN + len.next_multiple_of(4)
}

/// Builds a complete IP packet; the SYN option layout is used iff `hdr.flags` has SYN.
pub fn emit_packet(
    out: &mut [u8],
    src: IpAddr,
    dst: IpAddr,
    hdr: &Header,
    payload: [&[u8]; 2],
) -> Option<usize> {
    let syn = hdr.flags & SYN != 0;
    let hlen = header_len(&hdr.options, syn);
    let seg_len = hlen
        .checked_add(payload[0].len())?
        .checked_add(payload[1].len())?;
    let iplen = emit_ip_header(out, src, dst, PROTO_TCP, seg_len)?;
    let total = iplen + seg_len;
    let seg = out.get_mut(iplen..total)?;

    seg[0..2].copy_from_slice(&hdr.src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&hdr.dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&hdr.seq.to_be_bytes());
    seg[8..12].copy_from_slice(&hdr.ack.to_be_bytes());
    seg[12] = ((hlen / 4) as u8) << 4;
    seg[13] = hdr.flags;
    seg[14..16].copy_from_slice(&hdr.window.to_be_bytes());
    seg[16..18].copy_from_slice(&[0, 0]);
    seg[18..20].copy_from_slice(&hdr.urgent.to_be_bytes());
    seg[FIXED_LEN..hlen].fill(0);
    let olen = write_options(&hdr.options, syn, &mut seg[FIXED_LEN..hlen]);
    debug_assert_eq!(hlen, FIXED_LEN + olen);

    let mut ck = Checksum::pseudo(src, dst, PROTO_TCP, seg_len);
    let (head, body) = seg.split_at_mut(hlen);
    ck.add(head);
    let (b0, b1) = body.split_at_mut(payload[0].len());
    ck.copy_add(b0, payload[0]);
    ck.copy_add(b1, payload[1]);
    head[16..18].copy_from_slice(&ck.finish().to_be_bytes());
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::super::{PROTO_TCP, parse_ip};
    use super::*;

    fn base() -> Header {
        Header {
            src_port: 40_000,
            dst_port: 443,
            seq: 0xDEAD_BEEF,
            ack: 0x0102_0304,
            flags: ACK | PSH,
            window: 0xFFF0,
            urgent: 0,
            options: Options::default(),
        }
    }

    fn emit(src: IpAddr, dst: IpAddr, hdr: &Header, p: [&[u8]; 2]) -> Vec<u8> {
        let mut out = vec![0u8; 2000];
        let n = emit_packet(&mut out, src, dst, hdr, p).unwrap();
        out.truncate(n);
        out
    }

    fn pairs() -> [(IpAddr, IpAddr); 2] {
        [(v4(10, 0, 0, 1), v4(10, 0, 0, 2)), (v6(1), v6(2))]
    }

    fn sack3() -> SackBlocks {
        let mut s = SackBlocks::new();
        assert!(s.push(100, 200));
        assert!(s.push(300, 400));
        assert!(s.push(500, 600));
        s
    }

    #[test]
    fn sack_blocks_capacity() {
        let mut s = SackBlocks::new();
        assert!(s.is_empty());
        for i in 0..4 {
            assert!(s.push(i, i + 1));
        }
        assert!(!s.push(9, 10));
        assert_eq!(s.len(), 4);
        assert_eq!(s.as_slice()[3], (3, 4));
    }

    #[test]
    fn syn_full_roundtrip() {
        let mut h = base();
        h.flags = SYN;
        h.ack = 0;
        h.options = Options {
            mss: Some(1460),
            wscale: Some(7),
            sack_permitted: true,
            timestamps: Some((0x1111_2222, 0)),
            sack: SackBlocks::new(),
        };
        assert_eq!(header_len(&h.options, true), 40);
        for (s, d) in pairs() {
            let pkt = emit(s, d, &h, [&[], &[]]);
            let ip = parse_ip(&pkt).unwrap();
            let seg = &pkt[ip.payload.clone()];
            assert!(verify_checksum(s, d, seg));
            let (got, off) = parse(seg).unwrap();
            assert_eq!(got, h);
            assert_eq!(off, 40);
            assert_eq!(seg.len(), 40);
        }
    }

    #[test]
    fn syn_emits_only_what_is_set() {
        let mut o = Options::default();
        assert_eq!(header_len(&o, true), 20);
        o.mss = Some(536);
        assert_eq!(header_len(&o, true), 24);
        o.wscale = Some(3);
        assert_eq!(header_len(&o, true), 28);
        o = Options {
            sack_permitted: true,
            ..Options::default()
        };
        assert_eq!(header_len(&o, true), 24, "2 bytes padded to 4");
        let mut h = base();
        h.flags = SYN | ACK;
        h.options = o;
        let pkt = emit(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &h, [&[], &[]]);
        let (got, _) = parse(&pkt[20..]).unwrap();
        assert_eq!(got.options, o);
    }

    #[test]
    fn syn_linux_option_order() {
        let mut h = base();
        h.flags = SYN;
        h.options = Options {
            mss: Some(1400),
            wscale: Some(9),
            sack_permitted: true,
            timestamps: Some((1, 2)),
            sack: SackBlocks::new(),
        };
        let pkt = emit(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &h, [&[], &[]]);
        let o = &pkt[40..60];
        assert_eq!(&o[..2], &[2, 4]);
        assert_eq!(&o[4..6], &[4, 2]);
        assert_eq!(&o[6..8], &[8, 10]);
        assert_eq!(&o[16..], &[1, 3, 3, 9]);
    }

    #[test]
    fn data_layout_ts_plus_three_sack_blocks() {
        let mut h = base();
        h.options.timestamps = Some((7, 9));
        h.options.sack = sack3();
        assert_eq!(header_len(&h.options, false), 60);
        for (s, d) in pairs() {
            let pkt = emit(s, d, &h, [b"data", &[]]);
            let ip = parse_ip(&pkt).unwrap();
            let seg = &pkt[ip.payload];
            let o = &seg[20..60];
            assert_eq!(&o[..4], &[1, 1, 8, 10]);
            assert_eq!(&o[12..16], &[1, 1, 5, 26]);
            assert!(verify_checksum(s, d, seg));
            let (got, off) = parse(seg).unwrap();
            assert_eq!(off, 60);
            assert_eq!(&seg[off..], b"data");
            assert_eq!(got, h);
        }
    }

    #[test]
    fn data_layout_four_sack_blocks_without_ts() {
        let mut h = base();
        h.options.sack = sack3();
        h.options.sack.push(700, 800);
        assert_eq!(header_len(&h.options, false), 56);
        let pkt = emit(v6(1), v6(2), &h, [&[], &[]]);
        let (got, off) = parse(&pkt[40..]).unwrap();
        assert_eq!(off, 56);
        assert_eq!(got.options.sack.as_slice().len(), 4);
        assert_eq!(got, h);
    }

    #[test]
    fn excess_sack_blocks_dropped_and_header_never_exceeds_60() {
        let mut h = base();
        h.options.timestamps = Some((1, 2));
        h.options.sack = sack3();
        h.options.sack.push(700, 800);
        h.options.mss = Some(1000);
        h.options.wscale = Some(5);
        h.options.sack_permitted = true;
        assert_eq!(header_len(&h.options, false), 60);
        let pkt = emit(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &h, [b"x", &[]]);
        let (got, off) = parse(&pkt[20..]).unwrap();
        assert_eq!(off, 60);
        assert_eq!(
            got.options.sack.as_slice(),
            &[(100, 200), (300, 400), (500, 600)]
        );
        assert_eq!(
            got.options.mss, None,
            "SYN-only fields not on data segments"
        );
        assert_eq!(got.options.timestamps, Some((1, 2)));
    }

    #[test]
    fn odd_first_payload_slice_checksum_matches_naive() {
        let mut rng = Rng::new(5);
        for (s, d) in pairs() {
            for (a, b) in [
                (1usize, 0usize),
                (1, 1),
                (3, 4),
                (5, 7),
                (0, 9),
                (8, 3),
                (101, 100),
            ] {
                let (p0, p1) = (rng.bytes(a), rng.bytes(b));
                let mut h = base();
                h.options.timestamps = Some((rng.next() as u32, rng.next() as u32));
                let pkt = emit(s, d, &h, [&p0, &p1]);
                let ip = parse_ip(&pkt).unwrap();
                let seg = &pkt[ip.payload];
                let mut want = pseudo_bytes(s, d, PROTO_TCP, seg.len());
                want.extend_from_slice(seg);
                assert_eq!(naive_checksum(&want), 0, "{a}+{b}");
                assert!(verify_checksum(s, d, seg));
                let (_, off) = parse(seg).unwrap();
                let mut joined = p0.clone();
                joined.extend_from_slice(&p1);
                assert_eq!(&seg[off..], &joined[..]);
            }
        }
    }

    #[test]
    fn flipped_byte_detected() {
        let (s, d) = (v4(1, 1, 1, 1), v4(2, 2, 2, 2));
        let pkt = emit(s, d, &base(), [b"abcdef", &[]]);
        let seg = &pkt[20..];
        assert!(verify_checksum(s, d, seg));
        for i in 0..seg.len() {
            let mut bad = seg.to_vec();
            bad[i] ^= 0x10;
            assert!(!verify_checksum(s, d, &bad), "byte {i}");
        }
        assert!(
            !verify_checksum(s, v4(2, 2, 2, 3), seg),
            "pseudo header covers addresses"
        );
        assert!(!verify_checksum(s, v6(2), seg), "family mismatch");
    }

    #[test]
    fn emit_none_cases() {
        let (s, d) = (v4(1, 1, 1, 1), v4(2, 2, 2, 2));
        let need = 20 + 20 + 5;
        let mut out = vec![0u8; need];
        assert_eq!(
            emit_packet(&mut out, s, d, &base(), [b"ab", b"cde"]),
            Some(need)
        );
        assert_eq!(
            emit_packet(&mut out[..need - 1], s, d, &base(), [b"ab", b"cde"]),
            None
        );
        assert_eq!(emit_packet(&mut out, s, v6(1), &base(), [&[], &[]]), None);
        let big = vec![0u8; 65_536];
        let mut huge = vec![0u8; 70_000];
        assert_eq!(emit_packet(&mut huge, s, d, &base(), [&big, &[]]), None);
    }

    #[test]
    fn urgent_and_flags_pass_through() {
        let mut h = base();
        h.flags = 0xFF;
        h.urgent = 0xABCD;
        let pkt = emit(v4(1, 1, 1, 1), v4(2, 2, 2, 2), &h, [&[], &[]]);
        let (got, _) = parse(&pkt[20..]).unwrap();
        assert_eq!(got.flags, 0xFF);
        assert_eq!(got.urgent, 0xABCD);
    }

    fn seg_with_options(opts: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0);
        let mut s = vec![0u8; 20 + opts.len()];
        s[12] = ((s.len() / 4) as u8) << 4;
        s[20..].copy_from_slice(opts);
        s
    }

    #[test]
    fn header_bounds() {
        let mut s = vec![0u8; 19];
        assert_eq!(parse(&s), Err(ParseError::Malformed));
        s = vec![0u8; 20];
        s[12] = 4 << 4;
        assert_eq!(parse(&s), Err(ParseError::Malformed), "offset < 5");
        s[12] = 6 << 4;
        assert_eq!(parse(&s), Err(ParseError::Malformed), "offset > len");
        s[12] = 5 << 4;
        assert_eq!(parse(&s).unwrap().1, 20);
    }

    #[test]
    fn unknown_option_skipped_by_length() {
        let s = seg_with_options(&[99, 4, 0xAA, 0xBB, 2, 4, 5, 0xB4]);
        assert_eq!(parse(&s).unwrap().0.options.mss, Some(1460));
    }

    #[test]
    fn eol_and_bad_lengths_stop_parsing_keeping_prefix() {
        let s = seg_with_options(&[1, 3, 3, 6, 0, 0, 0, 0, 2, 4, 5, 0xB4]);
        let o = parse(&s).unwrap().0.options;
        assert_eq!(o.wscale, Some(6));
        assert_eq!(o.mss, None, "EOL stops");

        let s = seg_with_options(&[3, 3, 6, 1, 99, 0, 2, 4]);
        let o = parse(&s).unwrap().0.options;
        assert_eq!(o.wscale, Some(6));
        assert_eq!(o.mss, None, "zero length stops");

        let s = seg_with_options(&[3, 3, 6, 1, 99, 1, 2, 4]);
        let o = parse(&s).unwrap().0.options;
        assert_eq!(o.wscale, Some(6));
        assert_eq!(o.mss, None, "length 1 stops");

        let s = seg_with_options(&[3, 3, 6, 1, 2, 20, 5, 0xB4]);
        let o = parse(&s).unwrap().0.options;
        assert_eq!(o.wscale, Some(6));
        assert_eq!(o.mss, None, "overrunning length stops");

        let s = seg_with_options(&[1, 1, 1, 2]);
        assert_eq!(
            parse(&s).unwrap().0.options,
            Options::default(),
            "kind without length byte"
        );
    }

    #[test]
    fn wscale_clamped_and_wrong_lengths_ignored() {
        let s = seg_with_options(&[3, 3, 15, 1]);
        assert_eq!(parse(&s).unwrap().0.options.wscale, Some(14));
        let s = seg_with_options(&[3, 3, 200, 1]);
        assert_eq!(parse(&s).unwrap().0.options.wscale, Some(14));
        let s = seg_with_options(&[2, 3, 5, 1]);
        assert_eq!(parse(&s).unwrap().0.options.mss, None, "MSS len 3");
        let s = seg_with_options(&[2, 6, 5, 0xB4, 0, 0, 1, 1]);
        assert_eq!(parse(&s).unwrap().0.options.mss, None, "MSS len 6");
        let s = seg_with_options(&[3, 4, 7, 7]);
        assert_eq!(parse(&s).unwrap().0.options.wscale, None, "WS len 4");
        let s = seg_with_options(&[4, 3, 0, 1]);
        assert!(!parse(&s).unwrap().0.options.sack_permitted);
        let s = seg_with_options(&[8, 6, 0, 0, 0, 0, 1, 1]);
        assert_eq!(parse(&s).unwrap().0.options.timestamps, None, "TS len 6");
    }

    #[test]
    fn duplicate_options_first_wins() {
        let s = seg_with_options(&[2, 4, 0, 100, 2, 4, 0, 200, 3, 3, 4, 1, 3, 3, 9, 1]);
        let o = parse(&s).unwrap().0.options;
        assert_eq!(o.mss, Some(100));
        assert_eq!(o.wscale, Some(4));
        let mut v = vec![8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 9];
        v.extend_from_slice(&[1, 1, 1, 1]);
        let o = parse(&seg_with_options(&v)).unwrap().0.options;
        assert_eq!(o.timestamps, Some((1, 2)));
        let v = [
            1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1, 5, 10, 0, 0, 0, 7, 0, 0, 0, 8,
        ];
        let o = parse(&seg_with_options(&v)).unwrap().0.options;
        assert_eq!(o.sack.as_slice(), &[(1, 2)]);
    }

    #[test]
    fn sack_option_length_rules() {
        let s = seg_with_options(&[1, 1, 5, 9, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert!(
            parse(&s).unwrap().0.options.sack.is_empty(),
            "len 9 not 2+8n"
        );
        let s = seg_with_options(&[1, 1, 5, 2]);
        assert!(
            parse(&s).unwrap().0.options.sack.is_empty(),
            "zero blocks ignored"
        );
        let mut v = vec![5, 34];
        for i in 0..32u8 {
            v.push(i);
        }
        v.extend_from_slice(&[0, 0]);
        let mut seg = vec![0u8; 20];
        seg.extend_from_slice(&v);
        seg[12] = ((seg.len() / 4) as u8) << 4;
        let o = parse(&seg).unwrap().0.options;
        assert_eq!(o.sack.len(), 4);
        assert_eq!(o.sack.as_slice()[0], (0x0001_0203, 0x0405_0607));
    }

    #[test]
    fn every_prefix_never_panics() {
        let mut h = base();
        h.options.timestamps = Some((1, 2));
        h.options.sack = sack3();
        let pkt = emit(v6(1), v6(2), &h, [b"abc", b"de"]);
        for n in 0..=pkt.len() {
            let _ = parse(&pkt[..n]);
            let _ = parse_ip(&pkt[..n]);
            let _ = verify_checksum(v6(1), v6(2), &pkt[..n]);
        }
        let seg = &pkt[40..];
        for n in 0..60 {
            assert!(parse(&seg[..n]).is_err(), "prefix {n}");
        }
        assert!(parse(seg).is_ok());
    }
}
