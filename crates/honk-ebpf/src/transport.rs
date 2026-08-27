use crate::maps::PARSE_CTX_MAP;
use aya_ebpf::{
    bindings::{__be16, __be32},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use core::{ffi::c_long, mem, ptr};
use honk_ebpf_common::{Tuples, conn::ParseTransportCtx, dae_ip::In6Addr};
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

pub const PARSE_FRAGMENT: i32 = 2;
/// Fast-path pull size.  256 bytes covers Ethernet (14) + IPv6 (40) +
/// extension headers (up to ~120) + large TCP options (up to 40).
/// Previously 128 was too small for real-world IPv6 + TCP option combos,
/// causing unnecessary slow-path fallback.
pub const HEADER_PULL_SIZE: u32 = 256;
pub const ETH_HLEN: u32 = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPV6_MAX_EXTENSIONS: usize = 8;

/// True for IPv6 extension headers (hop-by-hop, routing, fragment, destination options).
#[inline(always)]
pub fn is_extension_header(nexthdr: u8) -> bool {
    matches!(
        nexthdr,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_FRAGMENT | IPPROTO_DSTOPTS
    )
}

#[inline(always)]
pub fn ipv6_optlen(hdr_ext_len: u8) -> u32 {
    (hdr_ext_len as u32 + 1) * 8
}

#[inline(always)]
pub fn is_pure_syn(tcph: &TcpHdr) -> bool {
    tcph.syn() != 0 && tcph.ack() == 0
}

/// Return `IPPROTO_TCP` when the TCP segment is a pure SYN (no ACK),
/// or `0` otherwise.  Used by `egress.rs` to populate `cb[1]` for listener
/// assignment at dae0peer ingress.
#[inline(always)]
pub fn tcp_listener_l4proto(tcph: &TcpHdr) -> u8 {
    if is_pure_syn(tcph) { IPPROTO_TCP } else { 0 }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragHdr {
    pub nexthdr: u8,
    pub reserved: u8,
    pub frag_off: __be16,
    pub identification: __be32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParsedPacket {
    pub ethh: EthHdr,
    pub tuples: Tuples,
    pub tcph: TcpHdr,
    pub udph: UdpHdr,
    pub l4proto: u8,
    pub listener_l4proto: u8,
}

/// Malformed packet: invalid header, bad length, too many extension headers.
/// Maps to -EFAULT (14) — drop the packet.
pub const ERR_MALFORMED: c_long = -14;

/// Fast path could not pull enough data; fall back to slow path.
pub const ERR_FALLBACK: c_long = -1;

/// Non-initial IP fragment that lacks L4 header; pass through for kernel reassembly.
pub const ERR_FRAGMENT: c_long = -2;

/// Unsupported L4 protocol; pass through to kernel stack.
pub const ERR_UNKNOWN_PROTO: c_long = -3;

/// Unsupported packet type (not IP); pass through.
pub const PASS_UNSUPPORTED: c_long = 1;

/// Destinations that must never enter routing/conntrack: L2
/// broadcast/multicast, IPv4 limited broadcast + multicast + 0.0.0.0, IPv6
/// multicast. DHCP, mDNS, SSDP and LLMNR ride these — routing them through
/// the proxy breaks LAN service discovery (and DHCP leases on OpenWrt).
/// The L2 check (I/G bit) needs no netmask math and covers subnet-directed
/// broadcasts for free.
#[inline(always)]
pub fn dst_is_special(pkt: &ParsedPacket, link_h_len: u32) -> bool {
    if link_h_len == ETH_HLEN && pkt.ethh.dst_addr[0] & 1 != 0 {
        return true;
    }
    let dst = &pkt.tuples.five.dst_ip;
    if dst.is_v4_mapped() {
        let ip = u32::from_be(unsafe { dst.u6_addr32[3] });
        // 0.0.0.0 / 255.255.255.255 / 224.0.0.0/4
        ip == 0 || ip == 0xFFFFFFFF || (ip & 0xF0000000) == 0xE0000000
    } else {
        // ff00::/8
        (unsafe { dst.u6_addr8[0] }) == 0xFF
    }
}

/// Proxy preliminaries need a userspace domain decision only for QUIC long headers.
#[inline(always)]
pub fn udp_has_quic_long_header(ctx: &TcContext, link_h_len: u32, pkt: &ParsedPacket) -> bool {
    if pkt.l4proto != IPPROTO_UDP {
        return false;
    }

    let skb = ctx.skb.skb as *mut _;
    let mut offset = link_h_len;
    let mut nexthdr = IPPROTO_UDP;

    if pkt.ethh.ether_type == ETH_P_IP.to_be() {
        let mut version_ihl = 0u8;
        if unsafe { bpf_skb_load_bytes(skb, offset, &mut version_ihl as *mut u8 as *mut _, 1) } != 0
        {
            return false;
        }
        let ihl = ((version_ihl & 0x0f) as u32) * 4;
        if ihl < 20 {
            return false;
        }
        offset += ihl;
    } else if pkt.ethh.ether_type == ETH_P_IPV6.to_be() {
        if unsafe { bpf_skb_load_bytes(skb, offset + 6, &mut nexthdr as *mut u8 as *mut _, 1) } != 0
        {
            return false;
        }
        offset += mem::size_of::<Ipv6Hdr>() as u32;

        for _ in 0..IPV6_MAX_EXTENSIONS {
            if nexthdr == IPPROTO_UDP {
                break;
            }
            if nexthdr == IPPROTO_FRAGMENT {
                let mut fragment: FragHdr = unsafe { mem::zeroed() };
                if unsafe {
                    bpf_skb_load_bytes(
                        skb,
                        offset,
                        &mut fragment as *mut FragHdr as *mut _,
                        mem::size_of::<FragHdr>() as u32,
                    )
                } != 0
                {
                    return false;
                }
                nexthdr = fragment.nexthdr;
                offset += mem::size_of::<FragHdr>() as u32;
                continue;
            }
            if !is_extension_header(nexthdr) {
                return false;
            }
            let mut extension = [0u8; 2];
            if unsafe {
                bpf_skb_load_bytes(
                    skb,
                    offset,
                    extension.as_mut_ptr() as *mut _,
                    extension.len() as u32,
                )
            } != 0
            {
                return false;
            }
            nexthdr = extension[0];
            offset += ipv6_optlen(extension[1]);
        }
        if nexthdr != IPPROTO_UDP {
            return false;
        }
    } else {
        return false;
    }

    let mut first = 0u8;
    if unsafe {
        bpf_skb_load_bytes(
            skb,
            offset + mem::size_of::<UdpHdr>() as u32,
            &mut first as *mut u8 as *mut _,
            1,
        )
    } != 0
    {
        return false;
    }
    first & 0x80 != 0
}

trait ParseTransportExt {
    fn parse_fast(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long>;
    fn parse_slow(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long>;
    fn parse(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long>;
    fn fill_tuples(&self, tuples: &mut Tuples);
}

impl ParseTransportExt for ParseTransportCtx {
    #[inline(always)]
    fn parse_slow(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long> {
        let skb_ptr = ctx.skb.skb as *mut _;
        let mut offset = 0u32;
        let mut ret: c_long;

        if link_h_len == ETH_HLEN {
            ret = unsafe {
                bpf_skb_load_bytes(
                    skb_ptr,
                    offset,
                    &mut self.ethh as *mut _ as *mut _,
                    mem::size_of::<EthHdr>() as u32,
                )
            };
            if ret != 0 {
                return Err(PASS_UNSUPPORTED);
            }
            offset += mem::size_of::<EthHdr>() as u32;
        } else {
            unsafe {
                ptr::write_bytes(
                    &mut self.ethh as *mut _ as *mut u8,
                    0,
                    mem::size_of::<EthHdr>(),
                )
            };
            self.ethh.ether_type = ctx.skb.protocol() as u16;
        }

        self.ihl = 0;
        self.l4proto = 0;
        self.listener_l4proto = 0;
        unsafe {
            ptr::write_bytes(
                &mut self.iph as *mut _ as *mut u8,
                0,
                mem::size_of::<Ipv4Hdr>(),
            );
            ptr::write_bytes(
                &mut self.ipv6h as *mut _ as *mut u8,
                0,
                mem::size_of::<Ipv6Hdr>(),
            );
            ptr::write_bytes(
                &mut self.icmp6h as *mut _ as *mut u8,
                0,
                mem::size_of::<Icmpv6Hdr>(),
            );
            ptr::write_bytes(
                &mut self.tcph as *mut _ as *mut u8,
                0,
                mem::size_of::<TcpHdr>(),
            );
            ptr::write_bytes(
                &mut self.udph as *mut _ as *mut u8,
                0,
                mem::size_of::<UdpHdr>(),
            );
        }

        if self.ethh.ether_type == ETH_P_IP.to_be() {
            ret = unsafe {
                bpf_skb_load_bytes(
                    skb_ptr,
                    offset,
                    &mut self.iph as *mut _ as *mut _,
                    mem::size_of::<Ipv4Hdr>() as u32,
                )
            };
            if ret != 0 {
                return Err(ERR_MALFORMED);
            }
            if self.iph.ihl() < 20 {
                return Err(ERR_MALFORMED);
            }
            self.ihl = self.iph.ihl();
            self.l4proto = self.iph.proto;

            let frag_off = u16::from_be(self.iph.frag_offset()) & 0x1FFF;
            if frag_off != 0 {
                return Err(PARSE_FRAGMENT as c_long);
            }

            offset += self.iph.ihl() as u32;

            match self.iph.proto {
                IPPROTO_TCP => {
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut self.tcph as *mut _ as *mut _,
                            mem::size_of::<TcpHdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    self.listener_l4proto = tcp_listener_l4proto(&self.tcph);
                }
                IPPROTO_UDP => {
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut self.udph as *mut _ as *mut _,
                            mem::size_of::<UdpHdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    self.listener_l4proto = IPPROTO_UDP;
                }
                _ => return Err(PASS_UNSUPPORTED),
            }
            return Ok(());
        }

        if self.ethh.ether_type == ETH_P_IPV6.to_be() {
            ret = unsafe {
                bpf_skb_load_bytes(
                    skb_ptr,
                    offset,
                    &mut self.ipv6h as *mut _ as *mut _,
                    mem::size_of::<Ipv6Hdr>() as u32,
                )
            };
            if ret != 0 {
                return Err(ERR_MALFORMED);
            }

            offset += mem::size_of::<Ipv6Hdr>() as u32;
            self.ihl = (mem::size_of::<Ipv6Hdr>() / 4) as u8;
            let mut nexthdr = self.ipv6h.next_hdr;

            for _ in 0..IPV6_MAX_EXTENSIONS {
                if nexthdr == IPPROTO_NONE {
                    return Err(ERR_MALFORMED);
                }
                if nexthdr == IPPROTO_FRAGMENT {
                    let mut fragh: FragHdr = unsafe { mem::zeroed() };
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut fragh as *mut _ as *mut _,
                            mem::size_of::<FragHdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    nexthdr = fragh.nexthdr;
                    self.l4proto = nexthdr;
                    offset += mem::size_of::<FragHdr>() as u32;
                    if (u16::from_be(fragh.frag_off) & 0xFFF8) != 0 {
                        return Err(PARSE_FRAGMENT as c_long);
                    }
                    continue;
                }

                if !is_extension_header(nexthdr) {
                    break;
                }

                {
                    let mut next = 0u8;
                    ret = unsafe {
                        bpf_skb_load_bytes(skb_ptr, offset, &mut next as *mut _ as *mut _, 1)
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    let mut hdr_ext_len = 0u8;
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset + 1,
                            &mut hdr_ext_len as *mut _ as *mut _,
                            1,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    nexthdr = next;
                    offset += ipv6_optlen(hdr_ext_len);
                    self.l4proto = nexthdr;
                }
            }

            if is_extension_header(nexthdr) {
                return Err(ERR_MALFORMED);
            }

            self.l4proto = nexthdr;
            match nexthdr {
                IPPROTO_TCP => {
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut self.tcph as *mut _ as *mut _,
                            mem::size_of::<TcpHdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    self.listener_l4proto = tcp_listener_l4proto(&self.tcph);
                }
                IPPROTO_UDP => {
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut self.udph as *mut _ as *mut _,
                            mem::size_of::<UdpHdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                    self.listener_l4proto = IPPROTO_UDP;
                }
                IPPROTO_ICMPV6 => {
                    ret = unsafe {
                        bpf_skb_load_bytes(
                            skb_ptr,
                            offset,
                            &mut self.icmp6h as *mut _ as *mut _,
                            mem::size_of::<Icmpv6Hdr>() as u32,
                        )
                    };
                    if ret != 0 {
                        return Err(ERR_MALFORMED);
                    }
                }
                _ => return Err(PASS_UNSUPPORTED),
            }
            return Ok(());
        }

        Err(PASS_UNSUPPORTED)
    }

    #[inline(always)]
    fn parse_fast(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long> {
        if ctx.pull_data(HEADER_PULL_SIZE).is_err() {
            return Err(ERR_FALLBACK);
        }

        let data = ctx.data() as *const u8;
        let data_end = ctx.data_end() as *const u8;
        let mut offset = 0u32;

        unsafe {
            ptr::write_bytes(
                self as *mut _ as *mut u8,
                0,
                mem::size_of::<ParseTransportCtx>(),
            );
        }

        if link_h_len == ETH_HLEN {
            let eth_ptr = data as *const EthHdr;
            if unsafe { data.add(mem::size_of::<EthHdr>()) } > data_end {
                return Err(ERR_FALLBACK);
            }
            let eth = unsafe { &*eth_ptr };
            self.ethh.ether_type = eth.ether_type;
            self.ethh.dst_addr.copy_from_slice(&eth.dst_addr);
            self.ethh.src_addr.copy_from_slice(&eth.src_addr);
            offset += mem::size_of::<EthHdr>() as u32;
        } else {
            self.ethh.ether_type = ctx.skb.protocol() as u16;
        }

        if self.ethh.ether_type == ETH_P_IP.to_be() {
            let iph_ptr = unsafe { data.add(offset as usize) as *const Ipv4Hdr };
            if unsafe { data.add(offset as usize + mem::size_of::<Ipv4Hdr>()) } > data_end {
                return Err(ERR_FALLBACK);
            }
            let iph = unsafe { &*iph_ptr };
            if iph.ihl() < 20 {
                return Err(ERR_MALFORMED);
            }

            // Deep-copy the entire IP header struct to preserve bitfield fields
            // that cannot be assigned field-by-field through method getters.
            self.iph = unsafe { ptr::read(iph_ptr) };
            self.ihl = iph.ihl();
            self.l4proto = iph.proto;

            let frag_off = u16::from_be(iph.frag_offset()) & 0x1FFF;
            if frag_off != 0 {
                return Err(PARSE_FRAGMENT as c_long);
            }

            let l4_offset = (offset as usize) + iph.ihl() as usize;

            match iph.proto {
                IPPROTO_TCP => {
                    let tcph_ptr = unsafe { data.add(l4_offset) as *const TcpHdr };
                    if unsafe { data.add(l4_offset + mem::size_of::<TcpHdr>()) } > data_end {
                        return Err(ERR_FALLBACK);
                    }
                    let tcph = unsafe { &*tcph_ptr };
                    self.tcph = unsafe { ptr::read(tcph_ptr) };
                    self.listener_l4proto = tcp_listener_l4proto(tcph);
                    return Ok(());
                }
                IPPROTO_UDP => {
                    let udph_ptr = unsafe { data.add(l4_offset) as *const UdpHdr };
                    if unsafe { data.add(l4_offset + mem::size_of::<UdpHdr>()) } > data_end {
                        return Err(ERR_FALLBACK);
                    }
                    self.udph = unsafe { ptr::read(udph_ptr) };
                    self.listener_l4proto = IPPROTO_UDP;
                    return Ok(());
                }
                _ => return Err(PASS_UNSUPPORTED),
            }
        }

        if self.ethh.ether_type == ETH_P_IPV6.to_be() {
            let ipv6h_ptr = unsafe { data.add(offset as usize) as *const Ipv6Hdr };
            if unsafe { data.add(offset as usize + mem::size_of::<Ipv6Hdr>()) } > data_end {
                return Err(ERR_FALLBACK);
            }
            let ipv6h = unsafe { &*ipv6h_ptr };

            self.ipv6h = unsafe { ptr::read(ipv6h_ptr) };
            self.l4proto = ipv6h.next_hdr;
            self.ihl = (mem::size_of::<Ipv6Hdr>() / 4) as u8;
            offset += mem::size_of::<Ipv6Hdr>() as u32;

            let mut nexthdr = ipv6h.next_hdr;

            for _ in 0..IPV6_MAX_EXTENSIONS {
                if nexthdr == IPPROTO_NONE {
                    return Err(ERR_MALFORMED);
                }
                if nexthdr == IPPROTO_FRAGMENT {
                    let fragh_ptr = unsafe { data.add(offset as usize) as *const FragHdr };
                    if unsafe { data.add(offset as usize + mem::size_of::<FragHdr>()) } > data_end {
                        return Err(ERR_FALLBACK);
                    }
                    let fragh = unsafe { &*fragh_ptr };
                    nexthdr = fragh.nexthdr;
                    self.l4proto = nexthdr;
                    offset += mem::size_of::<FragHdr>() as u32;
                    if (u16::from_be(fragh.frag_off) & 0xFFF8) != 0 {
                        return Err(PARSE_FRAGMENT as c_long);
                    }
                    continue;
                }
                if !is_extension_header(nexthdr) {
                    break;
                }
                let ext_hdr = unsafe { data.add(offset as usize) };
                if unsafe { data.add(offset as usize + 2) } > data_end {
                    return Err(ERR_FALLBACK);
                }
                nexthdr = unsafe { *ext_hdr };
                let hdr_ext_len = unsafe { *ext_hdr.add(1) };
                offset += ipv6_optlen(hdr_ext_len);
                self.l4proto = nexthdr;
            }

            if is_extension_header(nexthdr) {
                return Err(ERR_MALFORMED);
            }

            self.l4proto = nexthdr;
            match nexthdr {
                IPPROTO_TCP => {
                    let tcph_ptr = unsafe { data.add(offset as usize) as *const TcpHdr };
                    if unsafe { data.add(offset as usize + mem::size_of::<TcpHdr>()) } > data_end {
                        return Err(ERR_FALLBACK);
                    }
                    let tcph = unsafe { &*tcph_ptr };
                    self.tcph = unsafe { ptr::read(tcph_ptr) };
                    self.listener_l4proto = tcp_listener_l4proto(tcph);
                    return Ok(());
                }
                IPPROTO_UDP => {
                    let udph_ptr = unsafe { data.add(offset as usize) as *const UdpHdr };
                    if unsafe { data.add(offset as usize + mem::size_of::<UdpHdr>()) } > data_end {
                        return Err(ERR_FALLBACK);
                    }
                    self.udph = unsafe { ptr::read(udph_ptr) };
                    self.listener_l4proto = IPPROTO_UDP;
                    return Ok(());
                }
                IPPROTO_ICMPV6 => {
                    let icmp6h_ptr = unsafe { data.add(offset as usize) as *const Icmpv6Hdr };
                    if unsafe { data.add(offset as usize + mem::size_of::<Icmpv6Hdr>()) } > data_end
                    {
                        return Err(ERR_FALLBACK);
                    }
                    self.icmp6h = unsafe { ptr::read(icmp6h_ptr) };
                    return Ok(());
                }
                _ => return Err(PASS_UNSUPPORTED),
            }
        }

        Err(PASS_UNSUPPORTED)
    }

    #[inline(always)]
    fn parse(&mut self, ctx: &TcContext, link_h_len: u32) -> Result<(), c_long> {
        match self.parse_fast(ctx, link_h_len) {
            Err(ERR_FALLBACK) => self.parse_slow(ctx, link_h_len),
            other => other,
        }
    }

    #[inline(always)]
    fn fill_tuples(&self, tuples: &mut Tuples) {
        unsafe { ptr::write_bytes(tuples as *mut _ as *mut u8, 0, mem::size_of::<Tuples>()) };
        tuples.five.l4proto = self.l4proto;

        if self.iph.version() == 4 {
            tuples.five.src_ip = In6Addr::from_ipv4_bytes(self.iph.src_addr);
            tuples.five.dst_ip = In6Addr::from_ipv4_bytes(self.iph.dst_addr);
            tuples.dscp = self.iph.dscp();
        } else {
            tuples.five.src_ip = In6Addr::from_ipv6_addr(self.ipv6h.src_addr());
            tuples.five.dst_ip = In6Addr::from_ipv6_addr(self.ipv6h.dst_addr());
            tuples.dscp = self.ipv6h.dscp();
        }

        match self.l4proto {
            IPPROTO_TCP => {
                tuples.five.src_port = u16::from_be_bytes(self.tcph.source);
                tuples.five.dst_port = u16::from_be_bytes(self.tcph.dest);
            }
            IPPROTO_UDP => {
                tuples.five.src_port = u16::from_be_bytes(self.udph.src);
                tuples.five.dst_port = u16::from_be_bytes(self.udph.dst);
            }
            _ => {}
        }
    }
}

/// Parse the packet into `out` via the scratch-map-based fast/slow path.
///
/// Flow (mirroring C's `parse_lan_ingress_packet`):
///   1. Obtain `ParseTransportCtx` from `PARSE_CTX_MAP` (PerCpuArray)
///   2. Call `parse_transport` (fast → fallback to slow)
///   3. Copy headers + compute 5-tuple into `ParsedPacket`
#[inline(always)]
pub fn parse_packet(ctx: &TcContext, link_h_len: u32, out: &mut ParsedPacket) -> c_long {
    let scratch_key: u32 = 0;
    let tctx = match PARSE_CTX_MAP.get_ptr_mut(scratch_key) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return ERR_MALFORMED,
    };

    if let Err(e) = tctx.parse(ctx, link_h_len) {
        return e;
    }

    if tctx.l4proto == IPPROTO_ICMPV6 {
        return PASS_UNSUPPORTED;
    }

    *out = unsafe { mem::zeroed() };
    out.ethh = tctx.ethh;
    out.tcph = tctx.tcph;
    out.udph = tctx.udph;
    out.l4proto = tctx.l4proto;
    out.listener_l4proto = tctx.listener_l4proto;
    tctx.fill_tuples(&mut out.tuples);
    0
}
