//! Temporary, opt-in issue #415 evidence; never an input to packet decisions.

use aya_ebpf::{
    btf_maps::{Array, PerCpuArray},
    macros::btf_map,
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns};

use crate::transport::ParsedPacket;

#[repr(C)]
struct Filter {
    ifindex: u32,
    source_port: u32,
}

#[btf_map]
static WAN_DIAG_CFG: Array<Filter, 1> = Array::new();

#[repr(C)]
struct Sample {
    packets: u64,
    timestamp_ns: u64,
    socket_cookie: u64,
    ifindex: u32,
    ingress_ifindex: u32,
    mark: u32,
    protocol: u32,
    length: u32,
    parse_result: i32,
    link_h_len: u32,
    tuple_valid: u32,
    l4proto: u32,
    source_port: u32,
    destination_port: u32,
    first_byte: i32,
    source: [u8; 16],
    destination: [u8; 16],
}

#[btf_map]
static WAN_DIAG: PerCpuArray<Sample, 13> = PerCpuArray::new();

#[repr(u32)]
pub(super) enum Reason {
    ScratchUnavailable,
    ParsePass,
    ParseDrop,
    QueueCarrierDrop,
    VlanPass,
    NotReadyPass,
    SpecialPass,
    LocalDestinationPass,
    ForwardedPass,
    MarkedPass,
    TupleFenceDrop,
    TcpAcquireDrop,
    Dispatch,
}

#[inline(never)]
pub(super) fn record(
    ctx: &TcContext,
    packet: Option<&ParsedPacket>,
    link_h_len: u32,
    reason: Reason,
    parse_result: i32,
) {
    let Some(filter) = WAN_DIAG_CFG.get(0) else {
        return;
    };
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if filter.ifindex == 0
        || filter.ifindex != ifindex
        || filter.source_port == 0
        || filter.source_port > u16::MAX as u32
    {
        return;
    }
    if let Some(packet) = packet
        && u32::from(packet.tuples.five.src_port) != filter.source_port
    {
        return;
    }
    let Some(sample) = WAN_DIAG.get_ptr_mut(reason as u32) else {
        return;
    };
    let sample = unsafe { &mut *sample };
    sample.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    sample.socket_cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb.cast()) };
    sample.ifindex = ifindex;
    sample.ingress_ifindex = unsafe { (*ctx.skb.skb).ingress_ifindex };
    sample.mark = unsafe { (*ctx.skb.skb).mark };
    sample.protocol = u32::from(u16::from_be(ctx.skb.protocol() as u16));
    sample.length = ctx.len();
    sample.parse_result = parse_result;
    sample.link_h_len = link_h_len;
    sample.first_byte = ctx.load::<u8>(link_h_len as usize).map_or(-1, i32::from);
    // Failed parses leave scratch fields from an earlier packet; never export them.
    sample.tuple_valid = u32::from(packet.is_some());
    sample.l4proto = 0;
    sample.source_port = 0;
    sample.destination_port = 0;
    sample.source = [0; 16];
    sample.destination = [0; 16];
    if let Some(packet) = packet {
        sample.l4proto = u32::from(packet.l4proto);
        sample.source_port = u32::from(packet.tuples.five.src_port);
        sample.destination_port = u32::from(packet.tuples.five.dst_port);
        sample.source = unsafe { packet.tuples.five.src_ip.u6_addr8 };
        sample.destination = unsafe { packet.tuples.five.dst_ip.u6_addr8 };
    }
    sample.packets = sample.packets.wrapping_add(1);
}
