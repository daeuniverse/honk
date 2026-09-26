use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::time::Duration;

use honk_config::dns::{DnsClientSubnet, DnsConfig};
use ipnet::Ipv4Net;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use tokio::io::Interest;
use tracing::{info, warn};

use super::wire::skip_dns_name;

const ECS_OPTION_CODE: u16 = 8;
const OPT_RECORD_TYPE: u16 = 41;
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;
const PROBE_PORT: u16 = 33434;
const PROBES_PER_TTL: u16 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_TTL_EXCEEDED: u8 = 0;
const MAX_PROBE_TTL: u32 = 12;
const HOP_TIMEOUT: Duration = Duration::from_millis(150);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) async fn resolve_client_subnet(config: &mut DnsConfig) {
    config.resolved_client_subnet = None;
    let mode = match config.client_subnet_mode() {
        Ok(mode) => mode,
        Err(error) => {
            warn!(%error, "ignoring invalid DNS client subnet");
            return;
        }
    };
    match mode {
        None => {}
        Some(DnsClientSubnet::Preset(network)) => {
            config.resolved_client_subnet = Some(network);
            info!(client_subnet = %network, "DNS client subnet preset enabled");
        }
        Some(DnsClientSubnet::Auto { target }) => {
            match tokio::time::timeout(PROBE_TIMEOUT, first_public_hop(target)).await {
                Ok(Ok(Some(address))) => {
                    let network = Ipv4Net::new(address, 24)
                        .expect("IPv4 /24 is valid")
                        .trunc();
                    config.resolved_client_subnet = Some(network);
                    info!(%target, client_subnet = %network, "inferred DNS client subnet");
                }
                Ok(Ok(None)) => {
                    warn!(%target, "DNS client subnet inference found no public hop; ECS disabled");
                }
                Ok(Err(error)) => {
                    warn!(%target, %error, "DNS client subnet inference failed; ECS disabled");
                }
                Err(_) => {
                    warn!(%target, "DNS client subnet inference timed out; ECS disabled");
                }
            }
        }
    }
}

async fn first_public_hop(target: Ipv4Addr) -> io::Result<Option<Ipv4Addr>> {
    let route_socket = probe_socket(target, PROBE_PORT)?;
    if let SocketAddr::V4(local) = route_socket.local_addr()?
        && is_public_ipv4(*local.ip())
    {
        return Ok(Some(*local.ip()));
    }

    for ttl in 1..=MAX_PROBE_TTL {
        // Vary the UDP flow so one ICMP-silent ECMP path cannot promote a later backbone hop.
        let port = PROBE_PORT + (ttl as u16 - 1) * PROBES_PER_TTL;
        let replies = tokio::join!(
            probe_hop(target, port, ttl),
            probe_hop(target, port + 1, ttl),
            probe_hop(target, port + 2, ttl),
        );
        for reply in [replies.0?, replies.1?, replies.2?].into_iter().flatten() {
            if let HopReply::Public(address) = reply {
                return Ok(Some(address));
            }
        }
    }
    Ok(None)
}

fn probe_socket(target: Ipv4Addr, port: u16) -> io::Result<std::net::UdpSocket> {
    let socket = honk_outbound::util::marked_udp_socket(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        0,
    )))?;
    setsockopt(&socket, sockopt::Ipv4RecvErr, &true).map_err(io::Error::from)?;
    socket.connect(SocketAddrV4::new(target, port))?;
    Ok(socket)
}

async fn probe_hop(target: Ipv4Addr, port: u16, ttl: u32) -> io::Result<Option<HopReply>> {
    let socket = probe_socket(target, port)?;
    socket.set_ttl(ttl)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    socket.send(&[0]).await?;
    match tokio::time::timeout(
        HOP_TIMEOUT,
        socket.async_io(Interest::ERROR, || recv_hop(socket.as_raw_fd())),
    )
    .await
    {
        Ok(Ok(reply)) => Ok(Some(reply)),
        Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Ok(Err(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopReply {
    Public(Ipv4Addr),
    Other,
}

fn recv_hop(fd: std::os::fd::RawFd) -> io::Result<HopReply> {
    let mut payload = [0_u8; 1];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let mut cmsg = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in);
    let message = recvmsg::<SockaddrStorage>(
        fd,
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;

    for control in message.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::Ipv4RecvErr(error, Some(offender)) = control
            && error.ee_origin == libc::SO_EE_ORIGIN_ICMP
            && error.ee_type == ICMP_TIME_EXCEEDED
            && error.ee_code == ICMP_TTL_EXCEEDED
        {
            let address = Ipv4Addr::from(offender.sin_addr.s_addr.to_ne_bytes());
            return Ok(if is_public_ipv4(address) {
                HopReply::Public(address)
            } else {
                HopReply::Other
            });
        }
    }
    Ok(HopReply::Other)
}

// The US Department of Defense /8 blocks. Carriers, notably in China, route them inside their own networks as
// private space, so a traceroute there meets them before the first real public hop; and wherever such an address
// comes from, an ECS subnet in it places the client in the US.
const DOD_BLOCKS: [u8; 13] = [6, 7, 11, 21, 22, 26, 28, 29, 30, 33, 55, 214, 215];

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || DOD_BLOCKS.contains(&a)
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EcsWireError {
    #[error("malformed DNS message")]
    Malformed,
    #[error("multiple EDNS OPT records")]
    MultipleOpt,
    #[error("EDNS OPT record is not final")]
    NonFinalOpt,
    #[error("unsupported EDNS OPT record")]
    UnsupportedOpt,
    #[error("DNS message is too large for ECS")]
    TooLarge,
    #[error("upstream returned EDNS state that cannot be hidden")]
    UnsupportedResponseOpt,
    #[error("upstream returned mismatched ECS")]
    MismatchedResponse,
}

pub(crate) struct EcsQuery {
    wire: Vec<u8>,
    original_had_opt: bool,
    expected: ExpectedEcs,
}

#[derive(Clone, Copy)]
struct ExpectedEcs {
    source_prefix: u8,
    address: [u8; 4],
    address_len: usize,
}

#[derive(Clone)]
struct MessageLayout {
    opt: Option<OptRecord>,
    additional_count: u16,
}

#[derive(Clone)]
struct OptRecord {
    start: usize,
    end: usize,
    rdlength_offset: usize,
    rdata: Range<usize>,
    extended_rcode: u8,
    version: u8,
}

impl EcsQuery {
    pub(crate) fn prepare(raw: &[u8], subnet: Ipv4Net) -> Result<Option<Self>, EcsWireError> {
        let layout = message_layout(raw)?;
        let (option, expected) = encode_ecs(subnet);
        let original_had_opt = layout.opt.is_some();
        let wire = if let Some(opt) = layout.opt {
            if opt.end != raw.len() {
                return Err(EcsWireError::NonFinalOpt);
            }
            if opt.version != 0 {
                return Err(EcsWireError::UnsupportedOpt);
            }
            if find_ecs(raw, &opt.rdata)?.is_some() {
                return Ok(None);
            }
            let rdlength = opt.rdata.len();
            let new_rdlength = rdlength
                .checked_add(option.len())
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(EcsWireError::TooLarge)?;
            if raw
                .len()
                .checked_add(option.len())
                .is_none_or(|length| length > u16::MAX as usize)
            {
                return Err(EcsWireError::TooLarge);
            }
            let mut wire = Vec::with_capacity(raw.len() + option.len());
            wire.extend_from_slice(raw);
            wire.extend_from_slice(&option);
            wire[opt.rdlength_offset..opt.rdlength_offset + 2]
                .copy_from_slice(&new_rdlength.to_be_bytes());
            wire
        } else {
            let additional_count = layout
                .additional_count
                .checked_add(1)
                .ok_or(EcsWireError::TooLarge)?;
            let opt_len = 11_usize
                .checked_add(option.len())
                .ok_or(EcsWireError::TooLarge)?;
            if raw
                .len()
                .checked_add(opt_len)
                .is_none_or(|length| length > u16::MAX as usize)
            {
                return Err(EcsWireError::TooLarge);
            }
            let mut wire = Vec::with_capacity(raw.len() + opt_len);
            wire.extend_from_slice(raw);
            wire[10..12].copy_from_slice(&additional_count.to_be_bytes());
            wire.push(0);
            wire.extend_from_slice(&OPT_RECORD_TYPE.to_be_bytes());
            wire.extend_from_slice(&DEFAULT_EDNS_PAYLOAD.to_be_bytes());
            wire.extend_from_slice(&0_u32.to_be_bytes());
            wire.extend_from_slice(&(option.len() as u16).to_be_bytes());
            wire.extend_from_slice(&option);
            wire
        };
        Ok(Some(Self {
            wire,
            original_had_opt,
            expected,
        }))
    }

    pub(crate) fn wire(&self) -> &[u8] {
        &self.wire
    }

    pub(crate) fn restore_response(self, mut response: Vec<u8>) -> Result<Vec<u8>, EcsWireError> {
        let layout = message_layout(&response)?;
        let Some(opt) = layout.opt else {
            return Ok(response);
        };
        if opt.end != response.len() {
            return Err(EcsWireError::NonFinalOpt);
        }
        let ecs = find_ecs(&response, &opt.rdata)?;
        if let Some(ecs) = ecs.as_ref()
            && !ecs_matches(&response[ecs.clone()], self.expected)
        {
            return Err(EcsWireError::MismatchedResponse);
        }

        if !self.original_had_opt && opt.extended_rcode != 0 {
            return Err(EcsWireError::UnsupportedResponseOpt);
        }
        if !self.original_had_opt {
            let additional_count = layout
                .additional_count
                .checked_sub(1)
                .ok_or(EcsWireError::Malformed)?;
            response.truncate(opt.start);
            response[10..12].copy_from_slice(&additional_count.to_be_bytes());
        } else if let Some(ecs) = ecs {
            let option_start = ecs.start.checked_sub(4).ok_or(EcsWireError::Malformed)?;
            let option_length = ecs.len().checked_add(4).ok_or(EcsWireError::Malformed)?;
            let new_rdlength = opt
                .rdata
                .len()
                .checked_sub(option_length)
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(EcsWireError::Malformed)?;
            response.drain(option_start..ecs.end);
            response[opt.rdlength_offset..opt.rdlength_offset + 2]
                .copy_from_slice(&new_rdlength.to_be_bytes());
        }
        Ok(response)
    }
}

fn encode_ecs(subnet: Ipv4Net) -> (Vec<u8>, ExpectedEcs) {
    let source_prefix = subnet.prefix_len();
    let address_len = usize::from(source_prefix).div_ceil(8);
    let address = subnet.network().octets();
    let mut option = Vec::with_capacity(8 + address_len);
    option.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
    option.extend_from_slice(&(4_u16 + address_len as u16).to_be_bytes());
    option.extend_from_slice(&1_u16.to_be_bytes());
    option.push(source_prefix);
    option.push(0);
    option.extend_from_slice(&address[..address_len]);
    (
        option,
        ExpectedEcs {
            source_prefix,
            address,
            address_len,
        },
    )
}

fn ecs_matches(value: &[u8], expected: ExpectedEcs) -> bool {
    value.len() == 4 + expected.address_len
        && value[..2] == 1_u16.to_be_bytes()
        && value[2] == expected.source_prefix
        && value[3] <= 32
        && value[4..] == expected.address[..expected.address_len]
}

fn find_ecs(raw: &[u8], rdata: &Range<usize>) -> Result<Option<Range<usize>>, EcsWireError> {
    let mut cursor = rdata.start;
    let mut ecs = None;
    while cursor < rdata.end {
        if cursor + 4 > rdata.end {
            return Err(EcsWireError::Malformed);
        }
        let code = read_u16(raw, cursor)?;
        let length = usize::from(read_u16(raw, cursor + 2)?);
        let value_start = cursor + 4;
        let value_end = value_start
            .checked_add(length)
            .filter(|end| *end <= rdata.end)
            .ok_or(EcsWireError::Malformed)?;
        if code == ECS_OPTION_CODE {
            if ecs.is_some() {
                return Err(EcsWireError::MismatchedResponse);
            }
            ecs = Some(value_start..value_end);
        }
        cursor = value_end;
    }
    Ok(ecs)
}

fn message_layout(raw: &[u8]) -> Result<MessageLayout, EcsWireError> {
    if raw.len() < 12 {
        return Err(EcsWireError::Malformed);
    }
    let questions = usize::from(read_u16(raw, 4)?);
    let answers = usize::from(read_u16(raw, 6)?);
    let authorities = usize::from(read_u16(raw, 8)?);
    let additional_count = read_u16(raw, 10)?;
    let mut cursor = 12;
    for _ in 0..questions {
        if !skip_dns_name(raw, &mut cursor) || cursor + 4 > raw.len() {
            return Err(EcsWireError::Malformed);
        }
        cursor += 4;
    }
    for _ in 0..answers
        .checked_add(authorities)
        .ok_or(EcsWireError::Malformed)?
    {
        record(raw, &mut cursor)?;
    }

    let mut opt = None;
    for _ in 0..additional_count {
        let record = record(raw, &mut cursor)?;
        if record.0 == OPT_RECORD_TYPE {
            if opt.is_some() {
                return Err(EcsWireError::MultipleOpt);
            }
            opt = Some(record.1);
        }
    }
    if cursor != raw.len() {
        return Err(EcsWireError::Malformed);
    }
    Ok(MessageLayout {
        opt,
        additional_count,
    })
}

fn record(raw: &[u8], cursor: &mut usize) -> Result<(u16, OptRecord), EcsWireError> {
    let start = *cursor;
    if !skip_dns_name(raw, cursor) || cursor.checked_add(10).is_none_or(|end| end > raw.len()) {
        return Err(EcsWireError::Malformed);
    }
    let fields = *cursor;
    let record_type = read_u16(raw, fields)?;
    let rdlength_offset = fields + 8;
    let rdata_start = fields + 10;
    let rdlength = usize::from(read_u16(raw, rdlength_offset)?);
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(EcsWireError::Malformed)?;
    *cursor = end;
    if record_type == OPT_RECORD_TYPE && (fields != start + 1 || raw[start] != 0) {
        return Err(EcsWireError::UnsupportedOpt);
    }
    Ok((
        record_type,
        OptRecord {
            start,
            end,
            rdlength_offset,
            rdata: rdata_start..end,
            extended_rcode: raw[fields + 4],
            version: raw[fields + 5],
        },
    ))
}

fn read_u16(raw: &[u8], offset: usize) -> Result<u16, EcsWireError> {
    let bytes: [u8; 2] = raw
        .get(offset..offset + 2)
        .ok_or(EcsWireError::Malformed)?
        .try_into()
        .map_err(|_| EcsWireError::Malformed)?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        let mut wire = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        wire.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        wire
    }

    fn with_cookie_opt(mut wire: Vec<u8>) -> Vec<u8> {
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(&[
            0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 6, 0, 10, 0, 2, 0xaa, 0xbb,
        ]);
        wire
    }

    #[test]
    fn ecs_injection_and_response_cleanup_preserve_client_wire() {
        let original = query();
        let injected = EcsQuery::prepare(&original, "198.51.100.0/24".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            injected
                .wire()
                .ends_with(&[0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100])
        );

        let mut response = injected.wire().to_vec();
        response[2] |= 0x80;
        let restored = injected.restore_response(response).unwrap();
        let mut expected = original;
        expected[2] |= 0x80;
        assert_eq!(restored, expected);
    }

    #[test]
    fn synthetic_opt_does_not_hide_extended_response_code() {
        let original = query();
        let opt_start = original.len();
        let injected = EcsQuery::prepare(&original, "198.51.100.0/24".parse().unwrap())
            .unwrap()
            .unwrap();
        let mut response = injected.wire().to_vec();
        response[2] |= 0x80;
        response[opt_start + 5] = 1;

        assert!(matches!(
            injected.restore_response(response),
            Err(EcsWireError::UnsupportedResponseOpt)
        ));
    }

    #[test]
    fn ecs_injection_preserves_existing_edns_options() {
        let original = with_cookie_opt(query());
        let injected = EcsQuery::prepare(&original, "203.0.112.0/20".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            injected
                .wire()
                .ends_with(&[0, 8, 0, 7, 0, 1, 20, 0, 203, 0, 112])
        );

        let mut response = injected.wire().to_vec();
        response[2] |= 0x80;
        let restored = injected.restore_response(response).unwrap();
        let mut expected = original;
        expected[2] |= 0x80;
        assert_eq!(restored, expected);
    }

    #[test]
    fn existing_or_mismatched_ecs_is_never_overridden() {
        let injected = EcsQuery::prepare(&query(), "198.51.100.0/24".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            EcsQuery::prepare(injected.wire(), "203.0.113.0/24".parse().unwrap())
                .unwrap()
                .is_none()
        );

        let mut response = injected.wire().to_vec();
        response[2] |= 0x80;
        let source_prefix = response
            .windows(4)
            .position(|window| window == [0, 1, 24, 0])
            .unwrap()
            + 2;
        response[source_prefix] = 16;
        assert!(matches!(
            injected.restore_response(response),
            Err(EcsWireError::MismatchedResponse)
        ));
    }

    #[test]
    fn public_hop_filter_is_conservative() {
        for private in [
            "10.0.0.1",
            "100.64.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
        ] {
            assert!(!is_public_ipv4(private.parse().unwrap()), "{private}");
        }
        assert!(is_public_ipv4("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn public_hop_filter_skips_dod_blocks_carriers_route_internally() {
        // A carrier hop seen from a Chinese home router; as ECS it geolocates to the US.
        for hop in ["30.253.255.1", "11.0.0.1", "33.1.2.3", "215.0.0.1"] {
            assert!(!is_public_ipv4(hop.parse().unwrap()), "{hop}");
        }
        for hop in ["31.0.0.1", "116.228.111.1", "223.5.5.5"] {
            assert!(is_public_ipv4(hop.parse().unwrap()), "{hop}");
        }
    }
}
