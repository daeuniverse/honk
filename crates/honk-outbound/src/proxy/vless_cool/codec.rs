use super::*;

pub(super) const STATUS_NEW: u8 = 0x01;
pub(super) const STATUS_KEEP: u8 = 0x02;
pub(super) const STATUS_END: u8 = 0x03;
pub(super) const STATUS_KEEPALIVE: u8 = 0x04;
pub(super) const OPTION_DATA: u8 = 0x01;
pub(super) const OPTION_ERROR: u8 = 0x02;
pub(super) const NETWORK_TCP: u8 = 0x01;
pub(super) const NETWORK_UDP: u8 = 0x02;
pub(super) const ATYP_IPV4: u8 = 0x01;
pub(super) const ATYP_DOMAIN: u8 = 0x02;
pub(super) const ATYP_IPV6: u8 = 0x03;
pub(super) fn encode_address(
    output: &mut BytesMut,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<()> {
    output.extend_from_slice(&target.port().to_be_bytes());
    if let Some(domain) = target_domain {
        if domain.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mux.Cool target domain exceeds 255 bytes",
            ));
        }
        output.extend_from_slice(&[ATYP_DOMAIN, domain.len() as u8]);
        output.extend_from_slice(domain.as_bytes());
    } else {
        match target.ip() {
            IpAddr::V4(ip) => {
                output.extend_from_slice(&[ATYP_IPV4]);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.extend_from_slice(&[ATYP_IPV6]);
                output.extend_from_slice(&ip.octets());
            }
        }
    }
    Ok(())
}

pub(super) fn metadata_frame(metadata: BytesMut, payload: Option<&[u8]>) -> io::Result<Bytes> {
    if !(4..=MAX_METADATA).contains(&metadata.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mux.Cool metadata length is outside 4..=512",
        ));
    }
    let payload_len = payload.map_or(0, <[u8]>::len);
    if payload_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mux.Cool payload exceeds the wire length",
        ));
    }
    let mut frame = BytesMut::with_capacity(2 + metadata.len() + 2 + payload_len);
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    if let Some(payload) = payload {
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
    }
    Ok(frame.freeze())
}

pub(super) fn base_metadata(id: u16, status: u8, options: u8) -> BytesMut {
    let mut metadata = BytesMut::with_capacity(32);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[status, options]);
    metadata
}

pub(super) fn new_tcp_frame(
    id: u16,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let mut metadata = base_metadata(id, STATUS_NEW, 0);
    metadata.extend_from_slice(&[NETWORK_TCP]);
    encode_address(&mut metadata, target, target_domain)?;
    metadata_frame(metadata, None)
}

pub(super) fn keep_tcp_frame(id: u16, payload: &[u8]) -> io::Result<Bytes> {
    metadata_frame(base_metadata(id, STATUS_KEEP, OPTION_DATA), Some(payload))
}

pub(super) fn end_frame(id: u16) -> Bytes {
    metadata_frame(base_metadata(id, STATUS_END, 0), None)
        .expect("fixed Mux.Cool END metadata is valid")
}

pub(super) fn udp_frame(
    id: u16,
    first: bool,
    target: SocketAddr,
    target_domain: Option<&str>,
    global_id: [u8; 8],
    payload: &[u8],
) -> io::Result<Bytes> {
    let max_packet_size = if id == 0 {
        MAX_SINGLE_XUDP_PACKET_SIZE
    } else {
        MAX_MUX_XUDP_PACKET_SIZE
    };
    if payload.is_empty() || payload.len() > max_packet_size {
        return Err(crate::proxy::PacketRejection::InvalidSize.into());
    }
    let mut metadata = base_metadata(
        id,
        if first { STATUS_NEW } else { STATUS_KEEP },
        OPTION_DATA,
    );
    metadata.extend_from_slice(&[NETWORK_UDP]);
    encode_address(&mut metadata, target, target_domain)?;
    if first && global_id != [0; 8] {
        metadata.extend_from_slice(&global_id);
    }
    metadata_frame(metadata, Some(payload))
}

pub(super) struct IncomingFrame {
    pub(super) metadata: Bytes,
    pub(super) id: u16,
    pub(super) status: u8,
    pub(super) options: u8,
    pub(super) payload: Option<Bytes>,
}

pub(super) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<IncomingFrame> {
    let metadata_len = reader.read_u16().await? as usize;
    if !(4..=MAX_METADATA).contains(&metadata_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mux.Cool metadata length is outside 4..=512",
        ));
    }
    let mut metadata = BytesMut::zeroed(metadata_len);
    reader.read_exact(&mut metadata).await?;
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let options = metadata[3];
    let payload = if options & OPTION_DATA != 0 {
        let payload_len = reader.read_u16().await? as usize;
        let mut payload = BytesMut::zeroed(payload_len);
        reader.read_exact(&mut payload).await?;
        Some(payload.freeze())
    } else {
        None
    };
    Ok(IncomingFrame {
        metadata: metadata.freeze(),
        id,
        status,
        options,
        payload,
    })
}

pub(super) fn parse_keep_peer(
    metadata: &[u8],
    fallback: SocketAddr,
    expected_domain: Option<&str>,
) -> io::Result<SocketAddr> {
    if metadata.len() == 4 {
        return Ok(fallback);
    }
    if metadata.len() < 8 || metadata[4] != NETWORK_UDP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP KEEP metadata has an invalid UDP endpoint",
        ));
    }
    let port = u16::from_be_bytes([metadata[5], metadata[6]]);
    match metadata[7] {
        ATYP_IPV4 if metadata.len() == 12 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                metadata[8],
                metadata[9],
                metadata[10],
                metadata[11],
            )),
            port,
        )),
        ATYP_IPV6 if metadata.len() == 24 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&metadata[8..24]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        ATYP_DOMAIN if metadata.len() >= 9 && metadata.len() == 9 + metadata[8] as usize => {
            let domain = &metadata[9..];
            if !expected_domain
                .is_some_and(|expected| domain.eq_ignore_ascii_case(expected.as_bytes()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XUDP KEEP response domain differs from the requested target",
                ));
            }
            Ok(SocketAddr::new(fallback.ip(), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP KEEP metadata has a truncated or unknown address",
        )),
    }
}
