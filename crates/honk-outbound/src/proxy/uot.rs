use std::io;
use std::net::SocketAddr;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::addr;

pub(crate) const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub(crate) const MAX_PACKET_SIZE: usize = u16::MAX as usize;
const MAX_BUFFERED_BYTES: usize = 2 * (2 + MAX_PACKET_SIZE);
pub(crate) const V1_ATYP_V4: u8 = 0x00;
pub(crate) const V1_ATYP_V6: u8 = 0x01;
pub(crate) const V1_ATYP_DOMAIN: u8 = 0x02;

pub(crate) trait UotCodec {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UotV1;

impl UotV1 {
    pub(crate) fn header(data: &[u8]) -> io::Result<Option<(usize, usize)>> {
        if data.is_empty() {
            return Ok(None);
        }
        let address_len = match data[0] {
            V1_ATYP_V4 => 4,
            V1_ATYP_V6 => 16,
            V1_ATYP_DOMAIN => {
                let Some(length) = data.get(1) else {
                    return Ok(None);
                };
                1 + usize::from(*length)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid UoT v1 packet header",
                ));
            }
        };
        let payload_start = 1 + address_len + 2 + 2;
        if data.len() < payload_start {
            return Ok(None);
        }
        let length_at = payload_start - 2;
        let payload_len = u16::from_be_bytes([data[length_at], data[length_at + 1]]) as usize;
        Ok(Some((payload_start, payload_len)))
    }
}

impl UotCodec for UotV1 {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>> {
        let Some((payload_start, payload_len)) = Self::header(data)? else {
            return Ok(None);
        };
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UoT datagram"))?;
        Ok((data.len() >= frame_end).then_some(FrameBounds {
            payload_start,
            frame_end,
        }))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UotV2;

pub(crate) fn connect_request(
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let mut request = vec![1];
    request.extend(addr::encode_address(target, target_domain)?);
    Ok(Bytes::from(request))
}

pub(crate) fn encode_packet(data: &[u8], max_payload: usize) -> io::Result<Bytes> {
    validate_packet_len(data, max_payload)?;
    let mut frame = BytesMut::with_capacity(2 + data.len());
    frame.put_u16(data.len() as u16);
    frame.extend_from_slice(data);
    Ok(frame.freeze())
}

pub(crate) fn validate_packet_len(data: &[u8], max_payload: usize) -> io::Result<()> {
    if data.len() > max_payload.min(MAX_PACKET_SIZE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UoT datagram exceeds transport capacity",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct FrameBounds {
    pub(crate) payload_start: usize,
    pub(crate) frame_end: usize,
}

impl UotCodec for UotV2 {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>> {
        if data.len() < 2 {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let frame_end = 2usize
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UoT datagram"))?;
        Ok((data.len() >= frame_end).then_some(FrameBounds {
            payload_start: 2,
            frame_end,
        }))
    }
}

pub(crate) fn copy_frame(
    buffered: &mut BytesMut,
    frame: FrameBounds,
    output: &mut [u8],
) -> io::Result<usize> {
    let payload_len = frame.frame_end - frame.payload_start;
    if payload_len > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UoT datagram exceeds buffer",
        ));
    }
    output[..payload_len].copy_from_slice(&buffered[frame.payload_start..frame.frame_end]);
    buffered.advance(frame.frame_end);
    Ok(payload_len)
}

pub(crate) struct Decoder<C = UotV2> {
    buffered: BytesMut,
    _codec: std::marker::PhantomData<fn() -> C>,
}

impl<C> Default for Decoder<C> {
    fn default() -> Self {
        Self {
            buffered: BytesMut::new(),
            _codec: std::marker::PhantomData,
        }
    }
}

impl<C: UotCodec> Decoder<C> {
    pub(crate) fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.buffered.len().saturating_add(data.len()) > MAX_BUFFERED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT stream frame exceeds buffer limit",
            ));
        }
        self.buffered.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn next_packet(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = C::frame_bounds(&self.buffered)? else {
            return Ok(None);
        };
        copy_frame(&mut self.buffered, frame, output).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_rejects_overlong_domain() {
        let target = "127.0.0.1:53".parse().unwrap();
        assert!(connect_request(target, Some(&"a".repeat(255))).is_ok());
        let error = connect_request(target, Some(&"a".repeat(256))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn codec_supports_full_packets_and_preserves_short_buffer_frames() {
        let payload = vec![0x5a; MAX_PACKET_SIZE];
        let frame = encode_packet(&payload, MAX_PACKET_SIZE).unwrap();
        assert!(encode_packet(&[0; 1], 0).is_err());

        let mut decoder = Decoder::<UotV2>::default();
        decoder.push(&frame[..123]).unwrap();
        assert!(decoder.next_packet(&mut []).unwrap().is_none());
        decoder.push(&frame[123..]).unwrap();
        assert!(decoder.next_packet(&mut [0; 1]).is_err());

        let mut output = vec![0; MAX_PACKET_SIZE];
        assert_eq!(
            decoder.next_packet(&mut output).unwrap(),
            Some(MAX_PACKET_SIZE)
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn decoder_preserves_coalesced_packets() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_packet(b"first", MAX_PACKET_SIZE).unwrap());
        wire.extend_from_slice(&encode_packet(b"second", MAX_PACKET_SIZE).unwrap());
        let mut decoder = Decoder::<UotV2>::default();
        decoder.push(&wire).unwrap();
        let mut output = [0; 8];
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(5));
        assert_eq!(&output[..5], b"first");
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(6));
        assert_eq!(&output[..6], b"second");
    }

    #[test]
    fn v1_and_v2_share_the_bounded_codec_contract() {
        let v1 = [V1_ATYP_V4, 1, 2, 3, 4, 0, 53, 0, 3, b'a', b'b', b'c'];
        assert!(UotV1::frame_bounds(&v1[..11]).unwrap().is_none());
        let bounds = UotV1::frame_bounds(&v1).unwrap().unwrap();
        assert_eq!(bounds.payload_start, 9);
        assert_eq!(bounds.frame_end, 12);
        assert!(UotV1::frame_bounds(&[0xff]).is_err());

        let v2 = encode_packet(b"abc", MAX_PACKET_SIZE).unwrap();
        let bounds = UotV2::frame_bounds(&v2).unwrap().unwrap();
        assert_eq!(bounds.payload_start, 2);
        assert_eq!(bounds.frame_end, 5);
    }
}
