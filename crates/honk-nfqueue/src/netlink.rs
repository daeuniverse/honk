use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use bytes::{Bytes, BytesMut};

pub(crate) const NETLINK_NETFILTER: libc::c_int = 12;
pub(crate) const NFNL_SUBSYS_QUEUE: u16 = 3;
pub(crate) const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub(crate) const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub(crate) const NFNL_MSG_BATCH_END: u16 = 17;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLM_F_REQUEST: u16 = 0x01;
pub(crate) const NLM_F_ACK: u16 = 0x04;
pub(crate) const NLM_F_CREATE: u16 = 0x400;
pub(crate) const NLA_F_NESTED: u16 = 0x8000;
const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub(crate) const NLMSG_HDRLEN: usize = 16;
pub(crate) const NFGENMSG_LEN: usize = 4;
const NLA_HDRLEN: usize = 4;
pub(crate) const NFPROTO_INET: u8 = 1;
pub(crate) const NFNL_BATCH_RES_ID: u16 = NFNL_SUBSYS_NFTABLES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DecodeError {
    #[error("truncated netlink header")]
    TruncatedMessageHeader,
    #[error("invalid netlink message length {0}")]
    InvalidMessageLength(usize),
    #[error("truncated netlink message padding")]
    TruncatedMessagePadding,
    #[error("truncated netlink attribute header")]
    TruncatedAttributeHeader,
    #[error("invalid netlink attribute length {0}")]
    InvalidAttributeLength(usize),
    #[error("truncated netlink attribute padding")]
    TruncatedAttributePadding,
}

#[inline]
pub(crate) const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

pub(crate) fn put_message_header(
    buffer: &mut Vec<u8>,
    message_type: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    resource_id: u16,
) -> usize {
    let start = buffer.len();
    buffer.extend_from_slice(&[0; 4]);
    buffer.extend_from_slice(&message_type.to_ne_bytes());
    buffer.extend_from_slice(&flags.to_ne_bytes());
    buffer.extend_from_slice(&sequence.to_ne_bytes());
    buffer.extend_from_slice(&0u32.to_ne_bytes());
    buffer.push(family);
    buffer.push(0);
    buffer.extend_from_slice(&resource_id.to_be_bytes());
    start
}

pub(crate) fn seal_message(buffer: &mut [u8], start: usize) {
    let length = u32::try_from(buffer.len() - start).expect("netlink message fits u32");
    buffer[start..start + 4].copy_from_slice(&length.to_ne_bytes());
}

pub(crate) fn put_attribute(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = NLA_HDRLEN + payload.len();
    let encoded_length = u16::try_from(length).expect("netlink attribute fits u16");
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(buffer.len() + align4(length) - length, 0);
}

pub(crate) fn put_attribute_string(buffer: &mut Vec<u8>, kind: u16, value: &str) {
    let length = NLA_HDRLEN + value.len() + 1;
    let encoded_length = u16::try_from(length).expect("netlink attribute fits u16");
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(value.as_bytes());
    buffer.push(0);
    buffer.resize(buffer.len() + align4(length) - length, 0);
}

pub(crate) fn put_attribute_be16(buffer: &mut Vec<u8>, kind: u16, value: u16) {
    put_attribute(buffer, kind, &value.to_be_bytes());
}

pub(crate) fn put_attribute_be32(buffer: &mut Vec<u8>, kind: u16, value: u32) {
    put_attribute(buffer, kind, &value.to_be_bytes());
}

pub(crate) fn begin_nested(buffer: &mut Vec<u8>, kind: u16) -> usize {
    let start = buffer.len();
    buffer.extend_from_slice(&[0; 2]);
    buffer.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
    start
}

pub(crate) fn seal_nested(buffer: &mut [u8], start: usize) {
    let length = u16::try_from(buffer.len() - start).expect("nested attribute fits u16");
    buffer[start..start + 2].copy_from_slice(&length.to_ne_bytes());
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) message_type: u16,
    pub(crate) sequence: u32,
    pub(crate) flags: u16,
    pub(crate) body: Bytes,
}

pub(crate) struct Messages {
    bytes: Bytes,
    offset: usize,
    failed: bool,
}

pub(crate) fn messages(bytes: Bytes) -> Messages {
    Messages {
        bytes,
        offset: 0,
        failed: false,
    }
}

impl Iterator for Messages {
    type Item = Result<Message, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.bytes.len() {
            return None;
        }
        let remaining = self.bytes.len() - self.offset;
        if remaining < NLMSG_HDRLEN {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedMessageHeader));
        }
        let header = &self.bytes[self.offset..self.offset + NLMSG_HDRLEN];
        let length = u32::from_ne_bytes(header[0..4].try_into().expect("four bytes")) as usize;
        if length < NLMSG_HDRLEN || length > remaining {
            self.failed = true;
            return Some(Err(DecodeError::InvalidMessageLength(length)));
        }
        let aligned = align4(length);
        if aligned > remaining && length != remaining {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedMessagePadding));
        }
        let message_type = u16::from_ne_bytes(header[4..6].try_into().expect("two bytes"));
        let flags = u16::from_ne_bytes(header[6..8].try_into().expect("two bytes"));
        let sequence = u32::from_ne_bytes(header[8..12].try_into().expect("four bytes"));
        let body = self
            .bytes
            .slice(self.offset + NLMSG_HDRLEN..self.offset + length);
        self.offset += aligned.min(remaining);
        Some(Ok(Message {
            message_type,
            flags,
            sequence,
            body,
        }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub(crate) kind: u16,
    pub(crate) payload: Bytes,
}

pub(crate) struct Attributes {
    bytes: Bytes,
    offset: usize,
    failed: bool,
}

pub(crate) fn attributes(bytes: Bytes) -> Attributes {
    Attributes {
        bytes,
        offset: 0,
        failed: false,
    }
}

impl Iterator for Attributes {
    type Item = Result<Attribute, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.bytes.len() {
            return None;
        }
        let remaining = self.bytes.len() - self.offset;
        if remaining < NLA_HDRLEN {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedAttributeHeader));
        }
        let header = &self.bytes[self.offset..self.offset + NLA_HDRLEN];
        let length = u16::from_ne_bytes(header[0..2].try_into().expect("two bytes")) as usize;
        if length < NLA_HDRLEN || length > remaining {
            self.failed = true;
            return Some(Err(DecodeError::InvalidAttributeLength(length)));
        }
        let aligned = align4(length);
        if aligned > remaining && length != remaining {
            self.failed = true;
            return Some(Err(DecodeError::TruncatedAttributePadding));
        }
        let raw_kind = u16::from_ne_bytes(header[2..4].try_into().expect("two bytes"));
        let payload = self
            .bytes
            .slice(self.offset + NLA_HDRLEN..self.offset + length);
        self.offset += aligned.min(remaining);
        Some(Ok(Attribute {
            kind: raw_kind & !(NLA_F_NESTED | NLA_F_NET_BYTEORDER),
            payload,
        }))
    }
}

pub(crate) fn open_socket(nonblocking: bool) -> io::Result<OwnedFd> {
    let mut socket_type = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
    if nonblocking {
        socket_type |= libc::SOCK_NONBLOCK;
    }
    let fd = unsafe { libc::socket(libc::AF_NETLINK, socket_type, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let result = unsafe {
        libc::bind(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub(crate) fn send(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let sent = unsafe {
        libc::send(
            fd,
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short netlink datagram send",
        ));
    }
    Ok(())
}

pub(crate) fn recv_datagram(fd: RawFd, capacity: usize) -> io::Result<Bytes> {
    let mut buffer = BytesMut::zeroed(capacity);
    let received = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(received as usize);
    Ok(buffer.freeze())
}

pub(crate) fn send_and_acks(
    fd: RawFd,
    request: &[u8],
    sequence: u32,
    expected: usize,
) -> io::Result<()> {
    debug_assert_ne!(expected, 0);
    send(fd, request)?;
    let mut received = 0usize;
    loop {
        let datagram = recv_datagram(fd, 64 * 1024)?;
        for message in messages(datagram) {
            let message = message.map_err(invalid_data)?;
            if message.message_type != NLMSG_ERROR || message.sequence != sequence {
                continue;
            }
            if message.body.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated NLMSG_ERROR",
                ));
            }
            let code = i32::from_ne_bytes(message.body[..4].try_into().expect("four bytes"));
            if code != 0 {
                return Err(io::Error::from_raw_os_error(-code));
            }
            received += 1;
            if received == expected {
                return Ok(());
            }
        }
    }
}

pub(crate) fn send_and_ack(fd: RawFd, request: &[u8], sequence: u32) -> io::Result<()> {
    send_and_acks(fd, request, sequence, 1)
}

fn invalid_data(error: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_round_trip_with_alignment() {
        let mut encoded = Vec::new();
        put_attribute(&mut encoded, 7, &[1]);
        put_attribute_be32(&mut encoded, 8, 0x0102_0304);
        let decoded = attributes(Bytes::from(encoded))
            .collect::<Result<Vec<_>, _>>()
            .expect("valid attributes");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].kind, 7);
        assert_eq!(decoded[0].payload.as_ref(), &[1]);
        assert_eq!(decoded[1].kind, 8);
        assert_eq!(decoded[1].payload.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn malformed_messages_and_attributes_are_errors() {
        let mut short_message = vec![0u8; NLMSG_HDRLEN];
        short_message[..4].copy_from_slice(&15u32.to_ne_bytes());
        assert_eq!(
            messages(Bytes::from(short_message)).next().unwrap(),
            Err(DecodeError::InvalidMessageLength(15))
        );

        let mut truncated_attribute = vec![0u8; 8];
        truncated_attribute[..2].copy_from_slice(&9u16.to_ne_bytes());
        assert_eq!(
            attributes(Bytes::from(truncated_attribute)).next().unwrap(),
            Err(DecodeError::InvalidAttributeLength(9))
        );

        let mut missing_padding = vec![0u8; 6];
        missing_padding[..2].copy_from_slice(&5u16.to_ne_bytes());
        missing_padding[2..4].copy_from_slice(&1u16.to_ne_bytes());
        assert_eq!(
            attributes(Bytes::from(missing_padding)).next().unwrap(),
            Err(DecodeError::TruncatedAttributePadding)
        );
    }

    #[test]
    fn declared_message_length_cannot_exceed_its_datagram() {
        let mut truncated = vec![0u8; NLMSG_HDRLEN + NFGENMSG_LEN];
        let declared = truncated.len() + 1;
        truncated[..4].copy_from_slice(&(declared as u32).to_ne_bytes());
        assert_eq!(
            messages(Bytes::from(truncated)).next().unwrap(),
            Err(DecodeError::InvalidMessageLength(
                NLMSG_HDRLEN + NFGENMSG_LEN + 1
            ))
        );
    }
}
