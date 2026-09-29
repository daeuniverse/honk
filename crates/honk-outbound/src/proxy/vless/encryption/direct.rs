//! Vision Direct passthrough for VLESS Encryption.
//!
//! Xray unwraps `CommonConn` at Direct but deliberately leaves `XorConn` in
//! place: AEAD framing stops while the selected outer transport and random
//! mode's per-record header XOR continue.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use super::{AesCtr, EncryptedStream, FRAME_HEADER_LEN, PendingWrite, ReadPhase};

/// One direction of Xray `XorConn`: XOR each TLS-shaped header and skip its
/// body by the plaintext header's length.
#[derive(Debug, Default)]
pub(super) struct HeaderXor {
    header: [u8; FRAME_HEADER_LEN],
    filled: usize,
    skip: usize,
}

impl HeaderXor {
    /// `outgoing` bytes are plaintext before XOR; incoming bytes become
    /// plaintext after it. Either way the length comes from plaintext.
    pub(super) fn apply(&mut self, xor: &mut AesCtr, data: &mut [u8], outgoing: bool) {
        let mut offset = 0;
        while offset < data.len() {
            if self.skip > 0 {
                let count = self.skip.min(data.len() - offset);
                self.skip -= count;
                offset += count;
                continue;
            }
            let count = (FRAME_HEADER_LEN - self.filled).min(data.len() - offset);
            let piece = &mut data[offset..offset + count];
            let header = &mut self.header[self.filled..self.filled + count];
            if outgoing {
                header.copy_from_slice(piece);
                xor.apply(piece);
            } else {
                xor.apply(piece);
                header.copy_from_slice(piece);
            }
            self.filled += count;
            offset += count;
            if self.filled == FRAME_HEADER_LEN {
                // Xray `DecodeHeader`: the length counts whenever the type
                // bytes match, even when the record itself is invalid.
                self.skip = if self.header[..3] == [23, 3, 3] {
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize
                } else {
                    0
                };
                self.filled = 0;
            }
        }
    }
}

impl EncryptedStream {
    /// Bypass Encryption framing after an authenticated Vision Direct command.
    /// Pending authenticated plaintext remains ahead of the underlying outer
    /// transport.
    pub(crate) fn poll_direct_read(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.copy_plaintext(output) {
            return Poll::Ready(Ok(()));
        }
        if !self.direct_read {
            if !matches!(self.read_phase, ReadPhase::Header) || self.read_offset != 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS Encryption Direct switch outside a frame boundary",
                )));
            }
            self.direct_read = true;
        }

        let start = output.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, output);
        if let (Poll::Ready(Ok(())), Some(xor)) = (&poll, self.recv_xor.as_mut()) {
            let end = output.filled().len();
            self.recv_header_xor
                .apply(xor, &mut output.filled_mut()[start..end], false);
        }
        poll
    }

    /// Bypass Encryption framing after this side sent its Vision Direct
    /// command; the command frame must already have left the codec.
    pub(crate) fn poll_direct_write(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_some() {
            return self.poll_pending_write(cx);
        }
        if !self.direct_write {
            if self.prewrite.is_some() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS Encryption Direct switch before the first frame",
                )));
            }
            self.direct_write = true;
        }
        let Some(xor) = self.send_xor.as_mut() else {
            return Pin::new(&mut *self.inner).poll_write(cx, input);
        };
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // The XOR keystream advances once per byte, so retries must resend
        // these exact bytes instead of re-encoding the caller's buffer.
        let mut wire = std::mem::take(&mut self.direct_wire);
        wire.clear();
        wire.extend_from_slice(input);
        self.send_header_xor.apply(xor, &mut wire, true);
        self.pending_write = Some(PendingWrite {
            wire,
            offset: 0,
            plaintext_len: input.len(),
        });
        self.poll_pending_write(cx)
    }

    /// Authenticated plaintext still queued ahead of the outer transport.
    pub(crate) fn has_buffered_plaintext(&self) -> bool {
        self.read_plaintext_offset < self.read_plaintext.len()
    }
}
