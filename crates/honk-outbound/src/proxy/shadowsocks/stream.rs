//! Shadowsocks TCP stream as an inline codec: `AsyncRead`/`AsyncWrite`
//! implemented directly over the carrier without a relay task or duplex bridge.
//! The control plane's `copy_bidirectional` drives
//! encryption/decryption in the caller's task, removing two task hops and
//! two copies per byte from the old `shadowsocks_relay` data path (single
//! core saturated ~1.15Gbps → target dae's 1.5Gbps+).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::proxy::AsyncReadWrite;
use crate::transport_quality::tcp::TcpPressure;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::{
    AeadCipher, CipherConf, RELAY_BATCH, decrypt_chunks_in_place, hkdf_sha1_derive,
    seal_chunks_into,
};

/// Send/recv batch buffers (64KB batch + chunk/tag overhead). Sized to keep
/// a connection under ~300KB including the control-plane relay buffers —
/// 256KB-per-side buffers made 10k concurrent SS connections multi-GB.
const SEND_BUF_CAP: usize = RELAY_BATCH + 8192;
const RECV_BUF_CAP: usize = RELAY_BATCH + 8192;

/// Legacy and 2022 response prologues run on the read path because servers may wait for payload.
type PrologueFuture<R> = Pin<
    Box<dyn std::future::Future<Output = io::Result<(R, AeadCipher, Vec<u8>, Vec<u8>)>> + Send>,
>;

/// Carrier an [`SsStream`] runs over. A `TcpStream` splits into owned
/// halves and keeps its pressure sampler; a boxed stream (e.g. an inner
/// proxy hop) splits through `tokio::io::split` and has no physical socket
/// to sample.
pub(crate) trait SsTransport: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    type Read: AsyncRead + Unpin + Send + 'static;
    type Write: AsyncWrite + Unpin + Send + 'static;

    fn into_parts(self) -> (Self::Read, Self::Write, TcpPressure);

    /// The physical socket behind the write half, if any.
    fn socket(write: &Self::Write) -> Option<&TcpStream>;
}

impl SsTransport for TcpStream {
    type Read = OwnedReadHalf;
    type Write = OwnedWriteHalf;

    fn into_parts(self) -> (OwnedReadHalf, OwnedWriteHalf, TcpPressure) {
        let pressure = TcpPressure::new(&self);
        let (read_half, write_half) = self.into_split();
        (read_half, write_half, pressure)
    }

    fn socket(write: &OwnedWriteHalf) -> Option<&TcpStream> {
        Some(write.as_ref())
    }
}

impl SsTransport for Box<dyn AsyncReadWrite> {
    type Read = ReadHalf<Self>;
    type Write = WriteHalf<Self>;

    fn into_parts(self) -> (Self::Read, Self::Write, TcpPressure) {
        let (read_half, write_half) = tokio::io::split(self);
        (read_half, write_half, TcpPressure::default())
    }

    fn socket(_: &Self::Write) -> Option<&TcpStream> {
        None
    }
}

/// Inline Shadowsocks codec over a carrier with a deferred response prologue.
pub(crate) struct SsStream<T: SsTransport> {
    write_half: T::Write,
    pressure: TcpPressure,
    peer_authenticated: bool,
    /// The response prologue owns the carrier's read half until it completes.
    read_half: Option<T::Read>,
    send_cipher: AeadCipher,
    send_nonce: Vec<u8>,
    /// Sealed output waiting to be flushed (poll_write seals once, then
    /// flushes across polls).
    send_buf: Vec<u8>,
    send_off: usize,
    recv_cipher: Option<AeadCipher>,
    recv_nonce: Vec<u8>,
    /// Pending response salt (legacy) or salt, header, and first chunk (2022).
    recv_prologue: Option<PrologueFuture<T::Read>>,
    recv_pending_len: Option<u16>,
    /// Raw inbound bytes: plaintext at the front (`plain_start..plain_end`),
    /// undecrypted carry right after it (`carry` bytes).
    recv_buf: Vec<u8>,
    plain_start: usize,
    plain_end: usize,
    carry: usize,
}

impl<T: SsTransport> SsStream<T> {
    #[cfg(test)]
    pub(crate) fn new(
        inner: T,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        recv_cipher: AeadCipher,
        recv_nonce: Vec<u8>,
    ) -> Self {
        let (read_half, write_half, pressure) = inner.into_parts();
        Self {
            write_half,
            pressure,
            peer_authenticated: true,
            read_half: Some(read_half),
            send_cipher,
            send_nonce,
            send_buf: Vec::with_capacity(SEND_BUF_CAP),
            send_off: 0,
            recv_cipher: Some(recv_cipher),
            recv_nonce,
            recv_prologue: None,
            recv_pending_len: None,
            recv_buf: vec![0u8; RECV_BUF_CAP],
            plain_start: 0,
            plain_end: 0,
            carry: 0,
        }
    }

    /// 2022 constructor: the response prologue is deferred to the read
    /// path (see [`PrologueFuture`]).
    pub(crate) fn new_2022(
        inner: T,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        prologue: Ss2022Prologue,
    ) -> Self {
        let (read_half, write_half, pressure) = inner.into_parts();
        let recv_prologue: PrologueFuture<T::Read> = Box::pin(prologue.run(read_half));
        Self {
            write_half,
            pressure,
            peer_authenticated: false,
            read_half: None,
            send_cipher,
            send_nonce,
            send_buf: Vec::with_capacity(SEND_BUF_CAP),
            send_off: 0,
            recv_cipher: None,
            recv_nonce: vec![0u8; 12],
            recv_prologue: Some(recv_prologue),
            recv_pending_len: None,
            recv_buf: vec![0u8; RECV_BUF_CAP],
            plain_start: 0,
            plain_end: 0,
            carry: 0,
        }
    }

    /// Legacy constructor: only the request side (salt + header chunk) is
    /// written in `dial`; the response salt is read from the read path.
    pub(crate) fn new_legacy(
        inner: T,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        prologue: LegacyPrologue,
    ) -> Self {
        let (read_half, write_half, pressure) = inner.into_parts();
        let recv_prologue: PrologueFuture<T::Read> = Box::pin(prologue.run(read_half));
        Self {
            write_half,
            pressure,
            peer_authenticated: false,
            read_half: None,
            send_cipher,
            send_nonce,
            send_buf: Vec::with_capacity(SEND_BUF_CAP),
            send_off: 0,
            recv_cipher: None,
            recv_nonce: vec![0u8; 12],
            recv_prologue: Some(recv_prologue),
            recv_pending_len: None,
            recv_buf: vec![0u8; RECV_BUF_CAP],
            plain_start: 0,
            plain_end: 0,
            carry: 0,
        }
    }

    fn tag_len(&self) -> usize {
        16
    }

    /// Preload decrypted plaintext (the prologue's first response chunk) so
    /// the first `poll_read` serves it before reading from the carrier.
    pub(crate) fn prefill_plaintext(&mut self, data: &[u8]) {
        self.recv_buf[..data.len()].copy_from_slice(data);
        self.plain_start = 0;
        self.plain_end = data.len();
    }

    fn observe_pressure(&mut self) {
        if let Some(socket) = T::socket(&self.write_half) {
            self.pressure.observe(socket);
        }
    }
}

impl<T: SsTransport> std::fmt::Debug for SsStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsStream")
            .field("send_pending", &(self.send_buf.len() - self.send_off))
            .field("plain_pending", &(self.plain_end - self.plain_start))
            .field("carry", &self.carry)
            .finish_non_exhaustive()
    }
}

impl<T: SsTransport> AsyncRead for SsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // The response prologue supplies the cipher before payload decryption.
        if self.recv_prologue.is_some() {
            let this = self.as_mut().get_mut();
            let fut = this.recv_prologue.as_mut().expect("checked above");
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok((read_half, cipher, nonce, first_payload))) => {
                    this.read_half = Some(read_half);
                    this.recv_cipher = Some(cipher);
                    this.recv_nonce = nonce;
                    this.recv_prologue = None;
                    this.prefill_plaintext(&first_payload);
                    if !first_payload.is_empty() {
                        this.peer_authenticated = true;
                        this.observe_pressure();
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.plain_start == self.plain_end && self.carry == 0 {
            // Fast path (steady state): read the batch straight into the
            // caller's buffer and decrypt in place — no staging-buffer copy.
            let this = self.as_mut().get_mut();
            let tag_len = this.tag_len();
            let n = {
                let read_half = this.read_half.as_mut().expect("prologue completed");
                let mut read_buf = ReadBuf::new(out.initialize_unfilled());
                match Pin::new(read_half).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => read_buf.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };
            let (out_len, rest) = decrypt_chunks_in_place(
                this.recv_cipher.as_ref().expect("prologue completed"),
                &mut this.recv_nonce,
                &mut this.recv_pending_len,
                &mut out.initialize_unfilled()[..n],
                n,
                tag_len,
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, crate::proxy::NodeFailure(e))
            })?;
            if n == 0 {
                // Clean EOF (the fast path runs only with an empty carry).
                return Poll::Ready(Ok(()));
            }
            // Plaintext is compacted at the front of the caller's buffer
            // and the incomplete tail sits right behind it
            // (decrypt_chunks_in_place already moved it): hand the tail to
            // the staging buffer as carry.
            if rest > 0 {
                let buf = out.initialize_unfilled();
                this.recv_buf[..rest].copy_from_slice(&buf[out_len..out_len + rest]);
                this.carry = rest;
            }
            if out_len > 0 {
                this.peer_authenticated = true;
                this.observe_pressure();
                out.advance(out_len);
                return Poll::Ready(Ok(()));
            }
            // The caller's buffer was too small for even one chunk
            // (everything landed in carry): fall through to the staging
            // path — advancing 0 bytes here would look like EOF.
        }

        if self.plain_start == self.plain_end {
            // No buffered plaintext: pull and decrypt the next batch.
            // Greedily drain the socket while data is immediately
            // available — decrypt once per wakeup, not per read call.
            let this = self.as_mut().get_mut();
            let mut filled = 0usize;
            let mut eof = false;
            loop {
                let end = this.carry + filled;
                if end >= this.recv_buf.len() {
                    break; // batch full
                }
                let read_half = this.read_half.as_mut().expect("prologue completed");
                let mut read_buf = ReadBuf::new(&mut this.recv_buf[end..]);
                match Pin::new(read_half).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            eof = true;
                            break;
                        }
                        filled += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if filled == 0 {
                            return Poll::Pending;
                        }
                        break;
                    }
                }
            }
            if filled == 0 && eof {
                // EOF: a truncated tail (incomplete chunk or a decrypted
                // length without its payload) is a stream error, not a
                // clean close.
                if this.carry > 0 || this.recv_pending_len.is_some() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ss stream closed mid-chunk",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            let total = this.carry + filled;
            let tag_len = this.tag_len();
            let (out_len, rest) = decrypt_chunks_in_place(
                this.recv_cipher.as_ref().expect("prologue completed"),
                &mut this.recv_nonce,
                &mut this.recv_pending_len,
                &mut this.recv_buf,
                total,
                tag_len,
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, crate::proxy::NodeFailure(e))
            })?;
            if out_len > 0 {
                this.peer_authenticated = true;
                this.observe_pressure();
            }
            this.plain_start = 0;
            this.plain_end = out_len;
            this.carry = rest;
            if out_len == 0 {
                // Only an incomplete chunk so far: the socket poll above
                // already registered the waker; it fires when more data
                // arrives. (Waking ourselves here would busy-spin.)
                return Poll::Pending;
            }
        }
        let avail = self.plain_end - self.plain_start;
        let n = avail.min(out.remaining());
        out.put_slice(&self.recv_buf[self.plain_start..self.plain_start + n]);
        self.plain_start += n;
        if self.plain_start == self.plain_end {
            // Plaintext drained: prepend the carry for the next batch.
            let rest = self.carry;
            let plain_end = self.plain_end;
            if rest > 0 {
                self.recv_buf.copy_within(plain_end..plain_end + rest, 0);
            }
            self.plain_start = 0;
            self.plain_end = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: SsTransport> AsyncWrite for SsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        // Flush pending ciphertext first; only then take new plaintext.
        match this.poll_flush_ciphertext(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        // Take as much of the caller's buffer as the batch buffer holds.
        // Once sealed, the bytes are OWNED by the stream (they flush via
        // poll_flush / later writes), so returning Ok(n) here honors the
        // AsyncWrite contract — unlike the previous version, which could
        // return Pending after already consuming plaintext (advancing the
        // nonce and writing partial ciphertext). After the flush above the
        // buffer is empty, so non-empty writes are always fully accepted.
        let accepted = buf.len().min(SEND_BUF_CAP - this.send_buf.len());
        seal_chunks_into(
            &this.send_cipher,
            &mut this.send_nonce,
            &buf[..accepted],
            &mut this.send_buf,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Best-effort immediate flush; unwritten ciphertext stays buffered.
        let _ = this.poll_flush_ciphertext(cx);
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_ciphertext(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.write_half).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.write_half).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<T: SsTransport> SsStream<T> {
    /// Drive the sealed buffer toward the carrier. `Ok(())` means fully
    /// drained (buffer reset).
    fn poll_flush_ciphertext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.send_off < self.send_buf.len() {
            let n = match Pin::new(&mut self.write_half)
                .poll_write(cx, &self.send_buf[self.send_off..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ss stream write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            self.send_off += n;
            if self.peer_authenticated {
                self.observe_pressure();
            }
        }
        self.send_buf.clear();
        self.send_off = 0;
        Poll::Ready(Ok(()))
    }
}

/// Legacy response prologue: read the server's salt (may be delayed until
/// the first target payload — hence read from the read path, not `dial`).
pub(crate) struct LegacyPrologue {
    pub(crate) conf: CipherConf,
    pub(crate) master_key: Vec<u8>,
    pub(crate) method: String,
}

impl LegacyPrologue {
    async fn run<R: AsyncRead + Unpin>(
        self,
        mut read_half: R,
    ) -> io::Result<(R, AeadCipher, Vec<u8>, Vec<u8>)> {
        let mut recv_salt = vec![0u8; self.conf.salt_len];
        read_half.read_exact(&mut recv_salt).await?;
        let mut recv_subkey = vec![0u8; self.conf.key_len];
        hkdf_sha1_derive(&self.master_key, &recv_salt, &mut recv_subkey);
        let recv_cipher = AeadCipher::new(&self.method, &recv_subkey)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let recv_nonce = vec![0u8; self.conf.nonce_len];
        Ok((read_half, recv_cipher, recv_nonce, Vec::new()))
    }
}

/// 2022 response prologue: everything needed to read and validate the
/// server's fixed response header once the request is out.
pub(crate) struct Ss2022Prologue {
    pub(crate) method: super::aead2022::Ss2022Method,
    pub(crate) request_salt: Vec<u8>,
}

impl Ss2022Prologue {
    async fn run<R: AsyncRead + Unpin>(
        self,
        mut read_half: R,
    ) -> io::Result<(R, AeadCipher, Vec<u8>, Vec<u8>)> {
        use super::aead2022::{NONCE_LEN, TAG_LEN, unix_timestamp};
        use super::increment_nonce;
        use anyhow::anyhow;
        let method = &self.method;

        let mut recv_salt = vec![0u8; method.key_len];
        read_half.read_exact(&mut recv_salt).await?;
        let recv_subkey = method.session_subkey(&recv_salt);
        let recv_cipher = method
            .aead(&recv_subkey)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut recv_nonce = vec![0u8; NONCE_LEN];

        let fixed_len = 1 + 8 + method.key_len + 2;
        let mut fixed_buf = vec![0u8; fixed_len + TAG_LEN];
        read_half.read_exact(&mut fixed_buf).await?;
        let fixed = recv_cipher.open(&recv_nonce, &fixed_buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                crate::proxy::NodeFailure(anyhow!(e)),
            )
        })?;
        increment_nonce(&mut recv_nonce);
        if fixed[0] != super::aead2022::HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::proxy::NodeFailure(anyhow!("bad response header type {}", fixed[0])),
            ));
        }
        let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("8-byte timestamp"));
        if unix_timestamp().abs_diff(ts) > 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::proxy::NodeFailure(anyhow!("bad response timestamp")),
            ));
        }
        if fixed[9..9 + method.key_len] != self.request_salt[..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                crate::proxy::NodeFailure(anyhow!("response request-salt mismatch")),
            ));
        }
        let first_len = u16::from_be_bytes([fixed[fixed_len - 2], fixed[fixed_len - 1]]) as usize;

        let mut first = vec![0u8; first_len + TAG_LEN];
        read_half.read_exact(&mut first).await?;
        let first_payload = recv_cipher.open(&recv_nonce, &first).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                crate::proxy::NodeFailure(anyhow!(e)),
            )
        })?;
        increment_nonce(&mut recv_nonce);

        Ok((read_half, recv_cipher, recv_nonce, first_payload))
    }
}

pub(crate) async fn write_all_sealed<W: AsyncWrite + Unpin + ?Sized>(
    inner: &mut W,
    cipher: &AeadCipher,
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(payload.len() + 4096);
    seal_chunks_into(cipher, nonce, payload, &mut out)?;
    inner.write_all(&out).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
