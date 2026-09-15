//! Shadowsocks TCP stream as an inline codec: `AsyncRead`/`AsyncWrite`
//! implemented directly over the server socket, no relay task and no
//! duplex. The control plane's `copy_bidirectional` drives
//! encryption/decryption in the caller's task, removing two task hops and
//! two copies per byte from the old `shadowsocks_relay` data path (single
//! core saturated ~1.15Gbps → target dae's 1.5Gbps+).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::shadowsocks::{
    AeadCipher, CipherConf, RELAY_BATCH, decrypt_chunks_in_place, hkdf_sha1_derive,
    seal_chunks_into,
};

/// Send/recv batch buffers (64KB batch + chunk/tag overhead). Sized to keep
/// a connection under ~300KB including the control-plane relay buffers —
/// 256KB-per-side buffers made 10k concurrent SS connections multi-GB.
const SEND_BUF_CAP: usize = RELAY_BATCH + 8192;
const RECV_BUF_CAP: usize = RELAY_BATCH + 8192;

/// Response-prologue driver for 2022 connections: read and validate the
/// server's salt + fixed header (+ first payload chunk) from the read
/// path, not inline in `dial` — servers only answer after the first client
/// payload chunk, so reading the response in `dial` deadlocks.
type PrologueFuture = Pin<
    Box<
        dyn std::future::Future<Output = io::Result<(OwnedReadHalf, AeadCipher, Vec<u8>, Vec<u8>)>>
            + Send,
    >,
>;

/// Stream state for one Shadowsocks TCP connection after the salt/header
/// prologue (which `dial` completes before returning this type).
pub(crate) struct SsStream {
    write_half: OwnedWriteHalf,
    /// Read half, parked inside the pending 2022 prologue future until the
    /// response header has been consumed.
    read_half: Option<OwnedReadHalf>,
    send_cipher: AeadCipher,
    send_nonce: Vec<u8>,
    /// Sealed output waiting to be flushed (poll_write seals once, then
    /// flushes across polls).
    send_buf: Vec<u8>,
    send_off: usize,
    recv_cipher: Option<AeadCipher>,
    recv_nonce: Vec<u8>,
    /// 2022 only: pending response prologue (salt + fixed header).
    recv_prologue: Option<PrologueFuture>,
    recv_pending_len: Option<u16>,
    /// Raw inbound bytes: plaintext at the front (`plain_start..plain_end`),
    /// undecrypted carry right after it (`carry` bytes).
    recv_buf: Vec<u8>,
    plain_start: usize,
    plain_end: usize,
    carry: usize,
}

impl SsStream {
    #[cfg(test)]
    pub(crate) fn new(
        inner: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        recv_cipher: AeadCipher,
        recv_nonce: Vec<u8>,
    ) -> Self {
        let (read_half, write_half) = inner.into_split();
        Self {
            write_half,
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
        inner: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        prologue: Ss2022Prologue,
    ) -> Self {
        let (read_half, write_half) = inner.into_split();
        let recv_prologue: PrologueFuture = Box::pin(prologue.run(read_half));
        Self {
            write_half,
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
        inner: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        prologue: LegacyPrologue,
    ) -> Self {
        let (read_half, write_half) = inner.into_split();
        let recv_prologue: PrologueFuture = Box::pin(prologue.run(read_half));
        Self {
            write_half,
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
    /// the first `poll_read` serves it before touching the socket.
    pub(crate) fn prefill_plaintext(&mut self, data: &[u8]) {
        self.recv_buf[..data.len()].copy_from_slice(data);
        self.plain_start = 0;
        self.plain_end = data.len();
    }
}

impl std::fmt::Debug for SsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsStream")
            .field("send_pending", &(self.send_buf.len() - self.send_off))
            .field("plain_pending", &(self.plain_end - self.plain_start))
            .field("carry", &self.carry)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drive a pending 2022 response prologue first.
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
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

impl AsyncWrite for SsStream {
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

impl SsStream {
    /// Drive the sealed buffer toward the socket; `Ok(())` means fully
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
    async fn run(
        self,
        mut read_half: OwnedReadHalf,
    ) -> io::Result<(OwnedReadHalf, AeadCipher, Vec<u8>, Vec<u8>)> {
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
    pub(crate) method: super::shadowsocks_2022::Ss2022Method,
    pub(crate) request_salt: Vec<u8>,
}

impl Ss2022Prologue {
    async fn run(
        self,
        mut read_half: OwnedReadHalf,
    ) -> io::Result<(OwnedReadHalf, AeadCipher, Vec<u8>, Vec<u8>)> {
        use super::shadowsocks::increment_nonce;
        use super::shadowsocks_2022::{NONCE_LEN, TAG_LEN, unix_timestamp};
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
        let fixed = recv_cipher
            .open(&recv_nonce, &fixed_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        increment_nonce(&mut recv_nonce);
        if fixed[0] != super::shadowsocks_2022::HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad response header type {}", fixed[0]),
            ));
        }
        let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("8-byte timestamp"));
        if unix_timestamp().abs_diff(ts) > 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad response timestamp",
            ));
        }
        if fixed[9..9 + method.key_len] != self.request_salt[..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response request-salt mismatch",
            ));
        }
        let first_len = u16::from_be_bytes([fixed[fixed_len - 2], fixed[fixed_len - 1]]) as usize;

        let mut first = vec![0u8; first_len + TAG_LEN];
        read_half.read_exact(&mut first).await?;
        let first_payload = recv_cipher.open(&recv_nonce, &first).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, anyhow!("{e:?}").to_string())
        })?;
        increment_nonce(&mut recv_nonce);

        Ok((read_half, recv_cipher, recv_nonce, first_payload))
    }
}

/// Flush helper for the legacy prologue path (one-shot sealed write).
pub(crate) async fn write_all_sealed(
    inner: &mut TcpStream,
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
mod tests {
    use super::*;
    use crate::proxy::shadowsocks::{CipherConf, ShadowsocksHandler, hkdf_sha1_derive};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const METHOD: &str = "aes-128-gcm";
    const PASSWORD: &str = "test-password";

    fn ciphers(master: &[u8], c2s_salt: &[u8], s2c_salt: &[u8]) -> (AeadCipher, AeadCipher) {
        let conf = CipherConf::for_method(METHOD).unwrap();
        let mut c2s_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(master, c2s_salt, &mut c2s_subkey);
        let mut s2c_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(master, s2c_salt, &mut s2c_subkey);
        (
            AeadCipher::new(METHOD, &c2s_subkey).unwrap(),
            AeadCipher::new(METHOD, &s2c_subkey).unwrap(),
        )
    }

    fn legacy_stream(
        server: TcpStream,
        send_cipher: AeadCipher,
        recv_cipher: AeadCipher,
    ) -> SsStream {
        SsStream::new(
            server,
            send_cipher,
            vec![0u8; 12],
            recv_cipher,
            vec![0u8; 12],
        )
    }

    /// AsyncWrite contract: a peer that accepts only a few bytes at a time
    /// (forcing Pending flushes) must still receive a byte-exact stream,
    /// and a write issued after a Pending must not lose or duplicate data.
    #[tokio::test]
    async fn poll_write_contract_under_backpressure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conf = CipherConf::for_method(METHOD).unwrap();
        let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        let c2s_salt = vec![7u8; conf.salt_len];
        let s2c_salt = vec![9u8; conf.salt_len];
        let (send_cipher, peer_read_cipher) = ciphers(&master, &c2s_salt, &s2c_salt);

        let peer_salt = c2s_salt;
        let peer = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Slow reader: tiny reads with a delay so the writer's flush
            // path repeatedly hits Pending.
            let mut plain_seen = Vec::new();
            let mut buf = vec![0u8; RECV_BUF_CAP];
            let mut carry = 0usize;
            let mut pending_len = None;
            let mut nonce = vec![0u8; 12];
            let conf = CipherConf::for_method(METHOD).unwrap();
            let m = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
            let mut subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&m, &peer_salt, &mut subkey);
            let read_cipher = AeadCipher::new(METHOD, &subkey).unwrap();
            loop {
                let end = (carry + 977).min(buf.len());
                let n = sock.read(&mut buf[carry..end]).await.unwrap();
                if n == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                let total = carry + n;
                let (out_len, rest) = decrypt_chunks_in_place(
                    &read_cipher,
                    &mut nonce,
                    &mut pending_len,
                    &mut buf,
                    total,
                    conf.tag_len,
                )
                .unwrap();
                plain_seen.extend_from_slice(&buf[..out_len]);
                if rest > 0 {
                    buf.copy_within(out_len..out_len + rest, 0);
                }
                carry = rest;
                if plain_seen.len() >= 300_000 {
                    break;
                }
            }
            let expected: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            assert_eq!(plain_seen, expected);
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut stream = legacy_stream(client, send_cipher, peer_read_cipher);
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        // Many writes of varying size; write_all retries transparently.
        let mut off = 0;
        for chunk in [100_000usize, 1, 77, 150_000, 49_922] {
            let end = (off + chunk).min(payload.len());
            stream.write_all(&payload[off..end]).await.unwrap();
            off = end;
        }
        assert_eq!(off, payload.len());
        stream.flush().await.unwrap();
        drop(stream);
        peer.await.unwrap();
    }

    /// Legacy AEAD: a server that sends its response salt only AFTER the
    /// first client payload chunk (the strictest valid behavior) must not
    /// deadlock dial() and must receive that first chunk.
    #[tokio::test]
    async fn legacy_deferred_response_salt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conf = CipherConf::for_method(METHOD).unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let m = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
            // Client salt, then the header chunk (sealed).
            let mut c2s_salt = vec![0u8; conf.salt_len];
            sock.read_exact(&mut c2s_salt).await.unwrap();
            let mut subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&m, &c2s_salt, &mut subkey);
            let c2s_cipher = AeadCipher::new(METHOD, &subkey).unwrap();
            let mut c2s_nonce = vec![0u8; conf.nonce_len];

            // Read until BOTH the header chunk and the first payload chunk
            // have arrived (they may share one TCP segment).
            let mut buf = vec![0u8; 8192];
            let mut carry = 0usize;
            let mut pending_len = None;
            let mut plain_seen: Vec<u8> = Vec::new();
            let header_len = 4usize; // "t:80"
            while plain_seen.len() < header_len + 4 {
                let n = sock.read(&mut buf[carry..]).await.unwrap();
                if n == 0 {
                    panic!("client closed before first payload");
                }
                let total = carry + n;
                let (out_len, rest) = decrypt_chunks_in_place(
                    &c2s_cipher,
                    &mut c2s_nonce,
                    &mut pending_len,
                    &mut buf,
                    total,
                    conf.tag_len,
                )
                .unwrap();
                plain_seen.extend_from_slice(&buf[..out_len]);
                if rest > 0 {
                    buf.copy_within(out_len..out_len + rest, 0);
                }
                carry = rest;
            }
            assert_eq!(&plain_seen[..header_len], b"t:80");
            assert_eq!(&plain_seen[header_len..header_len + 4], b"ping");
            sock.write_all(&[9u8; 16]).await.unwrap();
            let mut s2c_subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&m, &[9u8; 16], &mut s2c_subkey);
            let s2c_cipher = AeadCipher::new(METHOD, &s2c_subkey).unwrap();
            let mut s2c_nonce = vec![0u8; conf.nonce_len];
            let mut sealed = Vec::new();
            seal_chunks_into(&s2c_cipher, &mut s2c_nonce, b"pong", &mut sealed).unwrap();
            sock.write_all(&sealed).await.unwrap();
        });

        let node_server = TcpStream::connect(addr).await.unwrap();
        let send_master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        let c2s_salt = vec![7u8; conf.salt_len];
        let mut send_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&send_master, &c2s_salt, &mut send_subkey);
        let send_cipher = AeadCipher::new(METHOD, &send_subkey).unwrap();

        let mut server = node_server;
        server.write_all(&c2s_salt).await.unwrap();
        let mut send_nonce = vec![0u8; conf.nonce_len];
        write_all_sealed(&mut server, &send_cipher, &mut send_nonce, b"t:80")
            .await
            .unwrap();

        let prologue = LegacyPrologue {
            conf,
            master_key: send_master,
            method: METHOD.to_string(),
        };
        // Emulate the handler's legacy dial tail through its production constructor.
        let mut stream = SsStream::new_legacy(server, send_cipher, send_nonce, prologue);
        // The payload goes out BEFORE the server salt exists anywhere.
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await
        .expect("response timed out")
        .unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// EOF with a truncated chunk tail is UnexpectedEof, not a clean close.
    #[tokio::test]
    async fn truncated_tail_is_unexpected_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conf = CipherConf::for_method(METHOD).unwrap();
        let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        let c2s_salt = vec![7u8; conf.salt_len];
        let s2c_salt = vec![9u8; conf.salt_len];
        let (send_cipher, peer_read_cipher) = ciphers(&master, &c2s_salt, &s2c_salt);

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Close immediately after a partial write (garbage tail).
            drop(sock);
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut stream = legacy_stream(client, send_cipher, peer_read_cipher);
        // Manually place a truncated chunk into the recv path: seal a chunk
        // with the peer's cipher, feed only half of it via the socket.
        let mut sealed = Vec::new();
        let peer_master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        let mut sub = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&peer_master, &s2c_salt, &mut sub);
        let s2c = AeadCipher::new(METHOD, &sub).unwrap();
        let mut nonce = vec![0u8; 12];
        seal_chunks_into(&s2c, &mut nonce, b"hello-tail", &mut sealed).unwrap();
        stream.recv_buf[..sealed.len() / 2].copy_from_slice(&sealed[..sealed.len() / 2]);
        stream.carry = sealed.len() / 2;
        let mut buf = [0u8; 64];
        let err = stream
            .read(&mut buf)
            .await
            .expect_err("must fail on truncated tail");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
