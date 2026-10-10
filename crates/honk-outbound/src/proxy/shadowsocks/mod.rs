//! Shadowsocks AEAD outbound handler.
//!
//! Supports the standard AEAD ciphers (legacy, per shadowsocks.org/doc/aead.html):
//! - `aes-128-gcm`
//! - `aes-256-gcm`
//! - `chacha20-ietf-poly1305` (alias `chacha20-poly1305`)
//!
//! and the Shadowsocks 2022 methods (SIP022, implemented in
//! [`aead2022`]):
//! - `2022-blake3-aes-128-gcm`
//! - `2022-blake3-aes-256-gcm`
//! - `2022-blake3-chacha20-poly1305`
//!
//! The handler dials the Shadowsocks server, writes the salt + request
//! prologue, and returns the inline codec in [`stream::SsStream`].
//! Caller-driven reads and writes apply Shadowsocks record chunking directly.
//!
//! UDP is supported for both cipher families through `dial_udp_transport`:
//! datagrams are sealed/opened in place and exchanged over a connected
//! server-facing socket (legacy: per-packet salt + AEAD; 2022: session-based
//! separate-header construction).
//!
//! References: <https://shadowsocks.org/doc/aead.html>,
//! <https://shadowsocks.org/doc/sip022.html>

mod aead2022;
mod stream;

use async_trait::async_trait;
use hkdf::Hkdf;
use honk_config::node::Node;
use rand::Rng;
use sha1::Sha1;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use super::addr;
use super::{PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound};
use aead2022::{Ss2022Method, Ss2022UdpSession};

pub(crate) const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub(crate) const CHUNK_MAX_LEN: usize = 0x3FFF; // 2^14 - 1
// The UDP wire-length bound includes address headers, padding, and AEAD tags.
const UDP_PACKET_BUFFER_SIZE: usize = u16::MAX as usize + 1;

/// Whether `method` names a Shadowsocks 2022 (SIP022) cipher.
pub(crate) fn is_2022_method(method: &str) -> bool {
    matches!(
        method.to_lowercase().as_str(),
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305"
    )
}

/// Cipher configuration shared by all supported AEAD methods.
pub(crate) struct CipherConf {
    pub(crate) key_len: usize,
    pub(crate) salt_len: usize,
    pub(crate) nonce_len: usize,
    pub(crate) tag_len: usize,
}

impl CipherConf {
    pub(crate) fn for_method(method: &str) -> anyhow::Result<Self> {
        let key_len = match method.to_lowercase().as_str() {
            "aes-128-gcm" | "2022-blake3-aes-128-gcm" => 16,
            "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "chacha20-poly1305"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305" => 32,
            _ => anyhow::bail!("unsupported Shadowsocks cipher: {}", method),
        };
        Ok(Self {
            key_len,
            salt_len: key_len,
            nonce_len: 12,
            tag_len: 16,
        })
    }
}

/// Owned AEAD cipher enum so we can avoid trait-object gymnastics.
///
/// AES-GCM and ChaCha20-Poly1305 go through **BoringSSL** (`AeadCtx`):
/// RustCrypto's `aes-gcm` measured 0.4–0.5 GB/s on AES-NI hardware vs
/// BoringSSL's 3.3–6.7 GB/s (benches/ss_aead.rs) — a 7–18× gap that made
/// SS2022 single-core-bound. Only XChaCha20-Poly1305 (no BoringSSL
/// equivalent) stays on RustCrypto.
pub(crate) enum AeadCipher {
    Aes128Gcm(boring::aead::AeadCtx),
    Aes256Gcm(boring::aead::AeadCtx),
    ChaCha20Poly1305(boring::aead::AeadCtx),
    XChaCha20Poly1305(Box<chacha20poly1305::XChaCha20Poly1305>),
}

/// Map a BoringSSL failure into the RustCrypto-shaped error callers use.
fn aead_err(_: boring::error::ErrorStack) -> aes_gcm::aead::Error {
    aes_gcm::aead::Error
}

impl AeadCipher {
    pub(crate) fn new(method: &str, key: &[u8]) -> anyhow::Result<Self> {
        use boring::aead::Algorithm;
        match method.to_lowercase().as_str() {
            "aes-128-gcm" | "2022-blake3-aes-128-gcm" => Ok(AeadCipher::Aes128Gcm(
                boring::aead::AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), key)?,
            )),
            "aes-256-gcm" | "2022-blake3-aes-256-gcm" => Ok(AeadCipher::Aes256Gcm(
                boring::aead::AeadCtx::new_default_tag(&Algorithm::aes_256_gcm(), key)?,
            )),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "2022-blake3-chacha20-poly1305" => {
                Ok(AeadCipher::ChaCha20Poly1305(
                    boring::aead::AeadCtx::new_default_tag(&Algorithm::chacha20_poly1305(), key)?,
                ))
            }
            _ => anyhow::bail!("unsupported Shadowsocks cipher: {}", method),
        }
    }

    #[cfg(feature = "rprx")]
    pub(crate) fn new_vless(use_aes: bool, key: &[u8]) -> anyhow::Result<Self> {
        Self::new(
            if use_aes {
                "aes-256-gcm"
            } else {
                "chacha20-poly1305"
            },
            key,
        )
    }

    /// XChaCha20-Poly1305 with a 24-byte nonce, used by the Shadowsocks 2022
    /// chacha UDP construction (keyed directly with the PSK).
    pub(crate) fn new_xchacha20(key: &[u8]) -> anyhow::Result<Self> {
        use aes_gcm::aead::KeyInit;
        Ok(AeadCipher::XChaCha20Poly1305(Box::new(
            chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)?,
        )))
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        use aes_gcm::aead::Aead;
        match self {
            AeadCipher::Aes128Gcm(_)
            | AeadCipher::Aes256Gcm(_)
            | AeadCipher::ChaCha20Poly1305(_) => {
                let mut out = Vec::with_capacity(plaintext.len() + 16);
                self.seal_into(nonce, plaintext, &mut out)?;
                Ok(out)
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.encrypt(nonce, plaintext)
            }
        }
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        use aes_gcm::aead::Aead;
        match self {
            AeadCipher::Aes128Gcm(_)
            | AeadCipher::Aes256Gcm(_)
            | AeadCipher::ChaCha20Poly1305(_) => {
                let mut buf = ciphertext.to_vec();
                let n = self.open_in_place(nonce, &mut buf)?;
                buf.truncate(n);
                Ok(buf)
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt(nonce, ciphertext)
            }
        }
    }

    /// Encrypt `plaintext`, appending ciphertext+tag to `out` (no allocation
    /// once `out` has capacity) — the hot-path batch form of [`Self::seal`].
    pub(crate) fn seal_into(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), aes_gcm::aead::Error> {
        self.seal_with_aad_into(nonce, plaintext, b"", out)
    }

    pub(crate) fn seal_with_aad_into(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), aes_gcm::aead::Error> {
        match self {
            AeadCipher::Aes128Gcm(c)
            | AeadCipher::Aes256Gcm(c)
            | AeadCipher::ChaCha20Poly1305(c) => boring_seal_into(c, nonce, plaintext, aad, out),
            AeadCipher::XChaCha20Poly1305(c) => {
                use aes_gcm::aead::AeadInOut;
                out.extend_from_slice(plaintext);
                let start = out.len() - plaintext.len();
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                let tag = c.encrypt_inout_detached(
                    nonce,
                    aad,
                    aes_gcm::aead::inout::InOutBuf::from(&mut out[start..]),
                )?;
                out.extend_from_slice(&tag);
                Ok(())
            }
        }
    }

    /// Decrypt `buf` in place (ciphertext+tag → plaintext, tag stripped) and
    /// return the plaintext length — the hot-path form of [`Self::open`].
    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, aes_gcm::aead::Error> {
        self.open_with_aad_in_place(nonce, buf, b"")
    }

    pub(crate) fn open_with_aad_in_place(
        &self,
        nonce: &[u8],
        buf: &mut [u8],
        aad: &[u8],
    ) -> Result<usize, aes_gcm::aead::Error> {
        let tag_len = self.tag_len();
        if buf.len() < tag_len {
            return Err(aes_gcm::aead::Error);
        }
        let (ct, tag) = buf.split_at_mut(buf.len() - tag_len);
        match self {
            AeadCipher::Aes128Gcm(c)
            | AeadCipher::Aes256Gcm(c)
            | AeadCipher::ChaCha20Poly1305(c) => {
                c.open_in_place(nonce, ct, tag, aad).map_err(aead_err)?;
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                use aes_gcm::aead::AeadInOut;
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                let tag: &chacha20poly1305::aead::Tag<chacha20poly1305::XChaCha20Poly1305> =
                    (&*tag).try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt_inout_detached(
                    nonce,
                    aad,
                    aes_gcm::aead::inout::InOutBuf::from(&mut *ct),
                    tag,
                )?;
            }
        }
        Ok(buf.len() - tag_len)
    }

    fn tag_len(&self) -> usize {
        16
    }
}

/// BoringSSL in-place seal appending to `out` (shared by the three
/// BoringSSL-backed variants).
fn boring_seal_into(
    ctx: &boring::aead::AeadCtx,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), aes_gcm::aead::Error> {
    out.extend_from_slice(plaintext);
    out.resize(out.len() + 16, 0);
    let start = out.len() - plaintext.len() - 16;
    let (body, tag) = out[start..].split_at_mut(plaintext.len());
    ctx.seal_in_place(nonce, body, tag, aad).map_err(aead_err)?;
    Ok(())
}

impl fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AeadCipher::Aes128Gcm(_) => f.write_str("Aes128Gcm"),
            AeadCipher::Aes256Gcm(_) => f.write_str("Aes256Gcm"),
            AeadCipher::ChaCha20Poly1305(_) => f.write_str("ChaCha20Poly1305"),
            AeadCipher::XChaCha20Poly1305(_) => f.write_str("XChaCha20Poly1305"),
        }
    }
}

/// Shadowsocks proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowsocksHandler;

impl ShadowsocksHandler {
    pub fn new() -> Self {
        Self
    }

    /// Derive the master key from the password using OpenSSL's EVP_BytesToKey.
    pub(crate) fn master_key(password: &str, key_len: usize) -> Vec<u8> {
        use md5::{Digest, Md5};
        let mut key = Vec::with_capacity(key_len);
        let mut last = Vec::new();
        while key.len() < key_len {
            let mut h = Md5::new();
            h.update(&last);
            h.update(password.as_bytes());
            last = h.finalize().to_vec();
            key.extend_from_slice(&last);
        }
        key.truncate(key_len);
        key
    }

    /// Shared dial tail: run the cipher-family prologue on the connected
    /// socket and return the inline codec stream (no relay task).
    async fn start_relay(
        &self,
        method: &str,
        password: &str,
        server: TcpStream,
        header: Vec<u8>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<ProxyStream> {
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let stream: Box<dyn super::AsyncReadWrite> = if is_2022_method(method) {
            let method_2022 = Ss2022Method::new(method, password)?;
            Box::new(aead2022::dial_stream(server, method_2022, header).await?)
        } else {
            let conf = CipherConf::for_method(method)?;
            let master_key = Self::master_key(password, conf.key_len);
            let mut server = server;

            // Legacy prologue: send salt and the header chunk, then return.
            // The response salt is read from the read path (2022 parity) —
            // servers may delay it until the first target payload, so
            // reading it here would deadlock dial().
            let mut send_salt = vec![0u8; conf.salt_len];
            rand::rng().fill_bytes(&mut send_salt);
            let mut send_subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&master_key, &send_salt, &mut send_subkey);
            let send_cipher = AeadCipher::new(method, &send_subkey)?;
            server.write_all(&send_salt).await?;

            let mut send_nonce = vec![0u8; conf.nonce_len];
            stream::write_all_sealed(&mut server, &send_cipher, &mut send_nonce, &header).await?;

            let prologue = stream::LegacyPrologue {
                conf,
                master_key,
                method: method.to_string(),
            };
            Box::new(stream::SsStream::new_legacy(
                server,
                send_cipher,
                send_nonce,
                prologue,
            ))
        };
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TargetRequestSent,
        );
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl TcpOutbound for ShadowsocksHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let config = node.shadowsocks().unwrap();
        let method = config.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = config.password.as_deref().unwrap_or("");
        // Validate the cipher/key material up front so dial fails fast.
        if is_2022_method(method) {
            Ss2022Method::new(method, password)?;
        } else {
            CipherConf::for_method(method)?;
        }

        let addr = format!("{}:{}", node.host(), node.port);
        debug!("Shadowsocks: connecting to {} for target {}", addr, target);
        let server = crate::util::connect_outbound(&addr, connect_timeout).await?;

        let header = addr::encode_address(target, target_domain)?;
        self.start_relay(method, password, server, header, target, target_domain)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        server: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let config = node.shadowsocks().unwrap();
        let method = config.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = config.password.as_deref().unwrap_or("");
        let header = addr::encode_address(target, target_domain)?;
        self.start_relay(method, password, server, header, target, target_domain)
            .await
    }
}

#[async_trait]
impl PacketOutbound for ShadowsocksHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (crypto, outbound, socks) =
            Self::udp_server_session(node, target, target_domain, connect_timeout).await?;
        Ok(Arc::new(SsUdpTransport {
            socket: outbound,
            crypto: tokio::sync::Mutex::new(crypto),
            recv_buf: tokio::sync::Mutex::new(None),
            socks,
            target,
        }))
    }
}

#[async_trait]
impl ProbeableOutbound for ShadowsocksHandler {}

impl ShadowsocksHandler {
    /// Set up a UDP relay session towards the server: cipher state plus a
    /// connected, bypass-marked server-facing socket.
    async fn udp_server_session(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<(SsUdpCrypto, tokio::net::UdpSocket, Vec<u8>)> {
        let config = node.shadowsocks().unwrap();
        let method = config.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = config.password.as_deref().unwrap_or("");
        let socks = addr::encode_address(target, target_domain)?;

        let crypto = if is_2022_method(method) {
            SsUdpCrypto::V2022(Box::new(Ss2022UdpSession::new(Ss2022Method::new(
                method, password,
            )?)?))
        } else {
            SsUdpCrypto::Legacy(LegacyUdpCrypto::new(method, password)?)
        };

        // Resolve the server address up front: the session socket is
        // connected, which also pins the reply peer.
        let lookup = format!("{}:{}", node.host(), node.port);
        let server_addr = tokio::time::timeout(connect_timeout, async {
            let resolution = crate::bootstrap::resolve(node.host());
            let (resolution, selection) =
                crate::runtime::flow_observation::observe_resolution(resolution).await;
            let ip = resolution?.into_iter().next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host")
            })?;
            if let Some(selection) = selection {
                selection.selected_ip(ip);
            }
            Ok::<_, std::io::Error>(SocketAddr::new(ip, node.port))
        })
        .await
        .map_err(|_| anyhow::anyhow!("Shadowsocks UDP: resolve {} timed out", lookup))??;

        // Server-facing socket (bypass-marked so eBPF does not re-route it).
        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
        } else {
            "[::]:0".parse().expect("hardcoded IPv6 bind address")
        };
        let outbound = crate::util::udp_marked_bind(bind_addr).await?;
        outbound.connect(server_addr).await?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        debug!(
            "Shadowsocks UDP: session to {} for target {}",
            server_addr, target
        );
        Ok((crypto, outbound, socks))
    }
}

/// Framed Shadowsocks UDP transport: datagrams are sealed/opened in place
/// and go straight over the connected server-facing socket.
struct SsUdpTransport {
    socket: tokio::net::UdpSocket,
    crypto: tokio::sync::Mutex<SsUdpCrypto>,
    recv_buf: tokio::sync::Mutex<Option<Vec<u8>>>,
    socks: Vec<u8>,
    target: SocketAddr,
}

impl fmt::Debug for SsUdpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsUdpTransport")
            .field("target", &self.target)
            .finish()
    }
}

#[async_trait]
impl PacketTransport for SsUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        // The endpoint driver already serializes this flow's sends. Receive
        // holds the shared cipher only for one decrypt, so awaiting that
        // short critical section preserves datagrams without an unobservable
        // overload drop or a per-packet task.
        let mut crypto = self.crypto.lock().await;
        let packet = crypto
            .seal(&self.socks, self.target.port(), data)
            .map_err(std::io::Error::other)?;
        drop(crypto);
        let sent = self.socket.send(&packet).await?;
        if sent != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial Shadowsocks UDP datagram send",
            ));
        }
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut recv_buf = self.recv_buf.lock().await;
        // Core already supplies a full datagram buffer; only smaller callers
        // need reusable ciphertext scratch separate from their plaintext output.
        let mut scratch = if buf.len() >= UDP_PACKET_BUFFER_SIZE {
            None
        } else {
            Some(recv_buf.get_or_insert_with(|| vec![0u8; UDP_PACKET_BUFFER_SIZE]))
        };
        // A datagram that fails to open (short, wrong key, replayed, bad
        // address) is that datagram's problem: the session and the endpoint
        // stay valid, so drop it and keep receiving. Only the socket ends the
        // transport.
        loop {
            let wire = match scratch.as_deref_mut() {
                Some(scratch) => scratch.as_mut_slice(),
                None => &mut *buf,
            };
            let n = self.socket.recv(wire).await?;
            let payload = match self.crypto.lock().await.open(&wire[..n]) {
                Ok(payload) => payload,
                Err(error) => {
                    debug!(
                        "Shadowsocks UDP: dropping {} byte datagram for {}: {}",
                        n, self.target, error
                    );
                    continue;
                }
            };
            if payload.len() > buf.len() {
                debug!(
                    "Shadowsocks UDP: dropping {} byte payload for {} that exceeds the {} byte buffer",
                    payload.len(),
                    self.target,
                    buf.len()
                );
                continue;
            }
            buf[..payload.len()].copy_from_slice(&payload);
            return Ok((payload.len(), self.target));
        }
    }
}

/// Steady-state relay read batch (64KB = 4 chunks): batched seal/decrypt
/// without the per-connection memory cost of the old 256KB draft — see
/// stream.rs for why it is not larger.
pub(crate) const RELAY_BATCH: usize = 64 * 1024;

/// Seal `payload` as Shadowsocks chunks into `out` (cleared first). One
/// allocation-free pass in steady state.
pub(crate) fn seal_chunks_into(
    cipher: &AeadCipher,
    nonce: &mut [u8],
    payload: &[u8],
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    out.clear();
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + CHUNK_MAX_LEN).min(payload.len());
        let chunk = &payload[offset..end];
        let len = (chunk.len() as u16).to_be_bytes();
        cipher
            .seal_into(nonce, &len, out)
            .map_err(|e| anyhow::anyhow!("encrypt length failed: {:?}", e))?;
        increment_nonce(nonce);
        cipher
            .seal_into(nonce, chunk, out)
            .map_err(|e| anyhow::anyhow!("encrypt payload failed: {:?}", e))?;
        increment_nonce(nonce);
        offset = end;
    }
    Ok(())
}

/// Batched chunk-decrypting reader: reads whatever is available into
/// `buf`, decrypts complete chunks in place, and compacts plaintext at the
/// front; returns `(plaintext_len, carry)` — the first `plaintext_len`
/// bytes of `buf` are ready for the client, and `carry` bytes after them
/// hold an incomplete chunk to prepend to the next batch.
///
/// `pending_len` carries the already-decrypted length of an incomplete
/// chunk across feeds: the length field is only ever decrypted once (the
/// nonce must advance exactly once per chunk part).
pub(crate) fn decrypt_chunks_in_place(
    cipher: &AeadCipher,
    nonce: &mut [u8],
    pending_len: &mut Option<u16>,
    buf: &mut [u8],
    total: usize,
    tag_len: usize,
) -> anyhow::Result<(usize, usize)> {
    let len_field = 2 + tag_len;
    let mut pos = 0;
    let mut out_len = 0;
    loop {
        let len = match *pending_len {
            Some(len) => len as usize,
            None => {
                if pos + len_field > total {
                    break; // no complete length field yet
                }
                cipher
                    .open_in_place(nonce, &mut buf[pos..pos + len_field])
                    .map_err(|e| anyhow::anyhow!("decrypt length failed: {:?}", e))?;
                increment_nonce(nonce);
                let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                *pending_len = Some(len as u16);
                len
            }
        };
        let chunk_end = pos + len_field + len + tag_len;
        if chunk_end > total {
            break; // incomplete chunk: wait for more data (len kept pending)
        }
        cipher
            .open_in_place(nonce, &mut buf[pos + len_field..chunk_end])
            .map_err(|e| anyhow::anyhow!("decrypt payload failed: {:?}", e))?;
        increment_nonce(nonce);
        *pending_len = None;
        // Compact plaintext to the front (out_len < pos always holds, since
        // plaintext is shorter than ciphertext).
        buf.copy_within(pos + len_field..pos + len_field + len, out_len);
        out_len += len;
        pos = chunk_end;
    }
    // Move the unparsed remainder behind the plaintext.
    let carry = total - pos;
    if carry > 0 && pos != out_len {
        buf.copy_within(pos..total, out_len);
    }
    Ok((out_len, carry))
}

/// Derive a per-session subkey with HKDF-SHA1.
pub(crate) fn hkdf_sha1_derive(master_key: &[u8], salt: &[u8], okm: &mut [u8]) {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    hk.expand(SS_SUBKEY_INFO, okm)
        .expect("valid HKDF output length");
}

/// Increment a nonce treating it as a little-endian counter.
pub(crate) fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
}

/// Legacy AEAD UDP encapsulation: `salt | AEAD(subkey)(addr | payload)`
/// with a fresh random salt and an all-zero nonce per datagram.
pub(crate) struct LegacyUdpCrypto {
    method: String,
    master_key: Vec<u8>,
    conf: CipherConf,
}

impl LegacyUdpCrypto {
    pub(crate) fn new(method: &str, password: &str) -> anyhow::Result<Self> {
        let conf = CipherConf::for_method(method)?;
        Ok(Self {
            method: method.to_string(),
            master_key: ShadowsocksHandler::master_key(password, conf.key_len),
            conf,
        })
    }

    pub(crate) fn seal(&self, socks: &[u8], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut salt = vec![0u8; self.conf.salt_len];
        rand::rng().fill_bytes(&mut salt);
        let mut subkey = vec![0u8; self.conf.key_len];
        hkdf_sha1_derive(&self.master_key, &salt, &mut subkey);
        let cipher = AeadCipher::new(&self.method, &subkey)?;
        let nonce = vec![0u8; self.conf.nonce_len];

        let mut body = Vec::with_capacity(socks.len() + payload.len());
        body.extend_from_slice(socks);
        body.extend_from_slice(payload);
        let sealed = cipher
            .seal(&nonce, &body)
            .map_err(|e| anyhow::anyhow!("seal UDP packet failed: {:?}", e))?;

        let mut out = salt;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub(crate) fn open(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        if packet.len() < self.conf.salt_len + self.conf.tag_len {
            anyhow::bail!("UDP packet too short");
        }
        let (salt, ciphertext) = packet.split_at(self.conf.salt_len);
        let mut subkey = vec![0u8; self.conf.key_len];
        hkdf_sha1_derive(&self.master_key, salt, &mut subkey);
        let cipher = AeadCipher::new(&self.method, &subkey)?;
        let nonce = vec![0u8; self.conf.nonce_len];
        let body = cipher
            .open(&nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("open UDP packet failed: {:?}", e))?;
        let skip = addr::socks_addr_len(&body)?;
        Ok(body[skip..].to_vec())
    }
}

/// UDP encapsulation for the two Shadowsocks cipher families.
pub(crate) enum SsUdpCrypto {
    Legacy(LegacyUdpCrypto),
    V2022(Box<Ss2022UdpSession>),
}

impl SsUdpCrypto {
    fn seal(&mut self, socks: &[u8], target_port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            SsUdpCrypto::Legacy(c) => c.seal(socks, payload),
            SsUdpCrypto::V2022(s) => s.seal_packet(socks, target_port, payload),
        }
    }

    fn open(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            SsUdpCrypto::Legacy(c) => c.open(packet),
            SsUdpCrypto::V2022(s) => s.open_packet(packet),
        }
    }
}

#[cfg(test)]
mod tests;
