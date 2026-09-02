//! Shadowsocks AEAD outbound handler.
//!
//! Supports the standard AEAD ciphers (legacy, per shadowsocks.org/doc/aead.html):
//! - `aes-128-gcm`
//! - `aes-256-gcm`
//! - `chacha20-ietf-poly1305` (alias `chacha20-poly1305`)
//!
//! and the Shadowsocks 2022 methods (SIP022, implemented in
//! [`super::shadowsocks_2022`]):
//! - `2022-blake3-aes-128-gcm`
//! - `2022-blake3-aes-256-gcm`
//! - `2022-blake3-chacha20-poly1305`
//!
//! The handler dials the Shadowsocks server, performs the salt + subkey
//! handshake, and returns a `ProxyStream` backed by a local duplex pipe.
//! A background task encrypts traffic to the server and decrypts traffic
//! back using Shadowsocks' record chunking (`[len][tag][payload][tag]`).
//!
//! UDP is supported for both cipher families through `dial_udp_transport`:
//! datagrams are sealed/opened in place and exchanged over a connected
//! server-facing socket (legacy: per-packet salt + AEAD; 2022: session-based
//! separate-header construction).
//!
//! References: <https://shadowsocks.org/doc/aead.html>,
//! <https://shadowsocks.org/doc/sip022.html>

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
use super::shadowsocks_2022::{self, Ss2022Method, Ss2022UdpSession};
use super::{PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound};

pub(crate) const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub(crate) const CHUNK_MAX_LEN: usize = 0x3FFF; // 2^14 - 1

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
        match method.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(CipherConf {
                key_len: 16,
                salt_len: 16,
                nonce_len: 12,
                tag_len: 16,
            }),
            "aes-256-gcm" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            // SIP022: salt length equals the key length.
            "2022-blake3-aes-128-gcm" => Ok(CipherConf {
                key_len: 16,
                salt_len: 16,
                nonce_len: 12,
                tag_len: 16,
            }),
            "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            _ => anyhow::bail!("unsupported Shadowsocks cipher: {}", method),
        }
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
            AeadCipher::Aes128Gcm(c) | AeadCipher::Aes256Gcm(c) => {
                boring_seal_into(c, nonce, plaintext, aad, out)
            }
            AeadCipher::ChaCha20Poly1305(c) => boring_seal_into(c, nonce, plaintext, aad, out),
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
            AeadCipher::Aes128Gcm(c) | AeadCipher::Aes256Gcm(c) => {
                c.open_in_place(nonce, ct, tag, aad).map_err(aead_err)?;
            }
            AeadCipher::ChaCha20Poly1305(c) => {
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
        let stream: Box<dyn super::AsyncReadWrite> = if is_2022_method(method) {
            let method_2022 = Ss2022Method::new(method, password)?;
            Box::new(shadowsocks_2022::dial_stream(server, method_2022, header).await?)
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
            crate::proxy::ss_stream::write_all_sealed(
                &mut server,
                &send_cipher,
                &mut send_nonce,
                &header,
            )
            .await?;

            let prologue = crate::proxy::ss_stream::LegacyPrologue {
                conf,
                master_key,
                method: method.to_string(),
            };
            Box::new(crate::proxy::ss_stream::SsStream::new_legacy(
                server,
                send_cipher,
                send_nonce,
                prologue,
            ))
        };
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
            socket: Arc::new(outbound),
            crypto: tokio::sync::Mutex::new(crypto),
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
            let ips = crate::bootstrap::resolve(node.host()).await?;
            ips.into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, node.port))
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host")
                })
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
    socket: Arc<tokio::net::UdpSocket>,
    crypto: tokio::sync::Mutex<SsUdpCrypto>,
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
        let n = self.socket.recv(buf).await?;
        let payload = self
            .crypto
            .lock()
            .await
            .open(&buf[..n])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if payload.len() > buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowsocks packet exceeds buffer",
            ));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok((payload.len(), self.target))
    }
}

/// Steady-state relay read batch (64KB = 4 chunks): batched seal/decrypt
/// without the per-connection memory cost of the old 256KB draft — see
/// ss_stream.rs for why it is not larger.
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
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_evp_bytes_to_key() {
        let key = ShadowsocksHandler::master_key("foobar", 32);
        assert_eq!(key.len(), 32);
        // MD5("foobar") == 3858f62230ac3c915f300c664312c63f, which is the first
        // block of EVP_BytesToKey output.
        assert_eq!(
            &key[..16],
            &[
                0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12,
                0xc6, 0x3f
            ]
        );
    }

    #[test]
    fn test_nonce_increment() {
        let mut n = [0u8; 12];
        increment_nonce(&mut n);
        assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        n[0] = 0xFF;
        increment_nonce(&mut n);
        assert_eq!(n, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_cipher_conf_lookup() {
        assert!(CipherConf::for_method("aes-128-gcm").is_ok());
        assert!(CipherConf::for_method("AES-256-GCM").is_ok());
        assert!(CipherConf::for_method("chacha20-ietf-poly1305").is_ok());
        assert!(CipherConf::for_method("chacha20-poly1305").is_ok());
        assert!(CipherConf::for_method("2022-blake3-aes-128-gcm").is_ok());
        assert!(CipherConf::for_method("2022-blake3-aes-256-gcm").is_ok());
        assert!(CipherConf::for_method("2022-blake3-chacha20-poly1305").is_ok());
        assert!(CipherConf::for_method("rc4-md5").is_err());
    }

    #[test]
    fn test_is_2022_method() {
        assert!(is_2022_method("2022-blake3-aes-128-gcm"));
        assert!(is_2022_method("2022-BLAKE3-AES-256-GCM"));
        assert!(is_2022_method("2022-blake3-chacha20-poly1305"));
        assert!(!is_2022_method("aes-256-gcm"));
        assert!(!is_2022_method("chacha20-ietf-poly1305"));
    }

    #[test]
    fn test_legacy_udp_roundtrip() {
        let crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
        let socks = addr::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            None,
        )
        .unwrap();
        let payload = b"\xde\xad\xbe\xef dns query";
        let packet = crypto.seal(&socks, payload).unwrap();
        // salt + tag minimum
        assert!(packet.len() > 16 + 16 + payload.len());
        let opened = crypto.open(&packet).unwrap();
        assert_eq!(opened, payload);
    }

    #[tokio::test]
    async fn udp_send_waits_for_cipher_instead_of_reporting_a_drop_as_success() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let transport = Arc::new(SsUdpTransport {
            socket: Arc::new(client),
            crypto: tokio::sync::Mutex::new(SsUdpCrypto::Legacy(
                LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap(),
            )),
            socks: addr::encode_address(target, None).unwrap(),
            target,
        });
        let guard = transport.crypto.lock().await;
        let sender = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move { transport.send_packet(b"retained").await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            !sender.is_finished(),
            "cipher contention must apply backpressure instead of returning false success"
        );

        drop(guard);
        sender.await.unwrap().unwrap();
        let mut packet = [0u8; 256];
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert!(received > b"retained".len());
    }

    #[test]
    fn test_legacy_udp_roundtrip_chacha() {
        let crypto = LegacyUdpCrypto::new("chacha20-ietf-poly1305", "test-password").unwrap();
        let socks = addr::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
            Some("one.one"),
        )
        .unwrap();
        let payload = b"quic initial";
        let packet = crypto.seal(&socks, payload).unwrap();
        let opened = crypto.open(&packet).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn test_legacy_udp_open_rejects_garbage() {
        let crypto = LegacyUdpCrypto::new("aes-256-gcm", "test-password").unwrap();
        assert!(crypto.open(&[0u8; 10]).is_err());
        let mut garbage = vec![0u8; 64];
        rand::rng().fill_bytes(&mut garbage);
        assert!(crypto.open(&garbage).is_err());
    }

    /// Batched seal/decrypt equivalence: any payload round-trips through
    /// `seal_chunks_into` + `decrypt_chunks_in_place` in one batch.
    #[test]
    fn test_batched_chunk_roundtrip() {
        let cipher =
            AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
        for payload_len in [0usize, 1, 100, CHUNK_MAX_LEN, CHUNK_MAX_LEN + 17, 100_000] {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
            let mut send_nonce = vec![0u8; 12];
            let mut sealed = Vec::new();
            seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();
            assert_eq!(
                sealed.len(),
                payload_len + payload_len.div_ceil(CHUNK_MAX_LEN) * (2 + 16 + 16)
            );

            let mut recv_nonce = vec![0u8; 12];
            let mut buf = sealed;
            let total = buf.len();
            let (out_len, carry) =
                decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut None, &mut buf, total, 16)
                    .unwrap();
            assert_eq!(carry, 0, "complete batch must leave no carry");
            assert_eq!(&buf[..out_len], payload.as_slice());
        }
    }

    /// Split feeds: chunks spanning batch boundaries must be carried and
    /// completed by the next feed.
    #[test]
    fn test_batched_decrypt_split_feeds() {
        let cipher =
            AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
        let mut send_nonce = vec![0u8; 12];
        let mut sealed = Vec::new();
        seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();

        let mut recv_nonce = vec![0u8; 12];
        let mut pending = None;
        let mut received = Vec::new();
        let mut carry_buf = vec![0u8; 0];
        // Feed in awkward slices that split len fields and chunk bodies.
        for slice_len in [1usize, 3, 7, 8192, 5, 4096, 65536] {
            let take = slice_len.min(sealed.len());
            let mut feed = carry_buf.clone();
            feed.extend_from_slice(&sealed[..take]);
            sealed.drain(..take);
            let total = feed.len();
            let (out_len, rest) = decrypt_chunks_in_place(
                &cipher,
                &mut recv_nonce,
                &mut pending,
                &mut feed,
                total,
                16,
            )
            .unwrap();
            received.extend_from_slice(&feed[..out_len]);
            carry_buf = feed[out_len..out_len + rest].to_vec();
        }
        assert!(sealed.is_empty());
        let total = carry_buf.len();
        let (out_len, rest) = decrypt_chunks_in_place(
            &cipher,
            &mut recv_nonce,
            &mut pending,
            &mut carry_buf,
            total,
            16,
        )
        .unwrap();
        received.extend_from_slice(&carry_buf[..out_len]);
        assert_eq!(rest, 0);
        assert_eq!(received, payload);
    }

    /// End-to-end UDP test: mock legacy-AEAD server, real
    /// `dial_udp_transport`, payload exchange through the framed transport.
    #[tokio::test]
    async fn test_dial_udp_legacy_end_to_end() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                let (n, src) = server.recv_from(&mut buf).await.unwrap();
                let payload = server_crypto.open(&buf[..n]).unwrap();
                let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
                let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
                let packet = server_crypto.seal(&socks, &reply).unwrap();
                server.send_to(&packet, src).await.unwrap();
            }
        });

        let node = Node {
            name: "test-ss-udp".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some("aes-128-gcm".into()),
                    password: Some("test-password".into()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let transport = handler
            .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();

        transport.send_packet(b"hello dns").await.unwrap();
        let mut buf = [0u8; 65536];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"HELLO DNS");
    }

    /// End-to-end TCP test: mock legacy-AEAD TCP server (salt + chunk
    /// codec), real `dial` through the inline `SsStream`, bulk data both
    /// ways (chunk boundaries crossed many times).
    #[tokio::test]
    async fn test_dial_tcp_legacy_end_to_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            let method = "aes-128-gcm";
            let password = "test-password";
            let conf = CipherConf::for_method(method).unwrap();
            let master = ShadowsocksHandler::master_key(password, conf.key_len);

            // Read the client salt + derive the c2s cipher.
            let mut c2s_salt = vec![0u8; conf.salt_len];
            server.read_exact(&mut c2s_salt).await.unwrap();
            let mut c2s_subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&master, &c2s_salt, &mut c2s_subkey);
            let c2s_cipher = AeadCipher::new(method, &c2s_subkey).unwrap();
            let mut c2s_nonce = vec![0u8; conf.nonce_len];

            // Send our salt back.
            let mut s2c_salt = vec![0u8; conf.salt_len];
            rand::rng().fill_bytes(&mut s2c_salt);
            server.write_all(&s2c_salt).await.unwrap();
            let mut s2c_subkey = vec![0u8; conf.key_len];
            hkdf_sha1_derive(&master, &s2c_salt, &mut s2c_subkey);
            let s2c_cipher = AeadCipher::new(method, &s2c_subkey).unwrap();
            let mut s2c_nonce = vec![0u8; conf.nonce_len];

            // Echo loop: decrypt chunks, uppercase the payload, re-seal.
            // The first plaintext bytes are the target header (own chunk);
            // skip them, echo the rest.
            let header_len = 7usize; // atyp + v4 + port of 93.184.216.34:80
            let mut skip = header_len;
            let mut buf = vec![0u8; 262144];
            let mut carry = 0usize;
            let mut pending_len = None;
            loop {
                let n = server.read(&mut buf[carry..]).await.unwrap();
                if n == 0 {
                    return;
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
                if out_len > 0 {
                    let start = skip.min(out_len);
                    skip -= start;
                    if start < out_len {
                        let upper: Vec<u8> = buf[start..out_len]
                            .iter()
                            .map(|b| b.to_ascii_uppercase())
                            .collect();
                        let mut sealed = Vec::new();
                        seal_chunks_into(&s2c_cipher, &mut s2c_nonce, &upper, &mut sealed).unwrap();
                        server.write_all(&sealed).await.unwrap();
                    }
                }
                if rest > 0 {
                    buf.copy_within(out_len..out_len + rest, 0);
                }
                carry = rest;
            }
        });

        let node = Node {
            name: "test-ss-tcp".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some("aes-128-gcm".into()),
                    password: Some("test-password".into()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut stream = handler
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();

        // Bulk transfer both ways: ~1MB in 8 uneven writes.
        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        let mut off = 0;
        for chunk in [3usize, 65536, 17, 262144, 999, 400_000, 131071, 271_329] {
            let end = (off + chunk).min(payload.len());
            stream.stream.write_all(&payload[off..end]).await.unwrap();
            off = end;
        }
        assert_eq!(off, payload.len());

        let mut received = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.stream.read_exact(&mut received),
        )
        .await
        .expect("echo timed out")
        .unwrap();
        let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
        assert_eq!(received, expected);
    }

    /// Same as `test_dial_udp_legacy_end_to_end` but through the framed
    /// `dial_udp_transport` path (no loopback pair).
    #[tokio::test]
    async fn test_dial_udp_transport_legacy_end_to_end() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                let (n, src) = server.recv_from(&mut buf).await.unwrap();
                let payload = server_crypto.open(&buf[..n]).unwrap();
                let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
                let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
                let packet = server_crypto.seal(&socks, &reply).unwrap();
                server.send_to(&packet, src).await.unwrap();
            }
        });

        let node = Node {
            name: "test-ss-udp".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some("aes-128-gcm".into()),
                    password: Some("test-password".into()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let transport = handler
            .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(transport.relay_addr(), target);

        transport.send_packet(b"hello dns").await.unwrap();
        let mut buf = [0u8; 65536];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"HELLO DNS");
    }
}
