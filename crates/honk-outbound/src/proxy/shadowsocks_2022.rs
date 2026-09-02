//! Shadowsocks 2022 (SIP022) method support.
//!
//! Implemented against the sing-shadowsocks2 reference implementation
//! (`shadowaead_2022/method.go`, `protocol.go`, `slidingwindow.go`):
//!
//! - Key derivation uses BLAKE3 derive-key mode with the exact context
//!   strings `shadowsocks 2022 session subkey` / `shadowsocks 2022 identity
//!   subkey`.
//! - TCP request: `salt | EIH* | AEAD(fixed header) | AEAD(variable header)`
//!   followed by the usual length/payload chunk stream (little-endian nonce
//!   counter). The response starts with a fixed header chunk that doubles as
//!   the first length chunk.
//! - UDP (AES methods): 16-byte separate header `AES-ECB(first psk,
//!   session_id | packet_id)`, optional EIH blocks, and the body sealed with
//!   `AEAD(SessionKey(last psk, session_id))` under nonce
//!   `plain_header[4..16]`.
//! - UDP (chacha method): XChaCha20-Poly1305 keyed directly with the PSK and
//!   a random 24-byte nonce per packet; nonces and the session id come from
//!   a BLAKE3 keyed-hash XOF like upstream's `Blake3KeyedHash`.
//! - Receive paths validate header type, timestamp (±30s), echoed salt /
//!   client session id, and enforce sliding-window replay protection.
//!
//! Reference: <https://shadowsocks.org/doc/sip022.html>

use rand::Rng;
use rand::RngExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use super::addr::socks_addr_len;
use super::shadowsocks::{AeadCipher, increment_nonce};

const HEADER_TYPE_CLIENT: u8 = 0;
pub(crate) const HEADER_TYPE_SERVER: u8 = 1;
/// sing-shadowsocks2 `MaxPaddingLength`.
const MAX_PADDING_LENGTH: usize = 900;
/// sing-shadowsocks2 `PacketMinimalHeaderSize`.
const UDP_MINIMAL_PACKET_SIZE: usize = 30;
/// XChaCha20-Poly1305 nonce size (sing-shadowsocks2 `PacketNonceSize`).
const UDP_XNONCE_SIZE: usize = 24;
/// AEAD tag size.
pub(crate) const TAG_LEN: usize = 16;
/// AEAD nonce size for the stream ciphers.
pub(crate) const NONCE_LEN: usize = 12;

pub(crate) fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parsed Shadowsocks 2022 method: cipher name plus PSK material.
///
/// The password is either a single base64 PSK or several base64 PSKs joined
/// by `:`. With multiple PSKs the *last* one is the encryption PSK and all
/// preceding ones are identity PSKs used for Extensible Identity Headers
/// (EIH, AES methods only).
pub(crate) struct Ss2022Method {
    method: String,
    pub(crate) key_len: usize,
    psks: Vec<Vec<u8>>,
    /// `psk_hashes[i] = BLAKE3(psks[i + 1])[..16]` — the EIH plaintexts.
    ///
    /// sing-shadowsocks2 uses `blake3.Sum512(psk)[:16]`; BLAKE3 XOF output
    /// is a prefix stream, so the first 16 bytes equal the first 16 bytes of
    /// the standard 32-byte `blake3::hash` output (verified against the Go
    /// implementation).
    psk_hashes: Vec<[u8; 16]>,
}

impl Ss2022Method {
    pub(crate) fn new(method: &str, password: &str) -> anyhow::Result<Self> {
        use base64::Engine;
        let lower = method.to_lowercase();
        let (key_len, is_chacha) = match lower.as_str() {
            "2022-blake3-aes-128-gcm" => (16, false),
            "2022-blake3-aes-256-gcm" => (32, false),
            "2022-blake3-chacha20-poly1305" => (32, true),
            _ => anyhow::bail!("unsupported Shadowsocks 2022 method: {}", method),
        };

        let mut psks = Vec::new();
        for part in password.split(':') {
            let psk = base64::engine::general_purpose::STANDARD
                .decode(part.trim())
                .map_err(|e| anyhow::anyhow!("decode Shadowsocks 2022 psk: {}", e))?;
            if psk.len() != key_len {
                anyhow::bail!(
                    "bad Shadowsocks 2022 key length, required {}, got {}",
                    key_len,
                    psk.len()
                );
            }
            psks.push(psk);
        }
        if psks.is_empty() {
            anyhow::bail!("missing Shadowsocks 2022 psk");
        }
        if psks.len() > 1 && is_chacha {
            anyhow::bail!("Shadowsocks 2022 EIH support only available in AES ciphers");
        }

        let psk_hashes = psks[1..]
            .iter()
            .map(|psk| {
                let hash = blake3::hash(psk);
                let mut out = [0u8; 16];
                out.copy_from_slice(&hash.as_bytes()[..16]);
                out
            })
            .collect();

        Ok(Self {
            method: lower,
            key_len,
            psks,
            psk_hashes,
        })
    }

    fn is_chacha(&self) -> bool {
        self.method.contains("chacha20")
    }

    /// The last PSK: encrypts the actual traffic.
    fn encryption_psk(&self) -> &[u8] {
        &self.psks[self.psks.len() - 1]
    }

    /// `blake3::derive_key("shadowsocks 2022 session subkey", psk || salt)`,
    /// truncated to the method key length.
    fn session_subkey_with(&self, psk: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut material = Vec::with_capacity(psk.len() + salt.len());
        material.extend_from_slice(psk);
        material.extend_from_slice(salt);
        blake3::derive_key("shadowsocks 2022 session subkey", &material)[..self.key_len].to_vec()
    }

    pub(crate) fn session_subkey(&self, salt: &[u8]) -> Vec<u8> {
        self.session_subkey_with(self.encryption_psk(), salt)
    }

    pub(crate) fn aead(&self, subkey: &[u8]) -> anyhow::Result<AeadCipher> {
        AeadCipher::new(&self.method, subkey)
    }

    /// TCP Extensible Identity Headers for `salt`, concatenated
    /// (`(n_psks - 1) * 16` bytes, empty for a single PSK).
    ///
    /// Per sing-shadowsocks2 `writeExtendedIdentityHeaders`:
    /// `EIH_i = AES-ECB(identity_subkey_i, psk_hashes[i])` with
    /// `identity_subkey_i = blake3::derive_key("shadowsocks 2022 identity
    /// subkey", psk_i || salt)` and `psk_hashes[i] = BLAKE3(psk_{i+1})[..16]`.
    fn tcp_identity_headers(&self, salt: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity((self.psks.len() - 1) * 16);
        for (i, psk) in self.psks.iter().take(self.psks.len() - 1).enumerate() {
            let mut material = Vec::with_capacity(psk.len() + salt.len());
            material.extend_from_slice(psk);
            material.extend_from_slice(salt);
            let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
            let block = AesBlock::new(&identity_subkey[..self.key_len])?;
            let mut eih = self.psk_hashes[i];
            block.encrypt(&mut eih);
            out.extend_from_slice(&eih);
        }
        Ok(out)
    }
}

/// Raw AES block cipher (single-block ECB), used for EIH blocks and the UDP
/// separate header. Reuses the `aes` crate re-exported by `aes-gcm`.
pub(crate) enum AesBlock {
    Aes128(Box<aes_gcm::aes::Aes128>),
    Aes256(Box<aes_gcm::aes::Aes256>),
}

impl AesBlock {
    pub(crate) fn new(key: &[u8]) -> anyhow::Result<Self> {
        use aes_gcm::aes::cipher::KeyInit;
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(
                aes_gcm::aes::Aes128::new_from_slice(key)?,
            ))),
            32 => Ok(Self::Aes256(Box::new(
                aes_gcm::aes::Aes256::new_from_slice(key)?,
            ))),
            _ => anyhow::bail!("bad AES key length {}", key.len()),
        }
    }

    pub(crate) fn encrypt(&self, data: &mut [u8; 16]) {
        use aes_gcm::aes::cipher::BlockCipherEncrypt;
        match self {
            Self::Aes128(c) => c.encrypt_block(data.into()),
            Self::Aes256(c) => c.encrypt_block(data.into()),
        }
    }

    pub(crate) fn decrypt(&self, data: &mut [u8; 16]) {
        use aes_gcm::aes::cipher::BlockCipherDecrypt;
        match self {
            Self::Aes128(c) => c.decrypt_block(data.into()),
            Self::Aes256(c) => c.decrypt_block(data.into()),
        }
    }
}

/// BLAKE3 keyed-hash XOF stream, mirroring sing-shadowsocks2
/// `Blake3KeyedHash` (32-byte random key, XOF used as a CSPRNG for the
/// chacha UDP session id and per-packet nonces).
struct Blake3Xof(blake3::OutputReader);

impl Blake3Xof {
    fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self::with_key(key)
    }

    fn with_key(key: [u8; 32]) -> Self {
        Self(blake3::Hasher::new_keyed(&key).finalize_xof())
    }

    fn fill(&mut self, buf: &mut [u8]) {
        use std::io::Read;
        self.0
            .read_exact(buf)
            .expect("BLAKE3 XOF output is infallible");
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_be_bytes(b)
    }
}

/// Sliding-window replay filter (port of sing-shadowsocks2
/// `slidingwindow.go`: 128 blocks of 64 bits).
struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

const SW_BLOCK_BIT_LOG: u64 = 6;
const SW_RING_BLOCKS: u64 = 128;
const SW_BLOCK_MASK: u64 = SW_RING_BLOCKS - 1;
const SW_BIT_MASK: u64 = (1 << SW_BLOCK_BIT_LOG) - 1;
const SW_SIZE: u64 = (SW_RING_BLOCKS - 1) << SW_BLOCK_BIT_LOG;

impl SlidingWindow {
    fn new() -> Self {
        Self {
            last: 0,
            ring: [0; 128],
        }
    }

    fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > SW_SIZE {
            return false;
        }
        let block_index = (counter >> SW_BLOCK_BIT_LOG) & SW_BLOCK_MASK;
        let bit_index = counter & SW_BIT_MASK;
        self.ring[block_index as usize] >> bit_index & 1 == 0
    }

    fn add(&mut self, counter: u64) {
        let block_index = counter >> SW_BLOCK_BIT_LOG;
        if counter > self.last {
            let mut last_block_index = self.last >> SW_BLOCK_BIT_LOG;
            let diff = (block_index - last_block_index).min(SW_RING_BLOCKS);
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & SW_BLOCK_MASK;
                self.ring[last_block_index as usize] = 0;
            }
            self.last = counter;
        }
        let bit_index = counter & SW_BIT_MASK;
        self.ring[(block_index & SW_BLOCK_MASK) as usize] |= 1 << bit_index;
    }
}

/// Dial a Shadowsocks 2022 TCP connection: write the request (salt, EIH,
/// header chunks) and return the codec stream. The response prologue
/// (salt + validated fixed header) is driven lazily from the read path —
/// reading it inline would deadlock against servers that only answer after
/// the first client payload chunk.
pub(crate) async fn dial_stream(
    mut server: TcpStream,
    method: Ss2022Method,
    socks_header: Vec<u8>,
) -> anyhow::Result<crate::proxy::ss_stream::SsStream> {
    // Request: salt | EIH* | enc(fixed header) | enc(variable header)
    let mut request_salt = vec![0u8; method.key_len];
    rand::rng().fill_bytes(&mut request_salt);
    let send_subkey = method.session_subkey(&request_salt);
    let send_cipher = method.aead(&send_subkey)?;
    let mut send_nonce = vec![0u8; NONCE_LEN];

    // No initial payload is available (the dial returns before the client
    // writes), so padding must be non-zero (SIP022 3.1.4).
    let padding_len = rand::rng().random_range(1..=MAX_PADDING_LENGTH);
    let variable_header_len = socks_header.len() + 2 + padding_len;

    let mut request = Vec::with_capacity(
        method.key_len
            + (method.psks.len() - 1) * 16
            + 11
            + TAG_LEN
            + variable_header_len
            + TAG_LEN,
    );
    request.extend_from_slice(&request_salt);
    request.extend_from_slice(&method.tcp_identity_headers(&request_salt)?);

    let mut fixed = Vec::with_capacity(11);
    fixed.push(HEADER_TYPE_CLIENT);
    fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
    fixed.extend_from_slice(&(variable_header_len as u16).to_be_bytes());
    request.extend_from_slice(
        &send_cipher
            .seal(&send_nonce, &fixed)
            .map_err(|e| anyhow::anyhow!("seal request fixed header failed: {:?}", e))?,
    );
    increment_nonce(&mut send_nonce);

    let mut variable = Vec::with_capacity(variable_header_len);
    variable.extend_from_slice(&socks_header);
    variable.extend_from_slice(&(padding_len as u16).to_be_bytes());
    variable.extend_from_slice(&vec![0u8; padding_len]);
    request.extend_from_slice(
        &send_cipher
            .seal(&send_nonce, &variable)
            .map_err(|e| anyhow::anyhow!("seal request variable header failed: {:?}", e))?,
    );
    increment_nonce(&mut send_nonce);

    // SIP022 3.1.4: salt + header chunks MUST go out in a single write.
    server.write_all(&request).await?;

    let prologue = crate::proxy::ss_stream::Ss2022Prologue {
        method,
        request_salt,
    };
    Ok(crate::proxy::ss_stream::SsStream::new_2022(
        server,
        send_cipher,
        send_nonce,
        prologue,
    ))
}

/// Client-side Shadowsocks 2022 UDP session.
///
/// One session per `dial_udp_transport` call: random session id, monotonically
/// increasing packet id for outgoing packets, and a sliding-window replay
/// filter per server session on the receive path.
pub(crate) struct Ss2022UdpSession {
    method: Ss2022Method,
    session_id: u64,
    next_packet_id: u64,
    /// AES methods: AEAD keyed with `SessionKey(last psk, session_id)`.
    send_cipher: Option<AeadCipher>,
    /// chacha method: XChaCha20-Poly1305 keyed directly with the PSK.
    xchacha_cipher: Option<AeadCipher>,
    /// chacha method nonce/session-id source.
    xof: Option<Blake3Xof>,
    remote_session_id: Option<u64>,
    remote_cipher: Option<AeadCipher>,
    window: SlidingWindow,
}

impl Ss2022UdpSession {
    pub(crate) fn new(method: Ss2022Method) -> anyhow::Result<Self> {
        let (session_id, send_cipher, xchacha_cipher, xof) = if method.is_chacha() {
            let mut xof = Blake3Xof::new();
            let session_id = xof.next_u64();
            let cipher = AeadCipher::new_xchacha20(method.encryption_psk())?;
            (session_id, None, Some(cipher), Some(xof))
        } else {
            let session_id = rand::rng().random::<u64>();
            let subkey = method.session_subkey(&session_id.to_be_bytes());
            let cipher = method.aead(&subkey)?;
            (session_id, Some(cipher), None, None)
        };
        Ok(Self {
            method,
            session_id,
            next_packet_id: 0,
            send_cipher,
            xchacha_cipher,
            xof,
            remote_session_id: None,
            remote_cipher: None,
            window: SlidingWindow::new(),
        })
    }

    /// Padding policy from sing-shadowsocks2: only DNS packets (port 53)
    /// shorter than 900 bytes get random padding.
    fn padding_len(target_port: u16, payload_len: usize) -> usize {
        if target_port == 53 && payload_len < MAX_PADDING_LENGTH {
            rand::rng().random_range(1..=(MAX_PADDING_LENGTH - payload_len))
        } else {
            0
        }
    }

    /// Encapsulate one payload datagram for the server.
    pub(crate) fn seal_packet(
        &mut self,
        socks: &[u8],
        target_port: u16,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let packet_id = self.next_packet_id;
        self.next_packet_id += 1;
        let padding_len = Self::padding_len(target_port, payload.len());

        // chacha construction: nonce | XChaCha20-Poly1305(body)
        if let Some(xchacha) = &self.xchacha_cipher {
            let mut nonce = [0u8; UDP_XNONCE_SIZE];
            self.xof
                .as_mut()
                .expect("XOF present for chacha method")
                .fill(&mut nonce);

            let mut body =
                Vec::with_capacity(8 + 8 + 1 + 8 + 2 + padding_len + socks.len() + payload.len());
            body.extend_from_slice(&self.session_id.to_be_bytes());
            body.extend_from_slice(&packet_id.to_be_bytes());
            body.push(HEADER_TYPE_CLIENT);
            body.extend_from_slice(&unix_timestamp().to_be_bytes());
            body.extend_from_slice(&(padding_len as u16).to_be_bytes());
            body.extend_from_slice(&vec![0u8; padding_len]);
            body.extend_from_slice(socks);
            body.extend_from_slice(payload);

            let sealed = xchacha
                .seal(&nonce, &body)
                .map_err(|e| anyhow::anyhow!("seal UDP packet failed: {:?}", e))?;
            let mut out = Vec::with_capacity(UDP_XNONCE_SIZE + sealed.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&sealed);
            return Ok(out);
        }

        // AES construction: enc(header) | EIH* | AEAD(body)
        let mut plain_header = [0u8; 16];
        plain_header[..8].copy_from_slice(&self.session_id.to_be_bytes());
        plain_header[8..].copy_from_slice(&packet_id.to_be_bytes());

        let mut body = Vec::with_capacity(1 + 8 + 2 + padding_len + socks.len() + payload.len());
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&unix_timestamp().to_be_bytes());
        body.extend_from_slice(&(padding_len as u16).to_be_bytes());
        body.extend_from_slice(&vec![0u8; padding_len]);
        body.extend_from_slice(socks);
        body.extend_from_slice(payload);

        // Body nonce = plaintext separate header bytes [4..16].
        let sealed = self
            .send_cipher
            .as_ref()
            .expect("send cipher present for AES methods")
            .seal(&plain_header[4..16], &body)
            .map_err(|e| anyhow::anyhow!("seal UDP packet failed: {:?}", e))?;

        let mut out = Vec::with_capacity(16 + (self.method.psks.len() - 1) * 16 + sealed.len());
        // Separate header encrypted with the *first* psk (the server's
        // identity psk in multi-user deployments).
        let mut enc_header = plain_header;
        AesBlock::new(&self.method.psks[0])?.encrypt(&mut enc_header);
        out.extend_from_slice(&enc_header);
        // UDP EIH blocks: AES-ECB(psk_i, psk_hashes[i] XOR plain_header).
        for i in 0..self.method.psks.len().saturating_sub(1) {
            let mut block_data = [0u8; 16];
            for j in 0..16 {
                block_data[j] = self.method.psk_hashes[i][j] ^ plain_header[j];
            }
            AesBlock::new(&self.method.psks[i])?.encrypt(&mut block_data);
            out.extend_from_slice(&block_data);
        }
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decapsulate one datagram from the server, returning the payload.
    pub(crate) fn open_packet(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(xchacha) = &self.xchacha_cipher {
            if packet.len() < UDP_XNONCE_SIZE + UDP_MINIMAL_PACKET_SIZE {
                anyhow::bail!("UDP packet too short");
            }
            let (nonce, ciphertext) = packet.split_at(UDP_XNONCE_SIZE);
            let body = xchacha
                .open(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("open UDP packet failed: {:?}", e))?;
            if body.len() < 16 {
                anyhow::bail!("UDP body too short");
            }
            let server_session_id = u64::from_be_bytes(body[..8].try_into().unwrap());
            let server_packet_id = u64::from_be_bytes(body[8..16].try_into().unwrap());
            self.begin_server_packet(server_session_id, server_packet_id)?;
            let payload = self.parse_server_body(&body[16..])?;
            self.window.add(server_packet_id);
            return Ok(payload);
        }

        // AES construction
        if packet.len() < UDP_MINIMAL_PACKET_SIZE {
            anyhow::bail!("UDP packet too short");
        }
        // The server encrypts the separate header with the encryption psk.
        let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
        AesBlock::new(self.method.encryption_psk())?.decrypt(&mut plain_header);
        let server_session_id = u64::from_be_bytes(plain_header[..8].try_into().unwrap());
        let server_packet_id = u64::from_be_bytes(plain_header[8..].try_into().unwrap());
        self.begin_server_packet(server_session_id, server_packet_id)?;
        if self.remote_cipher.is_none() {
            let subkey = self.method.session_subkey(&plain_header[..8]);
            self.remote_cipher = Some(self.method.aead(&subkey)?);
        }
        let body = self
            .remote_cipher
            .as_ref()
            .expect("remote cipher initialized above")
            .open(&plain_header[4..16], &packet[16..])
            .map_err(|e| anyhow::anyhow!("open UDP packet failed: {:?}", e))?;
        let payload = self.parse_server_body(&body)?;
        self.window.add(server_packet_id);
        Ok(payload)
    }

    /// Replay-window bookkeeping for a packet from `server_session_id`.
    ///
    /// Simplified relative to sing-shadowsocks2 (which tracks the current
    /// and one previous server session with a 60s rotation): a new server
    /// session id resets the window.
    fn begin_server_packet(
        &mut self,
        server_session_id: u64,
        packet_id: u64,
    ) -> anyhow::Result<()> {
        if self.remote_session_id != Some(server_session_id) {
            debug!(
                "Shadowsocks 2022 UDP: new server session {:016x}",
                server_session_id
            );
            self.remote_session_id = Some(server_session_id);
            self.remote_cipher = None;
            self.window = SlidingWindow::new();
            return Ok(());
        }
        if !self.window.check(packet_id) {
            anyhow::bail!("packet id not unique");
        }
        Ok(())
    }

    /// Validate and strip the server-to-client main header; returns payload.
    /// `body` starts at the header type byte.
    fn parse_server_body(&self, body: &[u8]) -> anyhow::Result<Vec<u8>> {
        if body.len() < 1 + 8 + 8 + 2 {
            anyhow::bail!("UDP body too short");
        }
        if body[0] != HEADER_TYPE_SERVER {
            anyhow::bail!("bad UDP header type {}", body[0]);
        }
        let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
        let diff = unix_timestamp().abs_diff(ts);
        if diff > 30 {
            anyhow::bail!("bad UDP timestamp (diff {}s)", diff);
        }
        let client_session_id = u64::from_be_bytes(body[9..17].try_into().unwrap());
        if client_session_id != self.session_id {
            anyhow::bail!("bad client session id");
        }
        let padding_len = u16::from_be_bytes([body[17], body[18]]) as usize;
        if body.len() < 19 + padding_len {
            anyhow::bail!("truncated UDP padding");
        }
        let rest = &body[19 + padding_len..];
        let skip = socks_addr_len(rest)?;
        Ok(rest[skip..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::shadowsocks::ShadowsocksHandler;
    use crate::proxy::{PacketOutbound, TcpOutbound};
    use honk_config::node::Node;
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Fixed test material (same values fed to the Go reference program).
    fn psk1() -> Vec<u8> {
        (0u8..16).collect()
    }
    fn psk2() -> Vec<u8> {
        (16u8..32).collect()
    }
    fn salt16() -> Vec<u8> {
        (32u8..48).collect()
    }
    fn psk32() -> Vec<u8> {
        (0u8..32).collect()
    }
    fn salt32() -> Vec<u8> {
        (32u8..64).collect()
    }

    #[test]
    fn test_psk_parse_single() {
        let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(m.psks.len(), 1);
        assert_eq!(m.psks[0], psk1());
        assert!(m.psk_hashes.is_empty());
    }

    #[test]
    fn test_psk_parse_multi() {
        let m = Ss2022Method::new(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
        )
        .unwrap();
        assert_eq!(m.psks.len(), 2);
        assert_eq!(m.encryption_psk(), &psk2()[..]);
        assert_eq!(m.psk_hashes.len(), 1);
        assert_eq!(m.psk_hashes[0], hex("ea5ff194405ece4f55ae7a150c523884")[..]);
    }

    #[test]
    fn test_psk_parse_bad_length() {
        // 32-byte psk with a 16-byte method.
        assert!(
            Ss2022Method::new(
                "2022-blake3-aes-128-gcm",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            )
            .is_err()
        );
        // 16-byte psk with a 32-byte method.
        assert!(Ss2022Method::new("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODw==").is_err());
    }

    #[test]
    fn test_psk_parse_bad_base64() {
        assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "!!!not-base64!!!").is_err());
        assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "").is_err());
    }

    #[test]
    fn test_psk_parse_chacha_rejects_multi() {
        assert!(Ss2022Method::new(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_err());
        assert!(
            Ss2022Method::new(
                "2022-blake3-chacha20-poly1305",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            )
            .is_ok()
        );
    }

    // BLAKE3 known-answer tests (generated with the Go reference).

    #[test]
    fn test_session_subkey_kat() {
        let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(
            m.session_subkey(&salt16()),
            hex("8180421f8f56092ca7544a64ff852536")
        );
    }

    #[test]
    fn test_session_subkey_kat_32() {
        let m = Ss2022Method::new(
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )
        .unwrap();
        assert_eq!(
            m.session_subkey(&salt32()),
            hex("374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda")
        );
    }

    #[test]
    fn test_identity_subkey_differs() {
        // Same material, different context strings → different output.
        let mut material = psk1();
        material.extend_from_slice(&salt16());
        let identity = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
        let session = blake3::derive_key("shadowsocks 2022 session subkey", &material);
        assert_ne!(identity, session);
        // KAT from the Go reference (16-byte truncation).
        assert_eq!(
            &identity[..16],
            &hex("1e3587415fc15417133c20d9e4b78ec3")[..]
        );
    }

    #[test]
    fn test_psk_hash_prefix_property() {
        // blake3::hash (32-byte output) first 16 bytes == Go blake3.Sum512 [:16].
        assert_eq!(
            &blake3::hash(&psk2()).as_bytes()[..16],
            &hex("ea5ff194405ece4f55ae7a150c523884")[..]
        );
    }

    #[test]
    fn test_eih_kat() {
        // psk list [psk1, psk2], salt16 → single EIH block, KAT from Go
        // (AES-ECB(identity_subkey, blake3(psk2)[..16])).
        let m = Ss2022Method::new(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
        )
        .unwrap();
        let eih = m.tcp_identity_headers(&salt16()).unwrap();
        assert_eq!(eih, hex("cfe4b97eb5c29f5dda417a22031c9f08"));
    }

    #[test]
    fn test_aes_block_kat() {
        // AES-ECB(psk1)(0x01020304050607081122334455667788) KAT from Go.
        let block = AesBlock::new(&psk1()).unwrap();
        let mut data: [u8; 16] = hex("01020304050607081122334455667788").try_into().unwrap();
        block.encrypt(&mut data);
        assert_eq!(data, hex("838e4115229deb1b278e7474a56e1893")[..]);
        block.decrypt(&mut data);
        assert_eq!(data, hex("01020304050607081122334455667788")[..]);
    }

    #[test]
    fn test_blake3_xof_kat() {
        let key: [u8; 32] = (0u8..32)
            .map(|i| i * 3)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut xof = Blake3Xof::with_key(key);
        let mut out = [0u8; 32];
        xof.fill(&mut out);
        assert_eq!(
            out,
            hex("4a77995a0df1a72023241481d0d6436f3ae93d3509691067cc834db52326b6c2")[..]
        );
    }

    #[test]
    fn test_sliding_window() {
        let mut w = SlidingWindow::new();
        assert!(w.check(0));
        w.add(0);
        assert!(!w.check(0)); // replay
        assert!(w.check(1));
        w.add(1);
        assert!(!w.check(0));
        assert!(!w.check(1));
        // Jump far ahead: old values fall out of the window.
        w.add(SW_SIZE + 200);
        assert!(w.check(SW_SIZE + 201));
        assert!(!w.check(0)); // behind window
        assert!(w.check(SW_SIZE + 199));
        w.add(SW_SIZE + 199);
        assert!(!w.check(SW_SIZE + 199));
    }

    fn udp_target() -> (Vec<u8>, SocketAddr) {
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        (
            crate::proxy::addr::encode_address(target, None).unwrap(),
            target,
        )
    }

    /// Server-side parse of an AES-construction client packet; returns
    /// (session_id, packet_id, payload).
    fn server_open_aes(method: &Ss2022Method, packet: &[u8]) -> (u64, u64, Vec<u8>) {
        let psk = method.encryption_psk();
        let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
        AesBlock::new(psk).unwrap().decrypt(&mut plain_header);
        let session_id = u64::from_be_bytes(plain_header[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plain_header[8..].try_into().unwrap());

        let subkey = method.session_subkey(&plain_header[..8]);
        let cipher = method.aead(&subkey).unwrap();
        let body = cipher.open(&plain_header[4..16], &packet[16..]).unwrap();
        assert_eq!(body[0], HEADER_TYPE_CLIENT);
        let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
        assert!(unix_timestamp().abs_diff(ts) <= 30);
        let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
        let rest = &body[11 + padding_len..];
        let skip = socks_addr_len(rest).unwrap();
        (session_id, packet_id, rest[skip..].to_vec())
    }

    /// Server-side build of an AES-construction response packet.
    fn server_seal_aes(
        method: &Ss2022Method,
        client_session_id: u64,
        server_session_id: u64,
        server_packet_id: u64,
        socks: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let psk = method.encryption_psk();
        let mut plain_header = [0u8; 16];
        plain_header[..8].copy_from_slice(&server_session_id.to_be_bytes());
        plain_header[8..].copy_from_slice(&server_packet_id.to_be_bytes());

        let subkey = method.session_subkey(&plain_header[..8]);
        let cipher = method.aead(&subkey).unwrap();

        let mut body = Vec::new();
        body.push(HEADER_TYPE_SERVER);
        body.extend_from_slice(&unix_timestamp().to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // no padding
        body.extend_from_slice(socks);
        body.extend_from_slice(payload);
        let sealed = cipher.seal(&plain_header[4..16], &body).unwrap();

        let mut out = Vec::new();
        let mut enc_header = plain_header;
        AesBlock::new(psk).unwrap().encrypt(&mut enc_header);
        out.extend_from_slice(&enc_header);
        out.extend_from_slice(&sealed);
        out
    }

    #[test]
    fn test_udp_2022_aes_roundtrip() {
        let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
        let mut session = Ss2022UdpSession::new(method).unwrap();
        let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
        let (socks, target) = udp_target();

        let payload = b"dns query payload";
        let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
        // DNS payload → padding present.
        assert!(packet.len() > 16 + 1 + 8 + 2 + socks.len() + payload.len() + TAG_LEN);

        let (session_id, packet_id, opened) = server_open_aes(&server_method, &packet);
        assert_eq!(packet_id, 0);
        assert_eq!(opened, payload);

        // Second packet increments the packet id.
        let packet2 = session.seal_packet(&socks, target.port(), payload).unwrap();
        let (_, packet_id2, _) = server_open_aes(&server_method, &packet2);
        assert_eq!(packet_id2, 1);

        // Server response.
        let response = server_seal_aes(
            &server_method,
            session_id,
            0xdeadbeef,
            0,
            &socks,
            b"dns response",
        );
        let opened = session.open_packet(&response).unwrap();
        assert_eq!(opened, b"dns response");

        // Replay of the same packet must be rejected.
        assert!(session.open_packet(&response).is_err());
    }

    #[test]
    fn test_udp_2022_aes_eih_multi_psk() {
        // Two psks: identity psk1 + encryption psk2 (16-byte AES method).
        let m = Ss2022Method::new(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
        )
        .unwrap();
        let mut session = Ss2022UdpSession::new(m).unwrap();
        let (socks, target) = udp_target();
        let payload = b"hello";
        let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
        // Layout: enc_header(16) | EIH(16) | body+tag.
        assert!(packet.len() > 32);

        // Decrypt the separate header with the FIRST psk (server identity psk).
        let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
        AesBlock::new(&psk1()).unwrap().decrypt(&mut plain_header);

        // EIH block: AES-ECB(psk1, psk_hash XOR plain_header).
        let mut eih: [u8; 16] = packet[16..32].try_into().unwrap();
        AesBlock::new(&psk1()).unwrap().decrypt(&mut eih);
        let expected_hash = blake3::hash(&psk2());
        for j in 0..16 {
            assert_eq!(eih[j], expected_hash.as_bytes()[j] ^ plain_header[j]);
        }

        // Body opens with SessionKey(encryption psk, session_id).
        let mut material = psk2();
        material.extend_from_slice(&plain_header[..8]);
        let subkey = &blake3::derive_key("shadowsocks 2022 session subkey", &material)[..16];
        let cipher = AeadCipher::new("2022-blake3-aes-128-gcm", subkey).unwrap();
        let body = cipher.open(&plain_header[4..16], &packet[32..]).unwrap();
        assert_eq!(body[0], HEADER_TYPE_CLIENT);
    }

    #[test]
    fn test_udp_2022_chacha_roundtrip() {
        let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let method = Ss2022Method::new("2022-blake3-chacha20-poly1305", psk_b64).unwrap();
        let mut session = Ss2022UdpSession::new(method).unwrap();
        let (socks, target) = udp_target();
        let payload = b"quic payload";

        let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
        assert!(packet.len() > UDP_XNONCE_SIZE + TAG_LEN);

        // Server-side parse: nonce || XChaCha20-Poly1305(psk)(body).
        let psk = psk32();
        let server_cipher = AeadCipher::new_xchacha20(&psk).unwrap();
        let (nonce, ct) = packet.split_at(UDP_XNONCE_SIZE);
        let body = server_cipher.open(nonce, ct).unwrap();
        let client_session_id = u64::from_be_bytes(body[..8].try_into().unwrap());
        let client_packet_id = u64::from_be_bytes(body[8..16].try_into().unwrap());
        assert_eq!(client_packet_id, 0);
        assert_eq!(body[16], HEADER_TYPE_CLIENT);
        let padding_len = u16::from_be_bytes([body[25], body[26]]) as usize;
        let rest = &body[27 + padding_len..];
        let skip = socks_addr_len(rest).unwrap();
        assert_eq!(&rest[skip..], payload);

        // Server response: server session/packet ids in the encrypted body.
        let mut resp_body = Vec::new();
        resp_body.extend_from_slice(&0xcafeu64.to_be_bytes());
        resp_body.extend_from_slice(&0u64.to_be_bytes());
        resp_body.push(HEADER_TYPE_SERVER);
        resp_body.extend_from_slice(&unix_timestamp().to_be_bytes());
        resp_body.extend_from_slice(&client_session_id.to_be_bytes());
        resp_body.extend_from_slice(&0u16.to_be_bytes());
        resp_body.extend_from_slice(&socks);
        resp_body.extend_from_slice(b"quic response");
        let mut resp_nonce = [0u8; UDP_XNONCE_SIZE];
        rand::rng().fill_bytes(&mut resp_nonce);
        let sealed = server_cipher.seal(&resp_nonce, &resp_body).unwrap();
        let mut response = resp_nonce.to_vec();
        response.extend_from_slice(&sealed);

        let opened = session.open_packet(&response).unwrap();
        assert_eq!(opened, b"quic response");
        assert!(session.open_packet(&response).is_err()); // replay
    }

    /// Mock Shadowsocks 2022 server: parses the request (including EIH),
    /// then echoes every received chunk payload back inside a proper
    /// response stream.
    async fn mock_2022_server(
        listener: tokio::net::TcpListener,
        password: &'static str,
        method_name: &'static str,
    ) {
        let method = Ss2022Method::new(method_name, password).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = stream.into_split();

        // Salt + EIH.
        let mut salt = vec![0u8; method.key_len];
        rd.read_exact(&mut salt).await.unwrap();
        let eih_len = (method.psks.len() - 1) * 16;
        let mut eihs = vec![0u8; eih_len];
        rd.read_exact(&mut eihs).await.unwrap();
        for (i, chunk) in eihs.chunks(16).enumerate() {
            let mut material = method.psks[i].clone();
            material.extend_from_slice(&salt);
            let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
            let mut block_data: [u8; 16] = chunk.try_into().unwrap();
            AesBlock::new(&identity_subkey[..method.key_len])
                .unwrap()
                .decrypt(&mut block_data);
            assert_eq!(block_data, method.psk_hashes[i], "EIH {} mismatch", i);
        }

        // Fixed + variable request headers.
        let subkey = method.session_subkey(&salt);
        let cipher = method.aead(&subkey).unwrap();
        let mut nonce = vec![0u8; NONCE_LEN];
        let mut fixed = vec![0u8; 11 + TAG_LEN];
        rd.read_exact(&mut fixed).await.unwrap();
        let fixed = cipher.open(&nonce, &fixed).unwrap();
        increment_nonce(&mut nonce);
        assert_eq!(fixed[0], HEADER_TYPE_CLIENT);
        let ts = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        assert!(unix_timestamp().abs_diff(ts) <= 30);
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut var = vec![0u8; var_len + TAG_LEN];
        rd.read_exact(&mut var).await.unwrap();
        let var = cipher.open(&nonce, &var).unwrap();
        increment_nonce(&mut nonce);
        let addr_len = socks_addr_len(&var).unwrap();
        let padding_len = u16::from_be_bytes([var[addr_len], var[addr_len + 1]]) as usize;
        assert!(padding_len > 0, "padding must be present without payload");
        assert_eq!(var.len(), addr_len + 2 + padding_len);

        // Response direction state.
        let mut resp_salt = vec![0u8; method.key_len];
        rand::rng().fill_bytes(&mut resp_salt);
        let resp_subkey = method.session_subkey(&resp_salt);
        let resp_cipher = method.aead(&resp_subkey).unwrap();
        let mut resp_nonce = vec![0u8; NONCE_LEN];
        let mut response_started = false;

        // Echo loop: read chunk payloads, echo them back.
        let mut len_buf = vec![0u8; 2 + TAG_LEN];
        loop {
            if rd.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len_plain = cipher.open(&nonce, &len_buf).unwrap();
            increment_nonce(&mut nonce);
            let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            let mut payload = vec![0u8; len + TAG_LEN];
            rd.read_exact(&mut payload).await.unwrap();
            let plain = cipher.open(&nonce, &payload).unwrap();
            increment_nonce(&mut nonce);

            if !response_started {
                response_started = true;
                // Fixed response header (doubles as first length chunk).
                let mut header = Vec::new();
                header.extend_from_slice(&resp_salt);
                let mut fixed = Vec::new();
                fixed.push(HEADER_TYPE_SERVER);
                fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
                fixed.extend_from_slice(&salt); // echo request salt
                fixed.extend_from_slice(&(plain.len() as u16).to_be_bytes());
                header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &fixed).unwrap());
                increment_nonce(&mut resp_nonce);
                header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
                increment_nonce(&mut resp_nonce);
                wr.write_all(&header).await.unwrap();
            } else {
                let mut chunk = Vec::new();
                chunk.extend_from_slice(
                    &resp_cipher
                        .seal(&resp_nonce, &(plain.len() as u16).to_be_bytes())
                        .unwrap(),
                );
                increment_nonce(&mut resp_nonce);
                chunk.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
                increment_nonce(&mut resp_nonce);
                wr.write_all(&chunk).await.unwrap();
            }
        }
    }

    async fn tcp_roundtrip(method_name: &'static str, password: &'static str) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(mock_2022_server(listener, password, method_name));

        let node = Node {
            name: "test-ss2022".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some(method_name.to_string()),
                    password: Some(password.to_string()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = handler
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        let mut stream = stream.stream;

        // First exchange (drives the response fixed-header path).
        stream.write_all(b"hello ss2022").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello ss2022");

        // Second exchange (drives the regular chunk path).
        stream.write_all(b"second message").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second message");
    }

    #[tokio::test]
    async fn test_tcp_2022_aes_128_roundtrip() {
        tcp_roundtrip("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").await;
    }

    #[tokio::test]
    async fn test_tcp_2022_aes_256_roundtrip() {
        tcp_roundtrip(
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )
        .await;
    }

    #[tokio::test]
    async fn test_tcp_2022_chacha_roundtrip() {
        tcp_roundtrip(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        )
        .await;
    }

    #[tokio::test]
    async fn test_tcp_2022_eih_roundtrip() {
        // Multi-psk: mock server asserts the EIH blocks decrypt correctly.
        tcp_roundtrip(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
        )
        .await;
    }

    /// End-to-end UDP test: mock Shadowsocks 2022 server, real
    /// `dial_udp_transport`, payload exchange through the framed transport.
    #[tokio::test]
    async fn test_dial_udp_2022_end_to_end() {
        let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let socks = crate::proxy::addr::encode_address(target, None).unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            let mut server_packet_id = 0u64;
            loop {
                let (n, src) = server.recv_from(&mut buf).await.unwrap();
                let (client_session_id, _pid, payload) = server_open_aes(&server_method, &buf[..n]);
                let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
                let packet = server_seal_aes(
                    &server_method,
                    client_session_id,
                    0xbeef,
                    server_packet_id,
                    &socks,
                    &reply,
                );
                server_packet_id += 1;
                server.send_to(&packet, src).await.unwrap();
            }
        });

        let node = Node {
            name: "test-ss2022-udp".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some("2022-blake3-aes-256-gcm".into()),
                    password: Some(psk_b64.to_string()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let transport = handler
            .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();

        transport.send_packet(b"quic data").await.unwrap();
        let mut buf = [0u8; 65536];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(src, target);
        assert_eq!(&buf[..n], b"QUIC DATA");

        // Second datagram on the same session (packet id continuity).
        transport.send_packet(b"more data").await.unwrap();
        let (n, _src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"MORE DATA");
    }
}
