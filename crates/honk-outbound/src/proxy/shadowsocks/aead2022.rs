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
use tracing::debug;

use super::{AeadCipher, UdpDatagram, increment_nonce};

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
pub(crate) async fn dial_stream<T: super::stream::SsTransport>(
    mut server: T,
    method: Ss2022Method,
    socks_header: Vec<u8>,
) -> anyhow::Result<super::stream::SsStream<T>> {
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
    server.flush().await?;

    let prologue = super::stream::Ss2022Prologue {
        method,
        request_salt,
    };
    Ok(super::stream::SsStream::new_2022(
        server,
        send_cipher,
        send_nonce,
        prologue,
    ))
}

// SIP022 permits current + previous tracking when a third session is held off
// for 60 seconds after the previous session is installed or last active.
const SERVER_SESSION_ROTATION_SECS: u64 = 60;

struct ServerSession {
    id: u64,
    cipher: Option<AeadCipher>,
    window: SlidingWindow,
}

#[derive(Clone, Copy)]
enum ServerSessionSlot {
    Current,
    Previous,
    New,
}

/// Client-side Shadowsocks 2022 UDP session.
///
/// One session per UDP transport, whatever destinations it carries: random
/// session id, monotonically increasing packet id for outgoing packets, and
/// current/previous server session replay windows on the receive path.
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
    remote_session: Option<ServerSession>,
    previous_remote_session: Option<ServerSession>,
    previous_remote_seen: u64,
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
            remote_session: None,
            previous_remote_session: None,
            previous_remote_seen: 0,
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

    /// Decapsulate one datagram from the server.
    pub(crate) fn open_packet(&mut self, packet: &[u8]) -> anyhow::Result<UdpDatagram> {
        self.open_packet_at(packet, unix_timestamp())
    }

    fn open_packet_at(&mut self, packet: &[u8], now: u64) -> anyhow::Result<UdpDatagram> {
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
            let slot = self.server_packet_slot(server_session_id, server_packet_id, now)?;
            let address_at = 16 + self.server_address_offset(&body[16..], now)?;
            let datagram = UdpDatagram::new(body, address_at)?;
            self.commit_server_packet(slot, server_session_id, server_packet_id, None, now);
            return Ok(datagram);
        }

        if packet.len() < UDP_MINIMAL_PACKET_SIZE {
            anyhow::bail!("UDP packet too short");
        }
        let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
        AesBlock::new(self.method.encryption_psk())?.decrypt(&mut plain_header);
        let server_session_id = u64::from_be_bytes(plain_header[..8].try_into().unwrap());
        let server_packet_id = u64::from_be_bytes(plain_header[8..].try_into().unwrap());
        let slot = self.server_packet_slot(server_session_id, server_packet_id, now)?;

        let mut new_cipher = None;
        let cipher = match slot {
            ServerSessionSlot::Current => self
                .remote_session
                .as_ref()
                .and_then(|session| session.cipher.as_ref())
                .expect("current AES server session has a cipher"),
            ServerSessionSlot::Previous => self
                .previous_remote_session
                .as_ref()
                .and_then(|session| session.cipher.as_ref())
                .expect("previous AES server session has a cipher"),
            ServerSessionSlot::New => {
                let subkey = self.method.session_subkey(&plain_header[..8]);
                new_cipher = Some(self.method.aead(&subkey)?);
                new_cipher.as_ref().unwrap()
            }
        };
        let body = cipher
            .open(&plain_header[4..16], &packet[16..])
            .map_err(|e| anyhow::anyhow!("open UDP packet failed: {:?}", e))?;
        let address_at = self.server_address_offset(&body, now)?;
        let datagram = UdpDatagram::new(body, address_at)?;
        self.commit_server_packet(slot, server_session_id, server_packet_id, new_cipher, now);
        Ok(datagram)
    }

    fn server_packet_slot(
        &self,
        server_session_id: u64,
        packet_id: u64,
        now: u64,
    ) -> anyhow::Result<ServerSessionSlot> {
        if let Some(session) = &self.remote_session
            && session.id == server_session_id
        {
            if !session.window.check(packet_id) {
                anyhow::bail!("packet id not unique");
            }
            return Ok(ServerSessionSlot::Current);
        }
        if let Some(session) = &self.previous_remote_session
            && session.id == server_session_id
        {
            if !session.window.check(packet_id) {
                anyhow::bail!("packet id not unique");
            }
            return Ok(ServerSessionSlot::Previous);
        }
        if self.previous_remote_session.is_some()
            && now.saturating_sub(self.previous_remote_seen) < SERVER_SESSION_ROTATION_SECS
        {
            anyhow::bail!("server session changed more than once during the last minute");
        }
        Ok(ServerSessionSlot::New)
    }

    fn commit_server_packet(
        &mut self,
        slot: ServerSessionSlot,
        server_session_id: u64,
        packet_id: u64,
        cipher: Option<AeadCipher>,
        now: u64,
    ) {
        match slot {
            ServerSessionSlot::Current => self
                .remote_session
                .as_mut()
                .expect("current server session exists")
                .window
                .add(packet_id),
            ServerSessionSlot::Previous => {
                self.previous_remote_session
                    .as_mut()
                    .expect("previous server session exists")
                    .window
                    .add(packet_id);
                self.previous_remote_seen = now;
            }
            ServerSessionSlot::New => {
                debug!(
                    "Shadowsocks 2022 UDP: new server session {:016x}",
                    server_session_id
                );
                if let Some(current) = self.remote_session.take() {
                    self.previous_remote_session = Some(current);
                    self.previous_remote_seen = now;
                }
                let mut window = SlidingWindow::new();
                window.add(packet_id);
                self.remote_session = Some(ServerSession {
                    id: server_session_id,
                    cipher,
                    window,
                });
            }
        }
    }

    /// Validate the server-to-client main header; returns the offset of the
    /// address that follows it. `body` starts at the header type byte.
    fn server_address_offset(&self, body: &[u8], now: u64) -> anyhow::Result<usize> {
        if body.len() < 1 + 8 + 8 + 2 {
            anyhow::bail!("UDP body too short");
        }
        if body[0] != HEADER_TYPE_SERVER {
            anyhow::bail!("bad UDP header type {}", body[0]);
        }
        let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
        let diff = now.abs_diff(ts);
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
        Ok(19 + padding_len)
    }
}

#[cfg(test)]
mod tests;
