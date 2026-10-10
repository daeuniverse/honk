//! Xray-compatible VLESS Encryption client codec.
//!
//! The encrypted prologue authenticates one or more server X25519/ML-KEM
//! public keys, establishes per-connection forward-secret keys, then frames
//! the ordinary VLESS request and payload with authenticated encryption.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPrivateKey, MlKemPublicKey};
use parking_lot::RwLock;
use rand::{Rng as _, RngExt as _};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::proxy::AsyncReadWrite;
use crate::proxy::shadowsocks::AeadCipher;

const X25519_KEY_LEN: usize = 32;
const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
const SHARED_SECRET_LEN: usize = 32;
const PFS_CLIENT_KEY_LEN: usize = MLKEM_PUBLIC_KEY_LEN + X25519_KEY_LEN;
const PFS_SERVER_KEY_LEN: usize = MLKEM_CIPHERTEXT_LEN + X25519_KEY_LEN;
const TICKET_LEN: usize = 16;
const IV_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FRAME_HEADER_LEN: usize = 5;
const MAX_FRAME_PLAINTEXT: usize = 8192;
const MAX_FRAME_CIPHERTEXT: usize = 16_640;
/// Largest write buffer kept between frames; a larger first-frame prewrite is not.
const MAX_RETAINED_WIRE: usize = FRAME_HEADER_LEN + MAX_FRAME_PLAINTEXT + TAG_LEN;
const MAX_NONCE: [u8; NONCE_LEN] = [u8::MAX; NONCE_LEN];
const KDF_CTR: &[u8] = b"VLESS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XorMode {
    Native,
    XorPub,
    Random,
}

impl XorMode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "native" => Ok(Self::Native),
            "xorpub" => Ok(Self::XorPub),
            "random" => Ok(Self::Random),
            _ => anyhow::bail!("unsupported VLESS Encryption mode '{value}'"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PaddingSpec {
    probability: u8,
    min: usize,
    max: usize,
}

enum AuthKey {
    X25519 {
        public: [u8; X25519_KEY_LEN],
        hash: [u8; 32],
    },
    MlKem {
        public: MlKemPublicKey,
        hash: [u8; 32],
    },
}

impl AuthKey {
    fn ciphertext_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => X25519_KEY_LEN,
            Self::MlKem { .. } => MLKEM_CIPHERTEXT_LEN,
        }
    }

    fn public_bytes(&self) -> &[u8] {
        match self {
            Self::X25519 { public, .. } => public,
            Self::MlKem { public, .. } => public.as_bytes(),
        }
    }

    fn hash(&self) -> &[u8; 32] {
        match self {
            Self::X25519 { hash, .. } | Self::MlKem { hash, .. } => hash,
        }
    }

    fn encapsulate(&self) -> anyhow::Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
        match self {
            Self::X25519 { public, .. } => {
                let (ephemeral_public, ephemeral_private) = x25519_keypair();
                let shared = x25519(&ephemeral_private, public)?;
                Ok((ephemeral_public.to_vec(), shared))
            }
            Self::MlKem { public, .. } => {
                let (ciphertext, shared) = public.encapsulate()?;
                Ok((ciphertext, shared))
            }
        }
    }
}

#[derive(Clone)]
struct SessionTicket {
    pfs_key: [u8; 64],
    ticket: [u8; TICKET_LEN],
    expires_at: Instant,
}

pub(crate) struct ClientConfig {
    auth_keys: Vec<AuthKey>,
    relays_len: usize,
    mode: XorMode,
    allow_0rtt: bool,
    padding_lengths: Vec<PaddingSpec>,
    padding_gaps: Vec<PaddingSpec>,
    ticket: RwLock<Option<SessionTicket>>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("auth_keys", &self.auth_keys.len())
            .field("mode", &self.mode)
            .field("allow_0rtt", &self.allow_0rtt)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    pub(crate) fn parse(value: &str) -> anyhow::Result<Arc<Self>> {
        let mut parts = value.split('.');
        let protocol = parts.next().unwrap_or_default();
        anyhow::ensure!(
            protocol == "mlkem768x25519plus",
            "unsupported VLESS Encryption protocol '{protocol}'"
        );
        let mode = XorMode::parse(parts.next().unwrap_or_default())?;
        let rtt = parts.next().unwrap_or_default();
        anyhow::ensure!(
            rtt == "0rtt" || rtt == "1rtt",
            "unsupported VLESS Encryption RTT mode '{rtt}'"
        );

        let mut padding_parts = Vec::new();
        let mut auth_keys = Vec::new();
        let mut saw_key = false;
        for part in parts {
            let decoded = decode_base64url(part);
            if !saw_key && !matches!(decoded.as_ref().map(Vec::len), Some(32 | 1184)) {
                padding_parts.push(part);
                continue;
            }
            saw_key = true;
            let raw = decoded.with_context(|| "invalid VLESS Encryption public key")?;
            let hash = *blake3::hash(&raw).as_bytes();
            match raw.len() {
                X25519_KEY_LEN => auth_keys.push(AuthKey::X25519 {
                    public: raw.try_into().expect("checked X25519 key length"),
                    hash,
                }),
                MLKEM_PUBLIC_KEY_LEN => auth_keys.push(AuthKey::MlKem {
                    public: MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &raw)
                        .context("invalid ML-KEM-768 public key")?,
                    hash,
                }),
                len => anyhow::bail!(
                    "invalid VLESS Encryption public key length {len} (expected 32 or 1184)"
                ),
            }
        }
        anyhow::ensure!(
            !auth_keys.is_empty(),
            "VLESS Encryption requires at least one server public key"
        );
        let (padding_lengths, padding_gaps) = parse_padding(&padding_parts)?;
        let relays_len = auth_keys.iter().map(AuthKey::ciphertext_len).sum::<usize>()
            + (auth_keys.len() - 1) * 32;
        Ok(Arc::new(Self {
            auth_keys,
            relays_len,
            mode,
            allow_0rtt: rtt == "0rtt",
            padding_lengths,
            padding_gaps,
            ticket: RwLock::new(None),
        }))
    }

    pub(crate) async fn connect(
        self: &Arc<Self>,
        mut stream: Box<dyn AsyncReadWrite>,
    ) -> anyhow::Result<EncryptedStream> {
        let use_aes = aes_gcm_hardware_available();
        let mut iv = [0u8; IV_LEN];
        rand::rng().fill_bytes(&mut iv);
        let (relays, nfs_key) = self.build_relays(&iv)?;
        let mut nfs_aead = StreamAead::new(&iv, &nfs_key, use_aes)?;
        let prior_ticket = if self.allow_0rtt {
            self.ticket
                .read()
                .as_ref()
                .filter(|ticket| ticket.expires_at > Instant::now())
                .cloned()
        } else {
            None
        };

        if let Some(ticket) = prior_ticket {
            let mut prewrite = Vec::with_capacity(IV_LEN + relays.len() + 18 + 32);
            prewrite.extend_from_slice(&iv);
            prewrite.extend_from_slice(&relays);
            nfs_aead.seal(&encode_length(32), b"", &mut prewrite)?;
            let ticket_context_start = prewrite.len();
            nfs_aead.seal(&ticket.ticket, b"", &mut prewrite)?;
            let ticket_context = prewrite[ticket_context_start..].to_vec();
            let mut united_key = Vec::with_capacity(96);
            united_key.extend_from_slice(&ticket.pfs_key);
            united_key.extend_from_slice(&nfs_key);
            let send = StreamAead::new(&ticket_context, &united_key, use_aes)?;
            let send_xor = (self.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &iv));
            return Ok(EncryptedStream::new(
                stream,
                united_key,
                use_aes,
                send,
                None,
                send_xor,
                None,
                Some(prewrite),
                PeerInit::ServerRandom,
                Some(TicketUse {
                    config: self.clone(),
                    pfs_key: ticket.pfs_key,
                }),
                self.mode == XorMode::Random,
            ));
        }

        let (padding_len, mut padding_lengths, padding_gaps) = self.make_padding();
        let (mlkem_public, mlkem_private) = MlKemPrivateKey::generate(MlKemAlgorithm::MlKem768)?;
        let (x_public, x_private) = x25519_keypair();
        let mut pfs_public = Vec::with_capacity(PFS_CLIENT_KEY_LEN);
        pfs_public.extend_from_slice(mlkem_public.as_bytes());
        pfs_public.extend_from_slice(&x_public);

        let mut hello = Vec::with_capacity(IV_LEN + relays.len() + 1250 + padding_len);
        hello.extend_from_slice(&iv);
        hello.extend_from_slice(&relays);
        nfs_aead.seal(
            &encode_length(PFS_CLIENT_KEY_LEN + TAG_LEN),
            b"",
            &mut hello,
        )?;
        nfs_aead.seal(&pfs_public, b"", &mut hello)?;
        anyhow::ensure!(padding_len >= 35, "VLESS Encryption padding is too short");
        nfs_aead.seal(&encode_length(padding_len - 18), b"", &mut hello)?;
        let padding_plaintext = vec![0; padding_len - 34];
        nfs_aead.seal(&padding_plaintext, b"", &mut hello)?;

        padding_lengths[0] += IV_LEN + relays.len() + 18 + PFS_CLIENT_KEY_LEN + TAG_LEN;
        let mut offset = 0;
        for (index, length) in padding_lengths.into_iter().enumerate() {
            if length > 0 {
                stream.write_all(&hello[offset..offset + length]).await?;
                offset += length;
            }
            if let Some(gap) = padding_gaps.get(index).copied() {
                tokio::time::sleep(gap).await;
            }
        }
        anyhow::ensure!(
            offset == hello.len(),
            "VLESS Encryption padding layout mismatch"
        );
        stream.flush().await?;

        let mut encrypted_server_key = vec![0u8; PFS_SERVER_KEY_LEN + TAG_LEN];
        stream.read_exact(&mut encrypted_server_key).await?;
        let server_key_len =
            nfs_aead.open_with_nonce(&MAX_NONCE, &mut encrypted_server_key, b"")?;
        anyhow::ensure!(
            server_key_len == PFS_SERVER_KEY_LEN,
            "invalid VLESS Encryption server key length"
        );
        let server_key = &encrypted_server_key[..server_key_len];
        let mlkem_shared = mlkem_private
            .decapsulate(&server_key[..MLKEM_CIPHERTEXT_LEN])
            .context("invalid VLESS Encryption server ML-KEM ciphertext")?;
        let server_x25519: &[u8; X25519_KEY_LEN] = server_key[MLKEM_CIPHERTEXT_LEN..]
            .try_into()
            .expect("checked server X25519 key length");
        let x_shared = x25519(&x_private, server_x25519)?;
        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(&mlkem_shared);
        pfs_key[32..].copy_from_slice(&x_shared);
        let mut united_key = Vec::with_capacity(96);
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);
        let send = StreamAead::new(&pfs_public, &united_key, use_aes)?;
        let mut recv = StreamAead::new(server_key, &united_key, use_aes)?;

        let mut encrypted_ticket = vec![0u8; TICKET_LEN + TAG_LEN];
        stream.read_exact(&mut encrypted_ticket).await?;
        let ticket_len = recv.open(&mut encrypted_ticket, b"")?;
        anyhow::ensure!(
            ticket_len == TICKET_LEN,
            "invalid VLESS Encryption ticket length"
        );
        let ticket: [u8; TICKET_LEN] = encrypted_ticket[..ticket_len]
            .try_into()
            .expect("checked ticket length");
        let ticket_seconds = u16::from_be_bytes([ticket[0], ticket[1]]);
        if self.allow_0rtt && ticket_seconds > 0 {
            *self.ticket.write() = Some(SessionTicket {
                pfs_key,
                ticket,
                expires_at: Instant::now() + Duration::from_secs(u64::from(ticket_seconds)),
            });
        }

        let mut encrypted_padding_len = vec![0u8; 18];
        stream.read_exact(&mut encrypted_padding_len).await?;
        let padding_len_plain = recv.open(&mut encrypted_padding_len, b"")?;
        anyhow::ensure!(
            padding_len_plain == 2,
            "invalid VLESS Encryption padding length"
        );
        let peer_padding_len =
            u16::from_be_bytes([encrypted_padding_len[0], encrypted_padding_len[1]]) as usize;
        anyhow::ensure!(
            (TAG_LEN..=u16::MAX as usize).contains(&peer_padding_len),
            "invalid VLESS Encryption peer padding length"
        );
        let send_xor = (self.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &iv));
        let recv_xor = (self.mode == XorMode::Random).then(|| AesCtr::new(&united_key, &ticket));

        Ok(EncryptedStream::new(
            stream,
            united_key,
            use_aes,
            send,
            Some(recv),
            send_xor,
            recv_xor,
            None,
            PeerInit::Padding(peer_padding_len),
            None,
            self.mode == XorMode::Random,
        ))
    }

    fn build_relays(&self, iv: &[u8; IV_LEN]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
        let mut relays = Vec::with_capacity(self.relays_len);
        let mut previous = None::<AesCtr>;
        let mut final_key = [0u8; 32];
        for (index, key) in self.auth_keys.iter().enumerate() {
            let (mut ciphertext, shared) = key.encapsulate()?;
            if self.mode != XorMode::Native {
                AesCtr::new(key.public_bytes(), iv).apply(&mut ciphertext);
            }
            if let Some(previous) = previous.as_mut() {
                previous.apply(&mut ciphertext[..32]);
            }
            relays.extend_from_slice(&ciphertext);
            final_key = shared;
            if index + 1 < self.auth_keys.len() {
                let mut chain = AesCtr::new(&shared, iv);
                let mut next_hash = *self.auth_keys[index + 1].hash();
                chain.apply(&mut next_hash);
                relays.extend_from_slice(&next_hash);
                previous = Some(chain);
            }
        }
        anyhow::ensure!(
            relays.len() == self.relays_len,
            "VLESS Encryption relay size mismatch"
        );
        Ok((relays, final_key))
    }

    fn make_padding(&self) -> (usize, Vec<usize>, Vec<Duration>) {
        let default_lengths = [
            PaddingSpec {
                probability: 100,
                min: 111,
                max: 1111,
            },
            PaddingSpec {
                probability: 50,
                min: 0,
                max: 3333,
            },
        ];
        let default_gaps = [PaddingSpec {
            probability: 75,
            min: 0,
            max: 111,
        }];
        let lengths = if self.padding_lengths.is_empty() {
            &default_lengths[..]
        } else {
            &self.padding_lengths
        };
        let gaps = if self.padding_lengths.is_empty() {
            &default_gaps[..]
        } else {
            &self.padding_gaps
        };
        let mut rng = rand::rng();
        let selected_lengths: Vec<_> = lengths
            .iter()
            .map(|spec| select_padding(&mut rng, *spec))
            .collect();
        let selected_gaps = gaps
            .iter()
            .map(|spec| Duration::from_millis(select_padding(&mut rng, *spec) as u64))
            .collect();
        (
            selected_lengths.iter().sum(),
            selected_lengths,
            selected_gaps,
        )
    }
}

fn select_padding(rng: &mut impl rand::Rng, spec: PaddingSpec) -> usize {
    if rng.random_range(0u8..100) < spec.probability {
        rng.random_range(spec.min..=spec.max)
    } else {
        0
    }
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn parse_padding(parts: &[&str]) -> anyhow::Result<(Vec<PaddingSpec>, Vec<PaddingSpec>)> {
    if parts.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut lengths = Vec::new();
    let mut gaps = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let values: Vec<_> = part.split('-').collect();
        anyhow::ensure!(
            values.len() == 3,
            "invalid VLESS Encryption padding parameter '{part}'"
        );
        let spec = PaddingSpec {
            probability: values[0].parse().context("invalid padding probability")?,
            min: values[1].parse().context("invalid padding minimum")?,
            max: values[2].parse().context("invalid padding maximum")?,
        };
        anyhow::ensure!(spec.probability <= 100, "padding probability exceeds 100");
        anyhow::ensure!(spec.min <= spec.max, "padding minimum exceeds maximum");
        if index == 0 {
            anyhow::ensure!(
                spec.probability == 100 && spec.min >= 35,
                "first VLESS Encryption padding must be certain and at least 35 bytes"
            );
        }
        if index % 2 == 0 {
            lengths.push(spec);
        } else {
            gaps.push(spec);
        }
    }
    anyhow::ensure!(
        lengths.iter().map(|spec| spec.max).sum::<usize>() <= 65_553,
        "total VLESS Encryption padding exceeds 65553 bytes"
    );
    Ok((lengths, gaps))
}

fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut public = [0u8; 32];
    let mut private = [0u8; 32];
    unsafe { boring_sys::X25519_keypair(public.as_mut_ptr(), private.as_mut_ptr()) };
    (public, private)
}

fn x25519(private: &[u8; 32], public: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let mut shared = [0u8; 32];
    let ok = unsafe { boring_sys::X25519(shared.as_mut_ptr(), private.as_ptr(), public.as_ptr()) };
    anyhow::ensure!(ok == 1, "invalid VLESS Encryption X25519 public key");
    Ok(shared)
}

fn encode_length(length: usize) -> [u8; 2] {
    (length as u16).to_be_bytes()
}

fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    raw_blake3::derive_key(context, material)
}

#[cfg(target_arch = "x86_64")]
fn aes_gcm_hardware_available() -> bool {
    std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("sse4.1")
        && std::is_x86_feature_detected!("ssse3")
}

#[cfg(target_arch = "aarch64")]
fn aes_gcm_hardware_available() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn aes_gcm_hardware_available() -> bool {
    false
}

struct AesCtr {
    cipher: Aes256,
    counter: [u8; 16],
    block: [u8; 16],
    used: usize,
}

impl AesCtr {
    fn new(material: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new_from_slice(&derive_key(KDF_CTR, material))
                .expect("AES-256 key length"),
            counter: *iv,
            block: [0; 16],
            used: 16,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == self.block.len() {
                let mut block = aes::cipher::Block::<Aes256>::default();
                block.copy_from_slice(&self.counter);
                self.cipher.encrypt_block(&mut block);
                self.block.copy_from_slice(&block);
                self.used = 0;
                for counter_byte in self.counter.iter_mut().rev() {
                    let (next, overflow) = counter_byte.overflowing_add(1);
                    *counter_byte = next;
                    if !overflow {
                        break;
                    }
                }
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

struct StreamAead {
    cipher: AeadCipher,
    nonce: [u8; NONCE_LEN],
}

impl StreamAead {
    fn new(context: &[u8], key: &[u8], use_aes: bool) -> anyhow::Result<Self> {
        Ok(Self {
            cipher: AeadCipher::new_vless(use_aes, &derive_key(context, key))?,
            nonce: [0; NONCE_LEN],
        })
    }

    fn seal(&mut self, plaintext: &[u8], aad: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.next_nonce();
        self.cipher
            .seal_with_aad_into(&nonce, plaintext, aad, output)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VLESS Encryption seal failed"))
    }

    fn open(&mut self, ciphertext: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.next_nonce();
        self.open_with_nonce(&nonce, ciphertext, aad)
    }

    fn open_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &mut [u8],
        aad: &[u8],
    ) -> io::Result<usize> {
        self.cipher
            .open_with_aad_in_place(nonce, ciphertext, aad)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS Encryption authentication failed",
                )
            })
    }

    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        for byte in self.nonce.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        self.nonce
    }
}

struct PendingWrite {
    wire: Vec<u8>,
    offset: usize,
    plaintext_len: usize,
}

struct TicketUse {
    config: Arc<ClientConfig>,
    pfs_key: [u8; 64],
}

impl TicketUse {
    fn invalidate(&self) {
        let mut ticket = self.config.ticket.write();
        if ticket
            .as_ref()
            .is_some_and(|current| current.pfs_key == self.pfs_key)
        {
            *ticket = None;
        }
    }
}

#[derive(Debug)]
enum ReadPhase {
    ServerRandom,
    Padding,
    Header,
    Body {
        header: [u8; FRAME_HEADER_LEN],
        ciphertext_len: usize,
    },
}

enum PeerInit {
    ServerRandom,
    Padding(usize),
    #[cfg(test)]
    Ready,
}

pub(crate) struct EncryptedStream {
    inner: Box<dyn AsyncReadWrite>,
    united_key: Vec<u8>,
    use_aes: bool,
    send: StreamAead,
    recv: Option<StreamAead>,
    send_xor: Option<AesCtr>,
    recv_xor: Option<AesCtr>,
    xor_headers: bool,
    prewrite: Option<Vec<u8>>,
    pending_write: Option<PendingWrite>,
    read_phase: ReadPhase,
    read_wire: Vec<u8>,
    read_offset: usize,
    read_plaintext: Vec<u8>,
    read_plaintext_offset: usize,
    read_eof: bool,
    direct_read: bool,
    recv_header_xor: direct::HeaderXor,
    direct_write: bool,
    send_header_xor: direct::HeaderXor,
    /// Write buffer reused while traffic flows; empty while `pending_write`
    /// owns it and released once the stream flushes idle.
    write_wire: Vec<u8>,
    ticket_use: Option<TicketUse>,
}

impl EncryptedStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: Box<dyn AsyncReadWrite>,
        united_key: Vec<u8>,
        use_aes: bool,
        send: StreamAead,
        recv: Option<StreamAead>,
        send_xor: Option<AesCtr>,
        recv_xor: Option<AesCtr>,
        prewrite: Option<Vec<u8>>,
        peer_init: PeerInit,
        ticket_use: Option<TicketUse>,
        xor_headers: bool,
    ) -> Self {
        let (read_phase, read_wire) = match peer_init {
            PeerInit::ServerRandom => (ReadPhase::ServerRandom, vec![0; IV_LEN]),
            PeerInit::Padding(length) => (ReadPhase::Padding, vec![0; length]),
            #[cfg(test)]
            PeerInit::Ready => (ReadPhase::Header, vec![0; FRAME_HEADER_LEN]),
        };
        Self {
            inner,
            united_key,
            use_aes,
            send,
            recv,
            send_xor,
            recv_xor,
            xor_headers,
            prewrite,
            pending_write: None,
            read_phase,
            read_wire,
            read_offset: 0,
            read_plaintext: Vec::new(),
            read_plaintext_offset: 0,
            read_eof: false,
            direct_read: false,
            recv_header_xor: direct::HeaderXor::default(),
            direct_write: false,
            send_header_xor: direct::HeaderXor::default(),
            write_wire: Vec::new(),
            ticket_use,
        }
    }

    fn frame(&mut self, plaintext: &[u8]) -> io::Result<(Vec<u8>, usize)> {
        let plaintext_len = plaintext.len().min(MAX_FRAME_PLAINTEXT);
        let mut header = [23, 3, 3, 0, 0];
        header[3..].copy_from_slice(&encode_length(plaintext_len + TAG_LEN));
        let rekey = self.send.nonce == MAX_NONCE;
        let prewrite = self.prewrite.as_deref().unwrap_or_default();
        let header_start = prewrite.len();
        let mut wire = std::mem::take(&mut self.write_wire);
        wire.clear();
        wire.reserve_exact(header_start + FRAME_HEADER_LEN + plaintext_len + TAG_LEN);
        wire.extend_from_slice(prewrite);
        wire.extend_from_slice(&header);
        // The AEAD appends, so the ciphertext lands after the unmasked header.
        self.send
            .seal(&plaintext[..plaintext_len], &header, &mut wire)?;
        if rekey {
            self.send = StreamAead::new(&wire[header_start..], &self.united_key, self.use_aes)
                .map_err(io::Error::other)?;
        }
        if let Some(xor) = self.send_xor.as_mut() {
            xor.apply(&mut wire[header_start..header_start + FRAME_HEADER_LEN]);
        }
        self.prewrite = None;
        Ok((wire, plaintext_len))
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let pending = self.pending_write.as_mut().expect("pending write exists");
        while pending.offset < pending.wire.len() {
            match Pin::new(&mut *self.inner).poll_write(cx, &pending.wire[pending.offset..]) {
                Poll::Ready(Ok(0)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => pending.offset += written,
                Poll::Ready(Err(error)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let done = self
            .pending_write
            .take()
            .expect("completed pending write exists");
        if done.wire.capacity() <= MAX_RETAINED_WIRE {
            self.write_wire = done.wire;
        }
        Poll::Ready(Ok(done.plaintext_len))
    }

    fn copy_plaintext(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.read_plaintext_offset == self.read_plaintext.len() {
            return false;
        }
        let count = output
            .remaining()
            .min(self.read_plaintext.len() - self.read_plaintext_offset);
        output.put_slice(
            &self.read_plaintext[self.read_plaintext_offset..self.read_plaintext_offset + count],
        );
        self.read_plaintext_offset += count;
        if self.read_plaintext_offset == self.read_plaintext.len() {
            self.read_plaintext.clear();
            self.read_plaintext_offset = 0;
        }
        true
    }

    fn at_frame_boundary(&self) -> bool {
        matches!(self.read_phase, ReadPhase::Header) && self.read_offset == 0
    }

    fn invalidate_ticket(&mut self) {
        if let Some(ticket_use) = self.ticket_use.take() {
            ticket_use.invalidate();
        }
    }
}

impl fmt::Debug for EncryptedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptedStream")
            .field("inner", &self.inner)
            .field("read_phase", &self.read_phase)
            .finish_non_exhaustive()
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let (wire, plaintext_len) = self.frame(input)?;
            self.pending_write = Some(PendingWrite {
                wire,
                offset: 0,
                plaintext_len,
            });
        }
        self.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let flushed = Pin::new(&mut *self.inner).poll_flush(cx);
        if flushed.is_ready() {
            // The relay flushes once its source would block: release until traffic resumes.
            self.write_wire = Vec::new();
        }
        flushed
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.copy_plaintext(output) {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            while self.read_offset < self.read_wire.len() {
                let start = self.read_offset;
                let (poll, read) = {
                    let this = self.as_mut().get_mut();
                    let mut wire_buf = ReadBuf::new(&mut this.read_wire[start..]);
                    let poll = Pin::new(&mut *this.inner).poll_read(cx, &mut wire_buf);
                    (poll, wire_buf.filled().len())
                };
                match poll {
                    Poll::Ready(Ok(())) if read == 0 => {
                        if self.at_frame_boundary() {
                            self.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated VLESS Encryption frame",
                        )));
                    }
                    Poll::Ready(Ok(())) => self.read_offset += read,
                    Poll::Ready(Err(error)) => {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => {
                        if self.at_frame_boundary() {
                            // Idle at a frame boundary: keep only the header buffer.
                            self.read_plaintext = Vec::new();
                        }
                        return Poll::Pending;
                    }
                }
            }

            let mut wire = std::mem::take(&mut self.read_wire);
            self.read_offset = 0;
            match std::mem::replace(&mut self.read_phase, ReadPhase::Header) {
                ReadPhase::ServerRandom => {
                    let recv = StreamAead::new(&wire, &self.united_key, self.use_aes)
                        .map_err(io::Error::other)?;
                    if self.xor_headers {
                        self.recv_xor = Some(AesCtr::new(
                            &self.united_key,
                            wire.as_slice().try_into().expect("server random length"),
                        ));
                    }
                    self.recv = Some(recv);
                    self.read_phase = ReadPhase::Header;
                    self.read_wire = vec![0; FRAME_HEADER_LEN];
                }
                ReadPhase::Padding => {
                    let result = self
                        .recv
                        .as_mut()
                        .expect("1-RTT has receive AEAD")
                        .open(&mut wire, b"");
                    if result.is_err() {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid VLESS Encryption peer padding",
                        )));
                    }
                    self.read_phase = ReadPhase::Header;
                    self.read_wire = vec![0; FRAME_HEADER_LEN];
                }
                ReadPhase::Header => {
                    let mut header: [u8; FRAME_HEADER_LEN] = wire
                        .as_slice()
                        .try_into()
                        .expect("VLESS Encryption frame header length");
                    if let Some(xor) = self.recv_xor.as_mut() {
                        xor.apply(&mut header);
                    }
                    let ciphertext_len = u16::from_be_bytes([header[3], header[4]]) as usize;
                    if header[..3] != [23, 3, 3]
                        || !(TAG_LEN + 1..=MAX_FRAME_CIPHERTEXT).contains(&ciphertext_len)
                    {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid VLESS Encryption frame header",
                        )));
                    }
                    self.read_phase = ReadPhase::Body {
                        header,
                        ciphertext_len,
                    };
                    // The drained plaintext buffer receives the body; the header
                    // buffer waits in the empty plaintext slot until it returns.
                    std::mem::swap(&mut wire, &mut self.read_plaintext);
                    self.read_plaintext.clear();
                    wire.clear();
                    wire.reserve_exact(ciphertext_len);
                    wire.resize(ciphertext_len, 0);
                    self.read_wire = wire;
                }
                ReadPhase::Body {
                    header,
                    ciphertext_len,
                } => {
                    let rekey =
                        self.recv.as_ref().expect("receive AEAD initialized").nonce == MAX_NONCE;
                    let rekey_context = rekey.then(|| {
                        let mut context = Vec::with_capacity(header.len() + wire.len());
                        context.extend_from_slice(&header);
                        context.extend_from_slice(&wire);
                        context
                    });
                    let result = self
                        .recv
                        .as_mut()
                        .expect("receive AEAD initialized")
                        .open(&mut wire, &header);
                    let Ok(plaintext_len) = result else {
                        self.invalidate_ticket();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VLESS Encryption frame authentication failed",
                        )));
                    };
                    debug_assert_eq!(plaintext_len + TAG_LEN, ciphertext_len);
                    if let Some(context) = rekey_context {
                        self.recv = Some(
                            StreamAead::new(&context, &self.united_key, self.use_aes)
                                .map_err(io::Error::other)?,
                        );
                    }
                    wire.truncate(plaintext_len);
                    self.ticket_use = None;
                    let mut header_wire = std::mem::replace(&mut self.read_plaintext, wire);
                    self.read_plaintext_offset = 0;
                    self.read_phase = ReadPhase::Header;
                    header_wire.clear();
                    header_wire.resize(FRAME_HEADER_LEN, 0);
                    self.read_wire = header_wire;
                    if self.copy_plaintext(output) {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

mod direct;
mod raw_blake3;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::proxy::vless) mod testutil;
