//! BoringSSL-backed QUIC crypto for quinn-proto (`crypto::Session`).
//!
//! Replaces rustls inside QUIC handshakes so QUIC outbounds (TUIC, Juicity,
//! Hysteria2, DoQ/DoH3) get the same BoringSSL ClientHello as the TCP path:
//! real Chrome fingerprint and, crucially, ECH — rustls has no client ECH,
//! and quiche exposes no per-connection ECH hook, which is why this backend
//! exists instead of a quiche port.
//!
//! Architecture: BoringSSL is callback-driven (`SSL_QUIC_METHOD`), quinn is
//! pull-driven (`write_handshake`/`read_handshake`). The trampolines below
//! stash traffic secrets, outgoing CRYPTO bytes, and alerts into
//! [`QuicCryptoState`] (reachable from the C callbacks via `SSL` ex_data);
//! the pull methods drain that state in the order quinn's `write_crypto`
//! loop expects: old-level bytes and the *next* level's keys in one call.
//!
//! Only the client side is implemented (honk is a client-side outbound).

use std::any::Any;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, LazyLock};

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use boring::aead::{AeadCtx, Algorithm as AeadAlgorithm};
use boring::error::ErrorStack;
use boring::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use bytes::BytesMut;
use foreign_types::ForeignTypeRef;
use hkdf::Hkdf;
use quinn_proto::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use sha2::{Sha256, Sha384};

// TLS 1.3 cipher suite IDs (RFC 8446 §B.4).
const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// RFC 9001 §5.2 initial salt (QUIC v1).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// RFC 9001 §5.3 retry integrity tag key/nonce (QUIC v1).
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

// BoringSSL encryption levels (ssl.h ssl_encryption_level_t).
const LEVEL_INITIAL: usize = 0;
const LEVEL_HANDSHAKE: usize = 2;
const LEVEL_APPLICATION: usize = 3;

/// HKDF-Expand-Label `info` block (RFC 8446 §7.1).
fn expand_label_info(label: &str, out_len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(3 + full_label.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty context
    info
}

/// HKDF-Expand-Label (RFC 8446 §7.1), SHA-256 variant.
fn hkdf_expand_label_sha256(secret: &[u8], label: &str, out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("traffic secret shorter than hash");
    hk.expand(&expand_label_info(label, out.len()), out)
        .expect("okm length within limits");
}

/// HKDF-Expand-Label (RFC 8446 §7.1), SHA-384 variant.
fn hkdf_expand_label_sha384(secret: &[u8], label: &str, out: &mut [u8]) {
    let hk = Hkdf::<Sha384>::from_prk(secret).expect("traffic secret shorter than hash");
    hk.expand(&expand_label_info(label, out.len()), out)
        .expect("okm length within limits");
}

/// A TLS 1.3 traffic secret plus the suite it belongs to.
#[derive(Clone)]
struct TrafficSecrets {
    suite: u16,
    secret: Vec<u8>,
}

impl TrafficSecrets {
    fn expand_label(&self, label: &str, out: &mut [u8]) {
        match self.suite {
            TLS13_AES_256_GCM_SHA384 => hkdf_expand_label_sha384(&self.secret, label, out),
            _ => hkdf_expand_label_sha256(&self.secret, label, out),
        }
    }

    fn hash_len(&self) -> usize {
        match self.suite {
            TLS13_AES_256_GCM_SHA384 => 48,
            _ => 32,
        }
    }

    /// QUIC key update (RFC 9001 §6): next traffic secret.
    fn next_secret(&self) -> Self {
        let mut secret = vec![0u8; self.hash_len()];
        self.expand_label("quic ku", &mut secret);
        Self {
            suite: self.suite,
            secret,
        }
    }
}

/// QUIC AEAD packet-protection key (RFC 9001 §5.3).
struct BoringPacketKey {
    aead: AeadCtx,
    iv: [u8; 12],
    tag_len: usize,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl BoringPacketKey {
    fn new(secrets: &TrafficSecrets) -> anyhow::Result<Self> {
        let (algorithm, key_len, confidentiality_limit, integrity_limit): (_, _, u64, u64) =
            match secrets.suite {
                TLS13_AES_128_GCM_SHA256 => (AeadAlgorithm::aes_128_gcm(), 16, 1 << 23, 1 << 52),
                TLS13_AES_256_GCM_SHA384 => (AeadAlgorithm::aes_256_gcm(), 32, 1 << 23, 1 << 52),
                TLS13_CHACHA20_POLY1305_SHA256 => {
                    (AeadAlgorithm::chacha20_poly1305(), 32, u64::MAX, 1 << 36)
                }
                other => anyhow::bail!("unsupported TLS 1.3 cipher suite 0x{other:04x}"),
            };
        let mut key = vec![0u8; key_len];
        secrets.expand_label("quic key", &mut key);
        let mut iv = [0u8; 12];
        secrets.expand_label("quic iv", &mut iv);
        let aead = AeadCtx::new_default_tag(&algorithm, &key)?;
        let tag_len = algorithm.max_tag_len();
        Ok(Self {
            aead,
            iv,
            tag_len,
            confidentiality_limit,
            integrity_limit,
        })
    }

    fn nonce(&self, packet: u64) -> [u8; 12] {
        // RFC 9001 §5.3: nonce = iv XOR packet number (left-padded).
        let mut nonce = self.iv;
        for (i, b) in packet.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }
}

impl PacketKey for BoringPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce = self.nonce(packet);
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len);
        let tag = self
            .aead
            .seal_in_place(&nonce, payload, tag_storage, header)
            .expect("AEAD seal failed");
        debug_assert_eq!(tag.len(), self.tag_len);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let nonce = self.nonce(packet);
        let payload_len = payload.len();
        let (body, tag) = payload.split_at_mut(payload_len - self.tag_len);
        self.aead
            .open_in_place(&nonce, body, tag, header)
            .map_err(|_| CryptoError)?;
        payload.truncate(payload_len - self.tag_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

/// QUIC header-protection key (RFC 9001 §5.4): AES-ECB or ChaCha20.
#[allow(clippy::large_enum_variant)] // AES-256 key schedule is large; HP keys are per-connection
enum BoringHeaderKey {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
    ChaCha20([u8; 32]),
}

impl BoringHeaderKey {
    fn new(secrets: &TrafficSecrets) -> anyhow::Result<Self> {
        let key_len = match secrets.suite {
            TLS13_AES_128_GCM_SHA256 => 16,
            _ => 32,
        };
        let mut key = vec![0u8; key_len];
        secrets.expand_label("quic hp", &mut key);
        Ok(match secrets.suite {
            TLS13_AES_128_GCM_SHA256 => {
                Self::Aes128(aes::Aes128::new_from_slice(&key).expect("key length"))
            }
            TLS13_AES_256_GCM_SHA384 => {
                Self::Aes256(aes::Aes256::new_from_slice(&key).expect("key length"))
            }
            TLS13_CHACHA20_POLY1305_SHA256 => Self::ChaCha20(key.try_into().expect("key length")),
            other => anyhow::bail!("unsupported TLS 1.3 cipher suite 0x{other:04x}"),
        })
    }

    fn compute_mask(&self, sample: &[u8]) -> [u8; 5] {
        match self {
            Self::Aes128(cipher) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(&sample[..16]);
                cipher.encrypt_block((&mut block).into());
                block[..5].try_into().expect("slice length")
            }
            Self::Aes256(cipher) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(&sample[..16]);
                cipher.encrypt_block((&mut block).into());
                block[..5].try_into().expect("slice length")
            }
            Self::ChaCha20(key) => {
                use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
                // RFC 9001 §5.4.4: sample[0..4] is the ChaCha20 BLOCK counter;
                // `StreamCipherSeek::seek` takes a BYTE offset, so convert.
                let counter = u32::from_le_bytes(sample[..4].try_into().expect("slice length"));
                let nonce: [u8; 12] = sample[4..16].try_into().expect("slice length");
                let mut cipher = chacha20::ChaCha20::new(key.into(), &nonce.into());
                cipher.seek(u64::from(counter) * 64);
                let mut mask = [0u8; 5];
                cipher.apply_keystream(&mut mask);
                mask
            }
        }
    }
}

impl HeaderKey for BoringHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Mirrors quinn-proto's rustls impl: same layout, same mask application.
        // NB: rustls's HeaderProtectionKey does two things internally that
        // this impl must mirror exactly:
        //  1. Bit-width masking (RFC 9001 §5.4.1): long header masks 4 bits of
        //     the first byte, short header 5.
        //  2. pn-LENGTH-aware masking: only pn_len bytes after the first byte
        //     are masked. Masking a fixed 4-byte span corrupts the payload
        //     bytes following a short (1-3 byte) packet number — and because
        //     XOR is self-inverse, a same-bug peer silently self-cancels
        //     (which is why every boring↔boring self-test passed while
        //     rustls correctly rejected our packets).
        // Removal order: unmask the first byte FIRST, then read pn_len from
        // it (the pn-length bits themselves were masked).
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let mask = self.compute_mask(&sample[..self.sample_size()]);
        first[0] ^= mask[0] & if first[0] & 0x80 == 0x80 { 0x0f } else { 0x1f };
        let pn_len = (first[0] & 0x03) as usize + 1;
        for (dst, m) in rest[pn_offset - 1..]
            .iter_mut()
            .zip(&mask[1..])
            .take(pn_len)
        {
            *dst ^= m;
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // Application order: pn_len comes from the first byte BEFORE masking
        // it (the pn-length bits are plaintext until we mask them).
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let mask = self.compute_mask(&sample[..self.sample_size()]);
        let pn_len = (first[0] & 0x03) as usize + 1;
        first[0] ^= mask[0] & if first[0] & 0x80 == 0x80 { 0x0f } else { 0x1f };
        for (dst, m) in rest[pn_offset - 1..]
            .iter_mut()
            .zip(&mask[1..])
            .take(pn_len)
        {
            *dst ^= m;
        }
    }

    fn sample_size(&self) -> usize {
        16
    }
}

fn keys_from_secrets(read: &TrafficSecrets, write: &TrafficSecrets) -> anyhow::Result<Keys> {
    Ok(Keys {
        header: KeyPair {
            local: Box::new(BoringHeaderKey::new(write)?),
            remote: Box::new(BoringHeaderKey::new(read)?),
        },
        packet: KeyPair {
            local: Box::new(BoringPacketKey::new(write)?),
            remote: Box::new(BoringPacketKey::new(read)?),
        },
    })
}

/// QUIC initial keys from the client's initial DCID (RFC 9001 §5.2).
fn initial_keys_v1(dst_cid: &ConnectionId, side: Side) -> Keys {
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dst_cid.as_ref());
    let initial_secret = &initial_secret[..];
    let mut client_secret = vec![0u8; 32];
    hkdf_expand_label_sha256(initial_secret, "client in", &mut client_secret);
    let mut server_secret = vec![0u8; 32];
    hkdf_expand_label_sha256(initial_secret, "server in", &mut server_secret);

    let client = TrafficSecrets {
        suite: TLS13_AES_128_GCM_SHA256,
        secret: client_secret,
    };
    let server = TrafficSecrets {
        suite: TLS13_AES_128_GCM_SHA256,
        secret: server_secret,
    };
    let (read, write) = match side {
        Side::Client => (server, client),
        Side::Server => (client, server),
    };
    keys_from_secrets(&read, &write).expect("initial keys derivation is infallible")
}

/// State shared between the `SSL_QUIC_METHOD` C callbacks and the quinn
/// `Session` pull methods. Owned by the session; the callbacks reach it via
/// `SSL` ex_data. All access happens either inside `SSL_do_handshake` (which
/// requires `&mut self` on the session) or from quinn's single connection
/// task, so the raw-pointer plumbing cannot race.
#[derive(Default)]
struct QuicCryptoState {
    read_secrets: [Option<TrafficSecrets>; 4],
    write_secrets: [Option<TrafficSecrets>; 4],
    /// Buffered outgoing CRYPTO bytes per level.
    outgoing: [Vec<u8>; 4],
    /// Fatal alert code from `send_alert`.
    alert: Option<u8>,
    handshake_complete: bool,
    /// Whether tickets from this connection may be cached and resumed.
    /// pinSHA256 connections never resume: a resumed PSK session would
    /// bypass the pin check on a later (possibly different-pin) config.
    allow_resumption: bool,
    /// Session-ticket cache key for `on_new_session_cb` (SNI|port — see
    /// [`BoringQuicOptions::ticket_key`]); falls back to the server name.
    ticket_key: Option<String>,
}

static EX_DATA_INDEX: LazyLock<i32> = LazyLock::new(|| unsafe {
    boring_sys::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
});

unsafe fn state_of<'a>(ssl: *mut boring_sys::SSL) -> &'a mut QuicCryptoState {
    unsafe {
        let ptr = boring_sys::SSL_get_ex_data(ssl, *EX_DATA_INDEX).cast::<QuicCryptoState>();
        assert!(!ptr.is_null(), "QUIC ex_data not initialized");
        &mut *ptr
    }
}

unsafe extern "C" fn on_set_read_secret(
    ssl: *mut boring_sys::SSL,
    level: boring_sys::ssl_encryption_level_t,
    cipher: *const boring_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> i32 {
    unsafe {
        let suite = boring_sys::SSL_CIPHER_get_protocol_id(cipher);
        let secret = std::slice::from_raw_parts(secret, secret_len).to_vec();
        state_of(ssl).read_secrets[level.0 as usize] = Some(TrafficSecrets { suite, secret });
    }
    1
}

unsafe extern "C" fn on_set_write_secret(
    ssl: *mut boring_sys::SSL,
    level: boring_sys::ssl_encryption_level_t,
    cipher: *const boring_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> i32 {
    unsafe {
        let suite = boring_sys::SSL_CIPHER_get_protocol_id(cipher);
        let secret = std::slice::from_raw_parts(secret, secret_len).to_vec();
        state_of(ssl).write_secrets[level.0 as usize] = Some(TrafficSecrets { suite, secret });
    }
    1
}

unsafe extern "C" fn on_add_handshake_data(
    ssl: *mut boring_sys::SSL,
    level: boring_sys::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> i32 {
    unsafe {
        let bytes = std::slice::from_raw_parts(data, len);
        state_of(ssl).outgoing[level.0 as usize].extend_from_slice(bytes);
    }
    1
}

extern "C" fn on_flush_flight(_ssl: *mut boring_sys::SSL) -> i32 {
    // quinn flushes packets itself; nothing to do.
    1
}

unsafe extern "C" fn on_send_alert(
    ssl: *mut boring_sys::SSL,
    _level: boring_sys::ssl_encryption_level_t,
    alert: u8,
) -> i32 {
    unsafe {
        state_of(ssl).alert = Some(alert);
    }
    1
}

static QUIC_METHOD: boring_sys::SSL_QUIC_METHOD = boring_sys::SSL_QUIC_METHOD {
    set_read_secret: Some(on_set_read_secret),
    set_write_secret: Some(on_set_write_secret),
    add_handshake_data: Some(on_add_handshake_data),
    flush_flight: Some(on_flush_flight),
    send_alert: Some(on_send_alert),
};

/// Process-wide client ticket cache: key → SSL_SESSION, bounded and
/// insertion-ordered (oldest evicted past [`SESSION_TICKETS_CAP`]).
/// TLS 1.3 resumption in BoringSSL is explicit (`SSL_set_session` before the
/// handshake) — the internal SSL_CTX cache only serves TLS 1.2-style id
/// lookups, so tickets are stashed here keyed by server identity.
#[derive(Default)]
struct TicketCache {
    slots: std::collections::HashMap<String, usize>,
    order: std::collections::VecDeque<String>,
}

impl TicketCache {
    fn get(&self, key: &str) -> Option<&usize> {
        self.slots.get(key)
    }

    /// Test-facing existence check.
    #[cfg(test)]
    fn contains_key(&self, key: &str) -> bool {
        self.slots.contains_key(key)
    }

    fn insert(&mut self, key: String, session: usize) {
        if let Some(old) = self.slots.insert(key.clone(), session) {
            self.order.retain(|k| k != &key);
            unsafe { boring_sys::SSL_SESSION_free(old as *mut boring_sys::SSL_SESSION) };
        }
        self.order.push_back(key);
        while self.slots.len() > SESSION_TICKETS_CAP {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.slots.remove(&oldest) {
                unsafe { boring_sys::SSL_SESSION_free(old as *mut boring_sys::SSL_SESSION) };
            }
        }
    }

    fn remove_if_current(&mut self, key: &str, session: usize) -> bool {
        if self.slots.get(key) != Some(&session) {
            return false;
        }
        if let Some(old) = self.slots.remove(key) {
            self.order.retain(|k| k != key);
            unsafe { boring_sys::SSL_SESSION_free(old as *mut boring_sys::SSL_SESSION) };
        }
        true
    }
}

static SESSION_TICKETS: LazyLock<parking_lot::Mutex<TicketCache>> =
    LazyLock::new(|| parking_lot::Mutex::new(TicketCache::default()));

/// Hard cap on cached tickets (insertion-order eviction). Tickets are
/// advisory only — a full cache just means more full handshakes, never a
/// leak of `SSL_SESSION` objects on long-running subscriptions.
const SESSION_TICKETS_CAP: usize = 64;

/// `new_session_cb`: retain each ticket the server issues (one ref held by
/// the map; replaced tickets are freed).
unsafe extern "C" fn on_new_session_cb(
    ssl: *mut boring_sys::SSL,
    session: *mut boring_sys::SSL_SESSION,
) -> i32 {
    let state = unsafe { state_of(ssl) };
    if !state.allow_resumption {
        return 0;
    }
    // SNI|port key when the config carries one (never cross-resume between
    // different servers sharing an SNI); the bare server name otherwise.
    let name = match state.ticket_key.clone() {
        Some(key) => key,
        None => {
            let name = unsafe {
                boring_sys::SSL_get_servername(ssl, boring_sys::TLSEXT_NAMETYPE_host_name)
            };
            if name.is_null() {
                return 0;
            }
            unsafe { std::ffi::CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned()
        }
    };
    unsafe { boring_sys::SSL_SESSION_up_ref(session) };
    SESSION_TICKETS.lock().insert(name, session as usize);
    0
}

/// Options for [`BoringQuicClientConfig::new`].
#[derive(Default)]
pub struct BoringQuicOptions {
    /// ALPN protocol list in TLS wire format (length-prefixed entries),
    /// e.g. `b"\x02h3"` for Hysteria2/Juicity.
    pub alpn_wire: Vec<u8>,
    /// Skip all certificate verification.
    pub skip_cert_verify: bool,
    /// Chrome ClientHello fingerprint.
    pub chrome: bool,
    /// ECH origin, resolved once at build time (`None` means no ECH).
    pub(crate) ech: Option<crate::ech_doh::Ech>,
    /// pinSHA256 leaf-certificate fingerprint; replaces PKI and hostname
    /// verification when set.
    pub pin_sha256: Option<[u8; 32]>,
    /// Session-ticket cache key (defaults to the server name). Servers are
    /// identified by SNI|port so different servers sharing an SNI (e.g. one
    /// certificate deployed on two protocol servers) never cross-resume.
    pub ticket_key: Option<String>,
}

/// `crypto::ClientConfig` backed by a BoringSSL `SSL_CTX` (TLS 1.3 only).
pub struct BoringQuicClientConfig {
    ctx: SslContext,
    alpn_wire: Vec<u8>,
    chrome: bool,
    ech: Option<crate::ech_doh::Ech>,
    /// pinSHA256 is in use: resumption disabled (PSK would bypass the pin).
    has_pin: bool,
    /// Session-ticket cache key (defaults to the server name when unset).
    ticket_key: Option<String>,
}

impl BoringQuicClientConfig {
    /// Build the config from [`BoringQuicOptions`].
    pub fn new(options: BoringQuicOptions) -> anyhow::Result<Self> {
        let BoringQuicOptions {
            alpn_wire,
            skip_cert_verify,
            chrome,
            ech,
            pin_sha256,
            ticket_key,
        } = options;
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        // QUIC mandates TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        if let Some(pin) = pin_sha256 {
            // pinSHA256: fingerprint check replaces PKI + hostname checks.
            builder.set_custom_verify_callback(
                SslVerifyMode::PEER,
                crate::tls::pin_sha256_custom_verify(pin),
            );
        } else if skip_cert_verify {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            builder.set_verify_cert_store(crate::tls::root_store()?)?;
        }
        if chrome {
            crate::tls::apply_chrome_ctx(&mut builder)?;
        }
        // Client-side TLS 1.3 session ticket cache: a repeat connection to
        // the same server can resume (and offer 0-RTT early data when the
        // server accepts it). BoringSSL has no implicit internal cache —
        // sessions are stored only when new_session_cb inserts them.
        unsafe {
            boring_sys::SSL_CTX_set_session_cache_mode(
                builder.as_ptr(),
                boring_sys::SSL_SESS_CACHE_CLIENT,
            );
            boring_sys::SSL_CTX_sess_set_new_cb(builder.as_ptr(), Some(on_new_session_cb));
        }

        Ok(Self {
            ctx: builder.build(),
            alpn_wire,
            chrome,
            ech,
            has_pin: pin_sha256.is_some(),
            ticket_key,
        })
    }
}

impl crypto::ClientConfig for BoringQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        // QUIC v1 only (0xff000021/0xff000022 are v1-compatible drafts).
        if version != 0x0000_0001 && !(0xff00_0021..=0xff00_0022).contains(&version) {
            return Err(ConnectError::UnsupportedVersion);
        }

        let mut ssl = Ssl::new(&self.ctx).expect("SSL_new failed");
        // Offer 0-RTT early data on resumed connections; whether any early
        // payload is actually sent is quinn's decision (into_0rtt), and
        // servers that ignore the offer are unaffected.
        unsafe { boring_sys::SSL_set_early_data_enabled(ssl.as_ptr(), 1) };
        ssl.set_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;
        // The hostname is also the client session-cache key — set it even
        // with verification off, or resumption can never hit.
        let cache_name = std::ffi::CString::new(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;
        let ok = unsafe { boring_sys::SSL_set1_host(ssl.as_ptr(), cache_name.as_ptr()) };
        if ok != 1 {
            return Err(ConnectError::InvalidServerName(server_name.into()));
        }
        // Resume a cached ticket when we have one for this server (PSK
        // handshake; the server may additionally accept 0-RTT early data).
        // pinSHA256 nodes never resume: PSK skips certificate verification,
        // so a ticket cached under a non-pin config would bypass the pin.
        // The key is recorded so a rejected ticket can be evicted — a stale
        // ticket (server restart, different server behind the same SNI, or
        // a session minted under a pre-reload SSL_CTX) must not poison every
        // subsequent dial until process restart.
        let mut resume_key = None;
        let lookup_key = self
            .ticket_key
            .clone()
            .unwrap_or_else(|| server_name.to_string());
        if !self.has_pin
            && let Some(&session) = SESSION_TICKETS.lock().get(&lookup_key)
        {
            unsafe {
                boring_sys::SSL_set_session(ssl.as_ptr(), session as *mut boring_sys::SSL_SESSION)
            };
            // Remember the exact entry offered so a failure evicts it only
            // if it is still the current one.
            resume_key = Some((lookup_key, session));
            tracing::debug!(server_name, "QUIC TLS: offering cached session ticket");
        }
        ssl.set_alpn_protos(&self.alpn_wire)
            .expect("invalid ALPN wire format");

        if self.chrome {
            ssl.set_permute_extensions(true);
            crate::tls::set_chrome_key_shares_ssl_ref(&ssl).expect("SSL_set1_client_key_shares");
        }
        // ECH is resolved per-connection from the TTL cache so key rotation
        // reaches later connections on a long-lived runtime. On a miss, a
        // background refill is triggered; this connection proceeds without
        // ECH (GREASE in Chrome mode) rather than blocking the handshake.
        let ech = match &self.ech {
            Some(crate::ech_doh::Ech::Static(list)) => Some(list.clone()),
            Some(crate::ech_doh::Ech::Source(source)) => {
                match crate::ech_doh::cached_ech_config(source) {
                    Some(config) => Some(config),
                    None => {
                        crate::ech_doh::spawn_ech_refresh(source.clone());
                        None
                    }
                }
            }
            // QUIC pins `DiscoverSni` to a concrete domain at build time.
            Some(crate::ech_doh::Ech::DiscoverSni) => None,
            None => None,
        };
        match ech {
            Some(list) => ssl
                .set_ech_config_list(&list)
                .expect("invalid ECHConfigList"),
            None if self.chrome => ssl.set_enable_ech_grease(true),
            None => {}
        }

        let ok = unsafe { boring_sys::SSL_set_quic_method(ssl.as_ptr(), &QUIC_METHOD) };
        assert_eq!(ok, 1, "SSL_set_quic_method");

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);
        let ok = unsafe {
            boring_sys::SSL_set_quic_transport_params(
                ssl.as_ptr(),
                transport_params.as_ptr(),
                transport_params.len(),
            )
        };
        assert_eq!(ok, 1, "SSL_set_quic_transport_params");

        let state = Box::new(QuicCryptoState {
            allow_resumption: !self.has_pin,
            ticket_key: self.ticket_key.clone(),
            ..Default::default()
        });
        let ok = unsafe {
            boring_sys::SSL_set_ex_data(
                ssl.as_ptr(),
                *EX_DATA_INDEX,
                (&*state as *const QuicCryptoState)
                    .cast_mut()
                    .cast::<c_void>(),
            )
        };
        assert_eq!(ok, 1, "SSL_set_ex_data");

        unsafe { boring_sys::SSL_set_connect_state(ssl.as_ptr()) };

        Ok(Box::new(BoringQuicSession {
            ssl,
            state,
            reported_level: LEVEL_INITIAL,
            got_handshake_data: false,
            driven: false,
            cur_1rtt: None,
            resume_key,
        }))
    }
}

/// Handshake data exposed to quinn consumers (ALPN only; no honk consumer
/// downcasts further).
pub struct BoringHandshakeData {
    /// Negotiated ALPN protocol, if any.
    pub protocol: Option<Vec<u8>>,
    /// Negotiated TLS 1.3 cipher suite id (RFC 8446 §B.4).
    pub cipher_suite: u16,
    /// Whether this handshake resumed a cached session (PSK).
    pub session_reused: bool,
    /// Whether the server accepted 0-RTT early data on this connection.
    pub early_data_accepted: bool,
}

/// quinn `crypto::Session` over a BoringSSL QUIC client handshake.
struct BoringQuicSession {
    ssl: Ssl,
    state: Box<QuicCryptoState>,
    /// Highest level whose keys quinn has been given (mirrors quinn's
    /// `highest_space`): INITIAL → HANDSHAKE → APPLICATION.
    reported_level: usize,
    got_handshake_data: bool,
    /// Whether `SSL_do_handshake` has been driven at least once.
    driven: bool,
    /// Current 1-RTT (read, write) secrets for key updates.
    cur_1rtt: Option<(TrafficSecrets, TrafficSecrets)>,
    /// Hostname whose cached ticket was offered on this handshake, plus the
    /// offered session — evicted on failure only if still current.
    resume_key: Option<(String, usize)>,
}

impl BoringQuicSession {
    /// Drive `SSL_do_handshake`; errors are mapped onto quinn transport
    /// errors, preferring the alert code captured by `send_alert`.
    fn drive_handshake(&mut self) -> Result<(), TransportError> {
        // One call processes all buffered CRYPTO data; WANT_READ just means
        // "feed me more", which arrives via the next read_handshake.
        let ret = unsafe { boring_sys::SSL_do_handshake(self.ssl.as_ptr()) };
        if ret == 1 {
            // `SSL_in_init` is authoritative (BoringSSL mock parity): a
            // resumed handshake can return 1 here while still in init.
            self.state.handshake_complete =
                unsafe { boring_sys::SSL_in_init(self.ssl.as_ptr()) } == 0;
            return Ok(());
        }
        let code = unsafe { boring_sys::SSL_get_error(self.ssl.as_ptr(), ret) };
        if code as u32 == boring_sys::SSL_ERROR_WANT_READ as u32 {
            return Ok(());
        }
        if code as u32 == boring_sys::SSL_ERROR_EARLY_DATA_REJECTED as u32 {
            // The server rejected 0-RTT (every official server does): reset
            // and continue the handshake without early data — the BoringSSL
            // contract (ssl.h:3362), not a ticket rejection.
            unsafe { boring_sys::SSL_reset_early_data_reject(self.ssl.as_ptr()) };
            return self.drive_handshake();
        }
        // Read the error queue exactly once (OpenSSL drains it per read):
        // reuse the same stack for the debug dump and the final reason.
        let stack = ErrorStack::get();
        let reason = stack.to_string();
        for e in stack.errors() {
            tracing::debug!(
                file = e.file(),
                line = e.line(),
                library = e.library(),
                reason = e.reason(),
                "QUIC TLS handshake error queue entry"
            );
        }
        // The cached ticket was rejected (server restart, a different server
        // behind the same SNI, or a session minted under a pre-reload
        // SSL_CTX). Evict ONLY if the entry is still the session we offered
        // — a concurrent connection may already have cached a fresh one,
        // and deleting that would repeat the failure once more.
        if let Some((key, offered)) = self.resume_key.take() {
            tracing::debug!(server_name = %key, error = %reason, "QUIC TLS: evicting rejected session ticket");
            SESSION_TICKETS.lock().remove_if_current(&key, offered);
        } else {
            tracing::debug!(error = %reason, "QUIC TLS: handshake failed with no ticket offered");
        }
        Err(self.fatal_error(&reason))
    }

    fn fatal_error(&self, reason: &str) -> TransportError {
        if let Some(alert) = self.state.alert {
            TransportError {
                code: TransportErrorCode::crypto(alert),
                frame: None,
                reason: format!("TLS alert {alert}: {reason}"),
            }
        } else {
            TransportError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame: None,
                reason: format!("TLS error: {reason}"),
            }
        }
    }

    /// Keys for the next packet space, once BoringSSL installed both
    /// directions of the next level.
    fn take_next_level_keys(&mut self) -> Option<Keys> {
        let next = match self.reported_level {
            LEVEL_INITIAL => LEVEL_HANDSHAKE,
            LEVEL_HANDSHAKE => LEVEL_APPLICATION,
            _ => return None,
        };
        if self.state.read_secrets[next].is_none() || self.state.write_secrets[next].is_none() {
            return None;
        }
        self.reported_level = next;
        let read = self.state.read_secrets[next]
            .clone()
            .expect("checked above");
        let write = self.state.write_secrets[next]
            .clone()
            .expect("checked above");
        if next == LEVEL_APPLICATION {
            self.cur_1rtt = Some((read.clone(), write.clone()));
        }
        Some(
            keys_from_secrets(&read, &write)
                .expect("key derivation from installed traffic secrets"),
        )
    }
}

impl Session for BoringQuicSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys_v1(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(BoringHandshakeData {
            protocol: self.ssl.selected_alpn_protocol().map(|p| p.to_vec()),
            cipher_suite: unsafe {
                let cipher = boring_sys::SSL_get_current_cipher(self.ssl.as_ptr());
                if cipher.is_null() {
                    0
                } else {
                    boring_sys::SSL_CIPHER_get_protocol_id(cipher)
                }
            },
            session_reused: unsafe { boring_sys::SSL_session_reused(self.ssl.as_ptr()) == 1 },
            early_data_accepted: unsafe {
                boring_sys::SSL_early_data_accepted(self.ssl.as_ptr()) == 1
            },
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // No honk consumer; skip building the cert chain.
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        // 0-RTT is not offered by the QUIC outbounds.
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        !self.state.handshake_complete
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if buf.is_empty() {
            return Ok(false);
        }
        let level = unsafe { boring_sys::SSL_quic_read_level(self.ssl.as_ptr()) };
        let ok = unsafe {
            boring_sys::SSL_provide_quic_data(self.ssl.as_ptr(), level, buf.as_ptr(), buf.len())
        };
        if ok != 1 {
            return Err(self.fatal_error("unexpected CRYPTO data at this level"));
        }

        // Branch on BoringSSL's own in-init state (its mock_quic_transport
        // does exactly this), not our flag: a resumed handshake can have
        // `SSL_do_handshake` return 1 while `SSL_in_init` is still true,
        // and calling `SSL_process_quic_post_handshake` then fails with
        // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED.
        if unsafe { boring_sys::SSL_in_init(self.ssl.as_ptr()) } == 1 {
            self.driven = true;
            self.drive_handshake()?;
        } else {
            let ok = unsafe { boring_sys::SSL_process_quic_post_handshake(self.ssl.as_ptr()) };
            if ok != 1 {
                for e in ErrorStack::get().errors() {
                    tracing::debug!(
                        file = e.file(),
                        line = e.line(),
                        library = e.library(),
                        reason = e.reason(),
                        "QUIC TLS post-handshake error queue entry"
                    );
                }
                return Err(self.fatal_error(&ErrorStack::get().to_string()));
            }
        }

        if !self.got_handshake_data
            && (self.ssl.selected_alpn_protocol().is_some() || !self.is_handshaking())
        {
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let mut data: *const u8 = ptr::null();
        let mut len: usize = 0;
        unsafe {
            boring_sys::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut data, &mut len);
        }
        if data.is_null() || len == 0 {
            return Ok(None);
        }
        let mut bytes: &[u8] = unsafe { std::slice::from_raw_parts(data, len) };
        TransportParameters::read(Side::Client, &mut bytes)
            .map(Some)
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        // The first write produces the ClientHello.
        if !self.driven {
            self.driven = true;
            // The first flight cannot fail meaningfully; real errors surface
            // through read_handshake.
            let _ = self.drive_handshake();
        }

        // Drain CRYPTO bytes for the level quinn currently occupies. New-level
        // bytes stay queued until quinn upgrades (it re-calls in a loop).
        let level = self.reported_level;
        let queued = std::mem::take(&mut self.state.outgoing[level]);
        buf.extend_from_slice(&queued);

        self.take_next_level_keys()
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let (read, write) = self.cur_1rtt.as_mut()?;
        let next_read = read.next_secret();
        let next_write = write.next_secret();
        *read = next_read;
        *write = next_write;
        Some(KeyPair {
            local: Box::new(BoringPacketKey::new(write).expect("key derivation from 1-RTT secret"))
                as Box<dyn PacketKey>,
            remote: Box::new(BoringPacketKey::new(read).expect("key derivation from 1-RTT secret"))
                as Box<dyn PacketKey>,
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        // RFC 9001 §5.8 retry integrity tag: AES-128-GCM over the pseudo-packet.
        let Some(tag_start) = payload.len().checked_sub(16) else {
            return false;
        };
        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        let Ok(ctx) =
            AeadCtx::new_default_tag(&AeadAlgorithm::aes_128_gcm(), &RETRY_INTEGRITY_KEY_V1)
        else {
            return false;
        };
        ctx.open_in_place(&RETRY_INTEGRITY_NONCE_V1, &mut [], tag, aad)
            .is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let ok = unsafe {
            boring_sys::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr().cast(),
                output.len(),
                label.as_ptr().cast(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if ok == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}

#[cfg(test)]
mod tests;
