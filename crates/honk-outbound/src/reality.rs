//! REALITY client handshake for VLESS+REALITY (xtls-rprx-vision) outbounds.
//!
//! Byte layout and key schedule follow Xray-core
//! `transport/internet/reality/reality.go`: the ephemeral X25519 private key
//! is preset into the ClientHello key_share (patched BoringSSL hook), and
//! the legacy session_id carries
//! `AES-256-GCM(authKey).Seal(version | 0x00 | timestamp | short_id)` where
//! `authKey = HKDF-SHA256(shared, salt = client_random[..20], "REALITY")`
//! and the AAD is the whole ClientHello with the session_id slot zeroed.
//!
//! Server authentication replaces PKI (which the mask target would always
//! fail): a genuine REALITY server presents an ephemeral ed25519
//! certificate whose signature equals
//! `HMAC-SHA512(authKey, ed25519_raw_public_key)`. Anything else — notably a
//! real certificate relayed from the mask target when our session_id did
//! not decrypt — is a hard failure, never a downgrade.

use std::ffi::c_void;
use std::os::raw::{c_int, c_long};
use std::sync::LazyLock;

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose;
use boring::error::ErrorStack;
use boring::pkey::Id;
use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use honk_config::node::Node;
use sha2::{Sha256, Sha512};

use crate::tls::TlsStream;

const SSL_GROUP_X25519: u16 = 29;
const HKDF_INFO: &[u8] = b"REALITY";
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

/// Parsed REALITY handshake parameters for one node.
#[derive(Clone, Debug)]
pub struct RealityConfig {
    /// Server's X25519 public key (share-link `pbk`, base64url-decoded).
    pub public_key: [u8; 32],
    /// Share-link `sid`, right-zero-padded to 8 bytes.
    pub short_id: [u8; 8],
    /// SNI sent in the ClientHello (`node.sni`, falling back to the host).
    pub server_name: String,
}

/// REALITY parameters from a node, or `None` when the node is not REALITY.
///
/// Like pinSHA256, these keys are security assertions: an unparseable
/// public key or short id fails closed instead of degrading the handshake.
pub fn parse_reality_config(node: &Node) -> anyhow::Result<Option<RealityConfig>> {
    let Some(tls) = node.tls() else {
        return Ok(None);
    };
    let Some(encoded) = tls
        .reality_public_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let public_key = decode_public_key(encoded).ok_or_else(|| {
        anyhow::anyhow!(
            "node '{}': invalid reality_public_key (expected a base64url 32-byte X25519 key)",
            node.name
        )
    })?;
    let short_id =
        parse_short_id(tls.reality_short_id.as_deref().unwrap_or("")).ok_or_else(|| {
            anyhow::anyhow!(
                "node '{}': invalid reality_short_id (expected even-length hex, at most 8 bytes)",
                node.name
            )
        })?;
    let server_name = tls
        .sni
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| node.host.clone());
    Ok(Some(RealityConfig {
        public_key,
        short_id,
        server_name,
    }))
}

/// TLS client handshake with a REALITY server over `stream`, including the
/// post-handshake ed25519 server authentication (fail-closed).
pub async fn reality_connect<S>(
    stream: S,
    config: &RealityConfig,
    chrome: bool,
) -> anyhow::Result<TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = crate::tls::build_reality_connector(chrome)?;
    let mut cfg = connector.configure()?;
    if chrome {
        cfg.set_permute_extensions(true);
        // Real Chrome GREASEs ECH whenever it holds no ECH keys.
        cfg.set_enable_ech_grease(true);
        crate::tls::add_chrome_alps(&mut cfg)?;
    }
    setup_reality_ssl(&cfg, config)?;
    let tls = tokio_boring::connect(cfg, &config.server_name, stream)
        .await
        .map_err(|e| {
            anyhow::anyhow!("REALITY handshake with {} failed: {e}", config.server_name)
        })?;
    let state = unsafe {
        boring_sys::SSL_get_ex_data(tls.ssl().as_ptr(), reality_ex_index())
            .cast::<RealityHandshake>()
    };
    anyhow::ensure!(
        !state.is_null(),
        "REALITY ClientHello fixup state missing (callback never ran?)"
    );
    let auth_key = unsafe { (*state).auth_key };
    verify_server_certificate(tls.ssl(), &auth_key)?;
    Ok(tls)
}

fn decode_public_key(encoded: &str) -> Option<[u8; 32]> {
    for engine in [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::STANDARD,
    ] {
        if let Ok(bytes) = engine.decode(encoded)
            && let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice())
        {
            return Some(key);
        }
    }
    None
}

/// Empty short id is valid (all zeros); anything else must be even-length
/// hex of at most 8 bytes, right-zero-padded.
fn parse_short_id(s: &str) -> Option<[u8; 8]> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || s.len() > 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate().take(s.len() / 2) {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Session id + auth key for one ClientHello. `aad` is the full handshake
/// message with the session_id slot already zeroed. Separated from the
/// callback so the byte-level construction stays unit-testable.
fn reality_session_id(
    eph_priv: &[u8; 32],
    server_pub: &[u8; 32],
    client_random: &[u8; 32],
    short_id: &[u8; 8],
    timestamp: u32,
    aad: &[u8],
) -> Option<([u8; 32], [u8; 32])> {
    let mut shared = [0u8; 32];
    let ok =
        unsafe { boring_sys::X25519(shared.as_mut_ptr(), eph_priv.as_ptr(), server_pub.as_ptr()) };
    if ok != 1 {
        return None;
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), &shared);
    let mut auth_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut auth_key).ok()?;

    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&[1, 3, 3]); // client version, reality.go
    plain[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plain[8..].copy_from_slice(short_id);

    let ctx =
        boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), &auth_key)
            .ok()?;
    let mut tag = [0u8; 16];
    ctx.seal_in_place(&client_random[20..32], &mut plain, &mut tag, aad)
        .ok()?;
    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(&plain);
    session_id[16..].copy_from_slice(&tag);
    Some((session_id, auth_key))
}

/// Per-connection state shared with the ClientHello fixup callback. Owned
/// by the SSL object via ex_data (`reality_state_free` drops it), so it
/// stays valid for a HelloRetryRequest second ClientHello without any
/// lifetime coupling to the async connect future.
struct RealityHandshake {
    eph_priv: [u8; 32],
    server_pub: [u8; 32],
    short_id: [u8; 8],
    auth_key: [u8; 32],
}

fn reality_ex_index() -> c_int {
    static INDEX: LazyLock<c_int> = LazyLock::new(|| unsafe {
        boring_sys::SSL_get_ex_new_index(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            None,
            Some(reality_state_free),
        )
    });
    *INDEX
}

unsafe extern "C" fn reality_state_free(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut boring_sys::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(ptr.cast::<RealityHandshake>()) });
    }
}

/// Rewrites the serialized ClientHello in place (patched BoringSSL hook,
/// see examples/reality_hook_spike.rs for the verified message layout):
/// [0..4] handshake header, [4..6] legacy_version, [6..38] client_random,
/// [38] session_id_len, [39..71] session_id. Returning 0 aborts the
/// handshake — a REALITY ClientHello must never go out unauthenticated.
extern "C" fn reality_fixup_cb(ssl: *mut boring_sys::SSL, msg: *mut u8, msg_len: usize) -> c_int {
    unsafe {
        let state = boring_sys::SSL_get_ex_data(ssl, reality_ex_index()).cast::<RealityHandshake>();
        if state.is_null() || msg.is_null() || msg_len < SESSION_ID_OFFSET + SESSION_ID_LEN {
            return 0;
        }
        let state = &mut *state;
        let msg = std::slice::from_raw_parts_mut(msg, msg_len);
        if msg[0] != 1 || msg[38] != SESSION_ID_LEN as u8 {
            return 0;
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&msg[6..38]);
        msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        match reality_session_id(
            &state.eph_priv,
            &state.server_pub,
            &client_random,
            &state.short_id,
            timestamp,
            msg,
        ) {
            Some((session_id, auth_key)) => {
                msg[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
                    .copy_from_slice(&session_id);
                state.auth_key = auth_key;
                1
            }
            None => 0,
        }
    }
}

fn setup_reality_ssl(ssl: &SslRef, config: &RealityConfig) -> anyhow::Result<()> {
    // The REALITY server's ephemeral certificate is ed25519, and BoringSSL
    // sanity-checks the leaf key type against the offered signature
    // algorithms even with verification disabled — Chrome's list has no
    // ed25519, so widen it per connection or the handshake dies with
    // WRONG_SIGNATURE_TYPE before authentication can even run. The ed25519
    // entry makes JA4_c differ from real Chrome; that is the price of a
    // BoringSSL client speaking REALITY at all, and is accepted.
    let sigalgs = c"ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
    let ok = unsafe { boring_sys::SSL_set1_sigalgs_list(ssl.as_ptr(), sigalgs.as_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_sigalgs_list");
    }
    let mut state = Box::new(RealityHandshake {
        eph_priv: [0u8; 32],
        server_pub: config.public_key,
        short_id: config.short_id,
        auth_key: [0u8; 32],
    });
    let ok = unsafe { boring_sys::RAND_bytes(state.eph_priv.as_mut_ptr(), state.eph_priv.len()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("RAND_bytes");
    }
    // Preset the ephemeral key so the key_share extension carries its public
    // half; the server reads it back out of the ClientHello.
    let ok = unsafe {
        boring_sys::SSL_set1_client_x25519_private_key(ssl.as_ptr(), state.eph_priv.as_ptr())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_x25519_private_key");
    }
    // X25519 only: the server scans key_share for X25519, and an MLKEM
    // hybrid share would bloat the ClientHello for nothing.
    let groups = c"X25519";
    let ok = unsafe { boring_sys::SSL_set1_groups_list(ssl.as_ptr(), groups.as_ptr()) };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_groups_list");
    }
    let shares = [SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    let ok = unsafe {
        boring_sys::SSL_set_ex_data(
            ssl.as_ptr(),
            reality_ex_index(),
            Box::into_raw(state).cast(),
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set_ex_data");
    }
    unsafe { boring_sys::SSL_set_client_hello_fixup_cb(ssl.as_ptr(), Some(reality_fixup_cb)) };
    Ok(())
}

/// REALITY server authentication: the leaf must be an ephemeral ed25519
/// certificate whose signature is HMAC-SHA512(authKey, raw public key).
/// A real certificate means the server relayed us to the mask target —
/// wrong key, MITM, or redirection — and is always fatal.
fn verify_server_certificate(ssl: &SslRef, auth_key: &[u8; 32]) -> anyhow::Result<()> {
    let cert = ssl
        .peer_certificate()
        .context("REALITY server presented no certificate")?;
    let pkey = cert.public_key()?;
    anyhow::ensure!(
        pkey.id() == Id::ED25519,
        "REALITY server presented a real certificate (potential MITM or redirection)"
    );
    let mut raw_pub = [0u8; 32];
    let raw_pub = pkey
        .raw_public_key(&mut raw_pub)
        .context("read ed25519 public key")?;
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(raw_pub);
    mac.verify_slice(cert.signature().as_slice()).map_err(|_| {
        anyhow::anyhow!("REALITY certificate authentication failed (potential MITM or redirection)")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Cross-checked against an independent Go stdlib implementation
    /// (crypto/ecdh + crypto/hkdf + crypto/aes/cipher) of the reality.go
    /// key schedule.
    #[test]
    fn session_id_matches_reference_vector() {
        let eph_priv = [0x42u8; 32];
        let server_pub: [u8; 32] = general_purpose::URL_SAFE_NO_PAD
            .decode("ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518")
            .unwrap()
            .try_into()
            .unwrap();
        let mut client_random = [0u8; 32];
        for (i, b) in client_random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let short_id: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        // Fake ClientHello: header, legacy_version, random, sid_len=32,
        // zeroed session_id slot, then arbitrary extension bytes.
        let mut msg = vec![0x01, 0x00, 0x00, 0x4d, 0x03, 0x03];
        msg.extend_from_slice(&client_random);
        msg.push(0x20);
        msg.extend_from_slice(&[0u8; 32]);
        msg.extend(0xa0u8..0xb0);

        let (session_id, auth_key) = reality_session_id(
            &eph_priv,
            &server_pub,
            &client_random,
            &short_id,
            1_754_300_000,
            &msg,
        )
        .unwrap();
        assert_eq!(
            auth_key.as_slice(),
            unhex("5becfd7970ef3964e9a57b8b5c5d45b6cb97644e88458e3c8d61f53e3ae4015e").as_slice()
        );
        assert_eq!(
            session_id.as_slice(),
            unhex("7cfcdadbd3a5640bceef2afc7951caf671f7a737b2ba3f30eadb2d32148c542d").as_slice()
        );
    }

    /// AAD covers the zeroed session_id slot: mutating any covered byte
    /// must change the seal.
    #[test]
    fn session_id_binds_full_client_hello() {
        let eph_priv = [0x42u8; 32];
        let server_pub = [0x07u8; 32];
        let client_random = [0x33u8; 32];
        let short_id = [0u8; 8];
        let mut msg = vec![0x01, 0x00, 0x00, 0x4d, 0x03, 0x03];
        msg.extend_from_slice(&client_random);
        msg.push(0x20);
        msg.extend_from_slice(&[0u8; 32]);
        msg.extend(0xa0u8..0xb0);
        let (sid_a, _) =
            reality_session_id(&eph_priv, &server_pub, &client_random, &short_id, 1, &msg).unwrap();
        msg[80] ^= 1;
        let (sid_b, _) =
            reality_session_id(&eph_priv, &server_pub, &client_random, &short_id, 1, &msg).unwrap();
        assert_ne!(sid_a, sid_b);
    }

    #[test]
    fn short_id_boundaries() {
        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
        assert_eq!(parse_short_id("ab").unwrap(), [0xab, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            parse_short_id("a1b2c3d4e5f60718").unwrap(),
            [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]
        );
        assert!(parse_short_id("A1B2").is_some(), "uppercase hex is valid");
        assert!(parse_short_id("abc").is_none(), "odd-length hex");
        assert!(
            parse_short_id("a1b2c3d4e5f6071890").is_none(),
            "over 8 bytes"
        );
        assert!(parse_short_id("zz").is_none(), "non-hex");
    }

    #[test]
    fn public_key_decode_variants() {
        let lab = decode_public_key("ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518");
        assert!(lab.is_some());
        let raw = [0x11u8; 32];
        assert_eq!(
            decode_public_key(&general_purpose::URL_SAFE.encode(raw)).unwrap(),
            raw
        );
        assert_eq!(
            decode_public_key(&general_purpose::STANDARD.encode(raw)).unwrap(),
            raw
        );
        assert!(decode_public_key("dG9vLXNob3J0").is_none(), "wrong length");
        assert!(decode_public_key("!!!").is_none());
    }

    fn reality_node() -> Node {
        Node {
            outbound: honk_config::node::OutboundConfig::Vless(Default::default()),
            ..Default::default()
        }
    }

    #[test]
    fn parse_config_none_without_public_key() {
        let node = reality_node();
        assert!(parse_reality_config(&node).unwrap().is_none());
    }

    #[test]
    fn parse_config_sni_fallback_and_errors() {
        let mut node = reality_node();
        node.name = "r".into();
        node.host = "203.0.113.9".into();
        let tls = node.tls_mut().unwrap();
        tls.reality_public_key = Some("ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518".into());
        tls.reality_short_id = Some("a1b2".into());
        let cfg = parse_reality_config(&node).unwrap().unwrap();
        assert_eq!(cfg.server_name, "203.0.113.9", "no sni: falls back to host");
        assert_eq!(cfg.short_id, [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);

        node.tls_mut().unwrap().sni = Some("dl.google.com".into());
        let cfg = parse_reality_config(&node).unwrap().unwrap();
        assert_eq!(cfg.server_name, "dl.google.com");

        let mut bad = reality_node();
        bad.tls_mut().unwrap().reality_public_key = Some("not-a-key".into());
        assert!(
            parse_reality_config(&bad).is_err(),
            "bad key must fail closed"
        );

        let mut bad = reality_node();
        let tls = bad.tls_mut().unwrap();
        tls.reality_public_key = Some("ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518".into());
        tls.reality_short_id = Some("abc".into());
        assert!(
            parse_reality_config(&bad).is_err(),
            "bad sid must fail closed"
        );
    }
}
