//! BoringSSL TLS client — real Chrome fingerprint (uTLS-grade) + ECH.
//!
//! Why: a rustls ClientHello is trivially fingerprinted by DPI. BoringSSL is
//! what Chrome itself ships, so a properly configured BoringSSL ClientHello
//! matches Chrome's: GREASE, permuted extensions, the X25519MLKEM768 hybrid
//! key share, ALPS, brotli certificate compression, and ECH GREASE.
//!
//! ECH: when a node carries an ECHConfigList (`ech_config` / `ech_config_path`)
//! the connector offers real ECH via `SSL_set1_ech_config_list`; `ech_enabled`
//! without a static config triggers DNS HTTPS-RR discovery (RFC 9460) at
//! connect time; without either, Chrome mode sends ECH GREASE like a real
//! browser.
//!
//! Controlled by global config: tls_implementation ("tls"|"utls"), utls_imitate
//! (only the Chrome profile exists; other values warn and fall back).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use base64::Engine;
use base64::engine::general_purpose;
use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslContextBuilder, SslMethod, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use boring::x509::store::X509StoreBuilder;
use foreign_types::ForeignTypeRef;
use honk_config::node::Node;

/// TLS client stream produced by [`TlsConnector::connect`].
pub type TlsStream<S> = tokio_boring::SslStream<S>;

/// Greedy-read wrapper for TLS streams.
///
/// BoringSSL `SSL_read` returns at most one record (~16 KiB) per call, so
/// a relay loop with a larger buffer would otherwise run a full
/// read→write iteration per record. Drain the inner stream until the
/// caller's buffer is full or the inner stream pends, delivering one
/// batch per wakeup. Writes pass through unchanged.
#[derive(Debug)]
pub struct BatchRead<S> {
    inner: S,
}

impl<S> BatchRead<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BatchRead<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        let start = buf.filled().len();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let before = buf.filled().len();
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        return Poll::Ready(Ok(())); // EOF: deliver what we have
                    }
                }
                Poll::Ready(Err(e)) => {
                    return if buf.filled().len() > start {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(e))
                    };
                }
                Poll::Pending => {
                    return if buf.filled().len() > start {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BatchRead<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

// Chrome's TLS 1.3 signature-algorithm list (order matters).
pub(crate) const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
     ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
     rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
// Chrome 131+: MLKEM hybrid first. Requires boring's `mlkem` feature.
pub(crate) const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";
pub(crate) const CHROME_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";
const HTTP11_ALPN_WIRE: &[u8] = b"\x08http/1.1";

/// Chrome's TLS 1.2 cipher list (TLS 1.3 ciphers are implicit and always
/// lead). Order is irrelevant to JA4 (it sorts), the set is not.
pub(crate) const CHROME_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
     ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
     ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
     ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
     AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

// BoringSSL group IDs (ssl.h) for SSL_set1_client_key_shares: Chrome sends
// exactly two shares, MLKEM hybrid then X25519.
const SSL_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const SSL_GROUP_X25519: u16 = 29;

/// Brotli certificate-compression algorithm (RFC 8879), as advertised by Chrome.
pub(crate) struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        // write_all + drop finalizes the brotli stream (same pattern as
        // boring's own cert-compression tests).
        let mut writer = brotli::CompressorWriter::new(output, 4096, 5, 22);
        io::Write::write_all(&mut writer, input)
    }

    fn decompress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut reader = brotli::Decompressor::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }
}

/// BoringSSL connector carrying per-node ECH settings and the global
/// fingerprint mode. Clone-cheap (Arc inside); build once per node.
#[derive(Clone, Debug)]
pub struct TlsConnector {
    connector: SslConnector,
    chrome: bool,
    alps: bool,
    ech_config_list: Option<Arc<Vec<u8>>>,
    /// `ech_enabled` without a static config: discover via DNS HTTPS RR at
    /// connect time (best-effort, fail-open).
    ech_discovery: bool,
}

impl TlsConnector {
    /// Per-connection `Ssl` configuration: applies the parts of the Chrome
    /// profile that only exist per-SSL (permuted extensions, key shares,
    /// ALPS, ECH) — BoringSSL has no ctx-level API for these.
    fn configuration(&self, ech: Option<Arc<Vec<u8>>>) -> anyhow::Result<ConnectConfiguration> {
        let mut cfg = self.connector.configure()?;
        if self.chrome {
            cfg.set_permute_extensions(true);
            set_chrome_key_shares(&mut cfg)?;
            if self.alps {
                add_chrome_alps(&mut cfg)?;
            }
        }
        match ech {
            Some(list) => cfg.set_ech_config_list(&list)?,
            // Real Chrome always GREASEs ECH when it holds no ECH keys.
            None if self.chrome => cfg.set_enable_ech_grease(true),
            None => {}
        }
        Ok(cfg)
    }

    /// TLS client handshake over `stream`, verifying the peer against
    /// `domain` (unless the node skips verification).
    pub async fn connect<S>(&self, domain: &str, stream: S) -> anyhow::Result<TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let ech = match &self.ech_config_list {
            Some(list) => Some(list.clone()),
            None if self.ech_discovery => discover_ech_config(domain).await.map(Arc::new),
            None => None,
        };
        let cfg = self.configuration(ech.clone())?;
        match tokio_boring::connect(cfg, domain, stream).await {
            Ok(stream) => {
                if ech.is_some() {
                    tracing::debug!(
                        ech_accepted = stream.ssl().ech_accepted(),
                        sni = domain,
                        "TLS handshake completed"
                    );
                }
                Ok(stream)
            }
            Err(e) => {
                // ECH rejection: the server may hand us fresh retry configs.
                // NB: SSL_get0_ech_retry_configs asserts unless the failure
                // reason really is ECH_REJECTED — gate on the error text.
                let rejected = e.to_string().contains("ECH_REJECTED");
                if rejected
                    && let Some(ssl) = e.ssl()
                    && ssl.get_ech_retry_configs().is_some()
                {
                    tracing::info!(
                        sni = domain,
                        "ECH rejected; server offered retry ECH configs (not persisted)"
                    );
                }
                Err(anyhow::anyhow!("TLS handshake with {domain} failed: {e}"))
            }
        }
    }

    /// Underlying BoringSSL connector (for QUIC-side reuse of the ctx).
    pub fn boring_connector(&self) -> &SslConnector {
        &self.connector
    }
}

/// Chrome sends two key shares: X25519MLKEM768 and X25519, in that order.
/// boring exposes this only via FFI.
fn set_chrome_key_shares(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    set_chrome_key_shares_ssl_ref(ssl)
}

/// Same as [`set_chrome_key_shares`] for a bare `Ssl` (QUIC path).
pub(crate) fn set_chrome_key_shares_ssl(ssl: &boring::ssl::Ssl) -> anyhow::Result<()> {
    set_chrome_key_shares_ssl_ref(ssl)
}

fn set_chrome_key_shares_ssl_ref(ssl: &boring::ssl::SslRef) -> anyhow::Result<()> {
    let shares = [SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    Ok(())
}

/// Chrome sends ALPS for h2 with an empty settings payload whenever ALPN
/// offers h2. boring exposes this only via FFI. Chrome uses the old ALPS
/// codepoint (0x4469) on TCP+h2; BoringSSL defaults to the new one (0x44cd),
/// which is JA4-distinguishable from real Chrome.
pub(crate) fn add_chrome_alps(cfg: &mut ConnectConfiguration) -> anyhow::Result<()> {
    let ssl: &boring::ssl::SslRef = cfg;
    let ok = unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 0);
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_add_application_settings");
    }
    Ok(())
}

/// Mozilla root CAs (full DER certs) loaded into a BoringSSL store.
///
/// The store is built once per process (~150 parsed certs, ~0.8 MiB) and
/// every caller gets a refcounted clone (`X509_STORE_up_ref`) — with a
/// per-node-per-probe-cycle call pattern, building it fresh each time would
/// pin hundreds of megabytes in connector caches.
pub(crate) fn root_store() -> Result<boring::x509::store::X509Store, ErrorStack> {
    static ROOT_STORE: LazyLock<Option<boring::x509::store::X509Store>> =
        LazyLock::new(|| build_root_store().ok());
    match &*ROOT_STORE {
        Some(store) => Ok(store.clone()),
        None => build_root_store(),
    }
}

fn build_root_store() -> Result<boring::x509::store::X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            builder.add_cert(cert)?;
        }
    }
    Ok(builder.build())
}

/// Decode a base64 ECHConfigList (standard or URL-safe, padded or not).
fn decode_ech_config_list(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = encoded.trim();
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::STANDARD_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("invalid base64 ECHConfigList")
}

/// Resolve the node's ECHConfigList, if any. Explicit `ech_config` wins over
/// `ech_config_path`. `ech_enabled` without configs is handled separately at
/// connect time via DNS HTTPS-RR discovery ([`discover_ech_config`]).
pub fn load_ech_config_list(node: &Node) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(tls) = node.tls() else {
        return Ok(None);
    };
    if let Some(encoded) = &tls.ech_config {
        return decode_ech_config_list(encoded)
            .map(Some)
            .with_context(|| format!("node {}: ech_config", node.name));
    }
    if let Some(path) = &tls.ech_config_path {
        let path = honk_config::paths::resolve_dependency_path(path);
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("node {}: read {}", node.name, path.display()))?;
        return decode_ech_config_list(&contents)
            .map(Some)
            .with_context(|| format!("node {}: ech_config_path", node.name));
    }
    Ok(None)
}
/// Validate fail-closed per-node TLS inputs without allocating an SSL_CTX or
/// root store. Runtime registries use this before publication; connectors are
/// built lazily when a node first enters the active working set.
pub fn validate_connector_config(node: &Node) -> anyhow::Result<()> {
    load_ech_config_list(node)?;
    if let Some(pin) = node.tls().and_then(|tls| tls.pin_sha256.as_deref())
        && parse_pin_sha256(pin).is_none()
    {
        anyhow::bail!(
            "node '{}': invalid tls_pin_sha256 (expected 64 hex chars)",
            node.name
        );
    }
    Ok(())
}

static USE_CHROME_TLS: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

/// Called from ControlPlane startup with GlobalConfig.tls_implementation.
pub fn set_tls_mode(implementation: &str) {
    let chrome = implementation.eq_ignore_ascii_case("utls");
    USE_CHROME_TLS.store(chrome, Ordering::Release);
    tracing::info!(
        "TLS mode: {} (Chrome fingerprint={})",
        implementation,
        chrome
    );
}

/// Called from ControlPlane startup with GlobalConfig.utls_imitate.
///
/// Only the Chrome profile exists today; any other requested value warns and
/// falls back to it (dae accepts `chrome*`/`firefox`/`safari`/... here).
pub fn set_utls_imitate(imitate: &str) {
    let requested = imitate.trim();
    if requested.is_empty() || requested.starts_with("chrome") {
        return;
    }
    tracing::warn!(
        "utls_imitate '{}' is not implemented; only the Chrome profile is available, using it",
        requested
    );
}

/// Chrome fingerprint active (global `tls_implementation: utls`).
pub fn chrome_mode() -> bool {
    USE_CHROME_TLS.load(Ordering::Acquire)
}

/// Process-wide cache for DNS-discovered ECHConfigLists (RFC 9460 HTTPS RR).
struct EchCacheEntry {
    config: Option<Vec<u8>>,
    expires: std::time::Instant,
}

static ECH_DISCOVERY_CACHE: LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, EchCacheEntry>>,
> = LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Discover a domain's ECHConfigList via DNS HTTPS records (RFC 9460),
/// cached per domain (positive: record TTL clamped to 60s..1d; negative:
/// 5 min). Best-effort and fail-open: any failure yields `None`, unlike
/// explicit `ech_config` which is fail-closed.
pub async fn discover_ech_config(domain: &str) -> Option<Vec<u8>> {
    let key = domain.trim_end_matches('.').to_ascii_lowercase();
    if key.is_empty() || key.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if let Some(hit) = ECH_DISCOVERY_CACHE.lock().unwrap().get(&key)
        && hit.expires > std::time::Instant::now()
    {
        return hit.config.clone();
    }
    let (config, ttl) = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::bootstrap::query_ech_config(&key),
    )
    .await
    {
        Ok(Ok(Some((ech, ttl)))) => (Some(ech), ttl.clamp(60, 86400)),
        _ => (None, 300),
    };
    if config.is_some() {
        tracing::debug!(domain = %key, "discovered ECH config via DNS HTTPS RR");
    }
    ECH_DISCOVERY_CACHE.lock().unwrap().insert(
        key,
        EchCacheEntry {
            config: config.clone(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(ttl as u64),
        },
    );
    config
}

/// Build the TLS connector for a node: BoringSSL with webpki roots,
/// optional real Chrome fingerprint, optional ECH.
fn base_builder(skip_cert_verify: bool) -> anyhow::Result<boring::ssl::SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    if skip_cert_verify {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_verify_cert_store(root_store()?)?;
    }
    Ok(builder)
}

/// Parse a `pinSHA256` value (hex, optionally colon-separated) into 32 bytes.
pub fn parse_pin_sha256(s: &str) -> Option<[u8; 32]> {
    let hex: String = s
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Custom verify callback matching the peer leaf certificate's SHA-256
/// against a configured pin (`pinSHA256` semantics: replaces PKI chain and
/// hostname verification entirely).
pub fn pin_sha256_custom_verify(
    pin: [u8; 32],
) -> impl Fn(&mut boring::ssl::SslRef) -> Result<(), boring::ssl::SslVerifyError> + Send + Sync + 'static
{
    move |ssl| {
        let matches = ssl
            .peer_certificate()
            .and_then(|cert| cert.digest(boring::hash::MessageDigest::sha256()).ok())
            .is_some_and(|digest| digest.as_ref() == pin);
        if matches {
            Ok(())
        } else {
            Err(boring::ssl::SslVerifyError::Invalid(
                boring::ssl::SslAlert::BAD_CERTIFICATE,
            ))
        }
    }
}

pub(crate) fn apply_chrome_ctx(builder: &mut SslContextBuilder) -> anyhow::Result<()> {
    builder.set_grease_enabled(true);
    builder.set_sigalgs_list(CHROME_SIGALGS)?;
    builder.set_curves_list(CHROME_CURVES)?;
    builder.add_certificate_compression_algorithm(BrotliCertCompression)?;
    Ok(())
}

pub fn build_connector(node: &Node) -> anyhow::Result<TlsConnector> {
    let chrome = chrome_mode();
    let ech_config_list = load_ech_config_list(node)?;
    let tls = node.tls().unwrap();

    let pin = match tls.pin_sha256.as_deref() {
        Some(s) => Some(parse_pin_sha256(s).ok_or_else(|| {
            // pinSHA256 is a security assertion: an unparseable pin
            // must fail closed, never degrade to plain PKI.
            anyhow::anyhow!(
                "node '{}': invalid tls_pin_sha256 (expected 64 hex chars)",
                node.name
            )
        })?),
        None => None,
    };
    let mut builder = base_builder(tls.skip_cert_verify || pin.is_some())?;
    if let Some(pin) = pin {
        builder.set_custom_verify_callback(SslVerifyMode::PEER, pin_sha256_custom_verify(pin));
    }
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_alpn_protos(
            if node
                .transport()
                .is_some_and(|transport| transport.transport == "ws")
            {
                HTTP11_ALPN_WIRE
            } else {
                CHROME_ALPN_WIRE
            },
        )?;
    }

    Ok(TlsConnector {
        connector: builder.build(),
        chrome,
        alps: chrome
            && !node
                .transport()
                .is_some_and(|transport| transport.transport == "ws"),
        ech_discovery: tls.ech_enabled && ech_config_list.is_none(),
        ech_config_list: ech_config_list.map(Arc::new),
    })
}

/// BoringSSL connector for DNS upstreams (DoT/DoH): caller-chosen ALPN,
/// webpki verification, the global Chrome fingerprint mode applies.
pub fn build_dns_connector(
    skip_cert_verify: bool,
    alpn_wire: &[u8],
) -> anyhow::Result<TlsConnector> {
    let chrome = chrome_mode();
    let mut builder = base_builder(skip_cert_verify)?;
    if chrome {
        apply_chrome_ctx(&mut builder)?;
    }
    builder.set_alpn_protos(alpn_wire)?;
    Ok(TlsConnector {
        connector: builder.build(),
        chrome,
        alps: chrome && alpn_wire.windows(3).any(|proto| proto == b"\x02h2"),
        ech_config_list: None,
        ech_discovery: false,
    })
}

/// ALPN wire offering HTTP/2 with HTTP/1.1 fallback (Chrome / Go-client
/// style: the server picks).
const PROBE_ALPN_WIRE: &[u8] = b"\x02h2\x08http/1.1";

/// Connector for urltest-style latency probes. Offers `h2,http/1.1` — the
/// probe dispatches on the negotiated protocol (HTTP/1.1 HEAD or a real H2
/// session), so h2-only and h2-preferring endpoints (gstatic & co.) work,
/// and in Chrome mode the offer matches the browser fingerprint anyway.
pub fn build_http_probe_connector(skip_cert_verify: bool) -> anyhow::Result<TlsConnector> {
    build_dns_connector(skip_cert_verify, PROBE_ALPN_WIRE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::pkey::PKey;

    #[test]
    fn root_store_clones_share_one_store() {
        use foreign_types::ForeignType;
        let a = root_store().unwrap();
        let b = root_store().unwrap();
        assert_eq!(a.as_ptr(), b.as_ptr());
    }
    use boring::ssl::{SslAcceptor, SslStream};
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    /// rcgen self-signed server cert (PEM) for loopback handshakes.
    fn server_cert() -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn spawn_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        (port, handle)
    }

    async fn loopback_connect(
        node: &Node,
        chrome: bool,
        port: u16,
    ) -> anyhow::Result<TlsStream<tokio::net::TcpStream>> {
        set_tls_mode(if chrome { "utls" } else { "tls" });
        let connector = build_connector(node)?;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        connector.connect("localhost", tcp).await
    }

    fn test_node() -> Node {
        Node {
            outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                tls: honk_config::node::TlsOptions {
                    skip_cert_verify: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn handshake_standard_and_chrome() {
        for chrome in [false, true] {
            let (cert, key) = server_cert();
            let (port, server) = spawn_server(&cert, &key);
            let mut stream = loopback_connect(&test_node(), chrome, port)
                .await
                .unwrap_or_else(|e| panic!("chrome={chrome}: {e:?}"));
            use tokio::io::AsyncWriteExt;
            stream.write_all(b"ping").await.unwrap();
            stream.shutdown().await.unwrap();
            let received = server.join().unwrap();
            assert_eq!(received, b"ping", "chrome={chrome}");
        }
    }

    #[tokio::test]
    async fn ech_grease_does_not_break_handshake() {
        // Chrome mode with no ECH config sends ECH GREASE; servers must ignore it.
        let (cert, key) = server_cert();
        let (port, server) = spawn_server(&cert, &key);
        let mut stream = loopback_connect(&test_node(), true, port).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(server.join().unwrap(), b"ok");
    }

    /// Spawn a server holding real ECH keys (boring test fixtures:
    /// public_name ech.com, DHKEM-P256-SHA256).
    fn spawn_ech_server(cert_pem: &str, key_pem: &str) -> (u16, thread::JoinHandle<Vec<u8>>) {
        use boring::hpke::HpkeKey;
        use boring::ssl::SslEchKeys;

        static ECH_CONFIG: &[u8] = include_bytes!("../tests/fixtures/echconfig");
        static ECH_KEY: &[u8] = include_bytes!("../tests/fixtures/echkey");

        // NB: boring's mozilla_intermediate/_modern set NO_TLSV1_3; ECH needs
        // TLS 1.3, so use the v5 profile (1.2+1.3) and pin 1.3.
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();

        let key = HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap();
        let mut ech_keys = SslEchKeys::builder().unwrap();
        ech_keys.add_key(true, ECH_CONFIG, key).unwrap();
        acceptor.set_ech_keys(&ech_keys.build()).unwrap();

        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).ok();
            buf
        });
        (port, handle)
    }

    /// Full ECH round-trip: client offers real ECH, server decrypts it,
    /// `ech_accepted()` must report true.
    #[tokio::test]
    async fn ech_accepted_end_to_end() {
        static ECH_CONFIG_LIST: &[u8] = include_bytes!("../tests/fixtures/echconfiglist");
        let mut node = test_node();
        let tls = node.tls_mut().unwrap();
        tls.ech_enabled = true;
        tls.ech_config = Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST));
        let (cert, key) = server_cert();
        let (port, server) = spawn_ech_server(&cert, &key);
        let mut stream = loopback_connect(&node, true, port).await.unwrap();
        assert!(stream.ssl().ech_accepted(), "ECH must be accepted");
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(server.join().unwrap(), b"ok");
    }

    /// Real ECH against a server with NO ECH keys fails closed
    /// (`ECH_REJECTED`): BoringSSL refuses to complete a handshake whose ECH
    /// offer was not confirmed, per RFC anti-downgrade rules. Proves the
    /// config list is actually parsed and offered.
    #[tokio::test]
    async fn ech_rejected_when_server_lacks_keys() {
        static ECH_CONFIG_LIST: &[u8] = include_bytes!("../tests/fixtures/echconfiglist");
        let mut node = test_node();
        let tls = node.tls_mut().unwrap();
        tls.ech_enabled = true;
        tls.ech_config = Some(general_purpose::STANDARD.encode(ECH_CONFIG_LIST));
        let (cert, key) = server_cert();
        let (port, _server) = spawn_server(&cert, &key);
        let err = loopback_connect(&node, true, port)
            .await
            .expect_err("handshake must fail when ECH is not accepted");
        let msg = format!("{err:?}");
        assert!(msg.contains("ECH_REJECTED"), "unexpected error: {msg}");
    }

    /// The urltest probe connector offers `h2,http/1.1` and honors the
    /// server's pick in both directions (the probe handles either).
    #[tokio::test]
    async fn probe_connector_negotiates_h2_and_http1() {
        use boring::ssl::AlpnError;

        fn spawn_alpn_server(cert_pem: &str, key_pem: &str, prefer_h2: bool) -> u16 {
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
                .unwrap();
            acceptor
                .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
                .unwrap();
            acceptor.set_alpn_select_callback(move |_ssl, protos| {
                let mut i = 0;
                let (mut h2, mut http11) = (None, None);
                while i < protos.len() {
                    let n = protos[i] as usize;
                    let p = &protos[i + 1..i + 1 + n];
                    if p == b"h2" {
                        h2 = Some(p);
                    }
                    if p == b"http/1.1" {
                        http11 = Some(p);
                    }
                    i += 1 + n;
                }
                if prefer_h2 {
                    h2.or(http11).ok_or(AlpnError::NOACK)
                } else {
                    // h1-only server: refuses anything else.
                    http11.ok_or(AlpnError::NOACK)
                }
            });
            let acceptor = acceptor.build();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut tls: SslStream<_> = acceptor.accept(stream).unwrap();
                let mut buf = Vec::new();
                tls.read_to_end(&mut buf).ok();
                buf
            });
            port
        }

        for chrome in [false, true] {
            set_tls_mode(if chrome { "utls" } else { "tls" });

            // h2-preferring server: probe must negotiate h2.
            let (cert, key) = server_cert();
            let port = spawn_alpn_server(&cert, &key, true);
            let connector = build_http_probe_connector(true).unwrap();
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let stream = connector.connect("localhost", tcp).await.unwrap();
            assert_eq!(
                stream.ssl().selected_alpn_protocol(),
                Some(b"h2".as_slice()),
                "chrome={chrome}: probe must take h2 when the server prefers it"
            );

            // h1-only server: probe must fall back to http/1.1.
            let (cert, key) = server_cert();
            let port = spawn_alpn_server(&cert, &key, false);
            let connector = build_http_probe_connector(true).unwrap();
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let stream = connector.connect("localhost", tcp).await.unwrap();
            assert_eq!(
                stream.ssl().selected_alpn_protocol(),
                Some(b"http/1.1".as_slice()),
                "chrome={chrome}: probe must fall back to http/1.1"
            );
        }
    }

    #[test]
    fn decode_ech_base64_variants() {
        let raw = b"\xff\x00abc";
        for encoded in [
            general_purpose::STANDARD.encode(raw),
            general_purpose::URL_SAFE.encode(raw),
            general_purpose::URL_SAFE_NO_PAD.encode(raw),
        ] {
            assert_eq!(decode_ech_config_list(&encoded).unwrap(), raw);
        }
        assert!(decode_ech_config_list("!!!not-base64!!!").is_err());
    }

    /// DNS response with one HTTPS answer carrying the given ech SvcParam
    /// (`None` → NODATA), for the discovery stub server.
    fn https_response(query: &[u8], ech: Option<&[u8]>, ttl: u32) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        let Some(ech) = ech else {
            resp[6] = 0;
            resp[7] = 0;
            return resp;
        };
        resp[6] = 0;
        resp[7] = 1;
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
        resp.extend_from_slice(&65u16.to_be_bytes()); // TYPE HTTPS
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        let mut rdata = vec![0, 1, 0]; // ServiceMode priority 1, root target name
        rdata.extend_from_slice(&5u16.to_be_bytes()); // SvcParam key ech
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        resp
    }

    /// Stub UDP DNS server answering every query with the canned HTTPS
    /// response, counting queries. Installed via the bootstrap resolver.
    async fn spawn_https_dns(
        ech: Option<Vec<u8>>,
        ttl: u32,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::AtomicUsize;
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, peer)) = server.recv_from(&mut buf).await {
                count2.fetch_add(1, Ordering::SeqCst);
                let resp = https_response(&buf[..n], ech.as_deref(), ttl);
                server.send_to(&resp, peer).await.ok();
            }
        });
        (addr, count)
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn discover_ech_config_caches_positive_and_negative() {
        use std::sync::atomic::Ordering as AOrd;
        let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();

        // Positive: two lookups for the same name cost one DNS query.
        let (addr, count) = spawn_https_dns(Some(b"\x00\x01ech-bytes".to_vec()), 120).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{addr}"
        )));
        let first = discover_ech_config("ech-pos-unique.test").await;
        let second = discover_ech_config("ech-pos-unique.test").await;
        assert_eq!(first.as_deref(), Some(b"\x00\x01ech-bytes".as_slice()));
        assert_eq!(second, first);
        assert_eq!(count.load(AOrd::SeqCst), 1, "second lookup must hit cache");

        // Negative: NODATA is cached too.
        let (addr, count) = spawn_https_dns(None, 120).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{addr}"
        )));
        assert_eq!(discover_ech_config("ech-neg-unique.test").await, None);
        assert_eq!(discover_ech_config("ech-neg-unique.test").await, None);
        assert_eq!(
            count.load(AOrd::SeqCst),
            1,
            "negative lookup must hit cache"
        );

        // IP literals never query.
        assert_eq!(discover_ech_config("203.0.113.7").await, None);
        crate::bootstrap::set_global(None);
    }

    /// End-to-end: `ech_enabled` with no static config discovers the
    /// ECHConfigList via DNS and completes a real ECH handshake.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn ech_discovery_end_to_end() {
        static ECH_CONFIG_LIST: &[u8] = include_bytes!("../tests/fixtures/echconfiglist");
        let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();

        let (addr, _count) = spawn_https_dns(Some(ECH_CONFIG_LIST.to_vec()), 300).await;
        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{addr}"
        )));
        let mut node = test_node();
        node.tls_mut().unwrap().ech_enabled = true;
        let (cert, key) = server_cert();
        let (port, server) = spawn_ech_server(&cert, &key);
        let mut stream = loopback_connect(&node, true, port).await.unwrap();
        assert!(
            stream.ssl().ech_accepted(),
            "ECH via DNS discovery must be accepted"
        );
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"ok").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(server.join().unwrap(), b"ok");
        crate::bootstrap::set_global(None);
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn parse_pin_sha256_variants() {
        let hex = "a".repeat(64);
        assert!(parse_pin_sha256(&hex).is_some());
        let colon = (0..32).map(|_| "ab").collect::<Vec<_>>().join(":");
        assert!(parse_pin_sha256(&colon).is_some());
        assert_eq!(parse_pin_sha256(&colon).unwrap(), [0xab; 32]);
        assert!(parse_pin_sha256("zz").is_none());
        assert!(parse_pin_sha256("abcd").is_none());
        // Uppercase hex is valid.
        assert!(parse_pin_sha256(&"AB".repeat(32)).is_some());
    }

    /// P0: an unparseable pinSHA256 must fail closed — never silently
    /// degrade to plain PKI.
    #[test]
    fn invalid_pin_fails_closed() {
        let mut node = Node {
            name: "pinned".into(),
            host: "example.com".into(),
            address: "example.com:443".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        node.tls_mut().unwrap().pin_sha256 = Some("not-a-pin".into());
        let err = build_connector(&node).unwrap_err();
        assert!(
            err.to_string().contains("invalid tls_pin_sha256"),
            "bad pin must be a hard error: {err}"
        );
    }
}

#[cfg(test)]
mod batch_read_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn drains_all_available_in_one_read() {
        let (mut w, r) = tokio::io::duplex(64);
        let mut s = BatchRead::new(r);
        w.write_all(&[1u8; 10]).await.unwrap();
        w.write_all(&[2u8; 20]).await.unwrap();
        // One read must coalesce both writes (a plain duplex read would
        // also return 30 here; the point is the wrapper never truncates
        // a wakeup's worth of data to the first inner read).
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 30);
        assert_eq!(&buf[..10], &[1u8; 10]);
        assert_eq!(&buf[10..30], &[2u8; 20]);
    }

    #[tokio::test]
    async fn eof_delivers_partial_then_zero() {
        let (mut w, r) = tokio::io::duplex(64);
        let mut s = BatchRead::new(r);
        w.write_all(&[7u8; 10]).await.unwrap();
        drop(w); // EOF
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 10, "buffered data must be delivered before EOF");
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn read_larger_than_inner_chunks() {
        // Simulate one-record-per-poll inner reads (TLS): cap each inner
        // poll at 8 bytes; the wrapper must still fill the big buffer.
        struct Chunked<R> {
            inner: R,
        }
        impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Chunked<R> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                let cap = buf.remaining().min(8);
                let (r, n) = {
                    let mut small = buf.take(cap);
                    let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut small);
                    (r, small.filled().len())
                };
                if r.is_ready() {
                    // SAFETY: `take` views the front of `buf`'s unfilled
                    // region; bytes it initialized are the front of ours.
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                }
                r
            }
        }
        let (mut w, r) = tokio::io::duplex(64);
        let mut s = BatchRead::new(Chunked { inner: r });
        for i in 0..4u8 {
            w.write_all(&[i; 8]).await.unwrap();
        }
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 32, "four 8-byte records must batch into one read");
        for i in 0..4usize {
            assert!(buf[i * 8..(i + 1) * 8].iter().all(|&b| b == i as u8));
        }
    }
}

/// REALITY connector: accept-all certificate verification (the real server
/// authentication runs post-handshake against the session-id auth key in
/// `reality::verify_server_certificate`). Chrome mode adds the pieces of
/// the real Chrome ClientHello the ctx controls: cipher list, ALPN,
/// OCSP stapling and SCT extensions. Session resumption stays impossible
/// because nothing ever calls `SSL_set_session` — the empty session_ticket
/// extension real Chrome sends is just an offer, never a resumption.
pub fn build_reality_connector(chrome: bool) -> anyhow::Result<SslConnector> {
    let mut builder = base_builder(true)?;
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_cipher_list(CHROME_CIPHER_LIST)?;
        builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
    }
    Ok(builder.build())
}
