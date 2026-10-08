//! BoringSSL TLS client with native and Chrome-oriented profiles plus ECH.
//!
//! The emulation configures GREASE, permuted extensions, hybrid key shares,
//! ALPS and certificate compression; it does not promise exact browser identity.
//!
//! ECH: when a node carries an ECHConfigList (`ech_config` / `ech_config_path`)
//! the connector offers real ECH via `SSL_set1_ech_config_list`;
//! `ech=<qname>+<doh-url>` fetches the list for `qname`'s HTTPS record from
//! the given DoH endpoint ([`crate::ech_doh`]); a bare `ech=<qname>` and
//! `ech_enabled` without either trigger DNS HTTPS-RR discovery (RFC 9460)
//! at connect time; without any of these, Chrome mode sends ECH GREASE like
//! a real browser.
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

use crate::ech_doh::{Ech, EchSource};

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
    pending_error: Option<io::Error>,
}

impl<S> BatchRead<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending_error: None,
        }
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
            if let Some(error) = self.pending_error.take() {
                return Poll::Ready(Err(error));
            }
            let before = buf.filled().len();
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == before {
                        return Poll::Ready(Ok(())); // EOF: deliver what we have
                    }
                }
                Poll::Ready(Err(error)) => {
                    if buf.filled().len() > start {
                        self.pending_error = Some(error);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(error));
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
    /// ECH origin, resolved once at build time. `None` means no ECH.
    ech: Option<Ech>,
}

impl TlsConnector {
    /// Per-connection `Ssl` configuration: applies the parts of the Chrome
    /// profile that only exist per-SSL (permuted extensions, key shares,
    /// ALPS, ECH) — BoringSSL has no ctx-level API for these.
    fn configuration(&self, ech: Option<Arc<[u8]>>) -> anyhow::Result<ConnectConfiguration> {
        let mut cfg = self.connector.configure()?;
        if self.chrome {
            cfg.set_permute_extensions(true);
            set_chrome_key_shares_ssl_ref(&cfg)?;
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
        let (ech, source) = match &self.ech {
            Some(Ech::Static(list)) => (Some(list.clone()), None),
            Some(Ech::Source(source)) => (
                crate::ech_doh::ech_config(source).await,
                Some(source.clone()),
            ),
            Some(Ech::DiscoverSni) => {
                let source = EchSource::Discover(domain.to_string());
                (crate::ech_doh::ech_config(&source).await, Some(source))
            }
            None => (None, None),
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
                    && let Some(retry) = ssl.get_ech_retry_configs()
                    && let Some(source) = source
                {
                    tracing::info!(
                        sni = domain,
                        "ECH rejected; publishing server retry configs for next dial"
                    );
                    crate::ech_doh::publish_ech_config(&source, retry.to_vec());
                }
                Err(anyhow::anyhow!("TLS handshake with {domain} failed: {e}"))
            }
        }
    }
}

/// Chrome sends X25519MLKEM768 and X25519 key shares, in that order.
/// BoringSSL exposes this only through FFI.
pub(crate) fn set_chrome_key_shares_ssl_ref(ssl: &boring::ssl::SslRef) -> anyhow::Result<()> {
    let shares = [SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519];
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get()).context("SSL_set1_client_key_shares");
    }
    Ok(())
}

/// Add h2 ALPS using the historical 0x4469 codepoint. The current uTLS
/// Chrome_133 profile uses 0x44cd; this compatibility choice is not parity.
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

/// Discover a domain's ECHConfigList via DNS HTTPS records (RFC 9460).
/// Thin wrapper over the unified ECH cache for external tools.
pub async fn discover_ech_config(domain: &str) -> Option<Vec<u8>> {
    crate::ech_doh::ech_config(&crate::ech_doh::EchSource::Discover(domain.to_string()))
        .await
        .map(|arc| arc.to_vec())
}

/// Resolve the node's static ECHConfigList, if any. Explicit `ech_config`
/// wins over `ech_config_path`. Dynamic sources (`ech_enabled`,
/// `ech=<qname>[+<doh-url>]`) are resolved separately via
/// [`crate::ech_doh::Ech`].
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
    if node.tls().is_some_and(|tls| !tls.alpn.is_empty()) {
        node.validate_protocol()?;
    }
    load_ech_config_list(node)?;
    crate::ech_doh::parse_node_ech_source(node)?;
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

/// Build the shared BoringSSL trust and protocol defaults.
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
    let tls = node.tls().ok_or_else(|| {
        anyhow::anyhow!(
            "internal configuration error: node '{}' protocol '{}' has no TLS options",
            node.name,
            node.protocol().as_str()
        )
    })?;
    let chrome = chrome_mode();
    let ech = crate::ech_doh::Ech::resolve(node)?;

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
    let custom_alpn = if tls.alpn.is_empty() {
        None
    } else {
        node.validate_protocol()?;
        let mut wire = Vec::with_capacity(tls.alpn.iter().map(|proto| 1 + proto.len()).sum());
        for proto in &tls.alpn {
            wire.push(proto.len() as u8);
            wire.extend_from_slice(proto.as_bytes());
        }
        Some(wire)
    };
    let websocket = node
        .transport()
        .is_some_and(|transport| transport.transport == "ws");
    let alps = chrome
        && if tls.alpn.is_empty() {
            !websocket
        } else {
            tls.alpn.iter().any(|protocol| protocol == "h2")
        };
    let default_alpn = if node
        .transport()
        .is_some_and(|transport| matches!(transport.transport.as_str(), "grpc" | "xhttp"))
    {
        Some(b"\x02h2".as_slice())
    } else {
        chrome.then_some(if websocket {
            HTTP11_ALPN_WIRE
        } else {
            CHROME_ALPN_WIRE
        })
    };
    let alpn_wire = custom_alpn.as_deref().or(default_alpn);
    let mut builder = base_builder(tls.skip_cert_verify || pin.is_some())?;
    if let Some(pin) = pin {
        builder.set_custom_verify_callback(SslVerifyMode::PEER, pin_sha256_custom_verify(pin));
    }
    if chrome {
        apply_chrome_ctx(&mut builder)?;
    }
    if let Some(alpn_wire) = alpn_wire {
        builder.set_alpn_protos(alpn_wire)?;
    }

    Ok(TlsConnector {
        connector: builder.build(),
        chrome,
        alps,
        ech,
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
        ech: None,
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
mod tests;

#[cfg(test)]
mod pin_tests;

#[cfg(test)]
mod batch_read_tests;

/// REALITY's TLS-1.3-only connector; authentication runs post-handshake in
/// `reality::verify_server_certificate`. Chrome mode configures the ctx-level
/// emulation fields. REALITY callers never restore a cached SSL session.
pub fn build_reality_connector(chrome: bool) -> anyhow::Result<SslConnector> {
    let mut builder = base_builder(true)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    if chrome {
        apply_chrome_ctx(&mut builder)?;
        builder.set_cipher_list(CHROME_CIPHER_LIST)?;
        builder.set_alpn_protos(CHROME_ALPN_WIRE)?;
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
    }
    Ok(builder.build())
}
