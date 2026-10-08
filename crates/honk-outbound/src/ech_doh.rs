//! ECH config resolution: static, DNS discovery, or DoH.
//!
//! A node can carry `ech=<qname>+<doh-url>` in its share-link `ech`
//! parameter (e.g. `ech=cloudflare-ech.com+https://223.5.5.5/dns-query`):
//! the ECHConfigList is read from the `ech` SvcParam of `qname`'s HTTPS
//! record, fetched with a DNS-over-HTTPS POST to the given endpoint.
//! A bare `ech=<qname>` (no URL) resolves through the bootstrap DNS path
//! (`EchSource::Discover`), honoring the user's own resolver instead of a
//! hard-coded third party.
//!
//! Resolution is on-demand against a single TTL cache keyed by source.
//! A cache miss fetches inline with a bounded timeout — the first TLS dial
//! after (re)start therefore waits for the fetch instead of leaking the
//! SNI in cleartext — and fail-open past it. QUIC resolves per-connection
//! from the cache and triggers a background refill on a miss, so key
//! rotation reaches long-lived runtimes without blocking the handshake.
//! Static `ech_config`/`ech_config_path` still win over dynamic sources.
//!
//! Every socket here (DoH host resolution through the bootstrap resolver,
//! the TCP dial) carries the bypass mark, so honk's own eBPF datapath never
//! routes this host-originated traffic through a proxy — possibly the very
//! ECH node waiting for the config.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;

/// Per-stage budget inside a DoH fetch: TCP connect, TLS handshake and the
/// H2 exchange each get this long.
const ECH_DOH_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const ECH_DISCOVER_TIMEOUT: Duration = Duration::from_secs(3);
/// Cap on a DoH response body; an ECH answer is a few hundred bytes.
const ECH_DOH_MAX_BODY: usize = 64 * 1024;
/// TTL clamp for positive cache entries, and negative-cache lifetime.
const ECH_TTL_MIN: u32 = 60;
const ECH_TTL_MAX: u32 = 86400;
const ECH_NEGATIVE_TTL: u32 = 300;

/// A parsed DoH endpoint: host, port and path, computed once.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DohEndpoint {
    /// Without IPv6 brackets; `dial_addr` re-adds them.
    host: String,
    port: u16,
    /// Path plus query; a bare `/` falls back to `/dns-query`.
    path: String,
}

impl DohEndpoint {
    fn parse(url: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(url).context("invalid DoH URL")?;
        let bracketed = parsed.host_str().context("DoH URL has no host")?;
        let host = bracketed
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(bracketed)
            .to_string();
        let port = parsed
            .port_or_known_default()
            .context("DoH URL has no port")?;
        let mut path = parsed.path().to_string();
        if path.is_empty() || path == "/" {
            path = "/dns-query".to_string();
        }
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(Self { host, port, path })
    }

    /// `host:port` with IPv6 brackets, always explicit: `connect_marked`
    /// requires the port, and omitting 443 breaks its `rsplit_once(':')`
    /// parse (or splits inside a bracketed IPv6 literal).
    fn dial_addr(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Value for the `:authority` pseudo-header; the default port is omitted.
    fn authority(&self) -> String {
        let host = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// A DoH endpoint plus the HTTPS-RR owner name whose `ech` SvcParam
/// supplies the ECHConfigList.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct EchDohSource {
    /// Lowercased owner name, without a trailing dot.
    pub qname: String,
    /// The DoH endpoint URL as configured (`https://...`).
    pub url: String,
    /// Endpoint parsed once at construction.
    pub endpoint: DohEndpoint,
}

/// A dynamic ECH source: the cache key and the fetch transport.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum EchSource {
    /// HTTPS RR via the bootstrap resolver (bare `ech=<qname>` or
    /// `ech_enabled`); lowercased domain without a trailing dot.
    Discover(String),
    /// `ech=<qname>+<doh-url>`: DoH fetch from the explicit endpoint.
    Doh(EchDohSource),
}

/// Fully resolved ECH origin for a connector, decided once at build time.
#[derive(Clone, Debug)]
pub(crate) enum Ech {
    /// Static `ech_config`/`ech_config_path`.
    Static(Arc<[u8]>),
    /// Dynamic source; resolved against the TTL cache per dial/connection.
    Source(EchSource),
    /// `ech_enabled`: discover via the connect-time SNI. TLS resolves this
    /// in `connect`; QUIC resolves it at build time from the configured
    /// SNI or host.
    DiscoverSni,
}

impl Ech {
    /// Resolve a node's ECH origin once. Static config wins, then
    /// `ech=<qname>[+<doh-url>]`, then `ech_enabled`.
    pub(crate) fn resolve(node: &honk_config::node::Node) -> anyhow::Result<Option<Ech>> {
        if let Some(list) = crate::tls::load_ech_config_list(node)? {
            return Ok(Some(Ech::Static(list.into())));
        }
        if let Some(source) = parse_node_ech_source(node)? {
            return Ok(Some(Ech::Source(source)));
        }
        let enabled = node.tls().is_some_and(|tls| tls.ech_enabled);
        Ok(enabled.then_some(Ech::DiscoverSni))
    }
}

/// Parse a node's `ech` value once; `None` when the node carries none.
pub(crate) fn parse_node_ech_source(
    node: &honk_config::node::Node,
) -> anyhow::Result<Option<EchSource>> {
    node.tls()
        .and_then(|tls| tls.ech_doh.as_deref())
        .map(parse_ech_source)
        .transpose()
        .with_context(|| format!("node '{}': invalid ech source", node.name))
}

/// Parse a share-link `ech` value into its fetch source. Validation is the
/// strict honk-config parser, so config-time and outbound agree.
pub(crate) fn parse_ech_source(raw: &str) -> anyhow::Result<EchSource> {
    let parts = honk_config::node::TlsOptions::parse_ech_doh(raw)
        .map_err(|message| anyhow::anyhow!("invalid ech source {raw:?}: {message}"))?;
    match parts.url {
        Some(url) => Ok(EchSource::Doh(EchDohSource {
            qname: parts.qname,
            endpoint: DohEndpoint::parse(&url)?,
            url,
        })),
        None => Ok(EchSource::Discover(parts.qname)),
    }
}

struct EchCacheEntry {
    config: Option<Arc<[u8]>>,
    expires: Instant,
}

static ECH_CACHE: LazyLock<Mutex<HashMap<EchSource, EchCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_get(source: &EchSource) -> Option<Option<Arc<[u8]>>> {
    ECH_CACHE
        .lock()
        .unwrap()
        .get(source)
        .filter(|hit| hit.expires > Instant::now())
        .map(|hit| hit.config.clone())
}

fn cache_put(source: &EchSource, config: Option<Arc<[u8]>>, ttl: u32) {
    ECH_CACHE.lock().unwrap().insert(
        source.clone(),
        EchCacheEntry {
            config,
            expires: Instant::now() + Duration::from_secs(ttl as u64),
        },
    );
}

/// Fetch `(ECHConfigList, ttl)` for a source. `None` when the lookup
/// yields no ECH record; failures are `Err`.
type EchFetchFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<Option<(Vec<u8>, u32)>>> + Send + 'a>,
>;

fn fetch_source(source: &EchSource) -> EchFetchFuture<'_> {
    Box::pin(async move {
        match source {
            EchSource::Discover(domain) => {
                if domain.is_empty() || domain.parse::<std::net::IpAddr>().is_ok() {
                    return Ok(None);
                }
                let query = tokio::time::timeout(
                    ECH_DISCOVER_TIMEOUT,
                    crate::bootstrap::query_ech_config(domain),
                )
                .await
                .context("ECH discovery timed out")?;
                Ok(query?)
            }
            EchSource::Doh(doh) => Ok(Some(fetch_ech_via_doh(doh).await?)),
        }
    })
}

/// Resolve a source's ECHConfigList: cache hit, or a bounded inline fetch
/// on miss/expiry (fail-open). TLS dials call this; the first dial after
/// (re)start waits for the fetch instead of leaking the SNI.
pub(crate) async fn ech_config(source: &EchSource) -> Option<Arc<[u8]>> {
    if let Some(hit) = cache_get(source) {
        return hit;
    }
    match fetch_source(source).await {
        Ok(Some((config, ttl))) => {
            let config: Arc<[u8]> = config.into();
            tracing::debug!("resolved ECH config");
            cache_put(
                source,
                Some(config.clone()),
                ttl.clamp(ECH_TTL_MIN, ECH_TTL_MAX),
            );
            Some(config)
        }
        Ok(None) => {
            cache_put(source, None, ECH_NEGATIVE_TTL);
            None
        }
        Err(error) => {
            tracing::debug!(%error, "ECH fetch failed; proceeding without ECH");
            // Don't cache failures: the next dial retries.
            None
        }
    }
}

/// Synchronous cache read for per-connection resolution (QUIC
/// `start_session`). Returns `None` on miss/expiry; call
/// [`spawn_ech_refresh`] to refill in the background.
pub(crate) fn cached_ech_config(source: &EchSource) -> Option<Arc<[u8]>> {
    cache_get(source).flatten()
}

/// Publish server-offered ECH retry configs (e.g. after `ECH_REJECTED`),
/// replacing the cached entry so the next dial uses them immediately.
pub(crate) fn publish_ech_config(source: &EchSource, config: Vec<u8>) {
    // Retry configs carry no TTL; keep them like a fresh lookup.
    cache_put(source, Some(config.into()), 3600);
}

/// Refill a source's cache entry in the background. QUIC calls this when
/// `start_session` finds no valid entry, so key rotation reaches
/// long-lived runtimes without blocking the handshake.
pub(crate) fn spawn_ech_refresh(source: EchSource) {
    tokio::spawn(async move {
        // `ech_config` rechecks the cache first, so concurrent triggers
        // collapse into one fetch.
        ech_config(&source).await;
    });
}

/// One RFC 8484 POST over HTTP/2: returns the raw DNS response message,
/// checked against the query (ID and question).
async fn doh_h2_post<S>(io: S, authority: &str, path: &str, query: &[u8]) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = h2::client::handshake(io)
        .await
        .context("DoH HTTP/2 handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{authority}{path}"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", query.len().to_string())
        .body(())
        .context("DoH request build")?;
    let (response_fut, mut send_stream) = sender
        .send_request(request, false)
        .context("DoH send_request")?;
    send_stream
        .send_data(Bytes::copy_from_slice(query), true)
        .context("DoH send_data")?;
    let response = response_fut.await.context("DoH response")?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("DoH HTTP status {status}");
    }
    let mut body = response.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("DoH body read")?;
        if buf.len() + chunk.len() > ECH_DOH_MAX_BODY {
            anyhow::bail!("DoH response too large");
        }
        buf.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    if !crate::bootstrap::answers_query(query, &buf) {
        anyhow::bail!("DoH response does not match the query");
    }
    Ok(buf)
}

/// Fetch `(ECHConfigList, ttl)` for the source's qname via its DoH endpoint.
/// The dial carries the bypass mark: this is host-originated traffic that
/// must never be routed through a proxy by honk's own eBPF datapath.
async fn fetch_ech_via_doh(source: &EchDohSource) -> anyhow::Result<(Vec<u8>, u32)> {
    let endpoint = &source.endpoint;
    // `connect_outbound` resolves, races and bypass-marks; the dial address
    // always carries an explicit port.
    let dial_addr = endpoint.dial_addr();
    let tcp = crate::util::connect_outbound(&dial_addr, ECH_DOH_FETCH_TIMEOUT)
        .await
        .with_context(|| format!("DoH TCP connect to {dial_addr}"))?;
    let connector =
        crate::tls::build_dns_connector(false, b"\x02h2").context("DoH TLS connector")?;
    let tls = tokio::time::timeout(
        ECH_DOH_FETCH_TIMEOUT,
        connector.connect(&endpoint.host, tcp),
    )
    .await
    .context("DoH TLS handshake timed out")?
    .with_context(|| format!("DoH TLS handshake with {}", endpoint.host))?;
    if tls.ssl().selected_alpn_protocol() != Some(b"h2".as_slice()) {
        anyhow::bail!("DoH endpoint {} did not negotiate h2", endpoint.host);
    }
    let query = crate::bootstrap::build_query(&source.qname, crate::bootstrap::QTYPE_HTTPS);
    let authority = endpoint.authority();
    let body = tokio::time::timeout(
        ECH_DOH_FETCH_TIMEOUT,
        doh_h2_post(tls, &authority, &endpoint.path, &query),
    )
    .await
    .context("DoH exchange timed out")??;
    crate::bootstrap::parse_https_rr_ech(&body)
        .ok_or_else(|| anyhow::anyhow!("DoH response for {} carried no ECH config", source.qname))
}

#[cfg(test)]
mod tests;
