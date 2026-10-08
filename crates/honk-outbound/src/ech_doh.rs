//! Dynamic ECH config fetch over DNS-over-HTTPS.
//!
//! A node can carry `ech=<qname>+<doh-url>` in its share-link `ech`
//! parameter (e.g. `ech=cloudflare-ech.com+https://223.5.5.5/dns-query`):
//! the ECHConfigList is read from the `ech` SvcParam of `qname`'s HTTPS
//! record, fetched with a DNS-over-HTTPS POST to the given endpoint.
//! A bare `ech=<qname>` (no URL) is *not* fetched here; it resolves through
//! the bootstrap DNS path (`discover_ech_config`), honoring the user's own
//! resolver instead of a hard-coded third party.
//!
//! Each distinct DoH source gets one background refresher. The first dial
//! after (re)start awaits the first fetch with a bounded timeout; if that
//! fetch fails, the dial proceeds without ECH while the refresher retries
//! every minute. The refresher renews the config on the record TTL
//! (floored at 60s); a failed refresh keeps the previous config.
//! Refreshers for sources no dial has consulted for
//! [`ECH_DOH_IDLE_TIMEOUT`] stop themselves, so a reload drops stale
//! sources. Static `ech_config`/`ech_config_path` still win over this
//! source.
//!
//! Every socket here (DoH host resolution through the bootstrap resolver,
//! the TCP dial) carries the bypass mark, so honk's own eBPF datapath never
//! routes this host-originated traffic through a proxy — possibly the very
//! ECH node waiting for the config.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;

/// How long the refresher waits between attempts before the first success.
const ECH_DOH_RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// Bound for the cold first fetch on the dial path (fail-open past it).
const ECH_DOH_COLD_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-stage budget inside a fetch: TCP connect, TLS handshake and the
/// H2 exchange each get this long.
const ECH_DOH_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// A refresher whose source saw no dial for this long stops itself.
const ECH_DOH_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Cap on a DoH response body; an ECH answer is a few hundred bytes.
const ECH_DOH_MAX_BODY: usize = 64 * 1024;

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

/// Where a share-link `ech` value resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EchFetchSource {
    /// Bare `ech=<qname>`: HTTPS RR through the bootstrap resolver
    /// (the user's own DNS config; see `discover_ech_config`).
    BootstrapDns(String),
    /// `ech=<qname>+<doh-url>`: DoH fetch from the explicit endpoint.
    Doh(EchDohSource),
}

/// Parse a node's `ech` value once; `None` when the node carries none.
/// All construction sites use this so the parse is never duplicated.
pub(crate) fn parse_node_ech_source(
    node: &honk_config::node::Node,
) -> anyhow::Result<Option<EchFetchSource>> {
    node.tls()
        .and_then(|tls| tls.ech_doh.as_deref())
        .map(parse_ech_source)
        .transpose()
        .with_context(|| format!("node '{}': invalid ech source", node.name))
}

/// Parse a share-link `ech` value into its fetch source. Validation is the
/// strict honk-config parser, so config-time and outbound agree.
pub(crate) fn parse_ech_source(raw: &str) -> anyhow::Result<EchFetchSource> {
    let parts = honk_config::node::TlsOptions::parse_ech_doh(raw)
        .map_err(|message| anyhow::anyhow!("invalid ech source {raw:?}: {message}"))?;
    match parts.url {
        Some(url) => Ok(EchFetchSource::Doh(EchDohSource {
            qname: parts.qname,
            endpoint: DohEndpoint::parse(&url)?,
            url,
        })),
        None => Ok(EchFetchSource::BootstrapDns(parts.qname)),
    }
}

/// Per-source fetch state. The config lock is only ever held for a plain
/// swap or clone — never across `.await` — so a dial can never observe a
/// half-written config or race the refresher into skipping ECH.
struct EchDohSlot {
    config: parking_lot::RwLock<Option<Arc<Vec<u8>>>>,
    last_used: parking_lot::Mutex<Instant>,
    /// Serializes the cold first fetch so concurrent dials share one.
    cold: tokio::sync::Mutex<()>,
}

impl EchDohSlot {
    fn new() -> Self {
        Self {
            config: parking_lot::RwLock::new(None),
            last_used: parking_lot::Mutex::new(Instant::now()),
            cold: tokio::sync::Mutex::new(()),
        }
    }
}

static ECH_DOH_CACHE: LazyLock<dashmap::DashMap<EchDohSource, Arc<EchDohSlot>>> =
    LazyLock::new(dashmap::DashMap::new);
/// Sources with a live refresher task.
static REFRESH_TASKS: LazyLock<dashmap::DashMap<EchDohSource, ()>> =
    LazyLock::new(dashmap::DashMap::new);

/// Boxed future returning a fetched ECHConfigList and its TTL.
type EchFetchFuture = Pin<Box<dyn Future<Output = anyhow::Result<(Vec<u8>, u32)>> + Send>>;

/// Boxed fetch used by the cold path and the refresh loop; production
/// passes [`real_fetch`], tests inject stubs.
type EchDohFetch = fn(&EchDohSource) -> EchFetchFuture;

fn real_fetch(source: &EchDohSource) -> EchFetchFuture {
    let source = source.clone();
    Box::pin(async move { fetch_ech_via_doh(&source).await })
}

/// Refresh wait from a DNS TTL, floored like the discovery cache.
fn ttl_wait(ttl: u32) -> Duration {
    Duration::from_secs(ttl.clamp(60, 86400) as u64)
}

fn spawn_refresher(
    source: EchDohSource,
    slot: Arc<EchDohSlot>,
    fetch: EchDohFetch,
    first_wait: Duration,
) {
    if REFRESH_TASKS.insert(source.clone(), ()).is_some() {
        return;
    }
    tokio::spawn(refresh_loop(
        source,
        slot,
        fetch,
        first_wait,
        ECH_DOH_RETRY_INTERVAL,
        ECH_DOH_IDLE_TIMEOUT,
    ));
}

/// Freshest fetched ECHConfigList for a DoH source, or `None` when no fetch
/// has succeeded yet. The cold path awaits the first fetch with a bounded
/// timeout instead of sending the SNI in cleartext — fail-open past it, as
/// the connect-time `ech=1` discovery is.
pub(crate) async fn ech_doh_config(source: &EchDohSource) -> Option<Arc<Vec<u8>>> {
    ech_doh_config_with(source, real_fetch).await
}

/// Synchronous read of the DoH cache: for per-connection resolution
/// (QUIC `start_session`) so refreshes reach later connections.
pub(crate) fn cached_ech_doh_config(source: &EchDohSource) -> Option<Arc<Vec<u8>>> {
    ECH_DOH_CACHE.get(source).and_then(|slot| {
        // A per-connection read counts as use: without this, QUIC-only nodes
        // would look idle to the refresher and lose their config 30 minutes
        // after start while connections never stopped.
        *slot.last_used.lock() = Instant::now();
        slot.config.read().clone()
    })
}

/// Publish server-offered ECH retry configs into the slot (e.g. after an
/// `ECH_REJECTED` handshake): the next dial uses them immediately instead
/// of waiting for the next refresh.
pub(crate) fn publish_config(source: &EchDohSource, config: Vec<u8>) {
    if let Some(slot) = ECH_DOH_CACHE.get(source) {
        *slot.config.write() = Some(Arc::new(config));
        *slot.last_used.lock() = Instant::now();
    }
}

async fn ech_doh_config_with(source: &EchDohSource, fetch: EchDohFetch) -> Option<Arc<Vec<u8>>> {
    let slot = ECH_DOH_CACHE
        .entry(source.clone())
        .or_insert_with(|| Arc::new(EchDohSlot::new()))
        .clone();
    if let Some(config) = cached_ech_doh_config(source) {
        *slot.last_used.lock() = Instant::now();
        return Some(config);
    }
    // Cold: one dial performs the first fetch; concurrent dials wait for it
    // (bounded) and then share the result.
    let _guard = tokio::time::timeout(ECH_DOH_COLD_TIMEOUT, slot.cold.lock())
        .await
        .ok()?;
    if let Some(config) = slot.config.read().clone() {
        *slot.last_used.lock() = Instant::now();
        return Some(config);
    }
    if REFRESH_TASKS.contains_key(source) {
        // A refresher is already retrying in the background; fail open
        // rather than adding dial latency.
        return None;
    }
    *slot.last_used.lock() = Instant::now();
    match tokio::time::timeout(ECH_DOH_COLD_TIMEOUT, fetch(source)).await {
        Ok(Ok((config, ttl))) => {
            let config = Arc::new(config);
            *slot.config.write() = Some(config.clone());
            spawn_refresher(source.clone(), slot.clone(), fetch, ttl_wait(ttl));
            Some(config)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                qname = %source.qname,
                url = %source.url,
                %error,
                "ECH DoH first fetch failed; retrying in the background"
            );
            spawn_refresher(source.clone(), slot.clone(), fetch, ECH_DOH_RETRY_INTERVAL);
            None
        }
        Err(_) => {
            tracing::warn!(
                qname = %source.qname,
                url = %source.url,
                "ECH DoH first fetch timed out; retrying in the background"
            );
            spawn_refresher(source.clone(), slot.clone(), fetch, ECH_DOH_RETRY_INTERVAL);
            None
        }
    }
}

/// Fetch loop for one source: the first fetch already ran on the cold dial
/// path, so this renews every `interval` after a success and retries every
/// minute after a failure, keeping the previous config. Stops itself once
/// the source goes idle past [`ECH_DOH_IDLE_TIMEOUT`] (e.g. after a reload
/// drops the node), removing its cache entry.
async fn refresh_loop(
    source: EchDohSource,
    slot: Arc<EchDohSlot>,
    fetch: EchDohFetch,
    first_wait: Duration,
    retry_interval: Duration,
    idle_timeout: Duration,
) {
    let mut wait = first_wait;
    loop {
        tokio::time::sleep(wait).await;
        if slot.last_used.lock().elapsed() > idle_timeout {
            ECH_DOH_CACHE.remove(&source);
            REFRESH_TASKS.remove(&source);
            tracing::debug!(
                qname = %source.qname,
                "stopping idle ECH DoH refresher"
            );
            return;
        }
        match fetch(&source).await {
            Ok((config, ttl)) => {
                tracing::debug!(
                    qname = %source.qname,
                    bytes = config.len(),
                    ttl,
                    "refreshed ECH config via DoH"
                );
                *slot.config.write() = Some(Arc::new(config));
                // Honor the record TTL (floored), like the DNS discovery cache.
                wait = ttl_wait(ttl);
            }
            Err(error) => {
                tracing::warn!(
                    qname = %source.qname,
                    url = %source.url,
                    %error,
                    "ECH DoH refresh failed; keeping previous config"
                );
                wait = retry_interval;
            }
        }
    }
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
pub(crate) async fn fetch_ech_via_doh(source: &EchDohSource) -> anyhow::Result<(Vec<u8>, u32)> {
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
