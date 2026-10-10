//! The one HTTP/1.1 GET honk's own downloads make, over a socket that carries
//! the process bypass mark before routing or over a stream the caller dialed.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, HOST, LOCATION,
    PROXY_AUTHORIZATION,
};
use hyper::body::{Body as _, Incoming};
use hyper_util::rt::TokioIo;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::{TlsConnector, rustls};

use crate::proxy::AsyncReadWrite;

type Stream = Box<dyn AsyncReadWrite>;

/// An answer whose body owns the connection it arrives on.
pub(crate) type Response = http::Response<ResponseBody>;

/// A download failure, with its stable output stage and original cause.
#[derive(Debug, thiserror::Error)]
#[error("{stage}")]
pub(crate) struct Error {
    pub(crate) stage: &'static str,
    #[source]
    source: Option<anyhow::Error>,
}

impl Error {
    fn caused(stage: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self {
            stage,
            source: Some(source.into()),
        }
    }

    fn timeout() -> Self {
        Self::caused(
            "download_timeout",
            std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP download timed out"),
        )
    }
}

impl From<&'static str> for Error {
    fn from(stage: &'static str) -> Self {
        Self {
            stage,
            source: None,
        }
    }
}

/// The existing GET inputs after its connection and any TLS are ready.
pub(crate) struct Prepared<'a> {
    stream: Stream,
    url: std::borrow::Cow<'a, reqwest::Url>,
    target: http::Uri,
    headers: http::HeaderMap,
}

struct Driver(tokio::task::JoinHandle<()>);

impl Driver {
    /// Ends the connection and waits until its stream is dropped.
    async fn close(mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct ResponseBody {
    body: Incoming,
    driver: Driver,
}

impl ResponseBody {
    /// The next data of the body; `None` at its end.
    pub(crate) async fn chunk(&mut self) -> hyper::Result<Option<bytes::Bytes>> {
        while let Some(frame) =
            std::future::poll_fn(|cx| Pin::new(&mut self.body).poll_frame(cx)).await
        {
            if let Ok(data) = frame?.into_data() {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }
}

/// reqwest has no socket-mark hook; keep Hyper's framing on our marked dialer.
pub(crate) struct Client {
    /// `None` only for [`Client::plain`], which never dials `https`.
    tls: Option<TlsConnector>,
}

impl Client {
    /// Fallible where `reqwest::Client::new` panics: a TLS setup failure must
    /// fail the download, not the task running it.
    pub(crate) fn new() -> anyhow::Result<Self> {
        use rustls_platform_verifier::BuilderVerifierExt;

        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth();
        config.alpn_protocols.push(b"http/1.1".to_vec());
        Ok(Self {
            tls: Some(TlsConnector::from(Arc::new(config))),
        })
    }

    /// A client for `http` only: no TLS config, so no system CA store.
    pub(crate) fn plain() -> Self {
        Self { tls: None }
    }

    #[cfg(all(test, feature = "clash-api"))]
    pub(crate) fn with_tls(config: rustls::ClientConfig) -> Self {
        Self {
            tls: Some(TlsConnector::from(Arc::new(config))),
        }
    }

    async fn connect(&self, uri: &http::Uri, timeout: Duration) -> anyhow::Result<Stream> {
        let host = uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("HTTP URL has no host"))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let stream =
            honk_outbound::util::connect_outbound(&format!("{host}:{port}"), timeout).await?;
        self.tls(Box::new(stream), uri).await
    }

    async fn tls(&self, stream: Stream, uri: &http::Uri) -> anyhow::Result<Stream> {
        match uri.scheme_str() {
            Some("https") => {
                let host = uri
                    .host()
                    .ok_or_else(|| anyhow::anyhow!("HTTPS URL has no host"))?;
                let name = rustls::pki_types::ServerName::try_from(
                    host.trim_matches(['[', ']']).to_owned(),
                )?;
                let tls = self
                    .tls
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("HTTPS needs a TLS client"))?;
                Ok(Box::new(tls.connect(name, stream).await?))
            }
            Some("http") => Ok(stream),
            _ => anyhow::bail!("unsupported HTTP URL scheme"),
        }
    }

    /// Execute one GET; the caller owns redirects and the whole-body deadline.
    pub(crate) async fn get(
        &self,
        url: &reqwest::Url,
        headers: &http::HeaderMap,
        timeout: Duration,
    ) -> anyhow::Result<Response> {
        send(self.prepare(url, headers, timeout).await?)
            .await
            .map_err(Into::into)
    }

    /// Prepare the direct GET, including environment proxy CONNECT and TLS.
    pub(crate) async fn prepare(
        &self,
        url: &reqwest::Url,
        headers: &http::HeaderMap,
        timeout: Duration,
    ) -> anyhow::Result<Prepared<'static>> {
        let mut url = url.clone();
        let mut headers = headers.clone();
        normalize_url(&mut url, &mut headers)?;
        let uri: http::Uri = url.as_str().parse()?;
        anyhow::ensure!(
            matches!(uri.scheme_str(), Some("http" | "https")),
            "unsupported HTTP URL scheme"
        );
        let proxy = hyper_util::client::proxy::matcher::Matcher::from_env().intercept(&uri);
        let mut stream = self
            .connect(proxy.as_ref().map_or(&uri, |proxy| proxy.uri()), timeout)
            .await?;
        let target: http::Uri = if let Some(proxy) = &proxy {
            if uri.scheme_str() == Some("https") {
                let authority =
                    format!("{}:{}", uri.host().unwrap(), uri.port_u16().unwrap_or(443));
                let mut tunnel = http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri(&authority)
                    .header(HOST, &authority);
                if let Some(auth) = proxy.basic_auth() {
                    tunnel = tunnel.header(PROXY_AUTHORIZATION, auth);
                }
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                let driver = Driver(tokio::spawn(async move {
                    let _ = connection.with_upgrades().await;
                }));
                let response = sender.send_request(tunnel.body(String::new())?).await;
                let upgraded = match response {
                    Ok(response) if response.status().is_success() => hyper::upgrade::on(response)
                        .await
                        .map_err(anyhow::Error::from),
                    Ok(_) => Err(anyhow::anyhow!("HTTP proxy refused CONNECT")),
                    Err(error) => Err(error.into()),
                };
                drop(driver);
                stream = self.tls(Box::new(TokioIo::new(upgraded?)), &uri).await?;
                uri.path_and_query()
                    .map_or("/", |path| path.as_str())
                    .parse()?
            } else {
                if !headers.contains_key(PROXY_AUTHORIZATION)
                    && let Some(auth) = proxy.basic_auth()
                {
                    headers.insert(PROXY_AUTHORIZATION, auth.clone());
                }
                uri.clone()
            }
        } else {
            uri.path_and_query()
                .map_or("/", |path| path.as_str())
                .parse()?
        };
        Ok(Prepared {
            stream,
            url: std::borrow::Cow::Owned(url),
            target,
            headers,
        })
    }

    /// Prepare a GET over the caller's stream, with TLS complete by `by`.
    pub(crate) async fn prepare_over<'a>(
        &self,
        stream: Stream,
        url: &'a reqwest::Url,
        headers: &http::HeaderMap,
        by: Instant,
    ) -> Result<Prepared<'a>, Error> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err("invalid_source".into());
        }
        let uri: http::Uri = url
            .as_str()
            .parse()
            .map_err(|error| Error::caused("invalid_source", error))?;
        let target = http::Uri::from(uri.path_and_query().ok_or("invalid_source")?.clone());
        let stream = timeout_at(by, self.tls(stream, &uri))
            .await
            .map_err(|_| Error::timeout())?
            .map_err(|error| Error::caused("tls_failed", error))?;
        Ok(Prepared {
            stream,
            url: std::borrow::Cow::Borrowed(url),
            target,
            headers: headers.clone(),
        })
    }
}

/// Send the prepared GET; only the actual response completes this future.
pub(crate) async fn send(prepared: Prepared<'_>) -> Result<Response, Error> {
    send_inner(prepared)
        .await
        .map_err(|error| Error::caused("http_failed", error))
}

async fn send_inner(prepared: Prepared<'_>) -> anyhow::Result<Response> {
    let Prepared {
        stream,
        url,
        target,
        mut headers,
    } = prepared;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("HTTP URL has no host"))?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    for (name, value) in [
        (HOST, host.as_str()),
        (CONNECTION, "close"),
        (ACCEPT_ENCODING, "identity"),
    ] {
        if !headers.contains_key(&name) {
            headers.insert(name, value.parse()?);
        }
    }
    let mut request = http::Request::new(String::new());
    *request.uri_mut() = target;
    *request.headers_mut() = headers;
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(64)
        .max_buf_size(32768)
        .handshake::<_, String>(TokioIo::new(stream))
        .await?;
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender.send_request(request).await?;
    Ok(response.map(|body| ResponseBody { body, driver }))
}

/// The answer to one GET. `body` is empty unless the caller wanted it.
pub(crate) struct Reply {
    pub(crate) status: http::StatusCode,
    /// Unchecked, so a caller that follows it can reject one that is not text.
    pub(crate) location: Option<http::HeaderValue>,
    pub(crate) body: Arc<[u8]>,
}

/// When a GET gives up. The answer's headers have to arrive by `headers`.
/// Without `idle` the body has to be complete by then as well; with
/// `idle: Some((pause, end))` it may run until `end`, as long as no wait for
/// more of it lasts `pause`.
#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    pub(crate) headers: Instant,
    pub(crate) idle: Option<(Duration, Instant)>,
}

impl From<Instant> for Deadline {
    fn from(at: Instant) -> Self {
        Self {
            headers: at,
            idle: None,
        }
    }
}

/// Reads the body of `response` when `wants_body` accepts its status and
/// headers, so an unwanted answer is neither waited for nor size checked.
/// The connection is closed before this returns. Errors name the stage that
/// failed.
pub(crate) async fn read(
    response: Response,
    wants_body: fn(http::StatusCode, &http::HeaderMap) -> bool,
    deadline: Deadline,
    max_bytes: usize,
) -> Result<Reply, Error> {
    let (parts, mut body) = response.into_parts();
    let result = async {
        let status = parts.status;
        let location = parts.headers.get(LOCATION).cloned();
        if !wants_body(status, &parts.headers) {
            return Ok(Reply {
                status,
                location,
                body: Arc::from([]),
            });
        }
        // The request asks for identity, so only identity may come back.
        if parts.headers.get_all(CONTENT_ENCODING).iter().any(|value| {
            !value
                .to_str()
                .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
        }) {
            return Err("content_encoding_rejected".into());
        }
        let size = body.body.size_hint();
        if size.upper().is_some_and(|size| size > max_bytes as u64) {
            return Err("asset_too_large".into());
        }
        // A declared length fills one buffer of that size, so a large body is
        // neither grown in steps nor copied once more into an `Arc`.
        let mut sized: Option<Arc<[u8]>> = size
            .exact()
            .map(|length| std::iter::repeat_n(0, length as usize).collect());
        let mut grown = Vec::new();
        let mut received = 0;
        let next_bytes = || {
            deadline.idle.map_or(deadline.headers, |(pause, end)| {
                end.min(Instant::now() + pause)
            })
        };
        while let Some(data) = timeout_at(next_bytes(), body.chunk())
            .await
            .map_err(|_| Error::timeout())?
            .map_err(|error| Error::caused("http_failed", error))?
        {
            if data.len() > max_bytes.saturating_sub(received) {
                return Err("asset_too_large".into());
            }
            match sized.as_mut() {
                Some(buffer) => Arc::get_mut(buffer)
                    .expect("a new buffer is unshared")
                    .get_mut(received..received + data.len())
                    .ok_or("http_failed")?
                    .copy_from_slice(&data),
                None => grown.extend_from_slice(&data),
            }
            received += data.len();
        }
        match sized {
            Some(buffer) if buffer.len() == received => Ok(Reply {
                status,
                location,
                body: buffer,
            }),
            Some(_) => Err("http_failed".into()),
            None => Ok(Reply {
                status,
                location,
                body: grown.into(),
            }),
        }
    }
    .await;
    body.driver.close().await;
    result
}

/// The redirect statuses a caller follows when they carry a Location. Every
/// request here is a bodiless GET, so 303 and 301/302 need no method change.
pub(crate) fn followed_redirect(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Move initial URL credentials into headers before a caller follows redirects.
pub(crate) fn normalize_url(
    url: &mut reqwest::Url,
    headers: &mut http::HeaderMap,
) -> anyhow::Result<()> {
    if (!url.username().is_empty() || url.password().is_some())
        && !headers.contains_key(AUTHORIZATION)
    {
        headers.insert(AUTHORIZATION, basic_auth(url.username(), url.password())?);
    }
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Ok(())
}

fn basic_auth(username: &str, password: Option<&str>) -> anyhow::Result<http::HeaderValue> {
    use base64::Engine;
    let decode = |text: &str| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8_lossy()
            .into_owned()
    };
    let credentials = format!(
        "{}:{}",
        decode(username),
        decode(password.unwrap_or_default())
    );
    let mut value: http::HeaderValue = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    )
    .parse()?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests;
