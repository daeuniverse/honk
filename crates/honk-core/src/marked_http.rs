//! HTTP downloads whose sockets carry the process bypass mark before routing.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::header::{AUTHORIZATION, HOST, PROXY_AUTHORIZATION};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use tokio_rustls::{TlsConnector, rustls};

use crate::proxy::AsyncReadWrite;

type Stream = Box<dyn AsyncReadWrite>;

struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ResponseBody {
    body: Incoming,
    _driver: Driver,
}

impl Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// reqwest has no socket-mark hook; keep Hyper's framing on our marked dialer.
pub(crate) struct Client {
    tls: TlsConnector,
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
            tls: TlsConnector::from(Arc::new(config)),
        })
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
                Ok(Box::new(self.tls.connect(name, stream).await?))
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
    ) -> anyhow::Result<reqwest::Response> {
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
        if !headers.contains_key(HOST) {
            headers.insert(
                HOST,
                uri.authority()
                    .ok_or_else(|| anyhow::anyhow!("HTTP URL has no authority"))?
                    .as_str()
                    .parse()?,
            );
        }
        let request_uri: http::Uri = if let Some(proxy) = &proxy {
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
                let response = sender
                    .send_request(tunnel.body(reqwest::Body::from(""))?)
                    .await;
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
        let mut request = http::Request::builder()
            .method(http::Method::GET)
            .uri(request_uri)
            .body(reqwest::Body::from(""))?;
        *request.headers_mut() = headers;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender.send_request(request).await?;
        Ok(reqwest::Response::from(response.map(|body| {
            reqwest::Body::wrap(ResponseBody {
                body,
                _driver: driver,
            })
        })))
    }
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
