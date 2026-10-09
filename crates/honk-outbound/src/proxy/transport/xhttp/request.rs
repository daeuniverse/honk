use honk_config::node::{Node, XhttpRange};

pub(super) use honk_config::node::XhttpResolvedMode as ResolvedMode;

#[derive(Debug)]
pub(super) struct RequestTemplate {
    pub(super) mode: ResolvedMode,
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    prefix: String,
    query: Option<String>,
    headers: http::HeaderMap,
    referer: String,
    no_grpc_header: bool,
    padding: XhttpRange,
    pub(super) post_bytes: XhttpRange,
    pub(super) post_interval: XhttpRange,
}

impl RequestTemplate {
    pub(super) fn new(node: &Node) -> anyhow::Result<Self> {
        let options = node
            .transport()
            .and_then(|transport| transport.xhttp.as_ref())
            .ok_or_else(|| anyhow::anyhow!("XHTTP options missing"))?;
        let tls = node.tls().unwrap();
        let mode = options.resolved_mode(tls).map_err(anyhow::Error::msg)?;
        let scheme = if tls.is_secure() {
            http::uri::Scheme::HTTPS
        } else {
            http::uri::Scheme::HTTP
        };
        let host = options
            .host
            .as_deref()
            .or(tls.sni.as_deref())
            .unwrap_or(node.host());
        let authority: http::uri::Authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]").parse()?
        } else {
            host.parse()?
        };
        let (prefix, query) = options
            .path
            .split_once('?')
            .map_or((options.path.as_str(), None), |(path, query)| {
                (path, Some(query))
            });
        let mut headers = http::HeaderMap::new();
        for (name, value) in &options.headers {
            headers.insert(
                http::header::HeaderName::from_bytes(name.as_bytes())?,
                value.parse()?,
            );
        }
        super::browser::apply_chrome_fetch(&mut headers);
        let referer = format!(
            "{scheme}://{authority}{}?x_padding=",
            escape_path(prefix.to_owned())
        );
        Ok(Self {
            mode,
            scheme,
            authority,
            prefix: prefix.to_owned(),
            query: query.map(str::to_owned),
            headers,
            referer,
            no_grpc_header: options.no_grpc_header,
            padding: options.x_padding_bytes,
            post_bytes: options.sc_max_each_post_bytes,
            post_interval: options.sc_min_posts_interval_ms,
        })
    }

    pub(super) fn request(
        &self,
        session: &str,
        seq: Option<u64>,
        post: bool,
        length: Option<usize>,
    ) -> anyhow::Result<http::Request<()>> {
        let mut path = self.prefix.clone();
        if !session.is_empty() {
            path.push_str(session);
            if let Some(seq) = seq {
                path.push('/');
                path.push_str(&seq.to_string());
            }
        }
        let mut path = escape_path(path);
        if let Some(query) = &self.query {
            path.push('?');
            path.push_str(query);
        }
        let uri = http::Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path)
            .build()?;
        let mut request = http::Request::builder()
            .method(if post { "POST" } else { "GET" })
            .uri(uri)
            .body(())?;
        *request.headers_mut() = self.headers.clone();
        if post && length.is_none() && !self.no_grpc_header {
            request.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
        }
        if let Some(length) = length {
            request
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, length.to_string().parse()?);
        }
        // Legacy padding uses the base URL, before session/sequence placement.
        let padding = "X".repeat(sample(self.padding) as usize);
        request.headers_mut().insert(
            http::header::REFERER,
            format!("{}{padding}", self.referer).parse()?,
        );
        Ok(request)
    }
}

fn escape_path(path: String) -> String {
    let needs_escape = |byte: u8| {
        !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' | b'/' | b'$' | b'&' | b'+'
            | b',' | b':' | b';' | b'=' | b'@')
    };
    let count = path.bytes().filter(|&byte| needs_escape(byte)).count();
    if count == 0 {
        return path;
    }
    let mut escaped = String::with_capacity(path.len() + 2 * count);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.bytes() {
        if needs_escape(byte) {
            escaped.push('%');
            escaped.push(HEX[(byte >> 4) as usize] as char);
            escaped.push(HEX[(byte & 15) as usize] as char);
        } else {
            escaped.push(byte as char);
        }
    }
    escaped
}

pub(super) fn sample(range: XhttpRange) -> u32 {
    use rand::RngExt;
    rand::rng().random_range(range.min..=range.max)
}
