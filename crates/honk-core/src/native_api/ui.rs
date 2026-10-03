//! Static assets embedded at build time or from a trusted administrator directory.
//!
//! The administrator also owns any symlink targets; this is not a sandbox for
//! untrusted uploads or downloaded archives.

use std::{borrow::Cow, io::ErrorKind};

use anyhow::{Context, ensure};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
};
use tower_http::services::{ServeDir, ServeFile};

use super::hashed_asset::is_hashed_asset;

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub(super) enum Ui {
    Directory(Box<(ServeDir, ServeFile)>),
    #[cfg(feature = "native-ui")]
    Embedded,
}

pub(super) async fn load(path: &str) -> anyhow::Result<Option<Ui>> {
    if path.is_empty() {
        return Ok(None);
    }
    if path == "embedded" {
        #[cfg(feature = "native-ui")]
        return Ok(Some(Ui::Embedded));
        #[cfg(not(feature = "native-ui"))]
        anyhow::bail!("embedded native UI requires the native-ui feature");
    }

    let root = honk_config::paths::resolve_dependency_path(path);
    ensure!(
        tokio::fs::metadata(&root)
            .await
            .context("failed to inspect native UI directory")?
            .is_dir(),
        "native UI path must be a directory"
    );
    let index = root.join("index.html");
    ensure!(
        tokio::fs::metadata(&index)
            .await
            .context("failed to inspect native UI index.html")?
            .is_file(),
        "native UI index.html must be a regular file"
    );
    tokio::fs::File::open(&index)
        .await
        .context("native UI index.html must be readable")?;

    Ok(Some(Ui::Directory(Box::new((
        ServeDir::new(root)
            .append_index_html_on_directories(false)
            .precompressed_br()
            .precompressed_gzip(),
        ServeFile::new(index)
            .precompressed_br()
            .precompressed_gzip(),
    )))))
}

impl Ui {
    pub(super) async fn serve(&self, request: Request) -> Response {
        let hashed = request
            .uri()
            .path()
            .strip_prefix("/ui/")
            .is_some_and(is_hashed_asset);
        let mut response = self.respond(request).await;
        let cache = cache_control(hashed, response.status());
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        // No framing header: dashboards such as LuCI embed the UI in a frame served from another port.
        response
    }

    async fn respond(&self, mut request: Request) -> Response {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "GET, HEAD")],
            )
                .into_response();
        }
        let path = request.uri().path();
        if matches!(path, "/" | "/ui") {
            return Redirect::temporary("/ui/").into_response();
        }
        let Some(relative) = path.strip_prefix("/ui/") else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(decoded) = decode_path(relative) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if decoded.starts_with('/')
            || decoded.contains('\\')
            || decoded.chars().any(char::is_control)
            || decoded.split('/').any(|part| matches!(part, "." | ".."))
        {
            return StatusCode::NOT_FOUND.into_response();
        }

        // Only validated navigation paths may reach the UI entry point.
        let navigation = !decoded.contains('.')
            && !matches!(
                decoded.split('/').next(),
                Some("assets" | "fonts" | "icons")
            );
        let (files, index) = match self {
            Self::Directory(directory) => (&directory.0, &directory.1),
            #[cfg(feature = "native-ui")]
            Self::Embedded => {
                return embedded_response(
                    &decoded,
                    navigation,
                    request.method() == Method::HEAD,
                    negotiate(request.headers()),
                );
            }
        };
        let Some(uri) = request
            .uri()
            .path_and_query()
            .and_then(|value| value.as_str().strip_prefix("/ui"))
            .and_then(|value| value.parse::<Uri>().ok())
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        *request.uri_mut() = uri;
        let result = if navigation {
            files
                .clone()
                .fallback(index.clone())
                .try_call(request)
                .await
        } else {
            files.clone().try_call(request).await
        };
        match result {
            Ok(response) => {
                let mut response = response.map(Body::new);
                // tower-http names accept-encoding in Vary only on responses carrying the file;
                // a cache must key its 304 or 412 for that file by encoding too.
                let status = response.status();
                if matches!(
                    status,
                    StatusCode::NOT_MODIFIED | StatusCode::PRECONDITION_FAILED
                ) {
                    response
                        .headers_mut()
                        .append(header::VARY, HeaderValue::from_static("accept-encoding"));
                }
                response
            }
            Err(error) => match error.kind() {
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::NotADirectory => {
                    StatusCode::NOT_FOUND.into_response()
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            },
        }
    }
}

/// Only hashed names are safe to keep: everything else, including `index.html` and
/// `sw.js`, must revalidate so a new build is picked up.
fn cache_control(hashed: bool, status: StatusCode) -> &'static str {
    if hashed && (status.is_success() || status == StatusCode::NOT_MODIFIED) {
        IMMUTABLE
    } else {
        "no-cache"
    }
}

#[cfg(feature = "native-ui")]
enum EmbeddedAsset {
    /// Formats that do not compress, embedded as stored.
    Identity(&'static [u8]),
    /// Text embedded only in compressed form; `len` is the decoded size.
    Encoded {
        br: &'static [u8],
        gzip: &'static [u8],
        len: usize,
    },
}

#[cfg(feature = "native-ui")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

/// Picks the coding with the highest q-value among br, gzip and identity, the three forms
/// every compressed asset has; an explicit token overrides `*`, and ties prefer br, then
/// gzip. Unlisted identity stays acceptable below any listed coding. When the header
/// refuses everything, identity is served anyway: RFC 9110 lets a server disregard the
/// header, and a 406 would only leave the UI blank.
#[cfg(feature = "native-ui")]
fn negotiate(headers: &axum::http::HeaderMap) -> Encoding {
    let (mut br, mut gzip, mut identity, mut any) = (None, None, None, None);
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for item in value.split(',') {
            let mut parameters = item.split(';');
            let coding = parameters.next().unwrap_or_default().trim();
            let quality = match parameters
                .filter_map(|parameter| parameter.split_once('='))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
            {
                None => 1.0,
                Some((_, quality)) => match quality.trim().parse::<f32>() {
                    Ok(quality) if (0.0..=1.0).contains(&quality) => quality,
                    _ => continue,
                },
            };
            let slot = if coding.eq_ignore_ascii_case("br") {
                &mut br
            } else if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
                &mut gzip
            } else if coding.eq_ignore_ascii_case("identity") {
                &mut identity
            } else if coding == "*" {
                &mut any
            } else {
                continue;
            };
            *slot = Some(quality);
        }
    }
    let br = br.or(any).unwrap_or(0.0);
    let gzip = gzip.or(any).unwrap_or(0.0);
    let identity = identity.or(any).unwrap_or(f32::MIN_POSITIVE);
    if br > 0.0 && br >= gzip && br >= identity {
        Encoding::Brotli
    } else if gzip > 0.0 && gzip >= identity {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

#[cfg(feature = "native-ui")]
fn embedded_response(path: &str, navigation: bool, head: bool, encoding: Encoding) -> Response {
    use std::io::Read;

    static FILES: &[(&str, EmbeddedAsset)] =
        include!(concat!(env!("OUT_DIR"), "/native_ui_assets.rs"));

    let path = if path.is_empty() { "index.html" } else { path };
    let Ok(index) = FILES.binary_search_by(|(name, _)| name.cmp(&path)) else {
        return if navigation {
            // The hash router's relative assets and service worker require /ui/.
            Redirect::temporary("/ui/").into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        };
    };
    let (path, ref asset) = FILES[index];
    let content_type = match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html",
        "js" => "text/javascript",
        "css" => "text/css",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "png" => "image/png",
        "webp" => "image/webp",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    };
    let (body, length, coding) = match (asset, encoding) {
        (EmbeddedAsset::Identity(bytes), _) => (Body::from(*bytes), bytes.len(), None),
        (EmbeddedAsset::Encoded { br, .. }, Encoding::Brotli) => {
            (Body::from(*br), br.len(), Some("br"))
        }
        (EmbeddedAsset::Encoded { gzip, .. }, Encoding::Gzip) => {
            (Body::from(*gzip), gzip.len(), Some("gzip"))
        }
        (EmbeddedAsset::Encoded { len, .. }, Encoding::Identity) if head => {
            (Body::empty(), *len, None)
        }
        (EmbeddedAsset::Encoded { gzip, len, .. }, Encoding::Identity) => {
            // Browsers all accept gzip, so this whole-buffer decode serves only rare clients.
            let mut decoded = Vec::with_capacity(*len);
            if flate2::read::GzDecoder::new(*gzip)
                .read_to_end(&mut decoded)
                .is_err()
            {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            (Body::from(decoded), *len, None)
        }
    };
    let mut response = Response::new(if head { Body::empty() } else { body });
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Some(coding) = coding {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    if matches!(asset, EmbeddedAsset::Encoded { .. }) {
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    response
}

fn decode_path(path: &str) -> Option<Cow<'_, str>> {
    // percent_decode passes a malformed escape through literally; reject it instead.
    let malformed = path.split('%').skip(1).any(|escape| {
        !escape
            .get(..2)
            .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    });
    if malformed {
        return None;
    }
    percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_successful_hashed_assets_are_immutable() {
        for (path, status, expected) in [
            ("assets/index-BOpK0UVB.js", StatusCode::OK, IMMUTABLE),
            ("assets/array-C0P64tl-.js", StatusCode::OK, IMMUTABLE),
            ("assets/locale-zh-CN-DF_91JnF.js", StatusCode::OK, IMMUTABLE),
            ("assets/lake-light-oWll36-V.webp", StatusCode::OK, IMMUTABLE),
            ("assets/match.worker-B2aIccpg.js", StatusCode::OK, IMMUTABLE),
            ("assets/x.y.z-AbCd1234.css", StatusCode::OK, IMMUTABLE),
            ("assets/match.worker.js", StatusCode::OK, "no-cache"),
            ("assets/match.worker-B2aIcc.js", StatusCode::OK, "no-cache"),
            (
                "assets/match-B2aIccpg.worker.js",
                StatusCode::OK,
                "no-cache",
            ),
            ("assets/index-BOpK0UVB.js.map", StatusCode::OK, "no-cache"),
            (
                "assets/match.worker-B2a.ccpg.js",
                StatusCode::OK,
                "no-cache",
            ),
            (
                "assets/index-BOpK0UVB.js",
                StatusCode::PARTIAL_CONTENT,
                IMMUTABLE,
            ),
            (
                "assets/index-BOpK0UVB.js",
                StatusCode::NOT_MODIFIED,
                IMMUTABLE,
            ),
            (
                "assets/index-BOpK0UVB.js",
                StatusCode::NOT_FOUND,
                "no-cache",
            ),
            ("assets/index-BOpK0UV.js", StatusCode::OK, "no-cache"),
            ("assets/index-BOpK0UVB", StatusCode::OK, "no-cache"),
            ("assets/-BOpK0UVB.js", StatusCode::OK, "no-cache"),
            ("assets/app.js", StatusCode::OK, "no-cache"),
            (
                "assets/nested/index-BOpK0UVB.js",
                StatusCode::OK,
                "no-cache",
            ),
            ("fonts/index-BOpK0UVB.js", StatusCode::OK, "no-cache"),
            ("index.html", StatusCode::OK, "no-cache"),
            ("sw.js", StatusCode::OK, "no-cache"),
            ("manifest.webmanifest", StatusCode::OK, "no-cache"),
            ("icons/icon-192.png", StatusCode::OK, "no-cache"),
            ("", StatusCode::OK, "no-cache"),
        ] {
            assert_eq!(
                cache_control(is_hashed_asset(path), status),
                expected,
                "{path} {status}"
            );
        }
    }

    #[cfg(feature = "native-ui")]
    #[test]
    fn accept_encoding_picks_the_best_stored_coding() {
        use Encoding::{Brotli, Gzip, Identity};

        for (values, expected) in [
            (&[][..], Identity),
            (&["br"], Brotli),
            (&["gzip"], Gzip),
            (&["x-gzip"], Gzip),
            (&["gzip, deflate, br, zstd"], Brotli),
            (&["identity"], Identity),
            (&["deflate"], Identity),
            (&[""], Identity),
            (&["br;q=0, gzip"], Gzip),
            (&["br;q=0.0, gzip;q=0.000"], Identity),
            (&["gzip;q=1, br;q=0.5"], Gzip),
            (&["gzip;q=0.5, br;q=0.5"], Brotli),
            (&["BR ; Q=0.8"], Brotli),
            (&["br;q=2, gzip"], Gzip),
            (&["br;q=bogus"], Identity),
            (&["*"], Brotli),
            (&["*;q=0"], Identity),
            (&["*, br;q=0"], Gzip),
            (&["gzip;q=0.5, *"], Brotli),
            (&["identity;q=0"], Identity),
            (&["deflate", "gzip"], Gzip),
            (&["identity;q=1, br;q=0.1"], Identity),
            (&["identity, gzip;q=0.5"], Identity),
            (&["IDENTITY;q=0.5, gzip"], Gzip),
            (&["identity;q=0, gzip;q=0.1"], Gzip),
            (&["identity;q=0, br;q=0, gzip;q=0"], Identity),
            (&["*;q=0.5, br;q=0.1"], Gzip),
            (&["*;q=0.5, gzip;q=0"], Brotli),
            (&["*;q=0.2, identity;q=0.9"], Identity),
            (&["*;q=0, identity"], Identity),
        ] {
            let mut headers = axum::http::HeaderMap::new();
            for value in values {
                headers.append(header::ACCEPT_ENCODING, HeaderValue::from_static(value));
            }
            assert_eq!(negotiate(&headers), expected, "{values:?}");
        }
    }
}
