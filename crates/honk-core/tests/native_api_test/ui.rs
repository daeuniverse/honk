use super::*;
#[tokio::test]
async fn ui_serves_only_its_directory_with_navigation_and_static_cache_policy() {
    let directory = tempfile::tempdir().unwrap();
    let ui = directory.path().join("ui");
    std::fs::create_dir_all(ui.join("assets")).unwrap();
    std::fs::create_dir(ui.join("fonts")).unwrap();
    std::fs::create_dir(ui.join("icons")).unwrap();
    std::fs::write(
        directory.path().join("private.dae"),
        "private-config-marker",
    )
    .unwrap();
    let index = "<!doctype html><title>hosting fixture only</title><script src='/ui/assets/app.js'></script>";
    for (path, content) in [
        ("index.html", index),
        ("assets/app.js", "window.hostingFixture = true;"),
        ("assets/app.css", "body { color: black; }"),
        ("manifest.webmanifest", "{\"name\":\"hosting fixture\"}"),
        ("sw.js", "self.addEventListener('fetch', () => {});"),
        ("assets/hashed-Ab_9-xYz.js", "window.hashedFixture = true;"),
        ("assets/hashed-Ab_9-xYz.js.gz", "gzip fixture"),
    ] {
        std::fs::write(ui.join(path), content).unwrap();
    }
    let app =
        TestApp::new(|config| config.experimental.native_api.ui = ui.to_str().unwrap().into())
            .await;
    for path in ["/", "/ui"] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert!(response.status().is_redirection());
        assert_eq!(response.headers()["location"], "/ui/");
    }
    for (path, mime) in [
        ("/ui/", "text/html"),
        ("/ui/deep/navigation", "text/html"),
        ("/ui/assets/app.js", "text/javascript"),
        ("/ui/assets/app.css", "text/css"),
        ("/ui/manifest.webmanifest", "application/manifest+json"),
        ("/ui/sw.js", "text/javascript"),
    ] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().get("x-frame-options").is_none());
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(mime),
            "{path}"
        );
        let body = response.text().await.unwrap();
        if mime == "text/html" {
            assert_eq!(body, index);
        }
        assert!(!body.contains(SECRET));
    }
    // Directory mode serves a precompressed sibling only when the administrator provides one.
    for (encoding, content_encoding, body) in [
        ("gzip", Some("gzip"), "gzip fixture"),
        ("br", None, "window.hashedFixture = true;"),
    ] {
        let response = app
            .client
            .get(app.url("/ui/assets/hashed-Ab_9-xYz.js"))
            .header("accept-encoding", encoding)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{encoding}");
        assert_eq!(
            response.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["vary"], "accept-encoding");
        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .map(|value| value.to_str().unwrap()),
            content_encoding
        );
        assert_eq!(response.text().await.unwrap(), body);
    }
    for path in ["/ui/assets/hashed-Ab_9-xYz.js", "/ui/deep/navigation"] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        let etag = response.headers()["etag"].clone();
        let response = app
            .client
            .get(app.url(path))
            .header("if-none-match", etag)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "{path}");
        let vary: Vec<_> = response.headers().get_all("vary").iter().collect();
        assert_eq!(vary, ["accept-encoding", "Origin"], "{path}");
    }
    let head = app
        .client
        .head(app.url("/ui/deep/navigation"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()["cache-control"], "no-cache");
    assert!(head.bytes().await.unwrap().is_empty());
    for path in [
        "/ui/missing.js",
        "/ui/missing.webmanifest",
        "/ui/assets/missing",
        "/ui/fonts/missing",
        "/ui/icons/missing",
        "/ui/assets/",
        "/private.dae",
        "/assets/app.js",
    ] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let body = response.text().await.unwrap();
        assert!(!body.contains("hosting fixture only") && !body.contains("private-config-marker"));
    }
    for path in [
        "/ui/../private.dae",
        "/ui/%2e%2e/private.dae",
        "/ui/%2E%2E%2Fprivate.dae",
        "/ui/%2e%2e%5cprivate.dae",
        "/ui/%00",
        "/ui/%FF",
        "/ui/%zz",
    ] {
        let response = raw_request(&app, path, "", b"").await;
        assert!(
            (400..500).contains(&response.status),
            "{path}: {}",
            response.status
        );
        let body = String::from_utf8_lossy(&response.body);
        assert!(!body.contains("hosting fixture only") && !body.contains("private-config-marker"));
    }
    error_response(
        app.get("/api/v1/missing").send().await.unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    // Serving the UI does not exempt the API: a protected route still needs its bearer.
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for (header, value) in [
        ("host", "attacker.example"),
        ("origin", "https://attacker.example"),
    ] {
        let response = app
            .client
            .get(app.url("/ui/"))
            .header(header, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().get("x-frame-options").is_none());
        error_body(
            &response.json::<Value>().await.unwrap(),
            "permission_denied",
        );
    }
    app.shutdown().await;
}

#[cfg(feature = "native-ui")]
#[tokio::test]
async fn embedded_ui_preserves_assets_head_and_safe_navigation() {
    use std::io::Read;

    let app = TestApp::new(|config| config.experimental.native_api.ui = "embedded".into()).await;
    for path in ["/", "/ui", "/ui/a/", "/ui/a/b"] {
        for method in [Method::GET, Method::HEAD] {
            let response = app
                .client
                .request(method, app.url(path))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
            assert_eq!(response.headers()["location"], "/ui/");
        }
    }

    let navigation = app.client.get(app.url("/ui/a/b")).send().await.unwrap();
    let entry_url = navigation
        .url()
        .join(navigation.headers()["location"].to_str().unwrap())
        .unwrap();
    let response = app.client.get(entry_url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.url().path(), "/ui/");
    assert_eq!(response.headers()["content-type"], "text/html");
    let entry_url = response.url().clone();
    let index = response.text().await.unwrap();
    assert_eq!(
        index,
        include_str!(concat!(env!("HONK_DOONA_DIR"), "/index.html"))
    );
    let references = regex::Regex::new(r#"(?:src|href)="(\./[^"]+)""#).unwrap();
    let paths = references
        .captures_iter(&index)
        .map(|value| value[1].to_owned());
    for path in paths.chain(["./index.html".into(), "./sw.js".into()]) {
        let url = entry_url.join(&path).unwrap();
        let expected =
            std::fs::read(std::path::Path::new(env!("HONK_DOONA_DIR")).join(&path)).unwrap();
        for method in [Method::GET, Method::HEAD] {
            let response = app
                .client
                .request(method.clone(), url.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()["cache-control"],
                if path.starts_with("./assets/") {
                    "public, max-age=31536000, immutable"
                } else {
                    "no-cache"
                },
                "{path}"
            );
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response.headers().get("x-frame-options").is_none());
            assert_eq!(
                response.headers()["content-length"]
                    .to_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                expected.len()
            );
            let mime = match path.rsplit('.').next().unwrap() {
                "html" => "text/html",
                "js" => "text/javascript",
                "css" => "text/css",
                "svg" => "image/svg+xml",
                "webmanifest" => "application/manifest+json",
                "png" => "image/png",
                extension => panic!("unexpected entry asset extension: {extension}"),
            };
            assert_eq!(response.headers()["content-type"], mime, "{path}");
            let body = response.bytes().await.unwrap();
            if method == Method::HEAD {
                assert!(body.is_empty(), "{path}");
            } else {
                assert_eq!(body.as_ref(), expected, "{path}");
            }
        }
        if path.ends_with(".png") {
            continue;
        }
        for encoding in ["br", "gzip"] {
            let response = app
                .client
                .get(url.clone())
                .header("accept-encoding", format!("identity;q=0.5, {encoding}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let Some(content_encoding) = response.headers().get("content-encoding") else {
                // The build stores a file as is when compression does not shrink it.
                assert!(expected.len() < 1024, "{path}");
                assert_eq!(response.headers()["vary"], "Origin", "{path}");
                assert_eq!(response.bytes().await.unwrap().as_ref(), expected, "{path}");
                continue;
            };
            assert_eq!(content_encoding, encoding, "{path}");
            assert_eq!(response.headers()["vary"], "accept-encoding", "{path}");
            let length = response.headers()["content-length"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let body = response.bytes().await.unwrap();
            assert_eq!(body.len(), length, "{path}");
            assert!(body.len() < expected.len(), "{path}");
            let mut decoded = Vec::new();
            if encoding == "br" {
                brotli::Decompressor::new(body.as_ref(), 4096)
                    .read_to_end(&mut decoded)
                    .unwrap();
            } else {
                flate2::read::GzDecoder::new(body.as_ref())
                    .read_to_end(&mut decoded)
                    .unwrap();
            }
            assert_eq!(decoded, expected, "{path}");
        }
    }
    let webp = std::fs::read_dir(std::path::Path::new(env!("HONK_DOONA_DIR")).join("assets"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".webp"))
        .unwrap();
    let response = app
        .client
        .get(entry_url.join(&format!("./assets/{webp}")).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{webp}");
    assert_eq!(response.headers()["content-type"], "image/webp", "{webp}");
    for path in [
        "/ui/missing.js",
        "/ui/assets/missing",
        "/ui/fonts/missing",
        "/ui/icons/missing",
        "/ui/missing.webmanifest",
        "/ui/provenance/source.tar.gz",
    ] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_ne!(response.text().await.unwrap(), index);
    }
    for path in [
        "/ui/../private",
        "/ui/%2e%2e/private",
        "/ui/%2E%2E%2Fprivate",
        "/ui/%2e%2e%5cprivate",
        "/ui/%00",
        "/ui/%FF",
        "/ui/%zz",
    ] {
        let response = raw_request(&app, path, "", b"").await;
        assert!(
            (400..500).contains(&response.status),
            "{path}: {}",
            response.status
        );
        assert_ne!(response.body, index.as_bytes());
    }
    for (header, value) in [
        ("host", "attacker.example"),
        ("origin", "https://attacker.example"),
    ] {
        let response = app
            .client
            .get(app.url("/ui/"))
            .header(header, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    // Serving the UI does not exempt the API: a protected route still needs its bearer.
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn ui_without_available_assets_rejects_startup() {
    let directory = tempfile::tempdir().unwrap();
    for path in [
        directory.path().to_str().unwrap(),
        #[cfg(not(feature = "native-ui"))]
        "embedded",
    ] {
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.secret = SECRET.into();
        config.experimental.native_api.ui = path.into();
        config.validate_detailed().unwrap();
        config.ensure_builtin_nodes();
        let mut control = control_plane(config);
        assert!(
            NativeState::new(
                &mut control,
                "127.0.0.1:9527".parse().unwrap(),
                SystemTime::now(),
                Instant::now(),
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn slow_public_file_readers_release_capacity_at_the_connection_deadline() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), "hosting fixture").unwrap();
    let file = std::fs::File::create(directory.path().join("large.bin")).unwrap();
    let file_size = 64 * 1024 * 1024;
    file.set_len(file_size).unwrap();
    let app = TestApp::new(|config| {
        config.experimental.native_api.ui = directory.path().to_str().unwrap().into()
    })
    .await;
    let mut peers = Vec::new();
    for _ in 0..64 {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        let mut stream = socket.connect(app.addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /ui/large.bin HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    app.addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut header = Vec::new();
        timeout(IO_TIMEOUT, async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
                assert!(header.len() < 4096);
            }
        })
        .await
        .unwrap();
        let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
        assert!(header.starts_with("http/1.1 200 "));
        assert!(header.contains(&format!("content-length: {file_size}")));
        peers.push(stream);
    }
    let mut waiting = TcpStream::connect(app.addr).await.unwrap();
    waiting.write_all(format!("GET /api HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n", app.addr).as_bytes()).await.unwrap();
    assert!(
        timeout(Duration::from_millis(50), waiting.read_u8())
            .await
            .is_err()
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    let response = read_raw_response(&mut waiting, "/api").await;
    assert_eq!(response.status, 200);
    let mut first = peers.remove(0);
    socket2::SockRef::from(&first)
        .set_recv_buffer_size(4 * 1024 * 1024)
        .unwrap();
    drop(peers);
    let received = timeout(
        IO_TIMEOUT,
        tokio::io::copy(&mut first, &mut tokio::io::sink()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        received < file_size,
        "the socket must close with the large response incomplete"
    );
    app.shutdown().await;
}
