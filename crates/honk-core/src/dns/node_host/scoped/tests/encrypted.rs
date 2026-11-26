use super::*;

#[cfg(feature = "native-api")]
#[tokio::test]
async fn download_dns_bootstrap_ignores_the_primary_node_address_pin() {
    let bootstrap = server(Ipv4Addr::LOCALHOST, false).await;
    let upstream = server(Ipv4Addr::new(192, 0, 2, 82), true).await;
    let sub = provider(
        "provider",
        &format!(
            "nameserver: ['tcp://dns.provider.test:{}']\nipv6: false",
            upstream.address.port()
        ),
    );
    let mut link =
        reqwest::Url::parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@dns.provider.test:443")
            .unwrap();
    link.query_pairs_mut()
        .append_pair("type", "xhttp")
        .append_pair("security", "tls")
        .append_pair(
            "extra",
            r#"{"downloadSettings":{"address":"download.provider.test","port":8443,"network":"xhttp","security":"tls","alpn":["h2"]}}"#,
        );
    let mut node = Node::from_share_link(link.as_str()).unwrap();
    node.subscription_id = Some(sub.id);
    let mut config = Config::default();
    config.global.bootstrap_resolver = bootstrap.address.to_string();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.nodes.push(node);
    config.subscriptions.push(sub);
    let (registry, _runtime, resources) = generation(&config, 4);
    let addresses = tokio::time::timeout(
        Duration::from_secs(2),
        registry.scope_node_dials(
            config.nodes[0].id,
            registry.scope_pinned_dials(
                "dns.provider.test",
                "127.0.0.2".parse().unwrap(),
                registry.resolve_node_host(config.nodes[0].id, "download.provider.test"),
            ),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 82))]);
    assert_eq!(*upstream.requests.lock(), ["download.provider.test"]);
    assert!(!bootstrap.requests.lock().is_empty());
    assert!(
        bootstrap
            .requests
            .lock()
            .iter()
            .all(|host| host == "dns.provider.test")
    );
    resources.close().await;
}

#[test]
fn query_only_https_import_keeps_endpoint_hostname_and_default_path() {
    let sub = provider(
        "provider",
        "nameserver: ['https://dns.provider.test:39933?token=x/y']",
    );
    let upstream = &sub.imported_dns.as_ref().unwrap().nameservers[0];
    let endpoint = crate::dns::endpoint::DnsEndpoint::parse(
        &upstream.address,
        upstream.protocol,
        upstream.tls_server_name.as_deref(),
    )
    .unwrap();
    assert_eq!(endpoint.host, "dns.provider.test");
    assert_eq!(endpoint.sni, "dns.provider.test");
    assert_eq!(endpoint.port, 39933);
    assert_eq!(endpoint.path, "/dns-query?token=x/y");
}

#[tokio::test]
async fn imported_doh_bootstraps_hostname_and_preserves_tls_and_http_endpoint() {
    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["dns.provider.test".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![CertificateDer::from(certificate.cert)], key)
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let bootstrap = server(Ipv4Addr::LOCALHOST, false).await;
    let expected = Ipv4Addr::new(192, 0, 2, 72);
    let (observed, receive) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let sni = tls.get_ref().1.server_name().map(str::to_owned);
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let authority = request.uri().authority().unwrap().as_str().to_owned();
        let path = request.uri().path_and_query().unwrap().as_str().to_owned();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/dns-message"
        );
        let response_task = tokio::spawn(async move {
            let mut body = request.into_body();
            let mut query = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                query.extend_from_slice(&bytes);
                body.flow_control().release_capacity(bytes.len()).unwrap();
            }
            let names = parking_lot::Mutex::new(Vec::new());
            let response = answer(&query, expected, &names);
            respond
                .send_response(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap()
                .send_data(bytes::Bytes::from(response), true)
                .unwrap();
            observed
                .send((sni, authority, path, names.into_inner()))
                .unwrap();
        });
        while connection.accept().await.is_some() {}
        response_task.await.unwrap();
    });
    let sub = provider(
        "provider",
        &format!(
            "default-nameserver: ['udp://{}']\nnameserver: ['https://dns.provider.test:{}/api-query?source=node']\nipv6: false",
            bootstrap.address,
            endpoint.port()
        ),
    );
    let mut node = Node::from_share_link("socks5://unreachable-node.provider.test:443").unwrap();
    node.subscription_id = Some(sub.id);
    let mut config = Config::default();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.nodes.push(node);
    config.subscriptions.push(sub);
    let (registry, _runtime, resources) = generation(&config, 4);
    let imported = &resources.nodes[&config.nodes[0].id];
    let dns = imported.claim.imported.as_ref().unwrap();
    imported
        .pool
        .as_ref()
        .unwrap()
        .seed_test_doh_connector(
            &dns.nameservers[0].name,
            endpoint,
            honk_outbound::tls::build_dns_connector(true, b"\x02h2").unwrap(),
        )
        .await;
    let addresses = tokio::time::timeout(
        Duration::from_secs(3),
        registry.resolve_node_host(config.nodes[0].id, config.nodes[0].host()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, [IpAddr::V4(expected)]);
    let (sni, authority, path, names) = receive.await.unwrap();
    assert_eq!(sni.as_deref(), Some("dns.provider.test"));
    assert_eq!(authority, format!("dns.provider.test:{}", endpoint.port()));
    assert_eq!(path, "/api-query?source=node");
    assert_eq!(names, ["unreachable-node.provider.test"]);
    assert!(!bootstrap.requests.lock().is_empty());
    assert!(
        bootstrap
            .requests
            .lock()
            .iter()
            .all(|name| name == "dns.provider.test")
    );
    resources.close().await;
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn imported_policy_nxdomain_never_queries_its_default_or_local_fallback() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let hits = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = Arc::clone(&hits);
    let negative = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let question = crate::dns::query::QueryContext::parse(&buffer[..size]).unwrap();
            captured
                .lock()
                .push(question.qname().unwrap().to_domain_name().unwrap());
            let mut response =
                crate::dns::forwarder::make_empty_response(&buffer[..size], &question);
            response[3] = (response[3] & 0xf0) | 3;
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let fallback = server(Ipv4Addr::new(192, 0, 2, 73), false).await;
    let sub = provider(
        "provider",
        &format!(
            "nameserver: ['udp://{}']\nnameserver-policy:\n '+.provider.test': ['udp://{}']\nipv6: false",
            fallback.address, address
        ),
    );
    let mut node = Node::from_share_link("socks5://node.provider.test:443").unwrap();
    node.subscription_id = Some(sub.id);
    let mut config = Config::default();
    config.dns.strategy = DnsStrategy::Ipv4Only;
    config.global.bootstrap_resolver = fallback.address.to_string();
    config.dns.upstream[0].address = fallback.address.to_string();
    config.nodes.push(node);
    config.subscriptions.push(sub);
    let (registry, _runtime, resources) = generation(&config, 4);
    assert!(
        registry
            .resolve_node_host(config.nodes[0].id, "node.provider.test")
            .await
            .is_err()
    );
    assert_eq!(*hits.lock(), ["node.provider.test"]);
    assert!(fallback.requests.lock().is_empty());
    resources.close().await;
    negative.abort();
    let _ = negative.await;
}
