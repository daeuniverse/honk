use super::*;
use axum::body::to_bytes;

#[test]
fn query_parameters_reject_semantic_duplicates_and_name_wire_overflow() {
    let id = RequestId("dns-test".into());
    for query in [
        "type=A&type=TYPE1",
        "type=1&type=A",
        "domain=a&domain=b",
        "type=A&unknown=x",
    ] {
        let uri: Uri = format!("/api/v1/dns/query?{query}").parse().unwrap();
        assert!(parameters(&uri, &["domain", "type"], &id).is_err());
    }
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert!(validate_name(&maximum));
    assert!(!validate_name(&format!("{maximum}x")));
    assert!(!validate_name(&format!("{}.example", "x".repeat(64))));
    assert!(!validate_name("example..com"));
    assert!(!validate_name("example.com.."));
    assert_eq!(canonical_name("EXAMPLE.Com.", &id).unwrap(), "example.com.");
}

#[tokio::test]
async fn cache_snapshot_filters_before_budget_admission_and_freezes_selected_pages() {
    use crate::dns::cache::{CacheInvalidation, CacheKey, OperationKind};
    use crate::dns::forwarder::build_dns_query;
    use crate::dns::planner::RequestScope;
    use crate::dns::query::QueryContext;

    let mut config = honk_config::Config::default();
    config.dns.cache.max_size = 8192;
    let state = dns_state(config).await;
    let service = state.dns.cache().lock().await.service();
    let scope = RequestScope::Upstream(UpstreamTag::new("default").unwrap());
    for index in 0..320 {
        let mut response = build_dns_query(&format!("bulk-{index}.example"), 16);
        let key = CacheKey::new(
            &QueryContext::parse(&response).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 1, 44]);
        response.extend_from_slice(&32768u16.to_be_bytes());
        for _ in 0..128 {
            response.push(255);
            response.extend_from_slice(&[b'x'; 255]);
        }
        service.put_exact(key, response, 300, None);
    }
    let mut expected_ids = Vec::new();
    for ingress in [IngressProfile::Internal, IngressProfile::Tcp] {
        let mut response = build_dns_query("Selected.Example", 1);
        let key = CacheKey::new(
            &QueryContext::parse_with_profile(&response, ingress).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        service.put_exact(key.clone(), response, 300, None);
        expected_ids.push(service.entry_id(&key).unwrap());
    }
    expected_ids.sort();

    for query in ["", "?type=TXT"] {
        let (status, body) = cache_page(&state, query).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "snapshot_unavailable");
    }
    for query in ["?name=missing.example", "?domain=missing", "?type=AAAA"] {
        let (status, page) = cache_page(&state, query).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["total"], 0);
        assert_eq!(page["entries"], json!([]));
    }

    let filters = "?name=SELECTED.Example.&domain=LECTED.EXA&type=TYPE1&limit=1";
    let (status, first) = cache_page(&state, filters).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["total"], 2);
    assert_eq!(
        first["usage"],
        json!({"entries":"322","entry_capacity":"8192"})
    );
    assert_eq!(first["entries"][0]["entry_id"], expected_ids[0]);
    assert_eq!(first["entries"][0]["type"], "A");
    let cursor = first["next_cursor"].as_str().unwrap();
    service.invalidate(CacheInvalidation::All).await.unwrap();
    let (status, second) = cache_page(&state, &format!("{filters}&cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["total"], 2);
    assert_eq!(second["entries"][0]["entry_id"], expected_ids[1]);
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["usage"], first["usage"]);
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        cache_page(
            &state,
            &format!("?name=selected.example&type=AAAA&cursor={cursor}")
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (limit, _) = filters.rsplit_once("&limit=").unwrap();
    for (query, status) in [
        (
            format!("{limit}&limit=2&cursor={cursor}"),
            StatusCode::BAD_REQUEST,
        ),
        (format!("{filters}&cursor=missing:1"), StatusCode::GONE),
        (format!("{filters}&cursor=bad"), StatusCode::GONE),
    ] {
        assert_eq!(cache_page(&state, &query).await.0, status);
    }
}

#[tokio::test]
async fn cache_pages_end_early_at_the_response_budget_and_walk_every_entry_once() {
    use crate::dns::cache::{CacheKey, OperationKind};
    use crate::dns::forwarder::build_dns_query;
    use crate::dns::planner::RequestScope;
    use crate::dns::query::QueryContext;

    let mut config = honk_config::Config::default();
    config.dns.cache.max_size = 8192;
    let state = dns_state(config).await;
    let service = state.dns.cache().lock().await.service();
    let scope = RequestScope::Upstream(UpstreamTag::new("default").unwrap());
    let put = |name: &str, qtype: u16, rdata: &[u8]| {
        let mut response = build_dns_query(name, qtype);
        let key = CacheKey::new(
            &QueryContext::parse(&response).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(rdata);
        service.put_exact(key, response, 300, None);
    };
    for index in 0..600 {
        put(&format!("small-{index}.example"), 1, &[192, 0, 2, 1]);
    }
    let text = [[255u8].as_slice(), &[b'x'; 255]].concat().repeat(64);
    for index in 0..24 {
        put(&format!("large-{index}.example"), 16, &text);
    }

    for (filters, expected) in [
        ("?domain=small-&limit=1000", 600),
        ("?domain=large-&limit=100&detail=full", 24),
    ] {
        let mut ids = std::collections::BTreeSet::new();
        let mut pages = 0;
        let mut cursor: Option<String> = None;
        loop {
            let query = match &cursor {
                Some(cursor) => format!("{filters}&cursor={cursor}"),
                None => filters.to_owned(),
            };
            let (status, page) = cache_page(&state, &query).await;
            assert_eq!(status, StatusCode::OK, "{query}");
            assert_eq!(page["total"], expected);
            let entries = page["entries"].as_array().unwrap();
            assert!(!entries.is_empty());
            for entry in entries {
                assert!(ids.insert(entry["entry_id"].as_str().unwrap().to_owned()));
            }
            pages += 1;
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        assert_eq!(ids.len(), expected, "{filters}");
        assert!(
            pages > 1,
            "{filters} fit one page; the budget was not reached"
        );
    }

    // An entry whose answers exceed any page is served alone, so the walk still reaches every entry.
    for index in 0..3 {
        let domain = [
            format!("wide{index}{}", "d".repeat(57)),
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(61),
        ]
        .join(".");
        let mut response = build_dns_query(&domain, 5);
        let key = CacheKey::new(
            &QueryContext::parse(&response).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        let count: u16 = if index == 1 { 2000 } else { 1 };
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&count.to_be_bytes());
        for _ in 0..count {
            response.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 44, 0, 2, 0xc0, 12]);
        }
        service.put_exact(key, response, 300, None);
    }
    let mut sizes = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(cursor) => format!("?domain=wide&limit=3&detail=full&cursor={cursor}"),
            None => "?domain=wide&limit=3&detail=full".to_owned(),
        };
        let (status, page) = cache_page(&state, &query).await;
        assert_eq!(status, StatusCode::OK, "{query}");
        for entry in page["entries"].as_array().unwrap() {
            sizes.push(entry["answers"].as_array().unwrap().len());
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    sizes.sort_unstable();
    assert_eq!(sizes, [1, 1, 2000]);
}

async fn cache_page(state: &NativeState, query: &str) -> (StatusCode, Value) {
    let uri = format!("/api/v1/dns/cache{query}").parse().unwrap();
    let response = cache(state, &uri, &RequestId("cache-test".into()))
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn dns_state(mut config: honk_config::Config) -> NativeState {
    use std::sync::Arc;
    use std::time::Instant;

    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;
    config.ensure_builtin_nodes();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        crate::routing::Router::new(&[], "direct").unwrap(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    let state = NativeState::new(
        &mut control,
        "127.0.0.1:9527".parse().unwrap(),
        SystemTime::now(),
        Instant::now(),
    )
    .await
    .unwrap();
    control.publish_phase(crate::control::EnginePhase::Running);
    state
}

#[tokio::test]
async fn root_query_replays_lists_and_invalidates_only_root() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut upstream = tokio::task::JoinSet::new();
    upstream.spawn(async move {
        for name in [".", "ordinary.example."] {
            let mut wire = [0u8; 512];
            let (length, peer) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
                    .await
                    .unwrap()
                    .unwrap();
            let question = records::question(&wire[..length], IngressProfile::Api).unwrap();
            assert_eq!(question.name, name);
            assert_eq!(question.rtype, "NS");
            if name == "." {
                assert_eq!(&wire[12..length], &[0, 0, 2, 0, 1]);
            }
            let mut response = wire[..length].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 1, 44, 0, 12]);
            response.extend_from_slice(b"\x02ns\x07example\0");
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut config = honk_config::Config::default();
    config.dns.cache.ttl = 0;
    config.dns.upstream = vec![honk_config::dns::DnsUpstream {
        name: "default".into(),
        address: address.to_string(),
        protocol: honk_config::types::DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    }];
    let state = dns_state(config).await;
    let id = RequestId("root-dns".into());
    for name in ["", "..", "ordinary..example"] {
        let request = query_request("", json!({"domain": name, "type": ["NS"]}));
        let response = query(&state, request, &id)
            .await
            .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut root_entry = Value::Null;
    for (name, expected, cached) in [
        (".", ".", false),
        (".", ".", true),
        ("OrDiNaRy.Example.", "ordinary.example.", false),
        ("ordinary.example", "ordinary.example.", true),
    ] {
        let request = query_request("?detail=full", json!({"domain": name, "type": ["NS"]}));
        let response = tokio::time::timeout(Duration::from_secs(2), query(&state, request, &id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["domain"], expected);
        let result = &value["results"][0];
        assert_eq!(
            result["question"],
            json!({"name":expected,"type":"NS","class":"IN"})
        );
        assert_eq!(result["status"], "NOERROR");
        assert_eq!(result["cached"], cached);
        assert_eq!(
            result["upstream"],
            if cached {
                Value::Null
            } else {
                json!("default")
            }
        );
        assert_eq!(result["answers"].as_array().unwrap().len(), 1);
        let answer = &result["answers"][0];
        assert_eq!(answer["name"], expected);
        assert_eq!(answer["type"], "NS");
        assert_eq!(answer["class"], "IN");
        assert_eq!(answer["data"], "ns.example.");
        assert!((1..=300).contains(&answer["ttl"].as_u64().unwrap()));
        if expected == "." {
            if cached {
                assert_eq!(result["cache_entry_id"], root_entry);
            } else {
                assert!(result["cache_entry_id"].is_string());
                root_entry = result["cache_entry_id"].clone();
            }
        }
    }
    upstream.join_next().await.unwrap().unwrap();

    let (status, page) = cache_page(&state, "?name=.&type=NS&detail=full").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 1);
    assert_eq!(page["entries"][0]["entry_id"], root_entry);
    assert_eq!(page["entries"][0]["domain"], ".");
    assert_eq!(page["entries"][0]["answers"][0]["name"], ".");
    assert_eq!(page["entries"][0]["answers"][0]["data"], "ns.example.");
    for (kind, deleted) in [("A", 0), ("NS", 1)] {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/dns/cache?name=.&type={kind}"))
            .body(Body::empty())
            .unwrap();
        let response = delete_name(&state, request, &id).await.unwrap();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"matched":deleted,"deleted":deleted}),
        );
    }
    let (status, page) = cache_page(&state, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 1);
    assert_eq!(page["entries"][0]["domain"], "ordinary.example.");
    assert_eq!(cache_page(&state, "?name=.").await.1["total"], 0);
    state.dns.provider().unwrap().shutdown().await;
}

fn query_request(query: &str, body: Value) -> Request {
    Request::post(format!("/api/v1/dns/query{query}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn query_takes_a_json_body_with_bounded_types() {
    let state = crate::native_api::tests::state().await;
    let status = |request| {
        let state = &state;
        async move {
            query(state, request, &RequestId("dns-test".into()))
                .await
                .unwrap_err()
                .into_response()
                .status()
        }
    };
    let types: Vec<_> = (1..=9).map(|value| format!("TYPE{value}")).collect();
    let body = json!({"domain": "example.com", "type": types});
    assert_eq!(
        status(query_request("", body)).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut request = query_request("", json!({"domain": "example.com"}));
    request.headers_mut().remove("content-type");
    assert_eq!(status(request).await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    for (query, body) in [
        ("?domain=example.com", json!({"domain": "example.com"})),
        ("", json!({"domain": "example.com", "type": []})),
        ("", json!({"domain": "example.com", "type": ["A", "TYPE1"]})),
        ("", json!({"domain": "example.com", "detail": "full"})),
        ("", json!({"type": ["A"]})),
    ] {
        assert_eq!(
            status(query_request(query, body.clone())).await,
            StatusCode::BAD_REQUEST,
            "{query} {body}"
        );
    }
}

#[tokio::test]
async fn rule_limit_never_hides_a_running_list() {
    let state = crate::native_api::tests::state().await;
    let rule = honk_config::dns::DnsResponseRule {
        conditions: Vec::new(),
        action: honk_config::dns::DnsResponseAction::Accept,
    };
    let mut config = (**state.config.read().await).clone();
    config.dns.routing.response.rules = vec![rule; 4096];
    *state.config.write().await = std::sync::Arc::new(config);
    let list = rules::snapshot(
        &state,
        std::time::Instant::now() + Duration::from_secs(5),
        &RequestId("test".into()),
    )
    .await
    .unwrap();
    assert_eq!(json!(list)["response"].as_array().unwrap().len(), 4097);
    let routing = &state.config.read().await.dns.routing;
    assert_eq!(rules_capability(routing)["max_rules"], 4097);
}

#[tokio::test]
async fn rules_lock_wait_past_deadline_is_retryable_snapshot_unavailable() {
    let state = crate::native_api::tests::state().await;
    let _reload = state.config.write().await;
    let error = rules::snapshot(
        &state,
        std::time::Instant::now() + Duration::from_millis(20),
        &RequestId("test".into()),
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.headers()["retry-after"], "1");
}
