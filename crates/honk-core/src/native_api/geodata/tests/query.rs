use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

use honk_config::Config;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_outbound::proxy::ProxyRegistry;
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::control::{ControlPlane, EnginePhase};
use crate::dns::DnsResolver;
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::ebpf::mock::MockEbpfBackend;
use crate::native_api::{NativeServer, NativeState};
use crate::routing::{GeoRequirements, GeoSourceSet, Router};

const SECRET: &str = "geodata-query-secret-token";
const CLASH_SECRET: &str = "clash-secret-token-value";
const QUERY_PATH: &str = "/api/v1/x-honk/geodata/query";
const MAX_RESPONSE_BYTES: usize = 262_144;

struct NoDns;

#[async_trait::async_trait]
impl DnsUpstreamPool for NoDns {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("geodata content queries must never issue DNS queries")
    }
}

struct QueryServer {
    dir: TempDir,
    addr: SocketAddr,
    client: Client,
    state: Weak<NativeState>,
    server: NativeServer,
}

impl QueryServer {
    async fn start(
        geosite: Option<Vec<u8>>,
        geoip: Option<Vec<u8>>,
        configure: impl FnOnce(&mut Config),
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        if let Some(bytes) = &geosite {
            std::fs::write(data_dir.join("geosite.dat"), bytes).unwrap();
        }
        if let Some(bytes) = &geoip {
            std::fs::write(data_dir.join("geoip.dat"), bytes).unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.global.data_dir = data_dir.to_str().unwrap().into();
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.listen = addr.to_string();
        config.experimental.native_api.secret = SECRET.into();
        config.experimental.clash_api.secret = CLASH_SECRET.into();
        if geosite.is_some() {
            config.routing.rules.push(RoutingRule {
                name: "geosite-seed".into(),
                condition: RoutingCondition {
                    geosite: vec!["seed".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: 0,
            });
        }
        if geoip.is_some() {
            config.routing.rules.push(RoutingRule {
                name: "geoip-seed".into(),
                condition: RoutingCondition {
                    geo_ip: vec!["seed".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 1,
                must: false,
                mark: 0,
            });
        }
        config.ensure_builtin_nodes();
        configure(&mut config);

        let requirements = GeoRequirements::for_traffic(&config.routing.rules)
            .union(&DnsRouter::geo_requirements(&config.dns));
        let geo_sources =
            GeoSourceSet::load_captured(&requirements, Path::new(&config.global.data_dir), |p| {
                std::fs::read(p).map(Arc::from)
            })
            .unwrap();
        let router = Router::from_config_with_geo_sources(&config.routing, &geo_sources).unwrap();
        let forwarder = Arc::new(DnsForwarder::new(
            Arc::new(NoDns),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            Arc::new(DnsRouter::new_with_geo_sources(&config.dns, &geo_sources).unwrap()),
        ));
        let resolver = DnsResolver::with_forwarder(&config.dns, Arc::clone(&forwarder)).unwrap();
        let mut control = ControlPlane::new(
            config,
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        control.publish_phase(EnginePhase::Running);
        let state = Arc::new(
            NativeState::new(&mut control, addr, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let weak = Arc::downgrade(&state);
        let server = NativeServer::start(listener, state);
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            dir,
            addr,
            client,
            state: weak,
            server,
        }
    }

    fn url(&self, target: &str) -> String {
        format!("http://{}{target}", self.addr)
    }

    async fn get(&self, query: &str) -> Response {
        let target = if query.is_empty() {
            QUERY_PATH.to_owned()
        } else {
            format!("{QUERY_PATH}?{query}")
        };
        self.client
            .get(self.url(&target))
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap()
    }

    async fn shutdown(self) {
        let dir = self.dir;
        drop(self.client);
        timeout(Duration::from_secs(6), self.server.shutdown())
            .await
            .unwrap();
        assert!(self.state.upgrade().is_none());
        drop(dir);
    }
}

fn push_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn push_len_delim(tag: u32, payload: &[u8], out: &mut Vec<u8>) {
    push_varint(((tag as u64) << 3) | 2, out);
    push_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn push_varint_field(tag: u32, v: u64, out: &mut Vec<u8>) {
    push_varint((tag as u64) << 3, out);
    push_varint(v, out);
}

fn domain_entry(dtype: u64, value: &str, attrs: &[(&str, Option<bool>)]) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint_field(1, dtype, &mut out);
    push_len_delim(2, value.as_bytes(), &mut out);
    for (key, flag) in attrs {
        let mut attr = Vec::new();
        push_len_delim(1, key.as_bytes(), &mut attr);
        if let Some(flag) = flag {
            push_varint_field(2, u64::from(*flag), &mut attr);
        }
        push_len_delim(3, &attr, &mut out);
    }
    out
}

fn geosite_dat(categories: &[(&str, Vec<Vec<u8>>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (code, entries) in categories {
        let mut cat = Vec::new();
        push_len_delim(1, code.as_bytes(), &mut cat);
        for entry in entries {
            push_len_delim(2, entry, &mut cat);
        }
        push_len_delim(1, &cat, &mut out);
    }
    out
}

type CidrSpec<'a> = (&'a [u8], u32);

fn geoip_dat(categories: &[(&str, Vec<CidrSpec<'_>>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (code, cidrs) in categories {
        let mut cat = Vec::new();
        push_len_delim(1, code.as_bytes(), &mut cat);
        for (ip, prefix) in cidrs {
            let mut cidr = Vec::new();
            push_len_delim(1, ip, &mut cidr);
            push_varint_field(2, u64::from(*prefix), &mut cidr);
            push_len_delim(2, &cidr, &mut cat);
        }
        push_len_delim(1, &cat, &mut out);
    }
    out
}

async fn ok_json(response: Response) -> (usize, Value) {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let bytes = response.bytes().await.unwrap();
    let len = bytes.len();
    assert!(len <= MAX_RESPONSE_BYTES, "response {len} > 256 KiB");
    (len, serde_json::from_slice(&bytes).unwrap())
}

async fn err_code(response: Response, status: StatusCode, code: &str) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], code);
    assert!(!body.to_string().contains(SECRET));
    assert!(!body.to_string().contains(CLASH_SECRET));
    body
}

#[tokio::test]
async fn geodata_query_requires_admin_auth_and_advertises_x_honk_capability() {
    let site = geosite_dat(&[("SEED", vec![domain_entry(2, "seed.example", &[])])]);
    let app = QueryServer::start(Some(site), None, |_| {}).await;

    let unauth = app
        .client
        .get(app.url(&format!("{QUERY_PATH}?action=list")))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.headers()["www-authenticate"], "Bearer");
    err_code(unauth, StatusCode::UNAUTHORIZED, "authentication_required").await;

    let clash_token = app
        .client
        .get(app.url(&format!("{QUERY_PATH}?action=list")))
        .bearer_auth(CLASH_SECRET)
        .send()
        .await
        .unwrap();
    err_code(
        clash_token,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;

    let discovery: Value = app
        .client
        .get(app.url("/api"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["links"]["x-honk"]["geodata_query"], QUERY_PATH);

    let caps: Value = app
        .client
        .get(app.url("/api/v1/capabilities"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cap = &caps["resources"]["x-honk"]["geodata_query"];
    assert_eq!(cap["available"], true);
    assert_eq!(cap["assets"], json!(["geosite"]));
    assert_eq!(cap["max_response_bytes"], MAX_RESPONSE_BYTES);
    assert_eq!(cap["per_principal_requests_per_minute"], 30);

    let (_, list) = ok_json(app.get("action=list").await).await;
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"], json!([{"code": "seed", "count": 1}]));

    let head = app
        .client
        .head(app.url(&format!("{QUERY_PATH}?action=list")))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.bytes().await.unwrap().is_empty());

    let post = app
        .client
        .request(Method::POST, app.url(&format!("{QUERY_PATH}?action=list")))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(post.headers()["allow"], "GET, HEAD");
    err_code(post, StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed").await;

    app.shutdown().await;
}

#[tokio::test]
async fn geodata_query_lists_categories_filters_attrs_and_reverse_matches_domain_and_ip() {
    let site = geosite_dat(&[
        ("SEED", vec![domain_entry(3, "seed.example", &[])]),
        (
            "SHOP",
            vec![
                domain_entry(2, "mall.example", &[("cn", Some(true))]),
                domain_entry(2, "global.example", &[("cn", Some(false))]),
                domain_entry(3, "exact.shop", &[("CN", Some(true)), ("ads", None)]),
                domain_entry(0, "ShopKey", &[]),
                domain_entry(1, "^promo-[0-9]+\\.example$", &[]),
            ],
        ),
        (
            "GOOGLE",
            vec![domain_entry(2, "google.com", &[("ads", Some(true))])],
        ),
    ]);
    let ip = geoip_dat(&[
        ("SEED", vec![(&[198, 51, 100, 0], 24)]),
        ("BROAD", vec![(&[1, 0, 0, 0], 8)]),
        ("NARROW", vec![(&[1, 1, 1, 0], 24)]),
        ("TIE", vec![(&[1, 1, 1, 0], 24)]),
        (
            "V6",
            vec![(
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            )],
        ),
    ]);
    let app = QueryServer::start(Some(site), Some(ip), |_| {}).await;

    let (_, site_list) = ok_json(app.get("action=list").await).await;
    assert_eq!(site_list["kind"], "geosite");
    assert_eq!(site_list["total"], 3);
    assert_eq!(site_list["truncated"], false);
    assert_eq!(site_list["next_offset"], Value::Null);
    assert_eq!(
        site_list["items"],
        json!([
            {"code": "google", "count": 1},
            {"code": "seed", "count": 1},
            {"code": "shop", "count": 5},
        ])
    );

    let (_, filtered_list) = ok_json(app.get("kind=geoip&action=list&filter=AR").await).await;
    assert_eq!(filtered_list["kind"], "geoip");
    assert_eq!(filtered_list["total"], 1);
    assert_eq!(
        filtered_list["items"],
        json!([{"code": "narrow", "count": 1}])
    );

    let (_, show_attr) = ok_json(app.get("action=show&code=SHOP&attr=Cn").await).await;
    assert_eq!(show_attr["code"], "shop");
    assert_eq!(show_attr["attr"], "Cn");
    assert_eq!(show_attr["total"], 2);
    assert_eq!(
        show_attr["items"],
        json!([
            {"type": "domain", "value": "mall.example", "attrs": ["cn"]},
            {"type": "full", "value": "exact.shop", "attrs": ["CN", "ads"]},
        ])
    );

    let (_, show_neg_attr) = ok_json(app.get("action=show&code=shop&attr=!cn").await).await;
    assert_eq!(show_neg_attr["total"], 1);
    assert_eq!(
        show_neg_attr["items"],
        json!([{"type": "domain", "value": "global.example", "attrs": ["!cn"]}])
    );

    let (_, show_empty_attr) = ok_json(app.get("action=show&code=shop&attr=missing").await).await;
    assert_eq!(show_empty_attr["total"], 0);
    assert_eq!(show_empty_attr["items"], json!([]));

    err_code(
        app.get("action=show&code=no-such-category").await,
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;

    let (_, show_geoip) = ok_json(app.get("kind=geoip&action=show&code=V6").await).await;
    assert_eq!(show_geoip["code"], "v6");
    assert_eq!(show_geoip["items"], json!([{"cidr": "2001:db8::/32"}]));

    let (_, domain_hits) = ok_json(app.get("action=find&value=sub.mall.example.").await).await;
    assert_eq!(domain_hits["total"], 1);
    assert_eq!(
        domain_hits["items"],
        json!([{"code": "shop", "type": "domain", "value": "mall.example", "attrs": ["cn"]}])
    );

    let (_, regex_hits) = ok_json(app.get("action=find&value=promo-42.example").await).await;
    assert_eq!(regex_hits["total"], 1);
    assert_eq!(regex_hits["items"][0]["type"], "regexp");

    let (_, ip_hits) = ok_json(app.get("kind=geoip&action=find&value=::ffff:1.1.1.9").await).await;
    assert_eq!(ip_hits["query"], "1.1.1.9");
    assert_eq!(ip_hits["total"], 2);
    assert_eq!(
        ip_hits["items"],
        json!([
            {"code": "narrow", "cidr": "1.1.1.0/24"},
            {"code": "tie", "cidr": "1.1.1.0/24"},
        ])
    );

    let (_, v6_hits) = ok_json(app.get("kind=geoip&action=find&value=2001:db8::1").await).await;
    assert_eq!(
        v6_hits["items"],
        json!([{"code": "v6", "cidr": "2001:db8::/32"}])
    );

    let (_, ip_miss) = ok_json(app.get("kind=geoip&action=find&value=9.9.9.9").await).await;
    assert_eq!(ip_miss["total"], 0);
    assert_eq!(ip_miss["items"], json!([]));

    app.shutdown().await;
}

#[tokio::test]
async fn geodata_query_paginates_large_categories_strictly_within_256_kib() {
    let total_entries = 4_200usize;
    let entries: Vec<Vec<u8>> = (0..total_entries)
        .map(|i| {
            let domain =
                format!("very-long-subdomain-entry-{i:05}.regional-cdn-cluster.example.org");
            domain_entry(2, &domain, &[("cn", Some(true)), ("cdn", None)])
        })
        .collect();
    let site = geosite_dat(&[
        ("SEED", vec![domain_entry(3, "seed.example", &[])]),
        ("CN", entries),
    ]);
    let app = QueryServer::start(Some(site), None, |_| {}).await;

    let mut collected = Vec::new();
    let mut offset = 0usize;
    let mut pages = 0usize;
    loop {
        let (byte_len, page) = ok_json(
            app.get(&format!("action=show&code=cn&limit=5000&offset={offset}"))
                .await,
        )
        .await;
        pages += 1;
        assert!(byte_len <= MAX_RESPONSE_BYTES, "page {pages}: {byte_len}");
        assert_eq!(page["total"], total_entries);
        assert_eq!(page["offset"], offset);
        let items = page["items"].as_array().unwrap();
        assert!(!items.is_empty());
        for item in items {
            collected.push(item["value"].as_str().unwrap().to_owned());
        }
        if page["truncated"].as_bool().unwrap() {
            let next = page["next_offset"].as_u64().unwrap() as usize;
            assert_eq!(next, offset + items.len());
            offset = next;
        } else {
            assert_eq!(page["next_offset"], Value::Null);
            break;
        }
    }
    assert!(
        pages >= 2,
        "4200 ~110B entries must span multiple 256 KiB pages"
    );
    assert_eq!(collected.len(), total_entries);
    assert_eq!(
        collected[0],
        "very-long-subdomain-entry-00000.regional-cdn-cluster.example.org"
    );
    assert_eq!(
        collected[total_entries - 1],
        format!(
            "very-long-subdomain-entry-{:05}.regional-cdn-cluster.example.org",
            total_entries - 1
        )
    );

    let (_, past_end) = ok_json(
        app.get(&format!(
            "action=show&code=cn&limit=10&offset={total_entries}"
        ))
        .await,
    )
    .await;
    assert_eq!(past_end["items"], json!([]));
    assert_eq!(past_end["truncated"], false);
    assert_eq!(past_end["next_offset"], Value::Null);

    app.shutdown().await;
}

#[tokio::test]
async fn geodata_query_masks_listener_secrets_and_handles_missing_or_mutated_assets() {
    let empty_app = QueryServer::start(None, None, |_| {}).await;
    let caps: Value = empty_app
        .client
        .get(empty_app.url("/api/v1/capabilities"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        caps["resources"]["x-honk"]["geodata_query"]["available"],
        false
    );
    err_code(
        empty_app.get("action=list").await,
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    err_code(
        empty_app.get("kind=geoip&action=list").await,
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    empty_app.shutdown().await;

    let mixed_secret = "MixedCaseSecret99";
    let site = geosite_dat(&[
        (
            "SEED",
            vec![domain_entry(
                2,
                &format!("sub.{SECRET}.example"),
                &[(mixed_secret, Some(true)), ("short", None)],
            )],
        ),
        (
            &format!("CAT-{mixed_secret}"),
            vec![domain_entry(3, "mixed.example", &[])],
        ),
    ]);
    let ip = geoip_dat(&[("SEED", vec![(&[198, 51, 100, 0], 24)])]);
    let app = QueryServer::start(Some(site.clone()), Some(ip), |cfg| {
        cfg.experimental.clash_api.secret = mixed_secret.into();
        let data_dir = Path::new(&cfg.global.data_dir);
        let real_geoip = data_dir.join("real-geoip.dat");
        let link_geoip = data_dir.join("geoip.dat");
        std::fs::rename(&link_geoip, &real_geoip).unwrap();
        std::os::unix::fs::symlink(&real_geoip, &link_geoip).unwrap();
    })
    .await;
    let (_, symlinked_geoip) = ok_json(app.get("kind=geoip&action=list").await).await;
    assert_eq!(
        symlinked_geoip["items"],
        json!([{"code": "seed", "count": 1}])
    );

    let (_, list_masked) = ok_json(app.get("action=list").await).await;
    assert!(!list_masked.to_string().contains(mixed_secret));
    assert_eq!(list_masked["items"][0]["code"], "cat-<redacted>");

    let (_, shown) = ok_json(app.get("action=show&code=seed").await).await;
    let raw = shown.to_string();
    assert!(!raw.contains(SECRET), "{raw}");
    assert!(!raw.contains(mixed_secret), "{raw}");
    assert_eq!(shown["items"][0]["value"], "sub.<redacted>.example");
    assert_eq!(shown["items"][0]["attrs"], json!(["<redacted>", "short"]));

    let geosite_path = app.dir.path().join("geosite.dat");
    let mut flipped = site.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    std::fs::write(&geosite_path, &flipped).unwrap();
    let mutated = app.get("action=show&code=seed").await;
    assert_eq!(mutated.headers()["retry-after"], "1");
    let body = err_code(
        mutated,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    assert!(!body.to_string().contains(app.dir.path().to_str().unwrap()));

    struct FifoWakeGuard(std::path::PathBuf);
    impl Drop for FifoWakeGuard {
        fn drop(&mut self) {
            let _ = nix::fcntl::open(
                &self.0,
                nix::fcntl::OFlag::O_RDWR
                    | nix::fcntl::OFlag::O_NONBLOCK
                    | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            );
        }
    }

    std::fs::remove_file(&geosite_path).unwrap();
    nix::unistd::mkfifo(
        &geosite_path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let _fifo_guard = FifoWakeGuard(geosite_path);
    let fifo_resp = app
        .client
        .get(app.url(&format!("{QUERY_PATH}?action=show&code=seed")))
        .bearer_auth(SECRET)
        .timeout(Duration::from_millis(800))
        .send()
        .await
        .expect("writerless FIFO replacement must not block geodata query");
    assert_eq!(fifo_resp.headers()["retry-after"], "1");
    err_code(
        fifo_resp,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;

    app.shutdown().await;
}

#[tokio::test]
async fn geodata_query_validates_parameters_before_spending_rate_budget() {
    let site = geosite_dat(&[("SEED", vec![domain_entry(3, "seed.example", &[])])]);
    let app = QueryServer::start(Some(site), None, |_| {}).await;

    for bad_query in [
        "",
        "action=unknown",
        "kind=mmdb&action=list",
        "action=list&action=show",
        "action=list&unknown=1",
        "action=list&code=seed",
        "action=list&value=seed.example",
        "action=list&attr=cn",
        "action=list&filter=",
        "action=show",
        "action=show&code=",
        "action=show&code=seed@cn",
        "action=show&code=seed&value=x",
        "action=show&code=seed&filter=x",
        "action=show&code=seed&attr=",
        "kind=geoip&action=show&code=seed&attr=cn",
        "action=find",
        "action=find&value=",
        "action=find&value=bad%20domain",
        "action=find&value=seed.example&code=seed",
        "action=find&value=seed.example&attr=cn",
        "kind=geoip&action=find&value=not-an-ip",
        "action=list&limit=0",
        "action=list&limit=5001",
        "action=list&limit=+10",
        "action=list&offset=-1",
        "action=list&offset=+1",
    ] {
        err_code(
            app.get(bad_query).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }

    for _ in 0..5 {
        err_code(
            app.get("kind=geoip&action=list").await,
            StatusCode::NOT_FOUND,
            "capability_not_supported",
        )
        .await;
    }

    for _ in 0..30 {
        ok_json(app.get("action=list").await).await;
    }

    let limited = app.get("action=list").await;
    assert!(limited.headers().contains_key("retry-after"));
    err_code(limited, StatusCode::TOO_MANY_REQUESTS, "rate_limited").await;

    app.shutdown().await;
}
