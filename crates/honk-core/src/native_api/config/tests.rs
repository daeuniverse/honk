//! File-authority regressions through real HTTP, reload publication and supervisor handoff.

mod creation;
mod database;
mod dns_rules;
mod geodata;
mod geodata_activation;
mod geodata_settings;
mod groups;
mod management;
mod management_providers;
mod secrets;
mod source_authority;
mod transactions;
mod validation;

use super::ConfigService;
use super::coordinator::ConfigCoordinator;
use crate::configuration::SourceUpdate;
use crate::control::{ControlCommand, ControlPlane, ReloadBehavior, StartupDowngrades};
use crate::dns::DnsResolver;
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::ebpf::mock::MockEbpfBackend;
use crate::native_api::store::{DatabaseStartup, DbStore, SourceStore};
use crate::native_api::{NativeServer, NativeState};
use crate::routing::Router;
use crate::subscription::SubscriptionSupervisor;
use honk_config::{Config, parser::SourceLimits};
use honk_outbound::proxy::ProxyRegistry;
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

const SECRET: &str = "native-config-fixture-credential";
const WAIT: Duration = Duration::from_secs(5);
const CONFIG: &str = "/api/v1/config";
const VALIDATE: &str = "/api/v1/config/validate";
const RELOAD: &str = "/api/v1/operations/reload";

#[derive(Clone, Copy)]
enum Access {
    Metadata,
    Admin,
    Anonymous,
}

struct NoDns;

#[async_trait::async_trait]
impl DnsUpstreamPool for NoDns {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("configuration administration must not query DNS")
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    originals: HashMap<&'static str, String>,
    addr: SocketAddr,
    client: Client,
    authenticated: bool,
    /// The bearer token; a test that declares another native secret sets it.
    bearer: &'static str,
    state: Weak<NativeState>,
    service: Arc<ConfigService>,
    server: Option<NativeServer>,
    coordinator: Option<ConfigCoordinator>,
    subscriptions: Option<SubscriptionSupervisor>,
    commands: mpsc::Sender<ControlCommand>,
    control: JoinSet<anyhow::Result<()>>,
    reloads: Arc<AtomicUsize>,
    gates: Option<mpsc::UnboundedReceiver<oneshot::Sender<()>>>,
    database: Option<Arc<DbStore>>,
    /// A [`ReloadBehavior`] stored as `u8`.
    reject_reloads: Arc<AtomicU8>,
    startup_downgrades: StartupDowngrades,
    active: Arc<tokio::sync::RwLock<Arc<honk_config::Config>>>,
}

impl Fixture {
    async fn new(access: Access, gated: bool) -> Self {
        Self::new_custom(access, gated, |_, _| {}).await
    }

    async fn new_custom(
        access: Access,
        gated: bool,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
    ) -> Self {
        Self::build(access, gated, setup, false, false).await
    }

    /// Also opens the state db, so geodata sources are configurable.
    async fn new_with_state(
        access: Access,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
    ) -> Self {
        Self::build(access, false, setup, false, true).await
    }

    /// Starts from `--store db`: the tree is imported as revision 1.
    async fn new_db(access: Access) -> Self {
        Self::new_db_custom(access, |_, _| {}).await
    }

    async fn new_db_custom(
        access: Access,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
    ) -> Self {
        Self::build(access, false, setup, true, false).await
    }

    async fn build(
        access: Access,
        gated: bool,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
        db: bool,
        state_db: bool,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let settings = match access {
            Access::Metadata => format!("secret: '{SECRET}'"),
            Access::Admin => format!("secret: '{SECRET}'\n config_write: true"),
            Access::Anonymous => "allow_anonymous_loopback: true".into(),
        };
        let main = format!(
            "# Entry comment retained verbatim.\ninclude {{\n 'auth.dae'\n 'editable.dae'\n 'locked.dae'\n}}\nglobal {{\n nfqueue_enable: false\n store_subscribe: false\n dial_mode: ip\n data_dir: '{}'\n}}\nrouting {{\n fallback: direct\n}}\n",
            directory.path().join("state").display()
        );
        let mut originals = HashMap::from([
            ("main.dae", main),
            (
                "auth.dae",
                format!(
                    "experimental {{ native_api {{\n enabled: true\n listen: '{addr}'\n {settings}\n}} }}\n"
                ),
            ),
            ("editable.dae", "# Explicitly writable include.\n".into()),
            ("locked.dae", "# Local-editor-only include.\n".into()),
        ]);
        setup(directory.path(), &mut originals);
        // The db fixture keeps its tree apart from `state` so a test can delete all of it.
        let tree = directory.path().join(if db { "etc" } else { "" });
        std::fs::create_dir_all(&tree).unwrap();
        for (name, text) in &originals {
            let path = tree.join(name);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let entry = tree.join("main.dae").canonicalize().unwrap();
        let mut diagnostics = Vec::new();
        let (mut config, initial, store, database) = if db {
            let state = directory.path().join("state");
            std::fs::create_dir_all(&state).unwrap();
            let mut startup = DatabaseStartup::open(&entry, &state, &mut diagnostics).unwrap();
            startup.record().unwrap();
            let store = Arc::clone(&startup.store);
            (
                startup.config,
                startup.sources,
                SourceStore::Db(Arc::clone(&store)),
                Some(store),
            )
        } else {
            let loaded = Config::from_dae_file_with_sources(
                &entry,
                &HashMap::new(),
                SourceLimits::default(),
                &mut diagnostics,
            )
            .unwrap();
            let store = SourceStore::File(loaded.sources[0].path.clone().into());
            let initial = SourceUpdate {
                sources: loaded.sources,
                dependencies: Vec::new(),
                geo_sources: None,
            };
            (loaded.config, initial, store, None)
        };
        config.validate_detailed().unwrap();
        config.ensure_builtin_nodes();
        let mut subscriptions = SubscriptionSupervisor::prepare(&mut config, None, diagnostics)
            .await
            .unwrap();
        let requirements = crate::routing::GeoRequirements::for_traffic(&config.routing.rules)
            .union(&DnsRouter::geo_requirements(&config.dns));
        let geo = crate::routing::GeoSourceSet::load_captured(
            &requirements,
            Path::new(&config.global.data_dir),
            |path| std::fs::read(path).map(Arc::from),
        )
        .unwrap();
        let router = Router::from_config_with_geo_sources(&config.routing, &geo).unwrap();
        let forwarder = Arc::new(DnsForwarder::new(
            Arc::new(NoDns),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            Arc::new(DnsRouter::new_with_geo_sources(&config.dns, &geo).unwrap()),
        ));
        let resolver = DnsResolver::with_forwarder(&config.dns, Arc::clone(&forwarder)).unwrap();
        let mut control_plane = ControlPlane::new(
            config,
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        control_plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", ""),
        )));
        control_plane.start_datapath_flags_coordinator().unwrap();
        control_plane
            .install_startup_diagnostics(subscriptions.take_startup_diagnostics())
            .await;
        if state_db {
            let db = crate::state::StateDb::open(&directory.path().join("state")).unwrap();
            control_plane.init_cache_db(Some(Arc::new(db)), None).await;
        }
        let state = Arc::new(
            NativeState::new(&mut control_plane, addr, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let service = Arc::clone(&state.observation.configuration);
        let commands = control_plane.command_sender();
        subscriptions.route_through(crate::download_route::SharedOutbounds {
            router: control_plane.traffic_router(),
            config: control_plane.config_handle(),
            group_manager: control_plane.group_manager(),
            proxy_registry: control_plane.proxy_registry(),
            runtime_registry: control_plane.runtime_registry(),
        });
        subscriptions.start(commands.clone());
        state.observation.providers.attach(subscriptions.handle());
        control_plane.attach_subscriptions(subscriptions.handle());
        let coordinator = service
            .start(
                store,
                Some(initial),
                directory.path().join("state"),
                control_plane.config_handle(),
                control_plane.log_files(),
                control_plane.startup_downgrades(),
                control_plane.diagnostics_handle(),
                commands.clone(),
                subscriptions.handle(),
            )
            .await;
        let reloads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reloads);
        let reject_reloads = Arc::new(AtomicU8::new(0));
        let rejecting = Arc::clone(&reject_reloads);
        let (gate, gates) = if gated {
            let (sender, receiver) = mpsc::unbounded_channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let startup_downgrades = control_plane.startup_downgrades();
        let active = control_plane.config_handle();
        let mut control = JoinSet::new();
        control.spawn(async move {
            control_plane
                .run_native_config_test_commands(observed, gate, rejecting)
                .await
        });
        let weak = Arc::downgrade(&state);
        let server = NativeServer::start(listener, state);
        Self {
            directory,
            originals,
            addr,
            client: Client::builder().no_proxy().timeout(WAIT).build().unwrap(),
            authenticated: !matches!(access, Access::Anonymous),
            bearer: SECRET,
            state: weak,
            service,
            server: Some(server),
            coordinator: Some(coordinator),
            subscriptions: Some(subscriptions),
            commands,
            control,
            reloads,
            gates,
            database,
            reject_reloads,
            startup_downgrades,
            active,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let request = self
            .client
            .request(method, format!("http://{}{path}", self.addr));
        if self.authenticated {
            request.bearer_auth(self.bearer)
        } else {
            request
        }
    }

    async fn get(&self, path: &str) -> Value {
        ok(self.request(Method::GET, path).send().await.unwrap()).await
    }

    fn replace(&self, source: &Value, content: &str) -> reqwest::RequestBuilder {
        self.request(Method::PUT, &source_path(source))
            .header("if-match", etag(source))
            .json(&json!({"content":content}))
    }

    fn validate(&self, mode: &str, content: &str) -> reqwest::RequestBuilder {
        self.request(Method::POST, VALIDATE).json(&json!({
            "mode":mode,"sources":[{"id":"candidate","path":"main.dae","content":content}]
        }))
    }

    async fn terminal(&self, accepted: &Value) -> Value {
        let href = accepted["href"].as_str().unwrap();
        timeout(WAIT, async {
            loop {
                let operation = self.get(href).await;
                assert_eq!(operation["operation_id"], accepted["operation_id"]);
                assert_eq!(operation["kind"], accepted["kind"]);
                match operation["status"].as_str().unwrap() {
                    "succeeded" | "failed" => {
                        for field in ["created_at", "started_at", "finished_at"] {
                            chrono::DateTime::parse_from_rfc3339(
                                operation[field].as_str().unwrap(),
                            )
                            .unwrap();
                        }
                        assert!(operation.get("result").is_some());
                        assert!(operation.get("error").is_some());
                        return operation;
                    }
                    "queued" | "running" => tokio::time::sleep(Duration::from_millis(5)).await,
                    _ => panic!("invalid operation status"),
                }
            }
        })
        .await
        .expect("reload operation did not settle")
    }

    async fn barrier(&self) {
        let result = ok(self
            .validate("syntax", "routing { fallback: direct }")
            .send()
            .await
            .unwrap())
        .await;
        assert_eq!(result["valid"], true);
    }

    async fn next_reload(&mut self) -> oneshot::Sender<()> {
        timeout(WAIT, self.gates.as_mut().unwrap().recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn pause_before_replace(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, wait) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        *self.service.before_replace.lock() = Some(Box::new(move || {
            let _ = entered.send(());
            resume
                .recv_timeout(WAIT)
                .expect("write gate was not released");
        }));
        (wait, release)
    }

    async fn assert_last_reload(&self, operation: &Value) {
        self.barrier().await;
        let runtime = self.get("/api/v1/runtime").await;
        assert_eq!(
            runtime["last_reload"]["operation_id"],
            operation["operation_id"]
        );
        assert_eq!(runtime["last_reload"]["status"], operation["status"]);
        assert_eq!(runtime["last_reload"]["error"], operation["error"]);
        chrono::DateTime::parse_from_rfc3339(
            runtime["last_reload"]["finished_at"].as_str().unwrap(),
        )
        .unwrap();
        let config = self.get(CONFIG).await;
        assert_eq!(runtime["generation"]["active_id"], config["generation_id"]);
        assert_eq!(runtime["generation"]["config_revision"], config["revision"]);
    }

    async fn shutdown(mut self) {
        if let Some(coordinator) = self.coordinator.take() {
            timeout(WAIT, coordinator.shutdown())
                .await
                .expect("coordinator shutdown stalled");
        }
        timeout(
            Duration::from_secs(6),
            self.server.take().unwrap().shutdown(),
        )
        .await
        .unwrap();
        self.gates.take();
        timeout(WAIT, self.commands.send(ControlCommand::Shutdown))
            .await
            .unwrap()
            .unwrap();
        timeout(WAIT, self.control.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(self.control.is_empty());
        assert_eq!(
            timeout(WAIT, self.subscriptions.take().unwrap().shutdown())
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(
            self.state.upgrade().is_none(),
            "HTTP state leaked after owned shutdown"
        );
    }
}

const GEO: &str = "/api/v1/geodata";
const UPDATE: &str = "/api/v1/geodata/update";

fn delimited(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut result = vec![tag << 3 | 2, value.len() as u8];
    result.extend_from_slice(value);
    result
}

fn geosite(domain: &str) -> Vec<u8> {
    geosite_code(b"test", domain)
}

fn geosite_code(code: &[u8], domain: &str) -> Vec<u8> {
    let mut entry = delimited(1, code);
    let mut rule = vec![8, 3];
    rule.extend(delimited(2, domain.as_bytes()));
    entry.extend(delimited(2, &rule));
    delimited(1, &entry)
}

fn geoip(first: u8) -> Vec<u8> {
    let mut entry = delimited(1, b"test");
    let mut cidr = delimited(1, &[first, 0, 0, 0]);
    cidr.extend([16, 8]);
    entry.extend(delimited(2, &cidr));
    delimited(1, &entry)
}

struct AssetServer {
    address: SocketAddr,
    assets: Arc<parking_lot::Mutex<(Vec<u8>, Vec<u8>)>>,
    requests: Arc<AtomicUsize>,
    entered: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl AssetServer {
    async fn new(site: Vec<u8>, ip: Vec<u8>, gated: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let assets = Arc::new(parking_lot::Mutex::new((site, ip)));
        let served = Arc::clone(&assets);
        let (entered, wait) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut entered = Some(entered);
            let mut resume = Some(resume);
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    head.push(byte);
                    assert!(head.len() <= 4096);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                // No checksum is published beside these assets.
                if head.split(|byte| *byte == b' ').nth(1).and_then(|target| target.split(|byte| *byte == b'?').next())
                    .is_some_and(|path| path.ends_with(b".sha256sum")) {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    stream.shutdown().await.unwrap();
                    continue;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    if gated {
                        resume.take().unwrap().await.unwrap();
                    }
                }
                let bytes = {
                    let assets = served.lock();
                    if head.starts_with(b"GET /geosite") {
                        assets.0.clone()
                    } else {
                        assets.1.clone()
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            assets,
            requests,
            entered: wait,
            release: Some(release),
            tasks,
        }
    }

    fn serve_geosite(&self, site: Vec<u8>) {
        self.assets.lock().0 = site;
    }

    async fn close(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

fn setup(root: &Path, files: &mut HashMap<&'static str, String>, address: SocketAddr) {
    setup_rules(root, files);
    let auth = files.get_mut("auth.dae").unwrap();
    *auth = auth.replace(" enabled: true", &format!(
        " geosite_download_url: 'http://{address}/geosite/PRIVATE?token=PRIVATE'\n geoip_download_url: 'http://{address}/geoip'\n enabled: true",
    ));
}

fn setup_rules(root: &Path, files: &mut HashMap<&'static str, String>) {
    let directory = root.join("state");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("geosite.dat"), geosite("old.example")).unwrap();
    std::fs::write(directory.join("geoip.dat"), geoip(198)).unwrap();
    let main = files.get_mut("main.dae").unwrap();
    *main = main.replace(
        " fallback: direct",
        " domain(geosite: test) -> block\n dip(geoip: test) -> block\n fallback: direct",
    );
}

async fn fixture(address: SocketAddr, gated_reload: bool) -> Fixture {
    Fixture::new_custom(Access::Admin, gated_reload, |root, files| {
        setup(root, files, address)
    })
    .await
}

async fn route(fixture: &Fixture, domain: &str, ip: &str) -> String {
    fixture
        .state
        .upgrade()
        .unwrap()
        .traffic_router
        .read()
        .await
        .route(&crate::routing::ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: ip.parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        })
        .to_owned()
}

const SETTINGS: &str = "/api/v1/runtime/settings";

async fn patch_settings(fixture: &Fixture, body: Value) -> Response {
    fixture
        .request(Method::PATCH, SETTINGS)
        .json(&body)
        .send()
        .await
        .unwrap()
}

const NODES: &str = "/api/v1/nodes";
const PROVIDERS: &str = "/api/v1/providers";
const LINK: &str = "socks5://127.0.0.1:11080#discarded-link-name";

fn create_node(fixture: &Fixture, name: &str, link: &str) -> reqwest::RequestBuilder {
    fixture
        .request(Method::POST, NODES)
        .json(&json!({"name":name,"link":link}))
}

async fn created(response: Response, collection: &str) -> Value {
    assert_eq!(response.status(), StatusCode::CREATED);
    headers(&response);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let value: Value = response.json().await.unwrap();
    assert_eq!(
        location,
        format!("/api/v1/{collection}/{}", value["id"].as_str().unwrap())
    );
    value
}

async fn reload(fixture: &Fixture) {
    let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
}

fn sha256(content: &str) -> String {
    crate::configuration::digest(content.as_bytes())
}
fn source_path(source: &Value) -> String {
    format!("/api/v1/config/sources/{}", source["id"].as_str().unwrap())
}
fn etag(source: &Value) -> String {
    format!("\"{}\"", source["content_sha256"].as_str().unwrap())
}
/// `GET /config/sources/{id}` leaves out the list members that change while the bytes do.
fn source_content(row: &Value) -> Value {
    let mut row = row.clone();
    let object = row.as_object_mut().unwrap();
    assert!(object.remove("writable").is_some() && object.remove("loaded_at").is_some());
    object.remove("read_only_reason");
    row
}
fn source<'a>(config: &'a Value, content: &str) -> &'a Value {
    config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["content_sha256"] == sha256(content))
        .unwrap()
}

fn headers(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

async fn ok(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    headers(&response);
    response.json().await.unwrap()
}

async fn accepted(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    headers(&response);
    assert!(
        response.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["href"], location);
    assert_eq!(
        location,
        format!(
            "/api/v1/operations/{}",
            body["operation_id"].as_str().unwrap()
        )
    );
    assert!(matches!(
        body["status"].as_str(),
        Some("queued" | "running")
    ));
    body
}

async fn error(response: Response, status: StatusCode, code: &str) -> Value {
    assert_eq!(response.status(), status);
    headers(&response);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], code);
    assert!(body["error"]["message"].is_string());
    assert!(body["error"].get("details").is_some());
    uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();
    assert!(!body.to_string().contains(SECRET));
    body
}

fn diagnostics(rows: &Value, source_id: &str, private: &str) {
    let rows = rows.as_array().unwrap();
    assert!(rows.iter().any(|row| row["level"] == "error"));
    for row in rows {
        for field in [
            "level",
            "source_id",
            "line",
            "column",
            "span",
            "code",
            "message",
        ] {
            assert!(row.get(field).is_some(), "missing diagnostic {field}");
        }
        assert_eq!(row["source_id"], source_id);
        assert!(!row["code"].as_str().unwrap().is_empty());
        assert!(!row.to_string().contains(private));
        assert!(!row.to_string().contains(SECRET));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DiskEntry {
    path: PathBuf,
    mode: u32,
    inode: u64,
    hash: String,
}

fn disk(root: &Path) -> Vec<DiskEntry> {
    fn visit(root: &Path, path: &Path, entries: &mut Vec<DiskEntry>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let hash = if metadata.is_file() {
            crate::configuration::digest(&std::fs::read(path).unwrap())
        } else {
            String::new()
        };
        entries.push(DiskEntry {
            path: path.strip_prefix(root).unwrap().to_owned(),
            mode: metadata.mode(),
            inode: metadata.ino(),
            hash,
        });
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}
