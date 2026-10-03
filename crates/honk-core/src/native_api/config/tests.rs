//! File-authority regressions through real HTTP, reload publication and supervisor handoff.

mod creation;
mod database;
mod dns_rules;
mod geodata;
mod groups;
mod management;
mod secrets;
mod transactions;
mod validation;

use super::ConfigService;
use super::coordinator::ConfigCoordinator;
use crate::configuration::SourceUpdate;
use crate::control::{ControlCommand, ControlPlane, ReloadBehavior};
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
use tokio::io::AsyncWriteExt;
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

#[tokio::test]
async fn metadata_defaults_and_anonymous_never_grant_source_authority() {
    for access in [Access::Metadata, Access::Anonymous] {
        let fixture = Fixture::new(access, false).await;
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert!(capabilities["resources"]["config"].get("content").is_none());
        assert_eq!(capabilities["resources"]["config"]["writable"], false);
        assert_eq!(capabilities["resources"]["config"]["create"], false);
        assert!(
            capabilities["resources"]["config"]["max_bytes"]
                .as_u64()
                .unwrap()
                < capabilities["limits"]["max_json_body_bytes"]
                    .as_u64()
                    .unwrap()
        );
        assert_eq!(
            capabilities["resources"]["operations"]["max_replay_keys"],
            1024
        );
        assert_eq!(
            capabilities["resources"]["providers"]["create_unfetched"],
            true
        );
        // Full validation also counts dependencies read from disk, not only the request body.
        assert_eq!(
            capabilities["resources"]["config_validate"]["max_bytes"],
            crate::configuration::MAX_SOURCE_BYTES
        );
        assert_eq!(capabilities["resources"]["groups"]["config_patch"], false);
        for resource in [
            "providers",
            "geodata",
            "rules",
            "routing_trace",
            "flows",
            "connections",
        ] {
            assert_eq!(capabilities["resources"][resource]["available"], true);
        }
        for path in [
            "/api/v1/providers",
            "/api/v1/providers/inline",
            "/api/v1/geodata",
            "/api/v1/connections",
            "/api/v1/rules",
            "/api/v1/flows",
        ] {
            fixture.get(path).await;
        }
        let config = fixture.get(CONFIG).await;
        assert_eq!(config["secrets_redacted"], fixture.authenticated);
        assert!(
            config["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["content"].is_string()
                    && row["writable"] == false
                    && row["read_only_reason"] == "writes_disabled")
        );
        assert!(!config.to_string().contains(SECRET));
        let main = source(&config, &fixture.originals["main.dae"]);
        assert_eq!(fixture.get(&source_path(main)).await, source_content(main));
        let before = disk(fixture.directory.path());
        let refused = error(
            fixture
                .replace(main, "routing { fallback: block }")
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
        assert_eq!(
            refused["error"]["details"],
            json!({"reason":"writes_disabled"})
        );
        assert_eq!(disk(fixture.directory.path()), before);
        assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn admin_reads_exact_accepted_bytes_but_never_auth_source_or_unapproved_writes() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["sources"].as_array().unwrap().len(), 4);
    for (name, original) in &fixture.originals {
        let row = source(&config, original);
        assert_eq!(row["path"], *name);
        assert_eq!(row["bytes"], original.len());
        assert_eq!(row["line_count"], original.lines().count());
        assert_eq!(
            row["kind"],
            if *name == "main.dae" {
                "main"
            } else {
                "include"
            }
        );
        chrono::DateTime::parse_from_rfc3339(row["loaded_at"].as_str().unwrap()).unwrap();
        let id = row["id"].as_str().unwrap();
        assert!(!id.is_empty() && !id.contains(name));
        assert_eq!(row["writable"], *name != "auth.dae");
        assert_eq!(
            row.get("read_only_reason").cloned(),
            (*name == "auth.dae").then(|| json!("listener_secret_source"))
        );
        assert_eq!(row["absolute_path"], fixture.path(name).to_str().unwrap());
        if *name == "auth.dae" {
            assert!(row["content"].as_str().unwrap().contains("enabled: true"));
            assert!(!row["content"].as_str().unwrap().contains(SECRET));
        } else {
            assert_eq!(row["content"], *original);
            assert_eq!(
                sha256(row["content"].as_str().unwrap()),
                row["content_sha256"]
            );
        }
        let response = fixture
            .request(Method::GET, &source_path(row))
            .send()
            .await
            .unwrap();
        // The auth source masks a listener secret, so its body is not what PUT replaces.
        assert_eq!(
            response
                .headers()
                .get("etag")
                .map(|value| value.to_str().unwrap().to_owned()),
            (*name != "auth.dae").then(|| etag(row)),
        );
        assert_eq!(ok(response).await, source_content(row));
    }
    assert!(!config.to_string().contains(SECRET));
    let before = disk(fixture.directory.path());
    let refused = error(
        fixture
            .replace(
                source(&config, &fixture.originals["auth.dae"]),
                "# not authorized\n",
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"listener_secret_source"})
    );
    let without_auth = fixture.originals["main.dae"].replace(" 'auth.dae'\n", "");
    let refused = error(
        fixture
            .replace(
                source(&config, &fixture.originals["main.dae"]),
                &without_auth,
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"credential_sources_changed"})
    );
    error(
        fixture
            .request(Method::GET, "/api/v1/config/sources/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    error(
        fixture
            .request(Method::PUT, "/api/v1/config/sources/unknown")
            .header("if-match", etag(&config["sources"][0]))
            .json(&json!({"content":"# unknown\n"}))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), before);
    std::fs::write(
        fixture.path("editable.dae"),
        "# External edit, not accepted.\n",
    )
    .unwrap();
    assert_eq!(fixture.get(CONFIG).await, config);
    assert_eq!(
        fixture
            .get(&source_path(source(
                &config,
                &fixture.originals["editable.dae"]
            )))
            .await,
        source_content(source(&config, &fixture.originals["editable.dae"]))
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn refused_source_writes_name_the_listener_secret_reason() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        files
            .get_mut("locked.dae")
            .unwrap()
            .push_str(&format!("# {SECRET}\n"));
    })
    .await;
    let config = fixture.get(CONFIG).await;
    let row = |name: &str| {
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == name)
            .unwrap()
            .clone()
    };
    let (locked, editable) = (row("locked.dae"), row("editable.dae"));
    assert_eq!(locked["read_only_reason"], "listener_secret_in_content");
    assert!(editable.get("read_only_reason").is_none());
    let before = disk(fixture.directory.path());
    let reason = |response: Response| async move {
        error(response, StatusCode::FORBIDDEN, "permission_denied").await["error"]["details"]
            ["reason"]
            .clone()
    };
    let refused = fixture
        .replace(&locked, "# replaced\n")
        .send()
        .await
        .unwrap();
    assert_eq!(reason(refused).await, "listener_secret_in_content");
    let copied = format!("# {SECRET}\n");
    let refused = fixture.replace(&editable, &copied).send().await.unwrap();
    assert_eq!(reason(refused).await, "listener_secret_in_content");
    // The same declaration again changes no listener setting, and it still carries the secret.
    let declared = &fixture.originals["auth.dae"];
    let refused = fixture.replace(&editable, declared).send().await.unwrap();
    assert_eq!(reason(refused).await, "listener_secret_source");
    assert_eq!(disk(fixture.directory.path()), before);
    let mut auth = fixture.originals["auth.dae"].clone();
    auth.push_str("# Edited on disk since the last reload.\n");
    std::fs::write(fixture.path("auth.dae"), auth).unwrap();
    let refused = fixture.replace(&editable, "# edit\n").send().await.unwrap();
    assert_eq!(reason(refused).await, "credential_sources_changed");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn writes_after_the_coordinator_stopped_are_unavailable() {
    let mut fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    let editable = source(&config, &fixture.originals["editable.dae"]).clone();
    fixture.coordinator.take().unwrap().shutdown().await;
    let refused = error(
        fixture.replace(&editable, "# edit\n").send().await.unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"configuration_unavailable"})
    );
    fixture.shutdown().await;
}

type LogLine = (tracing::Level, HashMap<String, String>);

/// Log lines with one message, as level and field text, from the test thread's own dispatcher.
#[derive(Clone)]
struct LogLines(&'static str, Arc<parking_lot::Mutex<Vec<LogLine>>>);

impl LogLines {
    fn new(message: &'static str) -> Self {
        Self(message, Arc::default())
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogLines {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(HashMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        let mut fields = Fields(HashMap::new());
        event.record(&mut fields);
        if fields.0.get("message").map(String::as_str) == Some(self.0) {
            self.1.lock().push((*event.metadata().level(), fields.0));
        }
    }
}

#[tokio::test]
async fn a_refused_write_logs_its_reason_on_the_request_line() {
    use tracing_subscriber::layer::SubscriberExt as _;
    // Callsite interest is process-wide; other tests' dispatchers would race this one.
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::a_refused_write_logs_its_reason_on_the_request_line",
    ) {
        return;
    }
    let lines = LogLines::new("native HTTP request");
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    let fixture = Fixture::new(Access::Metadata, false).await;
    let config = fixture.get(CONFIG).await;
    let main = source(&config, &fixture.originals["main.dae"]);
    error(
        fixture.replace(main, "# edit\n").send().await.unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    error(
        fixture
            .request(Method::GET, "/api/v1/config/sources/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    fixture.shutdown().await;
    let lines = lines.1.lock();
    let refused: Vec<_> = lines
        .iter()
        .filter(|(_, fields)| fields["method"] == "PUT")
        .collect();
    assert_eq!(refused.len(), 1, "{lines:?}");
    let (level, fields) = refused[0];
    assert_eq!(*level, tracing::Level::WARN);
    assert_eq!(fields["reason"], "writes_disabled");
    assert_eq!(fields["status"], "403");
    assert!(!fields.values().any(|value| value.contains("main.dae")));
    let (level, fields) = lines
        .iter()
        .find(|(_, fields)| fields["status"] == "404")
        .unwrap();
    assert_eq!(*level, tracing::Level::INFO);
    assert!(!fields.contains_key("reason"));
}

#[tokio::test]
async fn a_listener_secret_in_source_text_warns_once_per_accepted_reload() {
    use tracing_subscriber::layer::SubscriberExt as _;
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::a_listener_secret_in_source_text_warns_once_per_accepted_reload",
    ) {
        return;
    }
    let lines = LogLines::new(
        "configuration source is read-only because its text contains a listener secret value",
    );
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    // A glob loads the file so that only its own text and path hold the Clash secret.
    let fixture = Fixture::new_custom(Access::Admin, false, |directory, files| {
        std::fs::create_dir(directory.join("extra")).unwrap();
        files
            .get_mut("auth.dae")
            .unwrap()
            .push_str("experimental { clash_api { secret: 'clash-listener-token' } }\n");
        files
            .get_mut("main.dae")
            .unwrap()
            .push_str("include { 'extra/*.dae' }\n");
        files.insert(
            "extra/clash-listener-token.dae",
            "# clash-listener-token copied here\n".into(),
        );
    })
    .await;
    let config = fixture.get(CONFIG).await;
    let collided = source(
        &config,
        &fixture.originals["extra/clash-listener-token.dae"],
    );
    assert_eq!(collided["read_only_reason"], "listener_secret_in_content");
    let auth = source(&config, &fixture.originals["auth.dae"]);
    let expected = vec![
        (
            auth["id"].as_str().unwrap().to_owned(),
            "auth.dae".to_owned(),
        ),
        (
            collided["id"].as_str().unwrap().to_owned(),
            "extra/<redacted>.dae".to_owned(),
        ),
    ];
    let warnings = || {
        lines
            .1
            .lock()
            .iter()
            .map(|(level, fields)| {
                assert_eq!(*level, tracing::Level::WARN);
                (fields["source_id"].clone(), fields["path"].clone())
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(warnings(), expected);
    // A reload whose sources lost the acceptance race reports the snapshot already reported.
    fixture.service.warn_secret_collisions();
    assert_eq!(warnings().len(), 2);
    let reload = || async {
        let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
        fixture.terminal(&operation).await
    };
    // An unchanged configuration is accepted again as a no-op.
    assert_eq!(reload().await["status"], "succeeded");
    assert_eq!(warnings().len(), 4);
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    assert_eq!(reload().await["error"]["code"], "reload_rejected");
    assert_eq!(warnings().len(), 4);
    fixture
        .reject_reloads
        .store(ReloadBehavior::Degraded as u8, Ordering::SeqCst);
    let edited = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    std::fs::write(fixture.path("main.dae"), edited).unwrap();
    assert_eq!(reload().await["error"]["code"], "reload_degraded");
    assert_eq!(warnings(), vec![expected; 3].concat());
    fixture.shutdown().await;
}

#[tokio::test]
async fn mixed_listener_secrets_mask_values_and_keep_ordinary_content() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(&format!("secret: '{SECRET}'"),
            &format!("secret: 'overridden-listener-token'\n secret: '{SECRET}'"));
        auth.push_str("experimental { clash_api { secret: 'old-clash-token'\n secret: 'clash-listener-token' } }\n# old-clash-token copied here\n");
        files.get_mut("main.dae").unwrap().push_str("include { 'clash-listener-token.dae' }\n");
        files.insert("clash-listener-token.dae", "# Ordinary included content.\n".into());
        files.get_mut("locked.dae").unwrap().push_str(
            "# overridden-listener-token copied across sources\nnode { ordinary: 'socks5://user:ordinary-password@192.0.2.1:1080' }\n");
    }).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["secrets_redacted"], true);
    let encoded = config.to_string();
    for secret in [
        SECRET,
        "overridden-listener-token",
        "old-clash-token",
        "clash-listener-token",
    ] {
        assert!(!encoded.contains(secret), "listener value leaked");
    }
    let export = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    let export = export.text().await.unwrap();
    assert!(export.contains("# <redacted> copied across sources"));
    for secret in [
        SECRET,
        "overridden-listener-token",
        "old-clash-token",
        "clash-listener-token",
    ] {
        assert!(!export.contains(secret), "listener value exported");
    }
    let path_only = source(&config, &fixture.originals["clash-listener-token.dae"]);
    assert_eq!(path_only["content"], "# Ordinary included content.\n");
    assert_eq!(path_only["path"], "<redacted>.dae");
    let auth = source(&config, &fixture.originals["auth.dae"]);
    assert_eq!(auth["writable"], false);
    assert_eq!(
        auth["content"].as_str().unwrap().lines().count(),
        fixture.originals["auth.dae"].lines().count()
    );
    let mixed = source(&config, &fixture.originals["locked.dae"]);
    assert!(
        mixed["content"]
            .as_str()
            .unwrap()
            .contains("socks5://user:ordinary-password@192.0.2.1:1080")
    );
    assert_eq!(mixed["writable"], false);
    fixture.shutdown().await;
}

#[tokio::test]
async fn redaction_flag_is_unknown_in_config_write_bodies() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    let row = source(&config, &fixture.originals["locked.dae"]);
    assert_eq!(row["content"], fixture.originals["locked.dae"]);
    assert_eq!(row["writable"], true);
    let candidate = "# accepted include without an allowlist\n";
    error(
        fixture
            .replace(row, candidate)
            .json(&json!({"content": candidate, "secrets_redacted": false}))
            .send()
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    error(
        fixture
            .replace(row, &"#".repeat(super::MAX_CONTENT_BYTES + 1))
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    let admission = accepted(fixture.replace(row, candidate).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&admission).await["status"], "succeeded");
    for body in [
        json!({"mode":"syntax", "secrets_redacted":true,
            "sources":[{"content":"routing { fallback: direct }"}]}),
        json!({"mode":"syntax",
            "sources":[{"content":"routing { fallback: direct }", "secrets_redacted":false}]}),
    ] {
        let response = fixture
            .request(Method::POST, "/api/v1/config/validate")
            .json(&body)
            .send()
            .await
            .unwrap();
        error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }
    fixture.shutdown().await;
}

#[test]
fn listener_masking_preserves_wire_identifiers_and_enums() {
    use super::ListenerSecrets;

    let mut value = json!({
        "id": "12345678-abcd-1234-abcd-123456789012",
        "next_cursor": "12345678-abcd-1234-abcd-123456789012:1",
        "network": "tcp",
        "chain": ["node-with-secret"],
        "trace_status": "complete",
        "trace": {"status": "complete", "missing": [], "steps": [
            {"chain": "traffic", "rule_id": "instance-1:2:rule:0", "expression": "pname(node-with-secret)"}
        ]}
    });
    let original = value.clone();
    assert!(ListenerSecrets::new(&[], "with-secret").mask_value(&mut value));
    assert_eq!(value["id"], original["id"]);
    assert_eq!(value["next_cursor"], original["next_cursor"]);
    assert_eq!(value["network"], "tcp");
    assert_eq!(value["chain"][0], "node-<redacted>");
    assert_eq!(value["trace"]["steps"][0]["chain"], "traffic");
    assert_eq!(value["trace"]["steps"][0]["rule_id"], "instance-1:2:rule:0");
    assert_eq!(value["trace_status"], "partial");
    assert_eq!(value["trace"]["missing"], json!(["redacted"]));
    let mut value = json!({"network": "tcp", "expression": "pname(tcpsecret)"});
    assert!(ListenerSecrets::new(&[], "tcpsecret").mask_value(&mut value));
    assert_eq!(value["network"], "tcp");
    assert_eq!(value["expression"], "pname(<redacted>)");
    assert_eq!(
        ListenerSecrets::new(&[], "abababab").mask("ababababab"),
        ("<redacted>".into(), true)
    );
    // Below the minimum a secret is left alone rather than shredding common substrings.
    assert_eq!(
        ListenerSecrets::new(&[], "tcp").mask("l4proto(tcp)"),
        ("l4proto(tcp)".into(), false)
    );
    let secret = "quoted\"token";
    let mut value = json!({"expression": format!("pname({secret:?})")});
    assert!(ListenerSecrets::new(&[], secret).mask_value(&mut value));
    assert_eq!(value["expression"], "pname(\"<redacted>\")");
}

#[tokio::test]
async fn connection_projection_masks_listener_values_without_losing_flow_references() {
    use crate::connection_tracker::ConnectionEntry;
    use std::sync::atomic::AtomicU64;

    let fixture = Fixture::new(Access::Metadata, false).await;
    let state = fixture.state.upgrade().unwrap();
    state.observation.attach_for_test();
    let flow = state
        .observation
        .core
        .flows
        .begin(
            crate::observe::vocab::Network::Tcp,
            "192.0.2.1:31000".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        )
        .unwrap();
    let rule_id = format!("{}:1:rule:0", state.instance_id);
    flow.routed(
        "group/name@host",
        Some(&rule_id),
        Some(&format!("pname(\"/usr/bin/{SECRET}\")")),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    state.tracker.register(ConnectionEntry {
        id: "connection-visible-id".into(),
        source: "192.0.2.1:31000".into(),
        destination: "198.51.100.1:443".into(),
        proxy: "leaf".into(),
        routed_outbound: Some("group/name@host".into()),
        native_flow_id: Some(flow.id().into()),
        rule: String::new(),
        rule_payload: String::new(),
        chains: vec![],
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "tcp".into(),
        process: Some("/usr/bin/user@host".into()),
        process_path: None,
    });
    let value = fixture.get("/api/v1/connections?detail=full").await;
    let row = &value["tcp"][0];
    assert_eq!(row["id"], "connection-visible-id");
    assert_eq!(row["flow_id"], flow.id());
    assert_eq!(row["rule_id"], rule_id);
    assert_eq!(row["outbound"], "group/name@host");
    assert_eq!(row["pname"], "/usr/bin/user@host");
    assert_eq!(row["rule_expression"], "pname(\"/usr/bin/<redacted>\")");
    assert!(!value.to_string().contains(SECRET));
    drop(state);
    fixture.shutdown().await;
}

#[test]
fn malformed_credential_source_is_withheld_without_panicking() {
    let content = "experimental { native_api { secret: 'unfinished\n";
    let source = honk_config::parser::SourceSnapshot {
        path: PathBuf::from("/config/auth.dae"),
        content: Arc::from(content),
        parent: None,
        source: honk_config::diagnostic::DiagnosticSources::new(None).root(),
        contains_api_secret: true,
        loaded_at: SystemTime::now(),
    };
    let sources = [source];
    let secrets = super::ListenerSecrets::new(&sources, "listener-token");
    assert_eq!(secrets.mask(content), ("<redacted>\n".into(), true));
    assert_eq!(
        secrets.mask(&format!("before\n{content}after")),
        ("before\n<redacted>\nafter".into(), true)
    );
    assert_eq!(
        secrets.mask("ordinary content"),
        ("ordinary content".into(), false)
    );
}

#[test]
fn every_secret_bearing_accepted_source_warns_even_when_writes_are_disabled() {
    use tracing_subscriber::layer::SubscriberExt as _;
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::every_secret_bearing_accepted_source_warns_even_when_writes_are_disabled",
    ) {
        return;
    }
    let lines = LogLines::new(
        "configuration source is read-only because its text contains a listener secret value",
    );
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("extra")).unwrap();
    let entry = directory.path().join("main.dae");
    std::fs::write(&entry, "include { 'auth.dae'\n 'extra/*.dae' }\n").unwrap();
    std::fs::write(
        directory.path().join("auth.dae"),
        format!("experimental {{ native_api {{ secret: '{SECRET}' }} }}\n"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join(format!("extra/{SECRET}.dae")),
        format!("# {SECRET}\n"),
    )
    .unwrap();
    let loaded = Config::from_dae_file_with_sources(
        &entry,
        &HashMap::new(),
        SourceLimits::DEFAULT,
        &mut Vec::new(),
    )
    .unwrap();
    let owner = crate::native_api::observation::NativeObservation::new(&loaded.config);
    let service = &owner.configuration;
    let update = SourceUpdate {
        sources: loaded.sources,
        dependencies: vec![],
        geo_sources: None,
    };
    service
        .sources
        .accept(service.sources.prepare_accept(&update), 1);
    service.warn_secret_collisions();
    service.warn_secret_collisions();
    let accepted = service.sources.accepted.read().clone().unwrap();
    let expected = [
        (
            accepted.ids[&directory.path().join("auth.dae")].clone(),
            "auth.dae",
        ),
        (
            accepted.ids[&directory.path().join(format!("extra/{SECRET}.dae"))].clone(),
            "extra/<redacted>.dae",
        ),
    ];
    {
        let captured = lines.1.lock();
        assert_eq!(captured.len(), 2);
        for ((level, fields), (id, path)) in captured.iter().zip(&expected) {
            assert_eq!(*level, tracing::Level::WARN);
            assert_eq!(&fields["source_id"], id);
            assert_eq!(&fields["path"], path);
            assert!(!fields.values().any(|value| value.contains(SECRET)));
        }
    }
    service.sources.generation_committed("next-generation", 2);
    service.warn_secret_collisions();
    service.warn_secret_collisions();
    assert_eq!(lines.1.lock().len(), 4);
}
