#![recursion_limit = "256"]

//! honk-core: eBPF-based transparent proxy engine. Uses TC redirects and
//! `sk_lookup` BPF with an isolated `daens` network namespace — no iptables
//! TPROXY rules needed. The process (all threads) always stays in the host
//! netns; daens is entered only through scoped `with_daens_netns` switches
//! (dae0peer/sk_lookup attach, TPROXY listener bind, DNS/UDP reply socket
//! creation), mirroring Go dae's `DaeNetns.WithRequired` ("listen and serve
//! in dae netns"). Trait-based backends (real aya + mock) for testing
//! without kernel eBPF support.

pub mod cachedb;
#[cfg(feature = "clash-api")]
pub mod clash_api;
pub mod connection_tracker;
pub mod control;
pub mod dns;
pub mod ebpf;
pub mod mode;
#[cfg(feature = "ebpf")]
pub(crate) mod netlink;
pub mod pool;
pub mod relay;
pub mod routing;
pub mod sniffing;
pub mod stats;
pub mod subscription;

pub use honk_outbound::alive as outbound;
pub use honk_outbound::group;
pub use honk_outbound::proxy;

use clap::Parser;
use honk_config::Config;
use honk_ebpf_common::ParamKey;
use std::path::PathBuf;
use tracing::{info, warn};

/// Raise the soft descriptor limit toward the hard maximum, then return the
/// one startup snapshot used to size every control-plane descriptor owner.
fn raise_nofile_rlimit() -> anyhow::Result<usize> {
    use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, setrlimit};

    let (original_soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|error| anyhow::anyhow!("getrlimit(RLIMIT_NOFILE): {error}"))?;
    let desired_soft = if hard == RLIM_INFINITY {
        1_048_576
    } else {
        hard
    };
    let active_soft = if original_soft < desired_soft {
        match setrlimit(Resource::RLIMIT_NOFILE, desired_soft, hard) {
            Ok(()) => {
                info!("Raised NOFILE rlimit to {} (hard={})", desired_soft, hard);
                desired_soft
            }
            Err(error) => {
                warn!(
                    "Failed to raise NOFILE rlimit to {}: {}; using soft limit {}",
                    desired_soft, error, original_soft
                );
                original_soft
            }
        }
    } else {
        info!(
            "NOFILE rlimit already {} (soft) / {} (hard)",
            original_soft, hard
        );
        original_soft
    };

    Ok(usize::try_from(active_soft)
        .unwrap_or(control::MAX_EFFECTIVE_NOFILE)
        .min(control::MAX_EFFECTIVE_NOFILE))
}

#[cfg(feature = "ebpf")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfiguredInterfaces {
    pub(crate) lan: Vec<String>,
    pub(crate) wan: Vec<String>,
    pub(crate) single_homed: bool,
}

#[cfg(feature = "ebpf")]
pub(crate) fn configured_interfaces(config: &honk_config::Config) -> ConfiguredInterfaces {
    let default_interface = detect_default_interface();
    let lan = resolve_configured_interface_names(
        &config.global.lan_interface,
        default_interface.as_deref(),
    );
    let wan = resolve_configured_interface_names(
        &config.global.wan_interface,
        default_interface.as_deref(),
    );
    let single_homed = !wan.is_empty() && lan.iter().any(|name| wan.contains(name));
    ConfiguredInterfaces {
        lan,
        wan,
        single_homed,
    }
}

/// Resolve an interface list against one default-route snapshot. An unresolved
/// `auto` entry stays pending instead of binding the datapath to loopback.
#[cfg(feature = "ebpf")]
pub(crate) fn resolve_configured_interface_names(
    configured: &[String],
    default_interface: Option<&str>,
) -> Vec<String> {
    let mut resolved = Vec::with_capacity(configured.len());
    for name in configured {
        let name = if name == "auto" || name.is_empty() {
            let Some(default_interface) = default_interface else {
                continue;
            };
            default_interface
        } else {
            name.as_str()
        };
        if !resolved.iter().any(|existing| existing == name) {
            resolved.push(name.to_string());
        }
    }
    resolved
}

/// Detect the interface used by the IPv4 default route.
#[cfg(feature = "ebpf")]
///
/// Parses `/proc/net/route` and returns the interface with destination
/// `00000000` and mask `00000000` and the lowest metric.
fn detect_default_interface() -> Option<String> {
    honk_config::config::default_route_interface()
}

/// Default eBPF object file embedded into the binary.
/// Built-in eBPF object embedded at compile time by build.rs.
/// `--bpf-object` CLI flag overrides this at runtime.
#[cfg(feature = "ebpf")]
const DEFAULT_BPF_OBJECT: &[u8] = include_bytes!(env!("HONK_EBPF_OBJECT"));

#[derive(clap::Subcommand, Debug)]
pub enum ClashCommand {
    /// Set clash mode (rule / global / direct)
    Mode {
        /// Mode value: rule, global, or direct
        mode: String,
    },
    /// Set selector group proxy choice
    Proxy {
        /// Selector group name
        group: String,
        /// Node name to select
        node: String,
    },
    /// Test per-node TCP connect latency
    Delay {
        /// Node name to test
        node: String,
        /// Optional target URL (defaults to node address:port)
        #[arg(short, long)]
        url: Option<String>,
    },
    /// Ask the running instance to reload its configured file
    Reload,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand (reload, mode, proxy, delay)
    #[command(subcommand)]
    pub command: Option<ClashCommand>,

    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/honk/config.dae")]
    pub config: PathBuf,

    /// Append operational logs to this path, overriding `global.log_file`
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Path to an external eBPF object file (for real eBPF backend).
    /// If omitted, the built-in object file is used.
    #[arg(short = 'b', long)]
    pub bpf_object: Option<PathBuf>,

    /// BPF pin root directory
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub bpf_pin_root: PathBuf,

    /// Run in debug mode with verbose logging
    #[arg(short, long)]
    pub debug: bool,

    /// Use mock eBPF backend (for testing without kernel support)
    #[arg(long)]
    pub mock_ebpf: bool,
}

pub async fn handle_clash_command(cli: &Cli) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    let cmd = cli.command.as_ref().expect("subcommand required");

    match cmd {
        ClashCommand::Reload => {
            let pid = request_reload(std::path::Path::new(INSTANCE_LOCK_PATH))?;
            println!("Reload requested for honk-core process {pid}");
        }
        ClashCommand::Mode { mode } => {
            let valid_modes = ["rule", "global", "direct"];
            if !valid_modes.contains(&mode.as_str()) {
                anyhow::bail!(
                    "Invalid mode '{}'. Valid modes: {}",
                    mode,
                    valid_modes.join(", ")
                );
            }
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let mut config = config;
            config.experimental.clash_api.default_mode = mode.clone();
            config.validate()?;
            config.to_file(cli.config.to_str().unwrap())?;
            println!("Mode set to {}", mode);
        }
        ClashCommand::Proxy { group, node } => {
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let group_exists = config.groups.iter().any(|g| g.name == *group);
            if !group_exists {
                anyhow::bail!("Group '{}' not found in configuration", group);
            }
            let node_exists = config.nodes.iter().any(|n| n.name == *node);
            if !node_exists {
                anyhow::bail!("Node '{}' not found in configuration", node);
            }
            println!("Proxy group '{}' set to '{}'", group, node);
        }
        ClashCommand::Delay { node, url } => {
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let target_node = config
                .nodes
                .iter()
                .find(|n| n.name == *node)
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found in configuration", node))?;

            let addr = if let Some(u) = url {
                u.clone()
            } else {
                format!("{}:{}", target_node.host(), target_node.port)
            };

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            let socket_addrs: Vec<_> = addr.to_socket_addrs()?.collect();
            if socket_addrs.is_empty() {
                anyhow::bail!("Could not resolve address: {}", addr);
            }
            match std::net::TcpStream::connect_timeout(&socket_addrs[0], timeout) {
                Ok(stream) => {
                    let elapsed = start.elapsed();
                    drop(stream);
                    println!("{}: {}ms", node, elapsed.as_millis());
                }
                Err(e) => {
                    anyhow::bail!("Failed to connect to {} ({}): {}", node, addr, e);
                }
            }
        }
    }
    Ok(())
}

const INSTANCE_LOCK_PATH: &str = "/run/honk-core.lock";

fn publish_instance_pid(file: &mut std::fs::File) -> anyhow::Result<()> {
    use std::io::Write;

    file.set_len(0)
        .map_err(|error| anyhow::anyhow!("truncate instance lock: {error}"))?;
    writeln!(file, "{}", std::process::id())
        .map_err(|error| anyhow::anyhow!("write instance PID: {error}"))
}

fn running_instance_pid(path: &std::path::Path) -> anyhow::Result<libc::pid_t> {
    use nix::fcntl::{Flock, FlockArg};
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no running honk-core instance; {} does not exist",
                path.display()
            )
        } else {
            anyhow::anyhow!("open instance lock {}: {error}", path.display())
        }
    })?;
    let mut file = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(_) => anyhow::bail!("no running honk-core instance holds {}", path.display()),
        Err((file, error)) if error == nix::errno::Errno::EWOULDBLOCK => file,
        Err((_, error)) => {
            anyhow::bail!("inspect instance lock {}: {error}", path.display())
        }
    };
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(|error| anyhow::anyhow!("read instance lock {}: {error}", path.display()))?;
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!(
            "running honk-core instance has no PID in {}; restart it with this binary",
            path.display()
        );
    }
    let pid = value
        .parse::<libc::pid_t>()
        .map_err(|error| anyhow::anyhow!("invalid instance PID in {}: {error}", path.display()))?;
    if pid <= 0 {
        anyhow::bail!("invalid instance PID {pid} in {}", path.display());
    }
    Ok(pid)
}

fn request_reload(path: &std::path::Path) -> anyhow::Result<libc::pid_t> {
    let pid = running_instance_pid(path)?;
    // SAFETY: libc::kill has no pointer or lifetime requirements.
    if unsafe { libc::kill(pid, libc::SIGHUP) } == -1 {
        anyhow::bail!(
            "send SIGHUP to honk-core process {pid}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(pid)
}

/// Take the process-wide instance lock: the datapath uses fixed names
/// (dae0, daens, TC hooks) and a stopping instance's cleanup destroys
/// them, so a second instance must never start while the first is still
/// draining (its late cleanup would rip the fresh datapath out from
/// under it — the restart race that hung the lab for a day). Waits up
/// to 240s for the previous instance to exit (busy gateways can take
/// well over 90s to drain), then fails loudly.
fn acquire_instance_lock(
    _bpf_pin_root: &std::path::Path,
) -> anyhow::Result<nix::fcntl::Flock<std::fs::File>> {
    use nix::fcntl::{Flock, FlockArg};
    // /run (not the bpffs pin root, which rejects regular files).
    let path = std::path::PathBuf::from(INSTANCE_LOCK_PATH);
    let mut file = std::fs::File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open instance lock {}: {}", path.display(), e))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
    let mut logged = false;
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(mut flock) => {
                publish_instance_pid(&mut flock)?;
                return Ok(flock);
            }
            Err((f, _)) if std::time::Instant::now() < deadline => {
                file = f; // the failed lock hands the file back for the retry
                if !logged {
                    info!(
                        "another honk-core instance is shutting down; \
                         waiting for the datapath lock at {}",
                        path.display()
                    );
                    logged = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err((_, e)) => {
                anyhow::bail!(
                    "another honk-core instance holds {} ({}); refusing to start",
                    path.display(),
                    e
                )
            }
        }
    }
}

fn prepare_nfqueue_startup(config: &mut Config, mock_mode: bool) {
    if !config.global.nfqueue_enable {
        return;
    }

    let reason = if mock_mode {
        Some("the mock eBPF backend was selected".to_string())
    } else {
        #[cfg(not(feature = "ebpf"))]
        {
            Some("honk-core was built without the ebpf feature".to_string())
        }
        #[cfg(feature = "ebpf")]
        {
            honk_nfqueue::preflight()
                .err()
                .map(|error| error.to_string())
        }
    };

    if let Some(reason) = reason {
        warn!(
            requested = true,
            %reason,
            "NFQUEUE is unavailable at startup; continuing with NFQUEUE staging disabled"
        );
        config.global.nfqueue_enable = false;
    }
}

fn probe_runtime_data_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::create_dir_all(path)?;
    if !std::fs::metadata(path)?.is_dir() {
        return Err(std::io::Error::other(
            "runtime data path is not a directory",
        ));
    }

    let probe = path.join(format!(
        ".honk-write-probe-{}",
        uuid::Uuid::new_v4().as_simple()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&probe)?;
    drop(file);
    std::fs::remove_file(probe)
}

fn prepare_runtime_data_dir_with_fallback(
    requested: &std::path::Path,
    fallback: impl FnOnce() -> std::io::Result<PathBuf>,
) -> anyhow::Result<(PathBuf, Option<std::io::Error>)> {
    let requested_error = match probe_runtime_data_dir(requested) {
        Ok(()) => return Ok((requested.to_path_buf(), None)),
        Err(error) => error,
    };
    let fallback = fallback().map_err(|fallback_error| {
        anyhow::anyhow!(
            "runtime data directory {} is unusable: {requested_error}; determine fallback working directory: {fallback_error}",
            requested.display()
        )
    })?;
    probe_runtime_data_dir(&fallback).map_err(|fallback_error| {
        anyhow::anyhow!(
            "runtime data directory {} is unusable: {requested_error}; fallback {} is unusable: {fallback_error}",
            requested.display(),
            fallback.display()
        )
    })?;
    Ok((fallback, Some(requested_error)))
}

fn prepare_runtime_data_dir(
    requested: &std::path::Path,
) -> anyhow::Result<(PathBuf, Option<std::io::Error>)> {
    prepare_runtime_data_dir_with_fallback(requested, std::env::current_dir)
}

fn resolved_log_file_path(
    config: &Config,
    cli_override: Option<&std::path::Path>,
) -> Option<PathBuf> {
    cli_override
        .map(honk_config::paths::resolve_artifact_path)
        .or_else(|| match config.global.log_file.trim() {
            "" => None,
            path => Some(honk_config::paths::resolve_artifact_path(path)),
        })
}

fn open_log_file(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!("create log directory {}: {error}", parent.display())
        })?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| anyhow::anyhow!("open log file {}: {error}", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "log destination is not a regular file: {}",
        path.display()
    );
    Ok(file)
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Load the configuration before initializing logging so `log_level` in
    // the config file is honored (previously only --debug/RUST_LOG had any
    // effect and config log_level was silently ignored).
    let mut config = Config::from_file(cli.config.to_str().unwrap())?;
    config.validate()?;
    let requested_data_dir = PathBuf::from(&config.global.data_dir);
    let (runtime_data_dir, data_dir_creation_error) =
        prepare_runtime_data_dir(&requested_data_dir)?;
    honk_config::paths::set_data_dir(runtime_data_dir).map_err(|requested| {
        anyhow::anyhow!(
            "runtime data directory is already {}; cannot switch to {}",
            honk_config::paths::data_dir().display(),
            requested.display()
        )
    })?;
    // Make `direct`/`block` usable as group members without declaring them
    // in the config (Direct/Block protocols → DirectHandler/BlockHandler).
    config.ensure_builtin_nodes();
    // Traffic to the gateway's own addresses always goes direct (must),
    // keeping admin/API access alive even when every node is down.
    config.ensure_local_direct_rules();

    // Effective log level: --debug flag > RUST_LOG env > config log_level >
    // "info".
    let config_level = match config.global.log_level.trim() {
        "" => "info",
        other => other,
    };
    let default_level = if cli.debug { "debug" } else { config_level };
    // quinn logs every endpoint-driver death at ERROR; probe/warm endpoints
    // over retiring AnyTLS sessions die as a matter of course (the SYNACK
    // watchdog kills them on purpose), so that target is silenced unless
    // RUST_LOG says otherwise.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!("{default_level},quinn::endpoint=off"))
    });

    let log_file_path = resolved_log_file_path(&config, cli.log_file.as_deref());
    let log_file_layer = if let Some(path) = log_file_path.as_ref() {
        let file = open_log_file(path)?;
        Some(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .with_filter(env_filter.clone()),
        )
    } else {
        None
    };

    // Console, optional file, and Clash API output use independent layers.
    // With no `/logs` subscription, the API layer contributes no callsite interest.
    #[cfg(feature = "clash-api")]
    let (clash_log_layer, clash_log_handle) = clash_api::logs::layer();

    use tracing_subscriber::prelude::*;
    let registry = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
        .with(log_file_layer);
    #[cfg(feature = "clash-api")]
    let registry = registry.with(clash_log_layer);
    registry.init();

    info!("honk-core v{} starting", env!("CARGO_PKG_VERSION"));
    info!("Config: {}", cli.config.display());
    if let Some(error) = data_dir_creation_error {
        warn!(
            requested = %requested_data_dir.display(),
            fallback = %honk_config::paths::data_dir().display(),
            %error,
            "Runtime data directory is unusable; using process working directory"
        );
    }
    info!(directory = %honk_config::paths::data_dir().display(), "Runtime data directory configured");
    if let Some(path) = log_file_path.as_ref() {
        info!(path = %path.display(), "File logging enabled");
    }

    let effective_nofile = match raise_nofile_rlimit() {
        Ok(limit) => limit,
        Err(error) => {
            warn!(%error, "Failed to read NOFILE rlimit; using conservative budget");
            1_024
        }
    };
    let resource_budget = control::ResourceBudget::for_nofile(effective_nofile);
    let tcp_flow_max = resource_budget.active_tcp_flows.saturating_mul(2);
    if tcp_flow_max < 256 {
        warn!(
            nofile = resource_budget.effective_nofile,
            tcp_floor = resource_budget.active_tcp_flows,
            tcp_max = tcp_flow_max,
            "Low TCP flow admission ceiling; raise RLIMIT_NOFILE in the service limits to avoid gateway-wide backpressure"
        );
    }

    // Install the bootstrap resolver for proxy-server hostname lookups so
    // node dials never depend on the (potentially self-intercepted) regular
    // DNS path — without it a restart can deadlock: nodes are unreachable
    // because their hostnames do not resolve, and the hostnames do not
    // resolve because no node is reachable yet.
    honk_outbound::bootstrap::set_global(honk_outbound::bootstrap::BootstrapResolver::parse(
        &config.global.bootstrap_resolver,
    ));
    if !config.global.bootstrap_resolver.is_empty() {
        info!("Bootstrap resolver: {}", config.global.bootstrap_resolver);
    }

    // A valid stored body makes network refresh non-blocking for startup.
    // Missing subscriptions still get the bounded first-fetch grace period;
    // every fetch continues in the background after the control plane starts.
    let subscription_store = if config.global.store_subscribe {
        match subscription::SubscriptionStore::in_data_dir() {
            Ok(store) => {
                info!(directory = %store.root().display(), "Subscription store ready");
                Some(store)
            }
            Err(error) => {
                warn!(%error, "Subscription store unavailable; continuing without persistence");
                None
            }
        }
    } else {
        None
    };
    let mut sub_manager: Option<std::sync::Arc<subscription::SubscriptionManager>> = None;
    let mut late_sub_rx = None;
    let subscriptions: Vec<_> = config
        .subscriptions
        .iter()
        .filter(|sub| sub.enabled)
        .cloned()
        .collect();
    if !subscriptions.is_empty() {
        let manager = std::sync::Arc::new(subscription::SubscriptionManager::new()?);
        let sub_count = subscriptions.len();
        let mut requires_network = std::collections::HashSet::new();

        for (index, sub) in subscriptions.iter().enumerate() {
            let Some(store) = subscription_store.as_ref() else {
                requires_network.insert(index);
                continue;
            };
            match store.load_nodes(sub).await {
                Ok(Some(nodes)) => {
                    info!(
                        subscription = %sub.name,
                        nodes = nodes.len(),
                        "Restored subscription"
                    );
                    config
                        .nodes
                        .retain(|node| node.subscription_id != Some(sub.id));
                    config.nodes.extend(nodes);
                }
                Ok(None) => {
                    requires_network.insert(index);
                }
                Err(error) => {
                    warn!(
                        subscription = %sub.name,
                        %error,
                        "Failed to restore subscription"
                    );
                    requires_network.insert(index);
                }
            }
        }

        let (results_tx, mut results_rx) = tokio::sync::mpsc::unbounded_channel();
        for (index, sub) in subscriptions.iter().cloned().enumerate() {
            let manager = manager.clone();
            let store = subscription_store.clone();
            let tx = results_tx.clone();
            tokio::spawn(async move {
                let result = manager.fetch_and_store(&sub, store.as_ref()).await;
                let _ = tx.send((index, sub, result));
            });
        }
        drop(results_tx);

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(deadline);

        let mut received = 0usize;
        while !requires_network.is_empty() {
            tokio::select! {
                result = results_rx.recv() => {
                    match result {
                        Some((index, sub, Ok(nodes))) => {
                            info!(
                                subscription = %sub.name,
                                nodes = nodes.len(),
                                "Subscription fetched"
                            );
                            config
                                .nodes
                                .retain(|node| node.subscription_id != Some(sub.id));
                            config.nodes.extend(nodes);
                            requires_network.remove(&index);
                        }
                        Some((index, sub, Err(error))) => {
                            warn!(subscription = %sub.name, %error, "Failed to fetch subscription");
                            requires_network.remove(&index);
                        }
                        None => break,
                    }
                    received += 1;
                }
                _ = &mut deadline => {
                    info!(
                        received,
                        total = sub_count,
                        "Subscription fetch deadline reached; starting control plane"
                    );
                    break;
                }
            }
        }

        if received < sub_count {
            info!(
                pending = sub_count - received,
                "Subscriptions still refreshing in background"
            );
            late_sub_rx = Some(results_rx);
        }
        sub_manager = Some(manager);
    }

    // Resolve group filters into concrete node IDs. This must run for every
    // config — not just when subscriptions delivered nodes — because groups
    // defined with `filter:` (or with no filter at all, meaning "all nodes")
    // would otherwise end up with an empty member list for static configs.
    // Filter-backed membership is rebuilt from the current node provenance.
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );
    for group in &config.groups {
        info!(
            "Group '{}' resolved {} node(s)",
            group.name,
            group.nodes.len()
        );
    }

    info!(
        "Loaded {} nodes, {} groups, {} routing rules",
        config.nodes.len(),
        config.groups.len(),
        config.routing.rules.len()
    );

    let mock_mode = cli.mock_ebpf || cfg!(not(feature = "ebpf"));
    #[cfg(feature = "ebpf")]
    let configured_ifaces = configured_interfaces(&config);
    #[cfg(feature = "ebpf")]
    if !mock_mode
        && detect_default_interface().is_none()
        && config
            .global
            .lan_interface
            .iter()
            .chain(&config.global.wan_interface)
            .any(|name| name == "auto" || name.is_empty())
    {
        warn!(
            "default route unavailable; auto interface binding is pending until a network route appears"
        );
    }

    // Only the real datapath owns fixed dae0/daens/TC resources. Mock mode
    // must remain usable without access to the process-global /run lock.
    let _instance_lock = if mock_mode {
        None
    } else {
        Some(acquire_instance_lock(&cli.bpf_pin_root)?)
    };

    // The old instance owns queue 320 until this lock is released. Check
    // NFQUEUE only after the handoff so a transient busy result cannot turn
    // a healthy restart into a permanently degraded process.
    prepare_nfqueue_startup(&mut config, mock_mode);

    // Create the dae0 link pair before eBPF load so PARAM.dae0_ifindex is correct.
    // dae0peer stays in the host namespace during the dae0 attach, then moves
    // to the daens netns in setup_daens_namespace() below.
    #[cfg(feature = "ebpf")]
    let _dae0_guard: Option<Dae0Guard>;
    #[cfg(not(feature = "ebpf"))]
    let _dae0_guard: Option<()>;
    if !mock_mode {
        // QUIC socket headroom: the default 208 KiB rmem/wmem caps a
        // ~1ms-RTT QUIC path at ~2 Gbps (setsockopt is clamped to 2×max).
        // Raise the ceiling so the 8 MiB SO_RCVBUF/SO_SNDBUF requests in
        // honk-outbound's marked_udp_socket actually land. Best-effort —
        // caps, not allocations.
        for (key, val) in [
            ("net.core.rmem_max", "16777216"),
            ("net.core.wmem_max", "16777216"),
        ] {
            if let Err(e) = set_sysctl(key, val) {
                warn!("failed to set {}={}: {}", key, val, e);
            }
        }
        #[cfg(feature = "ebpf")]
        {
            if let Some(lan_ifname) = configured_ifaces.lan.first() {
                let _ = set_sysctl(&format!("net.ipv4.conf.{}.rp_filter", lan_ifname), "0");
            }
            _dae0_guard = Some(create_dae0_link()?);
            for wan_ifname in &configured_ifaces.wan {
                enable_wan_accept_ra(wan_ifname);
            }
            info!(
                "dae0 link created before eBPF load (ifindex={})",
                _dae0_guard.as_ref().unwrap().ifindex
            );
        }
        #[cfg(not(feature = "ebpf"))]
        {
            _dae0_guard = None;
        }
    } else {
        _dae0_guard = None;
    }

    #[cfg(feature = "ebpf")]
    let mut attached_ifaces: ebpf::real::AttachedMap = Default::default();
    let mut ebpf_backend: Box<dyn ebpf::EbpfBackend> = if cli.mock_ebpf {
        info!("Using mock eBPF backend");
        Box::new(ebpf::mock::MockEbpfBackend::new())
    } else {
        #[cfg(feature = "ebpf")]
        {
            let bpf_object_bytes = match &cli.bpf_object {
                Some(path) => {
                    info!("Loading real eBPF backend from {}", path.display());
                    std::fs::read(path).map_err(|e| {
                        anyhow::anyhow!("failed to read eBPF object file {}: {}", path.display(), e)
                    })?
                }
                None => {
                    info!("Loading real eBPF backend from built-in object");
                    DEFAULT_BPF_OBJECT.to_vec()
                }
            };
            let lan_ifnames = &configured_ifaces.lan;
            let wan_ifnames = &configured_ifaces.wan;
            let single_homed = configured_ifaces.single_homed;
            let primary_lan = lan_ifnames.first().map(String::as_str);
            let primary_wan = wan_ifnames.first().map(String::as_str).unwrap_or("");
            let mut backend = ebpf::real::RealEbpfBackend::load(
                &bpf_object_bytes,
                &cli.bpf_pin_root,
                config.global.tproxy_port,
                config.global.tproxy_mark,
                primary_lan,
                primary_wan,
                single_homed,
            )
            .await?;

            let ifindex_of = |name: &str| -> Option<u32> {
                std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
            };
            if let Some(primary_lan) = primary_lan
                && let Some(i) = ifindex_of(primary_lan)
            {
                attached_ifaces.insert(
                    primary_lan.to_string(),
                    ebpf::real::AttachedInterface {
                        ifindex: i,
                        role: if single_homed {
                            ebpf::IfaceRole::LanWan
                        } else {
                            ebpf::IfaceRole::Lan
                        },
                        hooks: ebpf::DynamicHooks {
                            ingress: true,
                            egress: true,
                        },
                    },
                );
            }
            if !single_homed
                && !primary_wan.is_empty()
                && let Some(i) = ifindex_of(primary_wan)
            {
                attached_ifaces.insert(
                    primary_wan.to_string(),
                    ebpf::real::AttachedInterface {
                        ifindex: i,
                        role: ebpf::IfaceRole::Wan,
                        hooks: ebpf::DynamicHooks {
                            ingress: true,
                            egress: true,
                        },
                    },
                );
            }
            for extra_lan in lan_ifnames.iter().skip(1) {
                match backend.attach_lan(extra_lan, single_homed) {
                    Ok(hooks) => {
                        if let Some(i) = ifindex_of(extra_lan) {
                            attached_ifaces.insert(
                                extra_lan.clone(),
                                ebpf::real::AttachedInterface {
                                    ifindex: i,
                                    role: if single_homed && wan_ifnames.contains(extra_lan) {
                                        ebpf::IfaceRole::LanWan
                                    } else {
                                        ebpf::IfaceRole::Lan
                                    },
                                    hooks,
                                },
                            );
                        }
                    }
                    Err(e) => warn!("Failed to attach LAN programs to {}: {}", extra_lan, e),
                }
            }
            for extra_wan in wan_ifnames.iter().skip(1) {
                let egress = backend.attach_wan_egress(extra_wan);
                if let Err(e) = &egress {
                    warn!("Failed to attach WAN egress to {}: {}", extra_wan, e);
                }
                let ingress = backend.attach_wan_ingress(extra_wan);
                if let Err(e) = &ingress {
                    warn!("Failed to attach WAN ingress to {}: {}", extra_wan, e);
                }
                let hooks = ebpf::DynamicHooks {
                    ingress: ingress.is_ok(),
                    egress: egress.is_ok(),
                };
                if (hooks.ingress || hooks.egress)
                    && let Some(i) = ifindex_of(extra_wan)
                {
                    attached_ifaces.insert(
                        extra_wan.clone(),
                        ebpf::real::AttachedInterface {
                            ifindex: i,
                            role: ebpf::IfaceRole::Wan,
                            hooks,
                        },
                    );
                }
            }

            Box::new(backend)
        }
        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF feature not compiled in, using mock backend");
            Box::new(ebpf::mock::MockEbpfBackend::new())
        }
    };

    let bpf_params = ebpf::BpfLoadParams {
        tproxy_port: config.global.tproxy_port,
        tproxy_mark: config.global.tproxy_mark,
        so_mark: 0,
        control_plane_pid: std::process::id(),
        ..Default::default()
    };
    ebpf_backend.inject(&bpf_params)?;
    info!(
        "eBPF backend initialized with tproxy_port={}",
        config.global.tproxy_port
    );

    // BigEndianTproxyPort is already configured by ebpf_backend.inject() above.
    ebpf_backend.set_param(ParamKey::SoMarkFromDae, 0)?;
    ebpf_backend.set_param(ParamKey::ControlPlanePid, std::process::id())?;
    info!("eBPF parameters set");

    if !mock_mode {
        #[cfg(feature = "ebpf")]
        {
            // Attach dae0_ingress on dae0 (host namespace) first, while
            // dae0peer is still in the host namespace as well.
            ebpf_backend.attach_dae0_programs()?;
            info!("dae0 programs attached");

            // Move dae0peer into daens and install the daens policy routing.
            // The process itself never leaves the host netns; daens exists
            // only as (a) the delivery environment for redirected packets
            // (policy routing + sk_lookup + bpf_sk_assign), (b) the place
            // where the dae0peer TC filter must be attached, and (c) the
            // home of the TPROXY listener sockets and the DNS/UDP reply
            // sockets (Go dae "listen and serve in dae netns" / "anyfrom"
            // semantics).  Listener bind and reply-socket creation enter
            // daens through scoped `with_daens_netns` switches; accepted
            // connections are then handled — and upstream dials made — from
            // ordinary host-netns worker threads.
            setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
            info!("dae0peer moved to daens netns");

            // Attach the sk_lookup program in daens (scoped switch inside
            // the backend).  It overrides socket selection for proxy-bound
            // packets arriving on dae0peer and delivers them to the TPROXY
            // listener while keeping the original destination intact.
            ebpf_backend.attach_sk_lookup()?;
            info!("tproxy_sk_lookup attached in daens");

            // Attach the dae0peer TC ingress program (scoped switch inside
            // the backend).  It uses bpf_sk_assign() to hand proxy-bound
            // packets to the transparent listener socket while preserving
            // the original destination.
            ebpf_backend.attach_dae0peer_ingress()?;
            info!("dae0peer_ingress attached in daens");
        }
    } else {
        info!("Skipping real interface binding (mock mode)");
    }

    // We follow Go dae-core: no global iptables PREROUTING rules. Proxy-bound
    // traffic is selected by the LAN ingress TC eBPF program and redirected to
    // the dae0 link; dae0peer_ingress / tproxy_sk_lookup in daens then assign
    // it (bpf_sk_assign) to the TPROXY listener sockets bound inside daens.
    // Accepted connections are handled on host-netns worker threads, and
    // replies to the client egress dae0peer and take the host dae0_ingress
    // rewrite path. Direct traffic bypasses userspace.
    if !mock_mode {
        info!(
            "Using eBPF TC redirect datapath (tproxy_mark=0x{:x})",
            config.global.tproxy_mark
        );
    } else {
        info!("Skipping eBPF datapath setup (mock mode)");
    }

    dns::ecs::resolve_client_subnet(&mut config.dns).await;
    let dns_client_subnet = config
        .dns
        .effective_client_subnet()
        .map_err(anyhow::Error::new)?;

    let traffic_geo = routing::GeoRequirements::for_traffic(&config.routing.rules);
    let dns_geo = dns::routing::DnsRouter::geo_requirements(&config.dns);
    let geo_sources = routing::GeoSourceSet::load(&traffic_geo.union(&dns_geo));
    let router = routing::Router::new_with_geo_sources(
        &config.routing.rules,
        &config.routing.default_outbound,
        &geo_sources,
    )?;
    info!("Router ready with {} compiled routes", router.route_count());

    let proxy_registry = std::sync::Arc::new(proxy::ProxyRegistry::default_resolver()?);
    info!(
        "Proxy registry ready ({} handlers)",
        proxy_registry.handler_count()
    );

    let dns_cache = std::sync::Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(
        config.dns.cache.max_size,
    )));
    let dns_router = std::sync::Arc::new(dns::routing::DnsRouter::new_with_geo_sources(
        &config.dns,
        &geo_sources,
    )?);
    // Keep a concrete Arc so we can attach SharedGroupManager after the
    // control plane builds it (same cell traffic dials use).
    let dns_upstream_pool = std::sync::Arc::new(
        dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
            &config.dns.upstream,
            dns_router.clone(),
            Some(proxy_registry.clone()),
            config.nodes.clone(),
            config.groups.clone(),
            honk_outbound::bootstrap::BootstrapResolver::parse(&config.global.bootstrap_resolver),
            config.dns.strategy,
        )?
        .with_client_subnet(dns_client_subnet)
        .with_timeouts(
            std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
            std::time::Duration::from_millis(config.global.connect_timeout_ms),
        ),
    );
    for u in &config.dns.upstream {
        info!(
            "DNS upstream config: name={} addr={} proto={:?} outbound={:?}",
            u.name, u.address, u.protocol, u.outbound
        );
    }
    let hosts_sources = dns::forwarder::HostsSourceSet::load(&config.dns)?;
    let dns_policy = dns::policy::PolicyId::from_config_with_artifacts(
        &config.dns,
        &hosts_sources.fingerprint(),
        &dns_router.geo_fingerprint(),
    )?;
    let hosts_snapshot = hosts_sources.parse()?;
    let dns_forwarder = std::sync::Arc::new(
        dns::forwarder::DnsForwarder::new(
            dns_upstream_pool.clone() as std::sync::Arc<dyn dns::forwarder::DnsUpstreamPool>,
            dns_cache,
            dns_router,
        )
        .with_timeouts(
            std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
            std::time::Duration::from_millis(config.global.connect_timeout_ms),
        )
        .with_strategy(config.dns.strategy)
        .with_cache_enabled(config.dns.cache.enabled)
        .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
        .with_policy_id(dns_policy)
        .with_hosts_snapshot(hosts_snapshot),
    );
    info!("DNS forwarder ready");

    let mut control_plane = control::ControlPlane::new_with_upstream_pool_and_budget(
        config,
        ebpf_backend,
        router,
        proxy_registry,
        dns_forwarder,
        dns_upstream_pool.clone(),
        resource_budget,
    )?;
    control_plane.set_log_file_override(cli.log_file.clone(), log_file_path);

    #[cfg(feature = "ebpf")]
    let iface_watcher = if !cli.mock_ebpf {
        ebpf::real::IfaceWatcher::spawn(
            control_plane.ebpf_handle(),
            control_plane.config_handle(),
            control_plane.command_sender(),
            attached_ifaces,
        )
    } else {
        None
    };
    #[cfg(feature = "ebpf")]
    control_plane.set_iface_watcher(iface_watcher);

    // Wire GroupManager into DNS outbound selection (Selector/URLTest/…).
    dns_upstream_pool.set_group_manager(Some(control_plane.group_manager()));
    dns_upstream_pool.set_traffic_router(Some(control_plane.traffic_router()));
    info!("DNS upstream pool attached to SharedGroupManager + traffic Router");

    // Persistent cache (selector choices, clash mode): opens cache.db when
    // `experimental.cache_file` is enabled, restores Selector choices, and
    // wires change persistence into the group manager.
    control_plane.init_cache_db(cli.config.parent()).await;

    #[cfg(feature = "clash-api")]
    let clash_cfg = control_plane
        .config_handle()
        .read()
        .await
        .experimental
        .clash_api
        .clone();
    let cache_db = control_plane.cache_db();
    #[cfg(feature = "clash-api")]
    let mode = cache_db
        .as_ref()
        .and_then(|db| db.load_clash_mode())
        .and_then(|mode| mode::ModeState::normalize(&mode))
        .or_else(|| mode::ModeState::normalize(&clash_cfg.default_mode))
        .unwrap_or_else(|| "Rule".to_string());
    #[cfg(not(feature = "clash-api"))]
    let mode = "Rule".to_string();
    let (default_selection, valid_global_selections) = {
        let config = control_plane.config_handle();
        let config = config.read().await;
        let selections = config
            .groups
            .iter()
            .map(|group| group.name.clone())
            .chain(config.nodes.iter().map(|node| node.name.clone()))
            .collect::<Vec<_>>();
        let default = selections.first().cloned().unwrap_or_default();
        (default, selections)
    };
    let global_selection = cache_db
        .as_ref()
        .and_then(|db| db.load_selector_choice("GLOBAL"))
        .filter(|selection| {
            valid_global_selections
                .iter()
                .any(|valid| valid == selection)
        })
        .unwrap_or(default_selection);
    let mode_state: mode::SharedModeState = std::sync::Arc::new(parking_lot::RwLock::new(
        mode::ModeState::new(&mode, global_selection),
    ));
    control_plane.set_mode_state(mode_state.clone());
    control_plane.start_datapath_flags_coordinator()?;

    // Starts only when external_controller is configured; bind/parse
    // failures are logged and never abort startup.
    #[cfg(feature = "clash-api")]
    if !clash_cfg.external_controller.is_empty() {
        let external_ui = if clash_cfg.external_ui.is_empty() {
            String::new()
        } else {
            honk_config::paths::resolve_dependency_path(&clash_cfg.external_ui)
                .to_string_lossy()
                .into_owned()
        };
        // Accept "host:port"; a bare ":port" listens on all interfaces.
        let listen_str = if clash_cfg.external_controller.starts_with(':') {
            format!("0.0.0.0{}", clash_cfg.external_controller)
        } else {
            clash_cfg.external_controller.clone()
        };
        match listen_str.parse::<std::net::SocketAddr>() {
            Ok(listen) => {
                let stream_samplers = std::sync::Arc::new(clash_api::StreamSamplers::new());
                let connection_tracker = control_plane.connection_tracker();
                let state = std::sync::Arc::new(clash_api::ClashState {
                    config: control_plane.config_handle(),
                    stats: control_plane.stats_handle(),
                    alive_set: control_plane.alive_set(),
                    group_manager: control_plane.group_manager(),
                    cache_db: control_plane.cache_db(),
                    connection_tracker,
                    proxy_registry: control_plane.proxy_registry(),
                    runtime_registry: control_plane.runtime_registry(),
                    mode_state,
                    datapath_flags: control_plane
                        .datapath_flags_handle()
                        .expect("datapath flags writer started above"),
                    secret: clash_cfg.secret.clone(),
                    connection_pool: control_plane.connection_pool(),
                    external_ui,
                    router: control_plane.traffic_router(),
                    log_handle: clash_log_handle.clone(),
                    dns_service: control_plane.dns_service(),
                    stream_samplers,
                });
                tokio::spawn(clash_api::serve(state, listen));
            }
            Err(error) => {
                warn!(
                    "invalid clash_api external_controller '{}': {}",
                    clash_cfg.external_controller, error
                );
            }
        }
    }

    info!("Starting control plane listeners and accept loop");

    let cmd_tx = control_plane.command_sender();

    // Late startup fetches and periodic refreshes both persist validated raw
    // bodies before delivering nodes through the serialized rebuild path.
    // Subscription nodes are never written back to the config file.
    let mut sub_tasks = Vec::new();
    if let Some(mut rx) = late_sub_rx {
        let merge_tx = cmd_tx.clone();
        sub_tasks.push(tokio::spawn(async move {
            while let Some((_index, sub, result)) = rx.recv().await {
                match result {
                    Ok(nodes) => {
                        info!(
                            "Background subscription '{}' fetched {} nodes; merging",
                            sub.name,
                            nodes.len()
                        );
                        if merge_tx
                            .send(control::ControlCommand::MergeSubscription {
                                subscription_id: sub.id,
                                name: sub.name.clone(),
                                nodes,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Background subscription '{}' fetch failed: {}", sub.name, e);
                    }
                }
            }
        }));
    }
    // Periodic refresh: each enabled subscription with a non-zero
    // update_interval is re-fetched on that cadence and merged through the
    // same path. A failed refresh keeps the previously merged nodes.
    if let Some(manager) = sub_manager {
        for sub in subscriptions
            .iter()
            .filter(|s| s.enabled && s.update_interval > 0)
        {
            let sub = sub.clone();
            let manager = manager.clone();
            let merge_tx = cmd_tx.clone();
            let store = subscription_store.clone();
            sub_tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(sub.update_interval)).await;
                    match manager.fetch_and_store(&sub, store.as_ref()).await {
                        Ok(nodes) => {
                            info!(
                                "Subscription '{}' refreshed: {} nodes",
                                sub.name,
                                nodes.len()
                            );
                            if merge_tx
                                .send(control::ControlCommand::MergeSubscription {
                                    subscription_id: sub.id,
                                    name: sub.name.clone(),
                                    nodes,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Subscription '{}' refresh failed; keeping existing nodes: {}",
                                sub.name, e
                            );
                        }
                    }
                }
            }));
        }
    }

    // SIGHUP handler: reload configuration from disk and push it to the
    // control plane without interrupting established connections.
    let config_path = cli.config.clone();
    let reload_tx = cmd_tx.clone();
    let config_handle = control_plane.config_handle();
    let reload_subscription_store = subscription_store.clone();
    let sighup_handle = tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to register SIGHUP handler: {}", e);
                return;
            }
        };
        let mut request_id = 0u64;
        loop {
            sighup.recv().await;
            request_id = request_id.wrapping_add(1).max(1);
            info!("SIGHUP reload request {request_id} received");
            match Config::from_file(config_path.to_str().unwrap_or("/etc/honk/config.dae")) {
                Ok(mut new_config) => {
                    if let Err(e) = new_config.validate() {
                        warn!("SIGHUP reload request {request_id} rejected: invalid config: {e}");
                        continue;
                    }
                    new_config.ensure_builtin_nodes();
                    new_config.ensure_local_direct_rules();
                    // The on-disk config contains no subscription nodes (they
                    // exist only in memory), so a naive reload would empty
                    // every subscription-fed group until the next periodic
                    // refresh. Stabilize subscription IDs by URL and carry
                    // the running subscription nodes over; then kick off an
                    // immediate background refresh for fresh data.
                    let refresh_subs: Vec<_> = {
                        let current = config_handle.read().await;
                        let mut matched_previous = std::collections::HashSet::new();
                        for sub in &mut new_config.subscriptions {
                            if let Some(old) = current.subscriptions.iter().find(|old| {
                                old.url == sub.url && !matched_previous.contains(&old.id)
                            }) {
                                matched_previous.insert(old.id);
                                sub.id = old.id;
                            }
                        }
                        let known: std::collections::HashSet<uuid::Uuid> = new_config
                            .subscriptions
                            .iter()
                            .filter(|sub| sub.enabled)
                            .map(|sub| sub.id)
                            .collect();
                        let carried: Vec<_> = current
                            .nodes
                            .iter()
                            .filter(|n| n.subscription_id.is_some_and(|id| known.contains(&id)))
                            .cloned()
                            .collect();
                        if !carried.is_empty() {
                            info!(
                                "Preserving {} subscription node(s) across reload",
                                carried.len()
                            );
                            new_config.nodes.extend(carried);
                        }
                        new_config
                            .subscriptions
                            .iter()
                            .filter(|s| s.enabled)
                            .cloned()
                            .collect()
                    };
                    if new_config.global.store_subscribe
                        && let Some(store) = reload_subscription_store.as_ref()
                    {
                        for sub in &refresh_subs {
                            if new_config
                                .nodes
                                .iter()
                                .any(|node| node.subscription_id == Some(sub.id))
                            {
                                continue;
                            }
                            match store.load_nodes(sub).await {
                                Ok(Some(nodes)) => {
                                    info!(
                                        subscription = %sub.name,
                                        nodes = nodes.len(),
                                        "Restored subscription during reload"
                                    );
                                    new_config.nodes.extend(nodes);
                                }
                                Ok(None) => {}
                                Err(error) => warn!(
                                    subscription = %sub.name,
                                    %error,
                                    "Failed to restore subscription during reload"
                                ),
                            }
                        }
                    }
                    // Resolve group filters into concrete node IDs, same as
                    // startup — otherwise filter-based groups keep stale
                    // (or empty) member lists in the rebuilt GroupManager.
                    honk_config::parser::resolve_group_filters(
                        &mut new_config.groups,
                        &new_config.nodes,
                        &new_config.subscriptions,
                    );
                    if let Err(e) = reload_tx
                        .send(control::ControlCommand::ReloadConfig {
                            request_id,
                            config: Box::new(new_config),
                        })
                        .await
                    {
                        warn!(
                            "SIGHUP reload request {request_id} rejected: command send failed: {e}"
                        );
                        break;
                    }
                    // Immediately re-fetch enabled subscriptions in the
                    // background so nodes don't stay at their startup
                    // snapshot for up to `update_interval`.
                    if !refresh_subs.is_empty() {
                        let tx = reload_tx.clone();
                        let store = reload_subscription_store.clone();
                        tokio::spawn(async move {
                            let manager = match crate::subscription::SubscriptionManager::new() {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("subscription manager init failed: {}", e);
                                    return;
                                }
                            };
                            for sub in refresh_subs {
                                match manager.fetch_and_store(&sub, store.as_ref()).await {
                                    Ok(nodes) => {
                                        let _ = tx
                                            .send(control::ControlCommand::MergeSubscription {
                                                subscription_id: sub.id,
                                                name: sub.name.clone(),
                                                nodes,
                                            })
                                            .await;
                                    }
                                    Err(e) => warn!(
                                        "post-reload subscription refresh failed for '{}': {}",
                                        sub.name, e
                                    ),
                                }
                            }
                        });
                    }
                }
                Err(e) => {
                    warn!("SIGHUP reload request {request_id} rejected: config load failed: {e}")
                }
            }
        }
    });

    let sig_handle = tokio::spawn(async move {
        // The shell may start us with SIGINT/SIGTERM ignored (e.g. background
        // job). Reset them to the default disposition so tokio can install its
        // own handlers.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }

        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to register SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
            }
        }
        let _ = cmd_tx.send(control::ControlCommand::Shutdown).await;
    });

    info!("honk-core is running. Press Ctrl+C to stop.");
    let control_result = control_plane.run().await;

    // Signal systemd that we're stopping (Type=notify)
    #[cfg(target_os = "linux")]
    let _ = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Stopping]);

    sig_handle.abort();
    sighup_handle.abort();
    for handle in sub_tasks {
        handle.abort();
    }
    info!("honk-core stopped");

    control_result
}

#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct Dae0Setup {
    pub ifindex: u32,
    pub peer_ifindex: u32,
    pub peer_mac: [u8; 6],
}

/// Guard that removes the `dae0` link pair and policy routing when it goes out
/// of scope. If setup fails mid-way, drop cleans up whatever was installed.
///
/// Link-local addressing (169.254.0.1/32 on dae0, 169.254.0.11/32 on dae0peer)
/// eliminates the need for iptables MASQUERADE and TCP MSS clamping — the kernel
/// already treats link-local traffic as local.
#[cfg(feature = "ebpf")]
struct Dae0Guard {
    pub ifindex: u32,
}

#[cfg(feature = "ebpf")]
impl Dae0Guard {
    fn new() -> Self {
        Self { ifindex: 0 }
    }
}

#[cfg(feature = "ebpf")]
impl Drop for Dae0Guard {
    fn drop(&mut self) {
        info!("Cleaning up dae0 side effects");
        // The recorded ifindex keeps cleanup pointed at the device THIS
        // instance created, never at a same-named replacement.
        cleanup_dae0_interface((self.ifindex != 0).then_some(self.ifindex));
    }
}

#[cfg(feature = "ebpf")]
fn create_dae0_link() -> anyhow::Result<Dae0Guard> {
    let mut guard = Dae0Guard::new();

    // Stale-state cleanup (previous run): drop the compat bind-mount (the
    // FD-held namespace dies with its owner process) and any leftover dae0.
    // The singleton lock guarantees no live sibling owns these names.
    if is_mountpoint("/run/netns/daens") {
        let _ = nix::mount::umount2(DAENS_NS_PATH, nix::mount::MntFlags::MNT_DETACH);
    }
    if let Ok(idx) = netlink::ifindex_of("dae0")
        && let Ok(mut nl) = netlink::NlSock::new()
    {
        let _ = nl.del_link(idx);
    }

    // FD-owned namespace (unshare + held FD, compat bind-mount inside).
    create_daens_namespace()?;

    let mut nl = netlink::NlSock::new().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    let link_kind = nl
        .add_link_pair("dae0", "dae0peer")
        .map_err(|e| anyhow::anyhow!("failed to add dae0 link pair: {e}"))?;
    info!(kind = ?link_kind, "Created dae0/dae0peer link pair");

    let dae0_idx = netlink::ifindex_of("dae0")?;
    let peer_idx = netlink::ifindex_of("dae0peer")?;

    // These are datapath-critical: a "successful" startup without them is
    // worse than a loud failure.
    nl.set_link_up(dae0_idx, true)
        .map_err(|e| anyhow::anyhow!("bring dae0 up: {e}"))?;
    nl.set_link_up(peer_idx, true)
        .map_err(|e| anyhow::anyhow!("bring dae0peer up: {e}"))?;

    for (key, val) in [
        ("net.ipv4.conf.dae0.rp_filter", "0"),
        ("net.ipv4.conf.dae0.accept_local", "1"),
    ] {
        match set_sysctl(key, val) {
            Ok(()) => info!("{} = {}", key, val),
            Err(e) => warn!("failed to set {}={}: {}", key, val, e),
        }
    }

    // Enable IPv6 on dae0 for the daens IPv6 reply path.
    let _ = set_sysctl("net.ipv6.conf.dae0.disable_ipv6", "0");
    let _ = set_sysctl("net.ipv6.conf.dae0.forwarding", "1");

    guard.ifindex = dae0_idx;

    // Assign a link-local /32 address to the host-side dae0.  Link-local
    // addressing eliminates the need for iptables MASQUERADE and TCP MSS
    // clamping — the kernel already treats 169.254.0.0/16 traffic as local.
    let host_v4: std::net::Ipv4Addr = DAENS_HOST_IP.parse().unwrap();
    // Idempotent: delete any stale address left by a previous run first.
    let _ = nl.addr_op(false, dae0_idx, netlink::FAM_V4, &host_v4.octets(), 32);
    nl.addr_op(true, dae0_idx, netlink::FAM_V4, &host_v4.octets(), 32)
        .map_err(|e| anyhow::anyhow!("dae0 IPv4 address {}: {e}", host_v4))?;

    // Assign an IPv6 ULA address to the host-side dae0 so the daens
    // namespace can route IPv6 replies back through this link.
    let host_v6: std::net::Ipv6Addr = DAENS_HOST_IPV6.parse().unwrap();
    let _ = nl.addr_op(false, dae0_idx, netlink::FAM_V6, &host_v6.octets(), 64);
    let _ = nl.addr_op(true, dae0_idx, netlink::FAM_V6, &host_v6.octets(), 64);

    // Enable IPv6 forwarding so daens-originated IPv6 packets reach the LAN.
    let _ = set_sysctl("net.ipv6.conf.all.forwarding", "1");

    Ok(guard)
}

#[cfg(feature = "ebpf")]
fn setup_daens_namespace(tproxy_mark: u32, tproxy_port: u16) -> anyhow::Result<()> {
    let _ = tproxy_port;
    use netlink::{FAM_V4, FAM_V6, NlSock};

    // Host-side dae0 MAC: the L2 next-hop for the daens default route.
    let dae0_mac = netlink::mac_of("dae0").map_err(|e| anyhow::anyhow!("read dae0 MAC: {e}"))?;
    let dae0_idx = netlink::ifindex_of("dae0")?;
    let peer_idx = netlink::ifindex_of("dae0peer")?;

    // Move dae0peer into daens (BPF programs are already attached).
    let mut nl = NlSock::new().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    nl.set_link_netns_fd(peer_idx, daens_fd()?)
        .map_err(|e| anyhow::anyhow!("move dae0peer to daens: {e}"))?;
    info!("Moved dae0peer to daens");

    let host_v4: std::net::Ipv4Addr = DAENS_HOST_IP.parse().unwrap();
    let peer_v4: std::net::Ipv4Addr = DAENS_PEER_IP.parse().unwrap();
    let host_v6: std::net::Ipv6Addr = DAENS_HOST_IPV6.parse().unwrap();
    let peer_v6: std::net::Ipv6Addr = DAENS_PEER_IPV6.parse().unwrap();

    // Configure daens in one scoped switch: a netlink socket opened inside
    // operates on the daens namespace, and /proc/sys writes hit the
    // namespace's sysctls.
    let peer_mac = with_daens_netns("configure daens", || {
        use anyhow::Context as _;
        let mut n = NlSock::new().context("daens netlink socket")?;
        // /sys inside a scoped setns still shows the HOST's devices (the
        // view is per-mount, not per-reader) — look links up over netlink,
        // whose socket is bound to the namespace it was created in.
        let (lo, _) = n.get_link("lo").context("lo in daens")?;
        let (peer, peer_mac) = n.get_link("dae0peer").context("dae0peer in daens")?;
        n.set_link_up(lo, true).context("lo up")?;
        n.set_link_up(peer, true).context("dae0peer up")?;

        // fwmark → table 100 with a local default route (v4 + v6 mirror):
        // marked packets are delivered to daens-local sockets.
        n.add_rule_fwmark(FAM_V4, tproxy_mark, 100)?;
        n.add_route(
            FAM_V4,
            100,
            netlink::ROUTE_LOCAL,
            netlink::SCOPE_HOST,
            netlink::PROTO_STATIC,
            None,
            None,
            Some(lo),
        )?;
        n.add_rule_fwmark(FAM_V6, tproxy_mark, 100)?;
        n.add_route(
            FAM_V6,
            100,
            netlink::ROUTE_LOCAL,
            netlink::SCOPE_HOST,
            netlink::PROTO_STATIC,
            None,
            None,
            Some(lo),
        )?;

        // Link-local /32 on dae0peer. The link-scope route tells the kernel
        // that 169.254.0.1 (dae0) is directly reachable at L2; without it,
        // /32 prevents treating 169.254.0.1 as a valid nexthop.
        n.addr_op(true, peer, FAM_V4, &peer_v4.octets(), 32)?;
        n.add_route(
            FAM_V4,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_LINK,
            netlink::PROTO_STATIC,
            Some((&host_v4.octets(), 32)),
            None,
            Some(peer),
        )?;
        n.add_route(
            FAM_V4,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_UNIVERSE,
            netlink::PROTO_STATIC,
            None,
            Some(&host_v4.octets()),
            Some(peer),
        )?;

        // IPv6 ULA on dae0peer + IPv6 default (non-fatal: v6 path degrades
        // to v4-only rather than aborting startup).
        let _ = n.addr_op(true, peer, FAM_V6, &peer_v6.octets(), 64);
        let _ = n.add_route(
            FAM_V6,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_UNIVERSE,
            netlink::PROTO_STATIC,
            None,
            Some(&host_v6.octets()),
            Some(peer),
        );

        // Static neighbours for the host side of the link (v4 + v6).
        n.neigh_replace(peer, FAM_V4, &host_v4.octets(), &dae0_mac)?;
        let _ = n.neigh_replace(peer, FAM_V6, &host_v6.octets(), &dae0_mac);

        // Disable rp_filter, enable accept_local/route_localnet in daens so
        // packets with foreign source/dest addresses can be delivered locally.
        for (key, val) in [
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.all.accept_local", "1"),
            ("net.ipv4.conf.all.route_localnet", "1"),
            ("net.ipv4.conf.dae0peer.rp_filter", "0"),
            ("net.ipv4.conf.dae0peer.accept_local", "1"),
            ("net.ipv4.conf.dae0peer.route_localnet", "1"),
            ("net.ipv4.conf.lo.accept_local", "1"),
            ("net.ipv4.conf.lo.route_localnet", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
            ("net.ipv6.conf.dae0peer.forwarding", "1"),
            ("net.ipv6.conf.dae0peer.accept_ra", "0"),
        ] {
            let _ = set_sysctl(key, val);
        }
        Ok(peer_mac)
    })?;

    // Install static neighbour entries on the host so replies to
    // daens-bound connections are forwarded to the correct dae0peer MAC.
    nl.neigh_replace(dae0_idx, FAM_V4, &peer_v4.octets(), &peer_mac)
        .map_err(|e| anyhow::anyhow!("host neighbour for daens peer: {e}"))?;
    let _ = nl.neigh_replace(dae0_idx, FAM_V6, &peer_v6.octets(), &peer_mac);

    // Make sure the host forwards traffic between dae0 and the LAN/WAN
    // interfaces; this is required for the SYN-ACK path back to the client.
    set_sysctl("net.ipv4.ip_forward", "1")
        .map_err(|e| anyhow::anyhow!("enable net.ipv4.ip_forward: {e}"))?;

    info!("Configured daens namespace (mark={:#x})", tproxy_mark);
    DAENS_READY.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Path of the daens network-namespace bind-mount, kept for external
/// tooling compatibility (`ip netns exec`, debug shells). The engine
/// itself never depends on it — the namespace is FD-owned (below).
#[cfg(target_os = "linux")]
pub(crate) const DAENS_NS_PATH: &str = "/var/run/netns/daens";

/// Runtime truth for "daens is set up", set by [`setup_daens_namespace`]
/// on success. Socket creation must key on this, never on
/// `DAENS_NS_PATH` existing — a leftover or failed compat mount says
/// nothing about the datapath (a first clean deploy once bound every
/// TPROXY listener into the host namespace because of that confusion).
#[cfg(target_os = "linux")]
pub(crate) static DAENS_READY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether THIS instance created the compat bind-mount at
/// [`DAENS_NS_PATH`]. Cleanup only ever unmounts what it mounted —
/// never a same-named mount belonging to another tool.
#[cfg(feature = "ebpf")]
static COMPAT_MOUNTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether THIS instance created the regular file used as the compat
/// bind-mount target. If `/run/netns` belongs to iproute2, unmounting the
/// child does not remove that file, so cleanup must remove its own target.
#[cfg(feature = "ebpf")]
static COMPAT_FILE_CREATED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The engine-owned daens namespace FD, created by
/// [`create_daens_namespace`] at startup. An open namespace FD pins the
/// namespace for the process lifetime — no `ip netns` registry involved.
#[cfg(feature = "ebpf")]
static DAENS_FD: std::sync::OnceLock<std::os::unix::io::OwnedFd> = std::sync::OnceLock::new();

/// Whether THIS instance mounted the tmpfs at /run/netns (the compat
/// bind-mount's parent). Tracked separately from [`COMPAT_MOUNTED`]:
/// cleanup unmounts the parent only when it is ours.
#[cfg(feature = "ebpf")]
static PARENT_TMPFS_MOUNTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Create the daens network namespace without iproute2: a throwaway thread
/// `unshare(CLONE_NEWNET)`s, hands its `/proc/thread-self/ns/net` FD back
/// (the FD pins the namespace after the thread exits), and the FD is stored
/// process-wide. For external tooling compatibility the namespace is also
/// bind-mounted to [`DAENS_NS_PATH`] (best-effort — the engine works fine
/// without the mount).
#[cfg(feature = "ebpf")]
fn create_daens_namespace() -> anyhow::Result<&'static std::os::unix::io::OwnedFd> {
    use std::os::unix::io::OwnedFd;

    if let Some(fd) = DAENS_FD.get() {
        return Ok(fd);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Err(error) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET) {
            let _ = tx.send(Err(std::io::Error::from(error)));
            return;
        }
        // /proc/self/ns/net always shows the main thread's namespace. This
        // thread-local path is the namespace created by unshare above.
        let task_ns = "/proc/thread-self/ns/net";
        // Best-effort compat mount: /var/run/netns/daens (iproute2 shape).
        // The target must be a FILE — namespace handles are files, and a
        // file bind-mount onto a directory fails with ENOTDIR. The parent
        // is made a mountpoint (tmpfs) only if it isn't one already —
        // crucially NOT via a self-MS_BIND, which would stack-duplicate
        // every nsfs mount beneath it (lab ns pins included) on every
        // engine restart.
        let _ = std::fs::create_dir_all("/var/run/netns");
        // /proc/mounts lists the real path (/var/run is a symlink to
        // /run) — check the canonical path or every engine start
        // mounts a fresh tmpfs over the registry, hiding iproute2's
        // namespace files (the lab netns "disappears"). The tmpfs must
        // be mounted BEFORE the target file is created, or the mount
        // hides it and the bind below fails on a first clean deploy.
        if !is_mountpoint("/run/netns") {
            match nix::mount::mount(
                Some("tmpfs"),
                "/var/run/netns",
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                None::<&str>,
            ) {
                Ok(()) => {
                    PARENT_TMPFS_MOUNTED.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Err(error) => warn!("tmpfs mount on /run/netns failed: {error}"),
            }
        }
        let compat_target_ready = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(DAENS_NS_PATH)
        {
            Ok(_) => {
                COMPAT_FILE_CREATED.store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => true,
            Err(error) => {
                warn!("create compat daens target failed: {error}");
                false
            }
        };
        if compat_target_ready {
            // The bind result is reported, never silently ignored — a failed
            // compat mount leaves debug tooling unable to find daens.
            match nix::mount::mount(
                Some(task_ns),
                DAENS_NS_PATH,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            ) {
                Ok(()) => COMPAT_MOUNTED.store(true, std::sync::atomic::Ordering::Relaxed),
                Err(error) => {
                    warn!("compat bind-mount of daens failed (debug tooling degraded): {error}");
                }
            }
        }
        let result = std::fs::File::open(task_ns).map(OwnedFd::from);
        if result.is_ok() {
            let link = std::fs::read_link(task_ns)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<readlink failed: {e}>"));
            info!("daens FD source: {} -> {}", task_ns, link);
        }
        let _ = tx.send(result);
    });
    let fd = rx
        .recv()
        .map_err(|_| anyhow::anyhow!("daens creator thread died"))?
        .map_err(|e| anyhow::anyhow!("create daens namespace: {e}"))?;
    info!("Created daens network namespace (FD-owned)");
    Ok(DAENS_FD.get_or_init(|| fd))
}

/// The process-wide daens FD (created on demand).
#[cfg(feature = "ebpf")]
pub(crate) fn daens_fd() -> anyhow::Result<&'static std::os::unix::io::OwnedFd> {
    create_daens_namespace()
}

/// Run `f` with the calling thread temporarily switched into the `daens`
/// network namespace, restoring the original namespace on every exit path —
/// including when `f` returns an error or panics (via the drop guard below).
///
/// This mirrors Go dae's `DaeNetns.WithRequired`: the process (all threads)
/// always stays in the host netns; only operations that need the
/// daens-internal view enter it for a scoped, synchronous call:
/// dae0peer TC filter attach, sk_lookup attach, and DNS/UDP reply socket
/// creation (Go "anyfrom" semantics — reply sockets must live in daens so
/// their packets egress dae0peer and take the host dae0_ingress rewrite path
/// back to the LAN).
///
/// `f` must be fully synchronous and must not `.await`: setns(2) is
/// per-thread, so a future parked while inside daens could resume on a
/// different worker thread that never switched, and this thread could
/// restore its namespace while the parked future still assumes daens.  A
/// process-wide mutex serializes the switches; it is not strictly required
/// for correctness (each switch is per-thread) but keeps enter/leave pairs
/// easy to reason about and the logs ordered.
#[cfg(target_os = "linux")]
pub(crate) fn with_daens_netns<R>(
    op: &str,
    f: impl FnOnce() -> anyhow::Result<R>,
) -> anyhow::Result<R> {
    static DAENS_SWITCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the saved network namespace on drop, so the original
    /// namespace is regained even when `f` panics. A failed restore
    /// aborts the process — a worker left in the wrong namespace would
    /// silently originate dials from daens forever after.
    struct RestoreNs<'a> {
        fd: std::fs::File,
        op: &'a str,
    }
    impl Drop for RestoreNs<'_> {
        fn drop(&mut self) {
            if let Err(error) = nix::sched::setns(&self.fd, nix::sched::CloneFlags::CLONE_NEWNET) {
                tracing::error!(
                    "failed to restore original netns after '{}': {} — aborting",
                    self.op,
                    error
                );
                std::process::abort();
            }
        }
    }

    // Lock FIRST: the save-and-switch is serialized before any namespace
    // reads, so no other scoped switch can interleave.
    let _switch_guard = DAENS_SWITCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // /proc/thread-self/ns/net is this thread's real namespace;
    // /proc/self/ns/net always resolves to the main thread.
    let orig_ns = std::fs::File::open("/proc/thread-self/ns/net")
        .map_err(|e| anyhow::anyhow!("{}: open /proc/thread-self/ns/net: {}", op, e))?;

    // The FD-owned namespace is the primary handle; the compat bind-mount
    // path is the fallback for tests, mock mode, and non-ebpf builds.
    #[cfg(feature = "ebpf")]
    {
        let daens = daens_fd()
            .map_err(|error| anyhow::anyhow!("{op}: daens namespace unavailable: {error:#}"))?;
        nix::sched::setns(daens, nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|error| anyhow::anyhow!("{op}: setns(daens): {error}"))?;
    }
    #[cfg(not(feature = "ebpf"))]
    {
        let daens = std::fs::File::open(DAENS_NS_PATH)
            .map_err(|error| anyhow::anyhow!("{op}: open {DAENS_NS_PATH}: {error}"))?;
        nix::sched::setns(&daens, nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|error| anyhow::anyhow!("{op}: setns(daens): {error}"))?;
    }
    let _restore_guard = RestoreNs { fd: orig_ns, op };
    f()
}

#[cfg(feature = "ebpf")]
fn cleanup_dae0_interface(recorded_ifindex: Option<u32>) {
    // Unmount the compat bind-mount only when THIS instance mounted it —
    // a same-named mount from another tool is never ours to tear down.
    if COMPAT_MOUNTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
        let _ = nix::mount::umount2(DAENS_NS_PATH, nix::mount::MntFlags::MNT_DETACH);
    }
    if COMPAT_FILE_CREATED.swap(false, std::sync::atomic::Ordering::Relaxed)
        && let Err(error) = std::fs::remove_file(DAENS_NS_PATH)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!("remove compat daens target failed: {error}");
    }
    // Same ownership rule for the parent tmpfs (child must go first).
    if PARENT_TMPFS_MOUNTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
        let _ = nix::mount::umount2("/run/netns", nix::mount::MntFlags::MNT_DETACH);
    }
    DAENS_READY.store(false, std::sync::atomic::Ordering::Release);
    // The FD-owned namespace dies with the process (dae0peer goes with it).

    let Ok(mut nl) = netlink::NlSock::new() else {
        return;
    };
    // Delete dae0 only when it is still the device this instance created:
    // the recorded ifindex must still match the name — an outsider's
    // same-named recreation is left alone.
    let victim = match recorded_ifindex {
        Some(idx) if netlink::ifindex_of("dae0").ok() == Some(idx) => Some(idx),
        Some(_) => None,
        None => netlink::ifindex_of("dae0").ok(),
    };
    if let Some(idx) = victim {
        let _ = nl.del_link(idx);
    }
    // Policy-routing rules for daens live inside the daens namespace and
    // disappear with it; these are only a safety net for stale
    // host-namespace rules.
    let _ = nl.del_rule_fwmark(netlink::FAM_V4, honk_ebpf_common::TPROXY_MARK, 100);
    let _ = nl.del_rule_fwmark(netlink::FAM_V6, honk_ebpf_common::TPROXY_MARK, 100);
}

/// Addressing for the dae0/dae0peer link pair between the host namespace and
/// the isolated `daens` namespace.  These strings are the canonical values:
/// the netns setup consumes them (ebpf feature only), while the control
/// plane's internal-traffic filter (`control::is_honk_internal_addr`) uses
/// the numeric forms `DAE0_IPV6_PREFIX_HI` / `DAE0_IPV4_NET` below in every
/// build.  `control` tests assert both forms agree.
///
/// Link-local addresses (169.254.0.0/16) are used instead of a private
/// subnet so that the kernel treats daens-originated traffic as local — no
/// iptables MASQUERADE or TCP MSS clamping is needed.
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_HOST_IP: &str = "169.254.0.1";
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_PEER_IP: &str = "169.254.0.11";
/// IPv6 ULA addresses of the dae0/dae0peer link pair (fd00:686f:6e6b::/64).
/// The middle hextets are ASCII "honk" (`68 6f 6e 6b`) so the mnemonic
/// stays readable while remaining a valid IPv6 ULA prefix.
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_HOST_IPV6: &str = "fd00:686f:6e6b::1";
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_PEER_IPV6: &str = "fd00:686f:6e6b::2";

/// First 64 bits of `DAENS_HOST_IPV6`/`DAENS_PEER_IPV6` — the
/// fd00:686f:6e6b::/64 ULA prefix — as a big-endian u64.
pub(crate) const DAE0_IPV6_PREFIX_HI: u64 = 0xfd00_686f_6e6b_0000;
/// `DAENS_HOST_IP`/`DAENS_PEER_IP` with the host bits masked off
/// (169.254.0.0/16), as a big-endian u32.
pub(crate) const DAE0_IPV4_NET: u32 = 0xA9FE_0000;

pub(crate) fn set_sysctl(key: &str, value: &str) -> anyhow::Result<()> {
    // Prefer /proc/sys because the standalone `sysctl` binary may not be on
    // PATH in minimal environments (e.g. NixOS containers).
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    if let Err(e) = std::fs::write(&path, format!("{}\n", value)) {
        // Fallback to the sysctl command if /proc/sys write fails.
        let output = std::process::Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, value)])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "sysctl -w {}={} failed: {} (proc write also failed: {})",
                key,
                value,
                String::from_utf8_lossy(&output.stderr),
                e
            );
        }
    }
    Ok(())
}

/// Keep RA reception alive on a WAN interface across the datapath's
/// all.forwarding=1 pin: with the stock accept_ra=1 the kernel drops RAs
/// once forwarding is on, and networkd's userspace RA disables itself the
/// same way — either path lets the SLAAC default route expire (#46).
#[cfg(feature = "ebpf")]
pub(crate) fn enable_wan_accept_ra(ifname: &str) {
    if let Err(e) = set_sysctl(&format!("net.ipv6.conf.{ifname}.accept_ra"), "2") {
        warn!("failed to set accept_ra for {ifname}: {e}");
    }
}

/// Whether `path` is a mountpoint (appears in /proc/mounts).
#[cfg(feature = "ebpf")]
fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| m.lines().any(|l| l.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}
#[cfg(test)]
mod startup_lifecycle_tests {
    use super::{
        ClashCommand, Cli, open_log_file, prepare_nfqueue_startup, prepare_runtime_data_dir,
        prepare_runtime_data_dir_with_fallback, publish_instance_pid, running_instance_pid,
    };
    use clap::Parser;

    #[test]
    fn nfqueue_requested_with_mock_backend_falls_back_to_disabled() {
        let mut config = honk_config::Config::default();
        config.global.nfqueue_enable = true;
        prepare_nfqueue_startup(&mut config, true);
        assert!(!config.global.nfqueue_enable);
    }

    #[cfg(not(feature = "ebpf"))]
    #[test]
    fn nfqueue_requested_without_ebpf_falls_back_to_disabled() {
        let mut config = honk_config::Config::default();
        config.global.nfqueue_enable = true;
        prepare_nfqueue_startup(&mut config, false);
        assert!(!config.global.nfqueue_enable);
    }

    #[test]
    fn config_reserved_mark_mask_matches_datapath_abi() {
        assert_eq!(
            honk_config::routing::DATAPATH_RESERVED_MARK_MASK,
            honk_ebpf_common::SKB_MARK_RESERVED_MASK,
        );
    }

    #[test]
    fn missing_runtime_data_directory_is_created() {
        let root = tempfile::tempdir().expect("create temporary directory");
        let data_dir = root.path().join("nested/data");
        assert!(!data_dir.exists());

        let (effective, error) =
            prepare_runtime_data_dir(&data_dir).expect("prepare runtime data directory");

        assert_eq!(effective, data_dir);
        assert!(error.is_none());
        assert!(effective.is_dir());
        assert_eq!(std::fs::read_dir(&effective).unwrap().count(), 0);
    }

    #[test]
    fn runtime_data_directory_symlink_remains_usable() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create temporary directory");
        let target = root.path().join("data");
        let link = root.path().join("data-link");
        std::fs::create_dir(&target).expect("create data directory");
        symlink(&target, &link).expect("create data directory symlink");

        let (effective, error) = prepare_runtime_data_dir_with_fallback(&link, || {
            Ok(root.path().join("unused-fallback"))
        })
        .expect("prepare symlinked runtime data directory");
        assert_eq!(effective, link);
        assert!(error.is_none());
    }

    #[test]
    fn existing_read_only_data_directory_uses_writable_fallback() {
        let fallback = tempfile::tempdir().expect("create fallback directory");

        let (effective, error) =
            prepare_runtime_data_dir_with_fallback(std::path::Path::new("/proc"), || {
                Ok(fallback.path().to_path_buf())
            })
            .expect("prepare fallback data directory");

        assert_eq!(effective, fallback.path());
        assert!(error.is_some());
    }

    #[test]
    fn unusable_data_directory_and_fallback_preserve_both_errors() {
        let root = tempfile::tempdir().expect("create temporary directory");
        let invalid = root.path().join("not-a-directory");
        std::fs::write(&invalid, "file").expect("create blocking file");

        let error = prepare_runtime_data_dir_with_fallback(&invalid, || {
            Ok(std::path::PathBuf::from("/proc"))
        })
        .expect_err("reject unusable fallback");
        let message = error.to_string();
        assert!(message.contains(&invalid.display().to_string()));
        assert!(message.contains("/proc"));
        assert!(message.contains("fallback"));
    }

    #[test]
    fn new_log_file_is_private_regular_and_existing_mode_is_preserved() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("create temporary directory");
        let path = root.path().join("logs/honk.log");
        drop(open_log_file(&path).expect("create log file"));
        let metadata = std::fs::metadata(&path).expect("read log metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set existing log permissions");
        drop(open_log_file(&path).expect("reopen existing log file"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn log_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create temporary directory");
        let target = root.path().join("target.log");
        let link = root.path().join("honk.log");
        std::fs::write(&target, "unchanged").expect("create target");
        symlink(&target, &link).expect("create log symlink");

        assert!(open_log_file(&link).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[test]
    fn non_regular_log_destination_is_rejected() {
        assert!(open_log_file(std::path::Path::new("/dev/null")).is_err());
    }

    #[test]
    fn log_file_option_parses() {
        let cli =
            Cli::try_parse_from(["honk-core", "--log-file", "/var/log/honk/cli.log", "reload"])
                .expect("parse log file option");
        assert_eq!(
            cli.log_file.as_deref(),
            Some(std::path::Path::new("/var/log/honk/cli.log"))
        );
    }

    #[test]
    fn reload_command_targets_only_a_locked_instance() {
        let cli = Cli::try_parse_from(["honk-core", "reload"]).expect("parse reload command");
        assert!(matches!(cli.command, Some(ClashCommand::Reload)));

        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("honk-core.lock");
        let file = std::fs::File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open instance lock");
        let mut lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .expect("acquire instance lock");
        publish_instance_pid(&mut lock).expect("publish instance PID");

        assert_eq!(
            running_instance_pid(&path).expect("read locked instance PID"),
            std::process::id() as libc::pid_t
        );
        drop(lock);
        assert!(running_instance_pid(&path).is_err());
    }
}
