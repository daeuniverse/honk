#![recursion_limit = "256"]

//! honk-core: eBPF-based transparent proxy engine. Uses TC redirects and
//! `sk_lookup` BPF with an isolated `daens` network namespace — no iptables
//! TPROXY rules needed. The process (all threads) always stays in the host
//! netns; daens is entered only through scoped `with_daens_netns` switches
//! (dae0peer/sk_lookup attach, TPROXY listener bind, DNS/UDP reply socket
//! creation), mirroring Go dae's `DaeNetns.WithRequired` ("listen and serve
//! in dae netns"). Trait-based backends (real aya + mock) for testing
//! without kernel eBPF support.

#[cfg(feature = "clash-api")]
pub mod clash_api;
pub mod config_diagnostics;
pub(crate) mod configuration;
pub mod connection_tracker;
pub mod control;
pub mod daens;
pub(crate) mod degradations;
pub mod dns;
pub(crate) mod download_route;
pub mod ebpf;
mod logging;
mod marked_http;
pub mod mode;
#[cfg(feature = "native-api")]
pub mod native_api;
#[cfg(feature = "ebpf")]
pub(crate) mod netlink;
#[cfg_attr(not(feature = "native-api"), path = "observe/inert.rs")]
pub(crate) mod observe;
pub mod pool;
pub mod relay;
pub mod routing;
pub mod sniffing;
pub mod state;
pub mod stats;
pub mod subscription;
mod sysctl;

pub use honk_outbound::alive as outbound;
pub use honk_outbound::group;
pub use honk_outbound::proxy;

/// Build-time release tag or Git description; package version without Git metadata.
pub const VERSION: &str = env!("HONK_VERSION");
/// The commit this binary was built from; empty when the build had no Git checkout.
pub const REVISION: &str = env!("HONK_REVISION");
/// The target triple this binary was built for.
pub const TARGET: &str = env!("HONK_TARGET");

use clap::Parser;
use honk_config::Config;
use honk_config::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, finish_attempt, report_detailed_diagnostics,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use logging::{
    LOG_FILE_LIMIT, LocalTime, QUIET_LOG_TARGETS, RotatingLogFile, console_ansi, console_log_layer,
    resolved_log_file_path,
};
use state::startup::{claim_state, open_state_db};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

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

// ponytail: MemTotal ignores cgroup memory.max; read it if limited containers appear.
fn total_memory_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kib.saturating_mul(1024))
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
    /// Read the configuration db
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    /// Manage the password-mode administrator
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum AdminCommand {
    /// Delete the administrator record so that setup opens again; refused while honk-core runs
    Reset,
}

#[derive(clap::Subcommand, Debug)]
pub enum ConfigCommand {
    /// Write the active revision as one dae file, listener secrets included
    Export {
        /// New file to write; an existing one is refused
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Leave the listener secrets out
        #[arg(long)]
        without_secrets: bool,
    },
}

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about, long_about = None, disable_version_flag = true)]
#[command(arg(clap::Arg::new("version")
    .short('v')
    .long("version")
    .action(clap::ArgAction::Version)
    .help("Print version")))]
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

    /// Omit timestamps from console log lines, for journald or another
    /// logger that stamps them itself. The log file keeps its timestamps.
    #[arg(long)]
    pub disable_timestamp: bool,

    /// Use mock eBPF backend (for testing without kernel support)
    #[arg(long)]
    pub mock_ebpf: bool,

    /// Where the administered configuration lives: the `-c` file tree, or the
    /// revisions in `<data-dir>/state/honk.db`
    #[arg(long, value_enum, default_value = "file")]
    pub store: ConfigStore,

    /// Runtime data directory holding the state db; must equal `global.data_dir`
    #[arg(long, value_name = "PATH", default_value = honk_config::paths::DEFAULT_DATA_DIR, global = true)]
    pub data_dir: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigStore {
    File,
    Db,
}

pub async fn handle_clash_command(cli: &Cli) -> anyhow::Result<()> {
    use std::time::Duration;

    let cmd = cli.command.as_ref().expect("subcommand required");
    let read_config = || -> anyhow::Result<Config> {
        match cli.store {
            ConfigStore::File => Ok(Config::from_file(cli.config.to_str().unwrap())?),
            #[cfg(feature = "native-api")]
            ConfigStore::Db => {
                let text = native_api::store::db::export(&cli.data_dir, true)
                    .map_err(|error| anyhow::anyhow!("configuration db: {error}"))?;
                Ok(honk_config::parser::parse_dae_config(&text)?)
            }
            #[cfg(not(feature = "native-api"))]
            ConfigStore::Db => anyhow::bail!("--store db needs the native-api feature"),
        }
    };

    match cmd {
        #[cfg(feature = "native-api")]
        ClashCommand::Config {
            action:
                ConfigCommand::Export {
                    out,
                    without_secrets,
                },
        } => {
            native_api::store::db::export_to(&cli.data_dir, out, !without_secrets)?;
            println!(
                "Exported the active configuration revision to {}",
                out.display()
            );
        }
        #[cfg(not(feature = "native-api"))]
        ClashCommand::Config { .. } => anyhow::bail!("config export needs the native-api feature"),
        ClashCommand::Admin {
            action: AdminCommand::Reset,
        } => {
            let deleted = state::reset_admin(&cli.data_dir)
                .map_err(|error| anyhow::anyhow!("admin reset: {error}"))?;
            if deleted {
                println!("Deleted the administrator; setup is open again");
            } else {
                println!("No administrator was set up");
            }
        }
        ClashCommand::Reload => {
            let pid = request_reload(std::path::Path::new(INSTANCE_LOCK_PATH))?;
            println!("Reload requested for honk-core process {pid}");
        }
        ClashCommand::Mode { mode } => {
            anyhow::ensure!(
                cli.store == ConfigStore::File,
                "mode edits the -c file; with --store db, change default_mode through the native API"
            );
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
            let config = read_config()?;
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
            let config = read_config()?;
            config.validate()?;
            honk_outbound::util::init_bypass_mark(config.global.effective_so_mark())?;
            honk_outbound::bootstrap::set_global(
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
            );
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
            match honk_outbound::util::connect_outbound(&addr, timeout).await {
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
///
/// It is taken before the configuration or the state db is opened, so a
/// successor that fails to take it leaves nothing behind.
fn acquire_instance_lock(
    path: &std::path::Path,
    wait: std::time::Duration,
) -> anyhow::Result<nix::fcntl::Flock<std::fs::File>> {
    use nix::fcntl::{Flock, FlockArg};
    let mut file = std::fs::File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("open instance lock {}: {}", path.display(), e))?;
    let deadline = std::time::Instant::now() + wait;
    let holder =
        || running_instance_pid(path).map_or_else(|_| String::new(), |pid| format!(" (PID {pid})"));
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
                    // Logging is not set up yet.
                    eprintln!(
                        "honk-core: another honk-core instance{} is shutting down; \
                         waiting up to {}s for the datapath lock at {}",
                        holder(),
                        wait.as_secs(),
                        path.display()
                    );
                    logged = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err((_, e)) => {
                anyhow::bail!(
                    "another honk-core instance{} did not release {} within {}s ({}); \
                     refusing to start",
                    holder(),
                    path.display(),
                    wait.as_secs(),
                    e
                )
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_INSTANCE_LOCK: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Only the real datapath owns fixed dae0/daens/TC resources. Mock mode must
/// remain usable without access to the process-global /run lock.
fn instance_lock(mock_mode: bool) -> anyhow::Result<Option<nix::fcntl::Flock<std::fs::File>>> {
    #[cfg(test)]
    if let Some(path) = TEST_INSTANCE_LOCK.with(|path| path.borrow().clone()) {
        return acquire_instance_lock(&path, std::time::Duration::ZERO).map(Some);
    }
    if mock_mode {
        return Ok(None);
    }
    // /run, not the bpffs pin root, which rejects regular files.
    acquire_instance_lock(
        std::path::Path::new(INSTANCE_LOCK_PATH),
        std::time::Duration::from_secs(240),
    )
    .map(Some)
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

/// A valid cached Clash mode, else `default_mode`, else `Rule`.
#[cfg(feature = "clash-api")]
fn startup_clash_mode(mode_db: Option<&state::cache::CacheDb>, default_mode: &str) -> String {
    mode_db
        .and_then(|db| db.load_clash_mode())
        .and_then(|mode| mode::ModeState::normalize(&mode))
        .or_else(|| mode::ModeState::normalize(default_mode))
        .unwrap_or_else(|| "Rule".to_owned())
}

fn load_operator_config(
    path: &str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let start = diagnostics.len();
    // The file loader already owns parse failures; only validation finishes here.
    let config = Config::from_file_with_detailed_diagnostics(path, diagnostics)?;
    let source = diagnostics.get(start).map_or_else(
        || DiagnosticSources::new(Some(path.into())).root(),
        |diagnostic| diagnostic.source.sources().root(),
    );
    admit_operator_config(config, source, diagnostics)
}

fn admit_operator_config(
    config: Config,
    source: honk_config::diagnostic::SourceRef,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    config.append_diagnostics(source.clone(), diagnostics);
    let result = config.validate_detailed().and_then(|()| {
        subscription::validate_subscription_ids(&config.subscriptions).map_err(|_| {
            DetailedConfigError::new(
                ErrorCategory::Validation,
                "invalid-subscription-id",
                source.clone(),
                SettingPath::new("subscriptions").field("id"),
                "subscription IDs must be non-nil and unique",
            )
        })
    });
    let result = result.map_err(|mut error| {
        error.diagnostic.source = source;
        error
    });
    finish_attempt(result.map(|()| config), diagnostics)
}

#[cfg(feature = "native-api")]
fn load_operator_config_captured(
    path: &std::path::Path,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<(Config, Option<configuration::SourceUpdate>), DetailedConfigError> {
    if !path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dae"))
    {
        return load_operator_config(path.to_str().unwrap_or(""), diagnostics)
            .map(|config| (config, None));
    }
    let start = diagnostics.len();
    let loaded = match Config::from_dae_file_with_sources(
        path,
        &std::collections::HashMap::new(),
        honk_config::parser::SourceLimits::default(),
        diagnostics,
    ) {
        Ok(loaded) => loaded,
        Err(captured_error) => {
            diagnostics.truncate(start);
            let config = load_operator_config(path.to_str().unwrap_or(""), diagnostics)?;
            if config.experimental.native_api.config_write {
                return Err(captured_error);
            }
            return Ok((config, None));
        }
    };
    let source = loaded.sources[0].source.clone();
    let config = admit_operator_config(loaded.config, source, diagnostics)?;
    Ok((
        config,
        Some(configuration::SourceUpdate {
            sources: loaded.sources,
            dependencies: Vec::new(),
            geo_sources: None,
        }),
    ))
}

fn report_startup_failure(diagnostics: &[DetailedDiagnostic]) {
    for diagnostic in diagnostics.iter().filter(|diagnostic| !diagnostic.terminal) {
        eprintln!(
            "{:?} code={} setting={} value={}: {}",
            diagnostic.severity,
            diagnostic.code,
            diagnostic.setting,
            diagnostic.value,
            diagnostic.message,
        );
    }
}

/// Render one runtime admission rejection at the process reporting boundary.
pub(crate) fn report_runtime_admission_error(error: &DetailedConfigError) {
    let diagnostic = error.diagnostic.as_ref();
    tracing::warn!(
        code = diagnostic.code,
        setting = %diagnostic.setting,
        value = %diagnostic.value,
        "runtime configuration rejected: {}",
        diagnostic.message
    );
}

/// Startup failed after the backend, watcher and maintenance owners went live;
/// the singleton lock must outlive their joined cleanup.
async fn abort_startup(
    control_plane: &mut control::ControlPlane,
    subscriptions: subscription::SubscriptionSupervisor,
    error: anyhow::Error,
) -> anyhow::Error {
    let error = control_plane.abort_startup(error).await;
    if let Err(shutdown) = subscriptions.shutdown().await {
        warn!(%shutdown, "subscription startup state failed to stop");
    }
    error
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    #[cfg(feature = "native-api")]
    let started_at = std::time::SystemTime::now();
    #[cfg(feature = "native-api")]
    let started = std::time::Instant::now();
    // Load the configuration before initializing logging so `log_level` in
    // the config file is honored (previously only --debug/RUST_LOG had any
    // effect and config log_level was silently ignored).
    let mut diagnostics = Vec::new();
    #[cfg(feature = "native-api")]
    let mut native_sources = None;
    #[cfg(not(feature = "native-api"))]
    anyhow::ensure!(
        cli.store == ConfigStore::File,
        "--store db needs the native-api feature"
    );
    let mock_mode = cli.mock_ebpf || cfg!(not(feature = "ebpf"));
    // Everything else in `run` drops before it.
    let _instance_lock = instance_lock(mock_mode)?;
    #[cfg(feature = "native-api")]
    let mut database = None;
    let startup = (|| -> anyhow::Result<_> {
        #[cfg(feature = "native-api")]
        let mut config = if cli.store == ConfigStore::Db {
            std::fs::create_dir_all(&cli.data_dir)?;
            // DbStore needs an absolute, lexically normal entry; a missing -c
            // is fine once the db holds a revision.
            let entry =
                std::fs::canonicalize(&cli.config).or_else(|_| std::path::absolute(&cli.config))?;
            let startup =
                native_api::store::DatabaseStartup::open(&entry, &cli.data_dir, &mut diagnostics)?;
            native_sources = Some(startup.sources.clone());
            let config = startup.config.clone();
            database = Some(startup);
            config
        } else {
            let (config, sources) = load_operator_config_captured(&cli.config, &mut diagnostics)?;
            anyhow::ensure!(
                sources.is_some() || !config.experimental.native_api.config_write,
                "native configuration administration requires a dae source file"
            );
            native_sources = sources;
            config
        };
        #[cfg(not(feature = "native-api"))]
        let mut config = load_operator_config(cli.config.to_str().unwrap(), &mut diagnostics)?;
        #[cfg(not(feature = "native-api"))]
        anyhow::ensure!(
            !config.experimental.native_api.enabled,
            "native-api feature is required"
        );
        let requested_data_dir = PathBuf::from(&config.global.data_dir);
        let (runtime_data_dir, data_dir_creation_error) =
            prepare_runtime_data_dir(&requested_data_dir)?;
        #[cfg(feature = "native-api")]
        anyhow::ensure!(
            cli.store == ConfigStore::File || runtime_data_dir == requested_data_dir,
            "the configuration db needs its data directory {}; refusing to fall back to {}",
            requested_data_dir.display(),
            runtime_data_dir.display()
        );
        #[cfg(feature = "native-api")]
        anyhow::ensure!(
            !(config.experimental.native_api.enabled
                && config.experimental.native_api.password_auth
                && runtime_data_dir != requested_data_dir),
            "native API password login needs its configured data directory {}; refusing to fall back to {}",
            requested_data_dir.display(),
            runtime_data_dir.display()
        );
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

        // Effective log level: --debug flag > RUST_LOG env > config log_level >
        // "info".
        let config_level = match config.global.log_level.trim() {
            "" => "info",
            other => other,
        };
        let default_level = if cli.debug { "debug" } else { config_level };
        let env_filter =
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("{default_level},{QUIET_LOG_TARGETS}"))
            });

        let log_file_path = resolved_log_file_path(&config, cli.log_file.as_deref());
        let (log_file_layer, log_file_level) = if let Some(path) = log_file_path.as_ref() {
            let file = RotatingLogFile::open(path, LOG_FILE_LIMIT)?;
            let (filter, level) = tracing_subscriber::reload::Layer::new(env_filter.clone());
            (
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_timer(LocalTime)
                        .with_ansi(false)
                        .with_writer(std::sync::Mutex::new(file))
                        .with_filter(filter),
                ),
                Some(level),
            )
        } else {
            (None, None)
        };
        Ok((
            config,
            requested_data_dir,
            data_dir_creation_error,
            log_file_path,
            log_file_layer,
            log_file_level,
            env_filter,
        ))
    })();
    let (
        mut config,
        requested_data_dir,
        data_dir_creation_error,
        log_file_path,
        log_file_layer,
        log_file_level,
        env_filter,
    ) = match startup {
        Ok(startup) => startup,
        Err(error) => {
            report_startup_failure(&diagnostics);
            return Err(error);
        }
    };

    // Console, optional file, and Clash API output use independent layers.
    // With no `/logs` subscription, the API layer contributes no callsite interest.
    #[cfg(feature = "clash-api")]
    let (clash_log_layer, clash_log_handle) = clash_api::logs::layer();
    #[cfg(feature = "native-api")]
    let (native_log_layer, native_log_binding) = native_api::logs::tracing_layer();

    use tracing_subscriber::prelude::*;
    let (console_filter, console_level) =
        tracing_subscriber::reload::Layer::new(env_filter.clone());
    let registry = tracing_subscriber::registry()
        .with(console_log_layer(
            cli.disable_timestamp,
            console_ansi(
                std::io::IsTerminal::is_terminal(&std::io::stdout()),
                std::env::var_os("NO_COLOR").as_deref(),
            ),
            std::io::stdout,
            console_filter,
        ))
        .with(log_file_layer);
    #[cfg(feature = "clash-api")]
    let registry = registry.with(clash_log_layer);
    #[cfg(feature = "native-api")]
    let registry = registry.with(native_log_layer);
    registry.init();
    #[cfg(feature = "native-api")]
    let engine_level = {
        let mut engine = native_api::logs::EngineLevel::default();
        engine.push(console_level, env_filter.clone());
        if let Some(level) = log_file_level {
            engine.push(level, env_filter);
        }
        engine
    };
    #[cfg(not(feature = "native-api"))]
    let _ = (console_level, log_file_level, env_filter);

    info!("honk-core {} starting", VERSION);
    info!("Config: {}", cli.config.display());
    if let Some(error) = data_dir_creation_error {
        warn!(
            requested = %requested_data_dir.display(),
            fallback = %honk_config::paths::data_dir().display(),
            %error,
            "Runtime data directory is unusable; using process working directory"
        );
    }
    report_detailed_diagnostics(&diagnostics);
    info!(directory = %honk_config::paths::data_dir().display(), "Runtime data directory configured");
    let degradations = Arc::new(degradations::Degradations::default());
    let (state_db, state_reset) =
        open_state_db(&cli, &config, honk_config::paths::data_dir(), &degradations)?;
    #[cfg(feature = "native-api")]
    let state_db = database
        .as_ref()
        .map(|database| database.store.state())
        .or(state_db);
    let legacy_cache = {
        let (path, cache_id) = config.experimental.cache_file.legacy_cache_file();
        let config_dir = cli.config.parent();
        #[cfg(feature = "native-api")]
        let config_dir = database
            .as_ref()
            .map_or(config_dir, |database| database.store.entry().parent());
        state::import::LegacyCache::locate(path, cache_id, config_dir)
    };
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
    let mut resource_budget = control::ResourceBudget::for_nofile(effective_nofile);
    match total_memory_bytes() {
        Some(memory) => resource_budget = resource_budget.with_memory(memory),
        None => warn!("Failed to read MemTotal; UDP endpoints are sized by descriptors only"),
    }
    let tcp_flow_max = resource_budget.active_tcp_flows.saturating_mul(2);
    if tcp_flow_max < 256 {
        warn!(
            nofile = resource_budget.effective_nofile,
            tcp_floor = resource_budget.active_tcp_flows,
            tcp_max = tcp_flow_max,
            "Low TCP flow admission ceiling; raise RLIMIT_NOFILE in the service limits to avoid gateway-wide backpressure"
        );
    }

    honk_outbound::util::init_bypass_mark(config.global.effective_so_mark())?;

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

    #[cfg(feature = "native-api")]
    if let Some(database) = database.as_mut() {
        database.record()?;
    }
    let claimed = claim_state(
        state_db,
        state_reset,
        &config,
        honk_config::paths::data_dir(),
        subscription::legacy_store_roots(),
        &degradations,
    );
    let state_db = claimed.state_db;

    // A valid stored body makes network refresh non-blocking for startup.
    // Missing subscriptions still get the bounded first-fetch grace period;
    // every fetch continues in the background after the control plane starts.
    let mut subscription_supervisor = subscription::SubscriptionSupervisor::prepare(
        &mut config,
        claimed.subscriptions,
        diagnostics,
    )
    .await?;
    let startup_diagnostics = subscription_supervisor.take_startup_diagnostics();

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
    config
        .validate_assembled()
        .map_err(|error| anyhow::anyhow!("invalid assembled configuration: {error}"))?;
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

    // The old instance owns queue 320 until this lock is released. Check
    // NFQUEUE only after the handoff so a transient busy result cannot turn
    // a healthy restart into a permanently degraded process.
    prepare_nfqueue_startup(&mut config, mock_mode);

    // Create the dae0 link pair before eBPF load so PARAM.dae0_ifindex is correct.
    // dae0peer stays in the host namespace during the dae0 attach, then moves
    // to the daens netns during namespace setup.
    #[cfg(feature = "ebpf")]
    let _dae0_guard: Option<daens::Dae0Guard>;
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
            if let Err(e) = sysctl::set_sysctl(key, val) {
                warn!("failed to set {}={}: {}", key, val, e);
            }
        }
        #[cfg(feature = "ebpf")]
        {
            if let Some(lan_ifname) = configured_ifaces.lan.first() {
                let _ = sysctl::set_sysctl(&format!("net.ipv4.conf.{}.rp_filter", lan_ifname), "0");
            }
            _dae0_guard = Some(daens::create_dae0_link()?);
            for wan_ifname in &configured_ifaces.wan {
                sysctl::enable_wan_accept_ra(wan_ifname);
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
    let ebpf_backend: Box<dyn ebpf::EbpfBackend> = if cli.mock_ebpf {
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
                primary_lan,
                primary_wan,
                single_homed,
            )
            .await?;

            if let Some(primary_lan) = primary_lan
                && let Ok(i) = netlink::ifindex_of(primary_lan)
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
                && let Ok(i) = netlink::ifindex_of(primary_wan)
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
                        if let Ok(i) = netlink::ifindex_of(extra_lan) {
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
                    && let Ok(i) = netlink::ifindex_of(extra_wan)
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
    #[cfg(feature = "ebpf")]
    let mut ebpf_backend = ebpf_backend;

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
            daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
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
    let mut shared = routing::SharedMatchers::default();
    let router = routing::Router::from_config_sharing(&config.routing, &geo_sources, &mut shared)?;
    info!("Router ready with {} compiled routes", router.route_count());
    ebpf::record_pname_routing(&router, ebpf_backend.as_ref(), &degradations);

    let proxy_registry = std::sync::Arc::new(proxy::ProxyRegistry::default_resolver()?);
    info!(
        "Proxy registry ready ({} handlers)",
        proxy_registry.handler_count()
    );

    let dns_cache = std::sync::Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(
        config.dns.cache.max_size,
    )));
    let dns_router = std::sync::Arc::new(dns::routing::DnsRouter::new_sharing(
        &config.dns,
        &geo_sources,
        &mut shared,
    )?);
    drop((geo_sources, shared));
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
        .with_configured_upstreams(&config.dns)
        .with_timeouts(
            std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
            std::time::Duration::from_millis(config.global.connect_timeout_ms),
        )
        .with_strategy(config.dns.strategy)
        .with_cache_enabled(config.dns.cache.enabled)
        .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
        .with_stale_reply_ttl(config.dns.cache.stale_reply_ttl)
        .with_policy_id(dns_policy)
        .with_hosts_snapshot(hosts_snapshot),
    );
    info!("DNS forwarder ready");

    #[cfg(feature = "native-api")]
    let native_enabled = config.experimental.native_api.enabled;
    let mut control_plane = control::ControlPlane::new_with_upstream_pool_and_budget(
        config,
        ebpf_backend,
        router,
        proxy_registry,
        dns_forwarder,
        dns_upstream_pool.clone(),
        resource_budget,
        Arc::clone(&degradations),
    )?;
    #[cfg(feature = "native-api")]
    let native_observation = if native_enabled {
        Some(native_api::observation::NativeObservation::attach(&mut control_plane).await)
    } else {
        None
    };
    control_plane
        .install_startup_diagnostics(startup_diagnostics)
        .await;
    control_plane.set_log_file_override(cli.log_file.clone(), log_file_path);
    #[cfg(feature = "ebpf")]
    let iface_watcher = if !cli.mock_ebpf {
        ebpf::real::IfaceWatcher::spawn(
            control_plane.ebpf_handle(),
            control_plane.config_handle(),
            control_plane.command_sender(),
            attached_ifaces,
            Arc::clone(&degradations),
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
    // The initial runtime owns the pool now; keeping this handle would pin the
    // startup traffic router snapshot after that runtime retires.
    drop(dns_upstream_pool);

    // Runtime state (selector choices, clash mode): with
    // `experimental.cache_file` enabled, imports a legacy cache.db, restores
    // Selector choices, and wires change persistence into the group manager.
    control_plane
        .init_cache_db(state_db.clone(), Some(legacy_cache))
        .await;

    #[cfg(feature = "clash-api")]
    let clash_cfg = control_plane
        .config_handle()
        .read()
        .await
        .experimental
        .clash_api
        .clone();
    let native_mode = cfg!(feature = "native-api")
        && control_plane
            .config_handle()
            .read()
            .await
            .experimental
            .native_api
            .enabled;
    let mode_value = match native_mode {
        #[cfg(feature = "native-api")]
        true => mode::ModeState::native(),
        #[cfg(not(feature = "native-api"))]
        true => unreachable!("native mode needs the native-api feature"),
        false => {
            let mode_db = control_plane.mode_db();
            #[cfg(feature = "clash-api")]
            let mode = startup_clash_mode(mode_db.as_deref(), &clash_cfg.default_mode);
            #[cfg(not(feature = "clash-api"))]
            let mode = "Rule".to_owned();
            let (default_selection, valid_global_selections) = {
                let config = control_plane.config_handle();
                let config = config.read().await;
                let selections = config
                    .groups
                    .iter()
                    .map(|group| group.name.clone())
                    .chain(config.nodes.iter().map(|node| node.name.clone()))
                    .collect::<Vec<_>>();
                (selections.first().cloned().unwrap_or_default(), selections)
            };
            let global_selection = mode_db
                .as_ref()
                .and_then(|db| db.load_clash_global())
                .filter(|selection| {
                    valid_global_selections
                        .iter()
                        .any(|valid| valid == selection)
                })
                .unwrap_or(default_selection);
            mode::ModeState::new(&mode, global_selection)
        }
    };
    let mode_state: mode::SharedModeState =
        std::sync::Arc::new(parking_lot::RwLock::new(mode_value));
    control_plane.set_mode_state(mode_state.clone());
    if let Err(error) = control_plane.start_datapath_flags_coordinator() {
        return Err(abort_startup(&mut control_plane, subscription_supervisor, error).await);
    }

    #[cfg(feature = "native-api")]
    let mut native = match native_observation {
        Some(observation) => {
            match native_api::NativeRuntime::start(
                &mut control_plane,
                observation,
                started_at,
                started,
                engine_level,
                &native_log_binding,
            )
            .await
            {
                Ok(native) => Some(native),
                Err(error) => {
                    return Err(
                        abort_startup(&mut control_plane, subscription_supervisor, error).await,
                    );
                }
            }
        }
        None => None,
    };

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
        // A bare ":port" listens on all IPv4 interfaces.
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
                    diagnostics: control_plane.diagnostics_handle(),
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
                    control: Some(control_plane.control_client()),
                    ui_download: control_plane.ui_download_handle(),
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

    subscription_supervisor.route_through(download_route::SharedOutbounds {
        router: control_plane.traffic_router(),
        config: control_plane.config_handle(),
        group_manager: control_plane.group_manager(),
        proxy_registry: control_plane.proxy_registry(),
        runtime_registry: control_plane.runtime_registry(),
    });
    subscription_supervisor.start(cmd_tx.clone());
    #[cfg(feature = "native-api")]
    control_plane.attach_subscriptions(subscription_supervisor.handle());
    let reload_subscription_supervisor = subscription_supervisor.handle();
    #[cfg(feature = "native-api")]
    let native_configuration = match native.as_mut() {
        Some(native) => Some(
            native
                .start_configuration(
                    &mut control_plane,
                    database.take(),
                    native_sources,
                    &cli.config,
                    cmd_tx.clone(),
                    reload_subscription_supervisor.clone(),
                )
                .await,
        ),
        None => None,
    };

    // SIGHUP handler: reload configuration from disk and push it to the
    // control plane without interrupting established connections.
    let config_path = cli.config.clone();
    let reload_tx = cmd_tx.clone();
    let mut activation =
        configuration::Activation::new(reload_tx.clone(), reload_subscription_supervisor);
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
            #[cfg(feature = "native-api")]
            if let Some(service) = &native_configuration {
                if service.request_sighup().is_err() {
                    warn!("SIGHUP reload coordinator is unavailable or busy");
                }
                continue;
            }
            let mut diagnostics = Vec::new();
            let result = load_operator_config(
                config_path.to_str().unwrap_or("/etc/honk/config.dae"),
                &mut diagnostics,
            );
            report_detailed_diagnostics(&diagnostics);
            match result {
                Ok(mut new_config) => {
                    new_config.ensure_builtin_nodes();
                    match activation
                        .activate(configuration::ActivationRequest {
                            candidate: new_config,
                            diagnostics,
                            #[cfg(feature = "native-api")]
                            sources: None,
                            #[cfg(feature = "native-api")]
                            expected_group_revision: None,
                            #[cfg(feature = "native-api")]
                            deferred_provider: None,
                        })
                        .await
                    {
                        Ok(_) | Err(configuration::ActivationFailure::Rejected) => {}
                        Err(configuration::ActivationFailure::Degraded(generation)) => {
                            warn!(generation, "SIGHUP reload committed with degraded datapath");
                        }
                        Err(configuration::ActivationFailure::Reconciliation(generation)) => {
                            error!(generation, "SIGHUP reload worker reconciliation failed");
                            break;
                        }
                        Err(failure) => {
                            error!(?failure, "SIGHUP reload request {request_id} failed");
                            let _ = reload_tx.send(control::ControlCommand::Shutdown).await;
                            break;
                        }
                    }
                }
                Err(error) => {
                    warn!("SIGHUP reload request {request_id} rejected: {error}")
                }
            }
        }
    });

    let shutdown_intent = control_plane.shutdown_intent();
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
        shutdown_intent.store(true, std::sync::atomic::Ordering::Release);
        let _ = cmd_tx.send(control::ControlCommand::Shutdown).await;
    });

    // Under a service manager nobody is at a terminal to press it.
    if std::io::IsTerminal::is_terminal(&std::io::stdin())
        || std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        info!("honk-core is running. Press Ctrl+C to stop.");
    } else {
        info!("honk-core is running.");
    }
    let control_result = control_plane.run().await;
    #[cfg(feature = "native-api")]
    native_api::NativeRuntime::shutdown(native, &control_plane, control_result.is_err()).await;

    // Signal systemd that we're stopping (Type=notify)
    #[cfg(target_os = "linux")]
    let _ = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Stopping]);

    sig_handle.abort();
    sighup_handle.abort();
    let _ = sig_handle.await;
    let _ = sighup_handle.await;
    let subscription_result = subscription_supervisor.shutdown().await;
    info!("honk-core stopped");

    control_result?;
    anyhow::ensure!(
        subscription_result? == 0,
        "subscription tasks remained after shutdown"
    );
    Ok(())
}

#[cfg(test)]
mod startup_lifecycle_tests {
    use super::{
        ClashCommand, Cli, RotatingLogFile, acquire_instance_lock, load_operator_config,
        prepare_nfqueue_startup, prepare_runtime_data_dir, prepare_runtime_data_dir_with_fallback,
        publish_instance_pid, running_instance_pid,
    };
    use crate::logging::open_log_file;
    use clap::Parser;

    #[test]
    fn a_reset_that_cannot_run_leaves_honk_running_without_persistence() {
        let directory = tempfile::tempdir().unwrap();
        drop(crate::state::StateDb::open(directory.path()).unwrap());
        let held = crate::state::StateDb::open(directory.path()).unwrap();
        let degradations = crate::degradations::Degradations::default();
        assert!(crate::state::startup::reset_non_strict(directory.path(), &degradations).is_none());
        let issue = degradations
            .get(crate::degradations::Component::Persistence)
            .expect("the failed reset is reported");
        // The reset's own failure is the cause, not the corruption.
        assert_eq!(issue.reason, "in_use");
        drop(held);
    }

    #[test]
    fn a_failed_reopen_bounds_the_log_to_twice_the_limit() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("honk.log");
        let mut log = RotatingLogFile::open(&path, 100).unwrap();
        log.fail_reopen = true;
        for _ in 0..20 {
            log.write_all(format!("{}\n", "x".repeat(59)).as_bytes())
                .unwrap();
        }
        let rotated = std::fs::metadata(directory.path().join("honk.log.1")).unwrap();
        assert!(
            rotated.len() <= 200,
            "{} bytes after a failed reopen",
            rotated.len()
        );
        assert!(!path.exists());
    }

    #[test]
    fn two_writers_sharing_the_log_rotate_it_once() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("honk.log");
        let mut first = RotatingLogFile::open(&path, 100).unwrap();
        let mut second = RotatingLogFile::open(&path, 100).unwrap();
        let line = |text: &str| format!("{}\n", text.repeat(59));
        first.write_all(line("a").as_bytes()).unwrap();
        second.write_all(line("b").as_bytes()).unwrap();
        first.write_all(line("c").as_bytes()).unwrap();
        second.write_all(line("d").as_bytes()).unwrap();
        let rotated = std::fs::read_to_string(directory.path().join("honk.log.1")).unwrap();
        assert_eq!(rotated, format!("{}\n{}\n", "a".repeat(59), "b".repeat(59)));
        let current = std::fs::read_to_string(&path).unwrap();
        assert_eq!(current, format!("{}\n{}\n", "c".repeat(59), "d".repeat(59)));
    }

    #[test]
    fn the_log_file_rotates_into_one_private_copy() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("honk.log");
        let rotated = directory.path().join("honk.log.1");
        let mut log = RotatingLogFile::open(&path, 100).unwrap();
        for line in ["a", "b", "c", "d"] {
            log.write_all(line.repeat(59).as_bytes()).unwrap();
            log.write_all(b"\n").unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "d".repeat(59) + "\n"
        );
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap(),
            "c".repeat(59) + "\n"
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
        for file in [&path, &rotated] {
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn a_non_strict_state_db_that_cannot_be_used_leaves_honk_running() {
        use std::os::unix::fs::PermissionsExt as _;

        let cli = Cli::parse_from(["honk-core"]);
        let mut config = honk_config::Config::default();
        config.experimental.cache_file.enabled = Some(true);

        let unsafe_dir = tempfile::tempdir().unwrap();
        let state = unsafe_dir.path().join(crate::state::STATE_DIR);
        std::fs::create_dir(&state).unwrap();
        // Only a writable directory is still refused; readable ones are tightened.
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o775)).unwrap();
        let reason = |degradations: &crate::degradations::Degradations| {
            degradations
                .get(crate::degradations::Component::Persistence)
                .map(|issue| issue.reason)
        };
        let degradations = crate::degradations::Degradations::default();
        let (db, reset) =
            super::open_state_db(&cli, &config, unsafe_dir.path(), &degradations).unwrap();
        assert!(db.is_none() && !reset);
        assert_eq!(reason(&degradations), Some("unsafe"));
        let entry = degradations.snapshot().pop().unwrap();
        assert_eq!(entry.rule, Some("group_or_other_bits"));

        let locked_dir = tempfile::tempdir().unwrap();
        drop(crate::state::StateDb::open(locked_dir.path()).unwrap());
        let held = nix::fcntl::Flock::lock(
            std::fs::File::open(locked_dir.path().join(crate::state::STATE_DIR)).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        let degradations = crate::degradations::Degradations::default();
        let (db, reset) =
            super::open_state_db(&cli, &config, locked_dir.path(), &degradations).unwrap();
        assert!(db.is_none() && !reset);
        assert_eq!(reason(&degradations), Some("locked"));
        drop(held);

        // Password mode makes the db strict: the same unsafe directory refuses startup.
        config.experimental.native_api.password_auth = true;
        assert!(
            super::open_state_db(&cli, &config, unsafe_dir.path(), &Default::default()).is_err()
        );

        // A newer schema refuses startup either way.
        config.experimental.native_api.password_auth = false;
        let newer_dir = tempfile::tempdir().unwrap();
        drop(crate::state::StateDb::open(newer_dir.path()).unwrap());
        rusqlite::Connection::open(
            newer_dir
                .path()
                .join(crate::state::STATE_DIR)
                .join(crate::state::DB_FILE),
        )
        .unwrap()
        .execute_batch(&format!(
            "PRAGMA user_version = {}",
            crate::state::SCHEMA_VERSION + 1
        ))
        .unwrap();
        assert!(
            super::open_state_db(&cli, &config, newer_dir.path(), &Default::default()).is_err()
        );
    }

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

    #[test]
    fn a_refused_instance_lock_names_the_holder_and_the_wait() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("honk-core.lock");
        let wait = std::time::Duration::ZERO;
        let _held = acquire_instance_lock(&path, wait).expect("take instance lock");
        let error = acquire_instance_lock(&path, wait).unwrap_err().to_string();
        assert!(
            error.contains(&format!("PID {}", std::process::id())),
            "{error}"
        );
        assert!(error.contains("within 0s"), "{error}");
    }

    #[test]
    fn startup_load_reports_duplicate_node_identity() {
        let file = tempfile::Builder::new().suffix(".dae").tempfile().unwrap();
        std::fs::write(
            file.path(),
            "node {\n a: 'socks5://127.0.0.1:1080'\n b: 'socks5://127.0.0.1:1080'\n}\n",
        )
        .unwrap();

        let mut diagnostics = Vec::new();
        let error = load_operator_config(file.path().to_str().unwrap(), &mut diagnostics)
            .expect_err("duplicate node IDs must reject startup");
        assert_eq!(error.diagnostic.code, "duplicate-node-id");
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[2]");
        assert_eq!(error.diagnostic.related_indices, [1]);
        let rendered = error.to_string();
        assert!(rendered.contains("node ID duplicates another node"));
        assert!(!rendered.contains("configuration validation failed"));
    }
}
