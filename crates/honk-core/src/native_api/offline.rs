//! Offline admission consumes captured bytes; it never starts runtime owners.

mod admission;

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use honk_config::Config;
use honk_config::diagnostic::{
    DetailedDiagnostic, SafeValue, SettingPath, SettingSegment, SourceRef, finish_attempt,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use honk_config::parser::{LoadedConfig, SourceLimits, SourceSnapshot};

use crate::configuration::{DependencyReader, DependencySnapshot};
use crate::control::ControlPlane;
use crate::dns::forwarder::HostsSourceSet;
use crate::dns::policy::PolicyId;
use crate::dns::routing::DnsRouter;
use crate::routing::{GeoRequirements, GeoSourceSet, Router};
use crate::subscription::{StoredBodies, parse_subscription_content_with_diagnostics};

/// Upper bound for one standard asset read during offline validation. A
/// `geoip.dat` is tens of megabytes; this only guards against a runaway file.
pub(crate) const MAX_ASSET_BYTES: usize = 256 * 1024 * 1024;

pub(crate) struct ValidatedConfig {
    pub(crate) config: Config,
    pub(crate) sources: Vec<SourceSnapshot>,
    pub(crate) dependencies: Vec<DependencySnapshot>,
    pub(crate) geo_sources: Option<GeoSourceSet>,
    ech_paths: Vec<String>,
    dependency_root: Option<PathBuf>,
}

pub(crate) struct CapturedConfig {
    config: Config,
    pub(crate) sources: Vec<SourceSnapshot>,
    pub(crate) dependencies: Vec<DependencySnapshot>,
    geo: GeoSourceSet,
    retain_geo: bool,
    hosts: HostsSourceSet,
    ech_paths: Vec<String>,
    dependency_root: Option<PathBuf>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_for_coordinator(
    loaded: LoadedConfig,
    dependency_root: Option<&Path>,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    deferred: &[honk_config::subscription::Subscription],
    geo: Option<&GeoSourceSet>,
) -> Result<CapturedConfig, DetailedConfigError> {
    let result = capture_inner(
        loaded,
        dependency_root,
        active,
        data_dir,
        limits,
        diagnostics,
        geo,
        deferred,
        &[],
    );
    finish_attempt(result, diagnostics)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_for_coordinator(
    loaded: LoadedConfig,
    dependency_root: Option<&Path>,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    deferred: &[honk_config::subscription::Subscription],
    geo: Option<&GeoSourceSet>,
    submitted: &[(PathBuf, Arc<str>)],
) -> Result<ValidatedConfig, DetailedConfigError> {
    let result = capture_inner(
        loaded,
        dependency_root,
        active,
        data_dir,
        limits,
        diagnostics,
        geo,
        deferred,
        submitted,
    )
    .and_then(CapturedConfig::validate);
    finish_attempt(result, diagnostics)
}

#[cfg(test)]
pub(crate) fn validate_with_data_dir(
    loaded: LoadedConfig,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<ValidatedConfig, DetailedConfigError> {
    let entry_dir = loaded
        .sources
        .first()
        .and_then(|source| source.path.parent())
        .map(Path::to_path_buf);
    let result = capture_inner(
        loaded,
        entry_dir.as_deref(),
        active,
        data_dir,
        limits,
        diagnostics,
        None,
        &[],
        &[],
    )
    .and_then(CapturedConfig::validate);
    finish_attempt(result, diagnostics)
}

#[allow(clippy::too_many_arguments)]
fn capture_inner(
    loaded: LoadedConfig,
    dependency_root: Option<&Path>,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    geo_override: Option<&GeoSourceSet>,
    deferred: &[honk_config::subscription::Subscription],
    submitted: &[(PathBuf, Arc<str>)],
) -> Result<CapturedConfig, DetailedConfigError> {
    let LoadedConfig {
        mut config,
        sources,
    } = loaded;
    let Some(entry) = sources.first() else {
        return Err(error(
            &honk_config::diagnostic::DiagnosticSources::new(None).root(),
            "config",
            "missing-config-source",
            "configuration has no entry source",
        ));
    };
    let source = &entry.source;
    let mut capture = Capture::new(
        &sources,
        dependency_root,
        active,
        data_dir,
        limits,
        submitted,
    )
    .map_err(|cause| dependency_error(source, "config", cause))?;
    config.append_diagnostics(source.clone(), diagnostics);
    config.validate_detailed().map_err(|mut error| {
        error.diagnostic.source = validated_subscription(&config, &error)
            .and_then(|subscription| declaring_source(&sources, subscription))
            .unwrap_or(source)
            .clone();
        error
    })?;
    crate::subscription::validate_subscription_ids(&config.subscriptions).map_err(|_| {
        error(
            source,
            "subscription",
            "invalid-subscription-id",
            "subscription identifiers must be unique and nonzero",
        )
    })?;
    config.ensure_builtin_nodes();

    if config.subscriptions.iter().any(|sub| sub.enabled) {
        // No state db yet means no subscription has ever been fetched on this host.
        let store = StoredBodies::open(&capture.data_dir)
            .map_err(|cause| dependency_error(source, "subscription", cause))?;
        for (index, subscription) in config
            .subscriptions
            .iter()
            .enumerate()
            .filter(|(_, sub)| sub.enabled)
        {
            let declared = declaring_source(&sources, subscription).unwrap_or(source);
            if deferred.iter().any(|owner| {
                crate::subscription::same_subscription_source_spec(owner, subscription)
            }) {
                continue;
            }
            let cached = match store.as_ref().map(|store| store.find(subscription)) {
                Some(Ok(cached)) => cached,
                Some(Err(cause)) => return Err(dependency_error(declared, "subscription", cause)),
                None => None,
            };
            // The runtime starts a never-fetched subscription with no nodes and
            // fills it in after the first fetch; offline admission mirrors that
            // instead of refusing the configuration that would add it.
            let Some(body) = cached else {
                diagnostics.push(DetailedDiagnostic::warning(
                    "subscription-not-fetched",
                    declared.clone(),
                    SettingPath::new("subscription").index(index + 1),
                    SafeValue::Redacted,
                    "subscription has not been fetched yet; its nodes join after the first fetch",
                ));
                continue;
            };
            let (label, length) = (body.label.clone(), body.length);
            let contents = capture
                .stored(label, length, DependencyReader::Subscription(index), || {
                    body.read()
                })
                .map_err(|cause| dependency_error(declared, "subscription", cause))?;
            let contents = std::str::from_utf8(&contents).map_err(|_| {
                error(
                    declared,
                    "subscription",
                    "invalid-offline-dependency",
                    "cached subscription is not valid UTF-8",
                )
            })?;
            let mut notices = Vec::new();
            let nodes =
                parse_subscription_content_with_diagnostics(subscription, contents, &mut notices);
            // Decoded-provider coordinates are not coordinates in the referring dae document.
            for mut notice in notices.into_iter().filter(|notice| !notice.terminal) {
                crate::config_diagnostics::declare_diagnostics(
                    declared,
                    std::slice::from_mut(&mut notice),
                );
                notice.setting = SettingPath::new("subscription").index(index + 1);
                notice.entry_index = None;
                notice.related_indices.clear();
                diagnostics.push(notice);
            }
            config.nodes.extend(nodes.map_err(|_| {
                error(
                    declared,
                    "subscription",
                    "invalid-offline-dependency",
                    "cached subscription contains no usable configuration",
                )
            })?);
        }
    }
    // Match the runtime's exact choice: same-fetch active nodes win over cached candidates.
    crate::control::reload::rebase_subscription_nodes(active, &mut config);
    config.validate_assembled().map_err(|mut error| {
        error.diagnostic.source = source.clone();
        error
    })?;

    let dns_requirements = DnsRouter::geo_requirements(&config.dns);
    let requirements = GeoRequirements::for_traffic(&config.routing.rules).union(&dns_requirements);
    let data_dir = capture.data_dir.clone();
    let geo = match geo_override {
        Some(geo) => geo.clone(),
        None => GeoSourceSet::capture_for_admission(&requirements, &data_dir, |kind, path| {
            capture.path(path, true, DependencyReader::Geo(kind))
        })
        .map_err(|cause| dependency_error(source, "routing", cause))?,
    };
    let mut dependencies = if geo_override.is_some() {
        geo_dependencies(&geo, &requirements)
            .map_err(|cause| dependency_error(source, "routing", cause))?
    } else {
        Vec::new()
    };
    let mut host_index = 0;
    let hosts = HostsSourceSet::load_captured(&config.dns, |path| {
        let reader = DependencyReader::Hosts(host_index, path.to_owned());
        host_index += 1;
        capture.text(path, reader)
    })
    .map_err(|cause| dependency_error(source, "dns", cause))?;
    let mut ech_paths = Vec::new();
    for node in &config.nodes {
        if node
            .tls()
            .is_some_and(|tls| tls.enabled || !tls.alpn.is_empty())
        {
            honk_outbound::tls::validate_connector_config_with_ech_reader(node, |path| {
                let reader = DependencyReader::Ech(ech_paths.len(), path.to_owned());
                ech_paths.push(path.to_owned());
                capture.text(path, reader).map_err(anyhow::Error::new)
            })
            .map_err(|cause| {
                if let Some(io) = cause
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<io::Error>())
                {
                    dependency_error(source, "node", io::Error::from(io.kind()))
                } else {
                    error(
                        source,
                        "node",
                        "invalid-tls-config",
                        "TLS configuration is invalid",
                    )
                }
            })?;
        }
    }
    dependencies.extend(capture.files.into_iter().map(|(snapshot, _)| snapshot));
    dependencies.sort_unstable();
    Ok(CapturedConfig {
        config,
        sources,
        geo,
        retain_geo: geo_override.is_some(),
        hosts,
        ech_paths,
        dependencies,
        dependency_root: dependency_root.map(Path::to_path_buf),
    })
}

/// Reads `reader` to its end into one buffer of the `expected` length, so a
/// large asset is neither grown in steps nor copied once more into an `Arc`.
/// A file whose length changed after it was measured is read as it is now.
fn read_sized(mut reader: impl io::Read, expected: usize) -> io::Result<Arc<[u8]>> {
    let mut buffer: Arc<[u8]> = std::iter::repeat_n(0, expected).collect();
    let slots = Arc::get_mut(&mut buffer).expect("a new buffer is unshared");
    let mut filled = 0;
    while filled < expected {
        match reader.read(&mut slots[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest)?;
    if filled == expected && rest.is_empty() {
        return Ok(buffer);
    }
    let mut bytes = slots[..filled].to_vec();
    bytes.append(&mut rest);
    Ok(bytes.into())
}

fn geo_dependencies(
    geo: &GeoSourceSet,
    requirements: &GeoRequirements,
) -> io::Result<Vec<DependencySnapshot>> {
    let mut dependencies: Vec<DependencySnapshot> = Vec::new();
    for snapshot in geo.snapshots(requirements) {
        let path = canonical_asset(&snapshot.path.ok_or(io::ErrorKind::InvalidData)?)?;
        let reader = DependencyReader::Geo(snapshot.kind);
        if let Some(dependency) = dependencies.iter_mut().find(|dependency| {
            dependency.path == path
                && dependency.sha256 == snapshot.sha256
                && dependency.bytes == snapshot.size_bytes as usize
        }) {
            dependency.readers.push(reader);
        } else {
            dependencies.push(DependencySnapshot {
                path,
                sha256: snapshot.sha256,
                bytes: snapshot.size_bytes as usize,
                asset: true,
                readers: vec![reader],
            });
        }
    }
    Ok(dependencies)
}

/// An update may validate a file it has yet to create in the data directory;
/// that path resolves through its directory.
fn canonical_asset(path: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(io::ErrorKind::InvalidData)?;
            Ok(fs::canonicalize(path.parent().ok_or(io::ErrorKind::InvalidData)?)?.join(name))
        }
        result => result,
    }
}

/// The subscription a `subscriptions[n]` validation error names.
fn validated_subscription<'a>(
    config: &'a Config,
    error: &DetailedConfigError,
) -> Option<&'a honk_config::subscription::Subscription> {
    match error.diagnostic.setting.0.as_slice() {
        [
            SettingSegment::Field("subscriptions"),
            SettingSegment::Index(ordinal),
            ..,
        ] => config.subscriptions.get(ordinal.checked_sub(1)?),
        _ => None,
    }
}

fn declaring_source<'a>(
    sources: &'a [SourceSnapshot],
    subscription: &honk_config::subscription::Subscription,
) -> Option<&'a SourceRef> {
    let index = subscription.source.as_ref()?.0.index();
    sources
        .iter()
        .map(|snapshot| &snapshot.source)
        .find(|source| source.index() == index)
}

fn error(
    source: &SourceRef,
    setting: &'static str,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Validation,
        code,
        source.clone(),
        SettingPath::new(setting),
        message,
    )
}

fn dependency_error(
    source: &SourceRef,
    setting: &'static str,
    cause: io::Error,
) -> DetailedConfigError {
    let (code, message) = match cause.kind() {
        io::ErrorKind::QuotaExceeded => (
            "config-source-limit",
            "configuration source count exceeds the limit",
        ),
        io::ErrorKind::FileTooLarge => (
            "config-byte-limit",
            "configuration source bytes exceed the limit",
        ),
        io::ErrorKind::PermissionDenied => (
            "offline-dependency-denied",
            "configuration dependency is not authorized or readable",
        ),
        io::ErrorKind::NotFound => (
            "missing-offline-dependency",
            "required offline configuration dependency is unavailable",
        ),
        io::ErrorKind::InvalidData => (
            "invalid-offline-dependency",
            "offline configuration dependency is malformed",
        ),
        _ => (
            "unreadable-offline-dependency",
            "offline configuration dependency cannot be read",
        ),
    };
    DetailedConfigError::new(
        ErrorCategory::Io(cause.kind()),
        code,
        source.clone(),
        SettingPath::new(setting),
        message,
    )
}

struct Capture {
    data_dir: PathBuf,
    roots: Vec<PathBuf>,
    explicitly_allowed: Vec<PathBuf>,
    limits: SourceLimits,
    source_count: usize,
    bytes: usize,
    files: Vec<(DependencySnapshot, Arc<[u8]>)>,
}

impl Capture {
    fn new(
        sources: &[SourceSnapshot],
        dependency_root: Option<&Path>,
        active: &Config,
        data_dir: &Path,
        limits: SourceLimits,
        submitted: &[(PathBuf, Arc<str>)],
    ) -> io::Result<Self> {
        let limits = SourceLimits {
            max_bytes: limits.max_bytes.min(SourceLimits::DEFAULT.max_bytes),
            max_sources: limits.max_sources.min(SourceLimits::DEFAULT.max_sources),
        };
        let unused = submitted
            .iter()
            .filter(|(path, _)| !sources.iter().any(|source| source.path == *path));
        let source_count = sources
            .len()
            .checked_add(unused.clone().count())
            .filter(|count| *count <= limits.max_sources)
            .ok_or(io::ErrorKind::QuotaExceeded)?;
        let bytes = sources
            .iter()
            .map(|source| source.content.len())
            .chain(unused.map(|(_, content)| content.len()))
            .try_fold(0usize, |total, bytes| total.checked_add(bytes))
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or(io::ErrorKind::FileTooLarge)?;
        let data_dir = data_dir.to_path_buf();
        let mut roots = Vec::new();
        if let Some(root) = dependency_root {
            roots.push(fs::canonicalize(root)?);
        }
        if let Ok(path) = fs::canonicalize(&data_dir) {
            roots.push(path);
        }
        let explicitly_allowed = active
            .dns
            .hosts
            .iter()
            .map(String::as_str)
            .chain(
                active
                    .nodes
                    .iter()
                    .filter_map(|node| node.tls()?.ech_config_path.as_deref()),
            )
            .chain(std::iter::once(honk_config::dns::SYSTEM_HOSTS_PATH))
            .filter_map(|path| {
                fs::canonicalize(honk_config::paths::resolve_dependency_path_from(
                    path, &data_dir,
                ))
                .ok()
            })
            .collect();
        Ok(Self {
            data_dir,
            roots,
            explicitly_allowed,
            limits,
            source_count,
            bytes,
            files: Vec::new(),
        })
    }

    fn text(&mut self, path: &str, reader: DependencyReader) -> io::Result<String> {
        let path = honk_config::paths::resolve_dependency_path_from(path, &self.data_dir);
        let bytes = self.path(&path, false, reader)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    fn authorized(&self, path: &Path) -> bool {
        self.roots.iter().any(|root| path.starts_with(root))
            || self
                .explicitly_allowed
                .iter()
                .any(|allowed| path == allowed)
    }

    fn path(
        &mut self,
        path: &Path,
        standard: bool,
        reader: DependencyReader,
    ) -> io::Result<Arc<[u8]>> {
        let canonical = fs::canonicalize(path)?;
        if !standard && !self.authorized(&canonical) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let descriptor = nix::fcntl::open(
            &canonical,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_NONBLOCK
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let file = File::from(descriptor);
        let path = fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if !standard && !self.authorized(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.admit(path, standard, reader, |remaining| {
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if metadata.len() > remaining as u64 {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            read_sized(file.take(remaining as u64 + 1), metadata.len() as usize)
        })
    }

    /// A trusted source body of `length` bytes in the state db, named by
    /// `label`; it takes the same budget as a file, checked before `read`.
    pub(crate) fn stored(
        &mut self,
        label: PathBuf,
        length: usize,
        reader: DependencyReader,
        read: impl FnOnce() -> io::Result<Arc<[u8]>>,
    ) -> io::Result<Arc<[u8]>> {
        self.admit(label, false, reader, |remaining| {
            if length > remaining {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            read()
        })
    }

    fn admit(
        &mut self,
        path: PathBuf,
        asset: bool,
        reader: DependencyReader,
        load: impl FnOnce(usize) -> io::Result<Arc<[u8]>>,
    ) -> io::Result<Arc<[u8]>> {
        if !asset && self.source_count >= self.limits.max_sources {
            return Err(io::ErrorKind::QuotaExceeded.into());
        }
        if let Some((snapshot, bytes)) = self
            .files
            .iter_mut()
            .find(|(snapshot, _)| snapshot.path == path && snapshot.asset == asset)
        {
            if asset {
                snapshot.readers.push(reader);
                return Ok(Arc::clone(bytes));
            }
            if bytes.len() > self.limits.max_bytes - self.bytes {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            // Each reference can materialize another hosts body or provider node set.
            self.source_count += 1;
            self.bytes += bytes.len();
            snapshot.readers.push(reader);
            return Ok(Arc::clone(bytes));
        }
        // Standard assets have their own bound: the engine loads them whole at
        // startup regardless of what an administrator submits.
        let remaining = if asset {
            MAX_ASSET_BYTES
        } else {
            self.limits.max_bytes - self.bytes
        };
        let bytes = load(remaining)?;
        if bytes.len() > remaining {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let snapshot = DependencySnapshot {
            path,
            sha256: crate::configuration::digest(&bytes),
            bytes: bytes.len(),
            asset,
            readers: vec![reader],
        };
        if !asset {
            self.bytes += bytes.len();
            self.source_count += 1;
        }
        self.files.push((snapshot, Arc::clone(&bytes)));
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
