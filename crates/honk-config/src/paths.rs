//! Runtime data-directory path resolution shared by the engine and handlers.
//!
//! Generated state and relative runtime dependencies use the process-wide
//! directory selected from `global.data_dir`. Existing legacy paths remain
//! usable during upgrades.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default home for generated state and runtime-supplied assets.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/honk";

/// Previous default home retained for existing runtime state and assets.
pub const LEGACY_DATA_DIR: &str = "/var/share/honk";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Return the configured process-wide runtime data directory.
pub fn data_dir() -> &'static Path {
    DATA_DIR
        .get_or_init(|| PathBuf::from(DEFAULT_DATA_DIR))
        .as_path()
}

/// Install the process-wide runtime data directory.
///
/// Repeating the same value is idempotent. A different value is returned to
/// the caller because path ownership cannot change after runtime consumers
/// have started.
pub fn set_data_dir(path: impl Into<PathBuf>) -> Result<(), PathBuf> {
    let requested = path.into();
    if let Some(configured) = DATA_DIR.get() {
        return if configured == &requested {
            Ok(())
        } else {
            Err(requested)
        };
    }
    match DATA_DIR.set(requested) {
        Ok(()) => Ok(()),
        Err(requested) if DATA_DIR.get() == Some(&requested) => Ok(()),
        Err(requested) => Err(requested),
    }
}

/// Resolve an artifact path for creation or mutation.
///
/// An absolute configured path remains explicit. Every relative path is rooted
/// in the configured data directory so automatic state never depends on the
/// service's working directory.
pub fn resolve_artifact_path(path: impl AsRef<Path>) -> PathBuf {
    resolve_artifact_path_from(path.as_ref(), data_dir())
}

fn resolve_artifact_path_from(path: &Path, data_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        data_dir.join(path)
    }
}

/// Resolve a writable runtime artifact while retaining existing legacy
/// locations during upgrades.
///
/// Absolute paths remain explicit. For a relative path, an existing copy below
/// the configured data directory wins, followed by the previous default data
/// directory and then the caller-supplied legacy path. If none exists, the
/// returned path is below the configured data directory for new artifacts.
pub fn resolve_artifact_path_with_legacy(
    path: impl AsRef<Path>,
    legacy_path: Option<&Path>,
) -> PathBuf {
    resolve_path_with_legacy_from(
        path.as_ref(),
        data_dir(),
        Path::new(LEGACY_DATA_DIR),
        legacy_path,
    )
}

fn resolve_path_with_legacy_from(
    path: &Path,
    data_dir: &Path,
    legacy_data_dir: &Path,
    legacy_path: Option<&Path>,
) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let preferred = data_dir.join(path);
    if preferred.exists() {
        return preferred;
    }

    let legacy_data_path = legacy_data_dir.join(path);
    if legacy_data_path.exists() {
        return legacy_data_path;
    }

    legacy_path
        .filter(|path| path.exists())
        .map_or(preferred, Path::to_path_buf)
}

/// Resolve a read-only runtime dependency.
///
/// Absolute paths remain explicit. For a relative path, an existing copy in
/// the configured data directory takes precedence, followed by the previous
/// default data directory and the current-working-directory path. A missing
/// path resolves to the configured data-directory location for clear errors
/// and future creation.
pub fn resolve_dependency_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    resolve_path_with_legacy_from(path, data_dir(), Path::new(LEGACY_DATA_DIR), Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifacts_honor_a_custom_data_directory() {
        assert_eq!(
            resolve_artifact_path_from(Path::new("cache.db"), Path::new("/srv/honk")),
            PathBuf::from("/srv/honk/cache.db")
        );
    }

    #[test]
    fn absolute_paths_stay_explicit() {
        assert_eq!(
            resolve_artifact_path("/srv/honk/cache.db"),
            PathBuf::from("/srv/honk/cache.db")
        );
        assert_eq!(
            resolve_dependency_path("/srv/honk/ech.txt"),
            PathBuf::from("/srv/honk/ech.txt")
        );
    }

    #[test]
    fn legacy_resolution_prefers_configured_then_old_root_then_caller() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let legacy_data_dir = temp.path().join("old");
        let caller_dir = temp.path().join("cwd");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&legacy_data_dir).unwrap();
        std::fs::create_dir_all(&caller_dir).unwrap();

        let relative = Path::new("asset.dat");
        let caller_path = caller_dir.join(relative);
        std::fs::write(&caller_path, "caller").unwrap();
        let resolve = || {
            resolve_path_with_legacy_from(relative, &data_dir, &legacy_data_dir, Some(&caller_path))
        };

        assert_eq!(resolve(), caller_path);
        std::fs::write(legacy_data_dir.join(relative), "old").unwrap();
        let chosen = resolve();
        assert_eq!(std::fs::read_to_string(&chosen).unwrap(), "old");

        std::fs::write(data_dir.join(relative), "new").unwrap();
        let chosen = resolve();
        assert_eq!(std::fs::read_to_string(&chosen).unwrap(), "new");

        std::fs::remove_file(data_dir.join(relative)).unwrap();
        std::fs::remove_file(legacy_data_dir.join(relative)).unwrap();
        assert_eq!(resolve(), caller_path);
        std::fs::remove_file(&caller_path).unwrap();
        assert_eq!(resolve(), data_dir.join(relative));

        let absolute = temp.path().join("explicit.dat");
        assert_eq!(
            resolve_path_with_legacy_from(
                &absolute,
                &data_dir,
                &legacy_data_dir,
                Some(&caller_path),
            ),
            absolute
        );

        let sub = Path::new(".sub");
        let old_sub = legacy_data_dir.join(sub);
        std::fs::create_dir_all(&old_sub).unwrap();
        assert_eq!(
            resolve_path_with_legacy_from(
                sub,
                &data_dir,
                &legacy_data_dir,
                Some(&caller_dir.join(sub)),
            ),
            old_sub
        );
    }
}
