//! Log plumbing: timestamps, the console layer and the rotating log file.

use std::path::PathBuf;

use honk_config::Config;

/// Log timestamps in the machine's local time zone with its UTC offset,
/// e.g. `2026-09-12T02:30:15.123456+10:00`. The default timer prints UTC,
/// which does not line up with a router's syslog or an operator's clock.
/// chrono reads the zone itself, so this stays sound after threads exist.
pub(crate) struct LocalTime;

impl tracing_subscriber::fmt::time::FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(
            w,
            "{}",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.6f%:z")
        )
    }
}

/// quinn logs every endpoint-driver death at ERROR; probe/warm endpoints over
/// retiring AnyTLS sessions die as a matter of course (the SYNACK watchdog
/// kills them on purpose), so that target is silenced unless `RUST_LOG` says
/// otherwise.
pub(crate) const QUIET_LOG_TARGETS: &str = "quinn::endpoint=off";

/// The target [`QUIET_LOG_TARGETS`] silences; Clash and native log capture
/// always exclude it.
#[cfg(any(feature = "clash-api", feature = "native-api"))]
pub(crate) const QUIET_TARGET: &str = "quinn::endpoint";

/// WARN when a persisting state is entered, DEBUG for its repeats, so a
/// failure retried every tick reports once per episode. The caller decides
/// entry (e.g. `!flag.swap(true)`); the event keeps the caller's target.
macro_rules! warn_on_entry {
    ($entered:expr, $($arg:tt)+) => {
        if $entered {
            tracing::warn!($($arg)+)
        } else {
            tracing::debug!($($arg)+)
        }
    };
}
pub(crate) use warn_on_entry;

/// [`warn_on_entry!`] for a failure that repeats per query with no episode
/// boundary: WARN at most once per 10 s per call site, DEBUG in between.
macro_rules! warn_throttled {
    ($($arg:tt)+) => {{
        static LAST: parking_lot::Mutex<Option<std::time::Instant>> =
            parking_lot::Mutex::new(None);
        $crate::logging::warn_on_entry!($crate::logging::warn_due(&LAST), $($arg)+)
    }};
}
pub(crate) use warn_throttled;

/// Monotonic clock: a wall-clock step must not mute the alarm.
pub(crate) fn warn_due(last: &parking_lot::Mutex<Option<std::time::Instant>>) -> bool {
    let mut last = last.lock();
    let due = last.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(10));
    if due {
        *last = Some(std::time::Instant::now());
    }
    due
}

/// Colour belongs on a terminal only: a service manager (procd, syslog) stores
/// the escape codes verbatim. A non-empty `NO_COLOR` turns it off everywhere.
pub(crate) fn console_ansi(is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    is_terminal && no_color.is_none_or(|value| value.is_empty())
}

/// The console layer, with or without the local timestamp. The file layer
/// always stamps: a file has no journal in front of it.
pub(crate) fn console_log_layer<S, W, F>(
    disable_timestamp: bool,
    ansi: bool,
    writer: W,
    filter: F,
) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
    F: tracing_subscriber::layer::Filter<S> + Send + Sync + 'static,
{
    use tracing_subscriber::Layer as _;
    if disable_timestamp {
        Box::new(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(ansi)
                .with_writer(writer)
                .with_filter(filter),
        )
    } else {
        Box::new(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_ansi(ansi)
                .with_writer(writer)
                .with_filter(filter),
        )
    }
}

pub(crate) fn resolved_log_file_path(
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

pub(crate) fn open_log_file(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
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

/// The log file rotates at this size: it becomes `<name>.1`, replacing an
/// older copy, so the file and its copy together stay under twice the limit.
pub(crate) const LOG_FILE_LIMIT: u64 = 10 * 1024 * 1024;

/// The tracing writer for `global.log_file`, rotating at `limit`.
pub(crate) struct RotatingLogFile {
    path: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
    limit: u64,
    /// Set when a rotation failed: no further attempts, and the current file
    /// takes lines only up to twice the limit.
    stuck: bool,
    /// Whether the one warning about dropped lines was printed.
    dropping: bool,
    #[cfg(test)]
    pub(crate) fail_reopen: bool,
}

impl RotatingLogFile {
    pub(crate) fn open(path: &std::path::Path, limit: u64) -> anyhow::Result<Self> {
        let file = open_log_file(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            limit,
            stuck: false,
            dropping: false,
            #[cfg(test)]
            fail_reopen: false,
        })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        // Another honk sharing the file during a restart handoff may have
        // rotated it already; renaming then would overwrite its copy.
        let ours = self.file.metadata()?;
        let current = std::fs::symlink_metadata(&self.path).ok();
        if current.is_some_and(|current| (current.dev(), current.ino()) == (ours.dev(), ours.ino()))
        {
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(".1");
            std::fs::rename(&self.path, rotated)?;
        }
        #[cfg(test)]
        if self.fail_reopen {
            return Err(std::io::Error::other("injected reopen failure"));
        }
        // Opened with the same checks as the first file.
        self.file = open_log_file(&self.path).map_err(std::io::Error::other)?;
        self.size = self.file.metadata()?.len();
        Ok(())
    }
}

impl std::io::Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let after = self.size.saturating_add(buf.len() as u64);
        if !self.stuck && self.size > 0 && after > self.limit && self.rotate().is_err() {
            self.stuck = true;
        }
        if self.stuck && after > self.limit.saturating_mul(2) {
            if !self.dropping {
                self.dropping = true;
                // Not through tracing: this is the tracing writer.
                eprintln!(
                    "honk-core: log file {} could not be rotated; dropping log lines until restart",
                    self.path.display()
                );
            }
            return Ok(buf.len());
        }
        let written = self.file.write(buf)?;
        self.size = self.size.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod local_time_tests {
    use tracing_subscriber::fmt::time::FormatTime;

    #[test]
    fn test_log_timestamp_carries_the_local_utc_offset() {
        let mut out = String::new();
        super::LocalTime
            .format_time(&mut tracing_subscriber::fmt::format::Writer::new(&mut out))
            .unwrap();
        // 2026-09-12T02:30:15.123456+10:00 — date, time with microseconds, signed offset.
        let (stamp, offset) = out.split_at(out.len() - 6);
        assert_eq!(stamp.len(), 26, "{out}");
        assert_eq!(&stamp[10..11], "T", "{out}");
        assert!(offset.starts_with('+') || offset.starts_with('-'), "{out}");
        assert_eq!(&offset[3..4], ":", "{out}");
        let expected = chrono::Local::now().format("%:z").to_string();
        assert_eq!(offset, expected, "{out}");
    }

    /// `--disable-timestamp` drops the stamp from the console line only.
    #[test]
    fn test_disable_timestamp_omits_the_console_stamp() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let render = |disable_timestamp: bool| {
            let sink = Sink::default();
            let writer = sink.clone();
            let layer = super::console_log_layer(
                disable_timestamp,
                true,
                move || writer.clone(),
                tracing_subscriber::EnvFilter::new("info"),
            );
            let subscriber = tracing_subscriber::registry().with(layer);
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!("stamp probe");
            });
            let bytes = sink.0.lock().unwrap().clone();
            let text = String::from_utf8(bytes).unwrap();
            // The console layer keeps its colours; strip the SGR sequences.
            let mut plain = String::new();
            let mut rest = text.as_str();
            while let Some(start) = rest.find("\u{1b}[") {
                plain.push_str(&rest[..start]);
                let after = &rest[start + 2..];
                rest = after.find('m').map_or("", |end| &after[end + 1..]);
            }
            plain.push_str(rest);
            plain
        };

        let stamped = render(false);
        assert!(stamped.starts_with("20"), "{stamped:?}");
        assert!(stamped.contains(" INFO "), "{stamped:?}");
        let bare = render(true);
        assert!(bare.trim_start().starts_with("INFO "), "{bare:?}");
        assert!(bare.contains("stamp probe"), "{bare:?}");
    }

    /// Colour only on a terminal, and never when `NO_COLOR` is set non-empty.
    #[test]
    fn test_console_colour_needs_a_terminal_and_no_no_color() {
        use std::ffi::OsStr;

        assert!(super::console_ansi(true, None));
        assert!(super::console_ansi(true, Some(OsStr::new(""))));
        assert!(!super::console_ansi(true, Some(OsStr::new("1"))));
        assert!(!super::console_ansi(false, None));
        assert!(!super::console_ansi(false, Some(OsStr::new("1"))));
    }
}
