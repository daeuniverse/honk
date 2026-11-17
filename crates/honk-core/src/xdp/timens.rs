use anyhow::{Context as _, ensure};
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;

pub(crate) fn monotonic_namespace_offset() -> anyhow::Result<Option<i128>> {
    let current = match File::open("/proc/self/ns/time") {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            require_time_namespace_absence(|path| match File::open(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            })?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let children = File::open("/proc/self/ns/time_for_children")?;
    let worker = File::open("/proc/thread-self/ns/time")?;
    let identity = |file: &File| -> std::io::Result<_> {
        let m = file.metadata()?;
        Ok((m.dev(), m.ino()))
    };
    ensure!(
        identity(&current)? == identity(&children)? && identity(&current)? == identity(&worker)?,
        "current and children time namespaces differ"
    );
    let offsets = std::fs::read_to_string("/proc/self/timens_offsets")?;
    let mut monotonic = None;
    let mut boottime = false;
    for line in offsets.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(words.len() == 3, "malformed time namespace offsets");
        let seconds: i64 = words[1].parse()?;
        let nanos: u32 = words[2].parse()?;
        ensure!(nanos < 1_000_000_000, "invalid time namespace nanoseconds");
        match words[0] {
            "monotonic" => {
                ensure!(monotonic.is_none(), "duplicate monotonic offset");
                monotonic = Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos));
            }
            "boottime" => {
                ensure!(!boottime, "duplicate boottime offset");
                boottime = true;
            }
            _ => anyhow::bail!("unknown time namespace clock"),
        }
    }
    ensure!(boottime, "missing time namespace offsets");
    monotonic
        .context("missing time namespace offsets")
        .map(Some)
}

fn require_time_namespace_absence(
    mut present: impl FnMut(&str) -> std::io::Result<bool>,
) -> anyhow::Result<()> {
    for path in [
        "/proc/self/ns/time_for_children",
        "/proc/thread-self/ns/time",
        "/proc/self/timens_offsets",
    ] {
        ensure!(!present(path)?, "incomplete time namespace interfaces");
    }
    for path in ["/proc/self/ns/net", "/proc/thread-self/ns/net"] {
        ensure!(present(path)?, "process namespace inspection unavailable");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn absent_time_namespace_requires_complete_proc_evidence() {
        let without_timens = |path: &str| Ok(path.ends_with("/ns/net"));
        super::require_time_namespace_absence(without_timens).unwrap();
        for remaining in [
            "/proc/self/ns/time_for_children",
            "/proc/thread-self/ns/time",
            "/proc/self/timens_offsets",
        ] {
            assert!(
                super::require_time_namespace_absence(|path| {
                    Ok(path == remaining || path.ends_with("/ns/net"))
                })
                .is_err()
            );
        }
        assert!(super::require_time_namespace_absence(|_| Ok(false)).is_err());
        assert!(
            super::require_time_namespace_absence(|_| {
                Err(std::io::ErrorKind::PermissionDenied.into())
            })
            .is_err()
        );
    }
}
