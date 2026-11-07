//! Running-kernel release checks for features that predate any probe.

/// `(major, minor, patch)` of the running kernel; `patch` is 0 when absent.
pub(crate) fn release() -> Option<(u32, u32, u32)> {
    parse_release(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()?
            .trim(),
    )
}

pub(crate) fn parse_release(release: &str) -> Option<(u32, u32, u32)> {
    let mut parts = release.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()
        .and_then(|patch| patch.parse().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// `SO_RCVMARK` arrived in Linux 5.19; earlier listeners cannot read skb marks.
pub(crate) fn so_rcvmark_supported() -> bool {
    release().is_some_and(|release| release >= (5, 19, 0))
}

#[cfg(test)]
mod tests {
    use super::parse_release;

    #[test]
    fn releases_parse_with_vendor_suffixes() {
        assert_eq!(parse_release("4.19.113-g820a424c538c"), Some((4, 19, 113)));
        assert_eq!(parse_release("5.15.0-051500-generic"), Some((5, 15, 0)));
        assert_eq!(parse_release("6.12"), Some((6, 12, 0)));
        assert_eq!(parse_release("7.3.0+"), Some((7, 3, 0)));
        assert_eq!(parse_release("linux"), None);
    }
}
