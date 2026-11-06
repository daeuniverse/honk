//! Bounded HTTP header maps shared by the stream transports.

use std::collections::BTreeMap;

pub(super) const MAX_HEADERS: usize = 64;
pub(super) const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Insert one entry under its lowercase name, merging equal-value aliases.
pub(super) fn merge(
    headers: &mut BTreeMap<String, String>,
    name: String,
    value: String,
) -> Result<(), &'static str> {
    match headers.entry(name.to_ascii_lowercase()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &value => {}
        _ => return Err("header aliases conflict"),
    }
    Ok(())
}

/// Lowercase names before identity derivation, merging equal-value aliases.
pub(super) fn normalize(headers: &mut BTreeMap<String, String>) -> Result<(), &'static str> {
    let mut normalized = BTreeMap::new();
    for (name, value) in std::mem::take(headers) {
        merge(&mut normalized, name, value)?;
    }
    *headers = normalized;
    Ok(())
}

/// Validate normalized names, values, and the transport's managed set.
pub(super) fn validate(
    headers: &BTreeMap<String, String>,
    managed: &[&str],
) -> Result<(), &'static str> {
    if headers.len() > MAX_HEADERS {
        return Err("too many headers");
    }
    let mut bytes = 0usize;
    for (name, value) in headers {
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err("headers must be normalized before admission");
        }
        if name.parse::<http::header::HeaderName>().is_err()
            || managed.contains(&name.as_str())
            || http::header::HeaderValue::from_str(value).is_err()
            || value.bytes().any(|byte| byte < 32 || byte == 127)
        {
            return Err("invalid or protocol-managed header");
        }
        bytes += name.len() + value.len();
    }
    if bytes > MAX_HEADER_BYTES {
        return Err("headers exceed supported bounds");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_reject_oversized_maps() {
        let map = |count: usize, value: &str| {
            (0..count)
                .map(|index| (format!("x-{index}"), value.to_string()))
                .collect()
        };
        assert!(validate(&map(64, "v"), &[]).is_ok());
        assert!(validate(&map(65, "v"), &[]).is_err());
        assert!(validate(&map(1, &"a".repeat(16 * 1024 - 3)), &[]).is_ok());
        assert!(validate(&map(1, &"a".repeat(16 * 1024 - 2)), &[]).is_err());
    }
}
