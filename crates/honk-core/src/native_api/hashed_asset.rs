//! Content-hashed UI asset names, shared with `build.rs`, which refuses an embedded
//! doona build whose `assets/` holds a name this does not accept.

/// Length of the hash Vite appends to every emitted file name.
const HASH_LEN: usize = 8;

/// Whether `path` names a file the build emitted as `assets/<name>-<hash>.<ext>`,
/// so its bytes never change under that name. `<name>` may contain dots (Vite
/// workers are `<name>.worker-<hash>.js`) and the hash may contain `-`.
pub(crate) fn is_hashed_asset(path: &str) -> bool {
    let Some(name) = path.strip_prefix("assets/") else {
        return false;
    };
    let Some((stem, _)) = name.rsplit_once('.') else {
        return false;
    };
    let stem = stem.as_bytes();
    !name.contains('/')
        && stem.len() > HASH_LEN + 1
        && stem[stem.len() - HASH_LEN - 1] == b'-'
        && stem[stem.len() - HASH_LEN..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
