//! Build script for honk-core.
//!
//! Embeds the release tag or Git description for the CLI and Clash API, and
//! the full source commit that TUN setup receipts record.
//!
//! When the `ebpf` feature is enabled, this script ensures the eBPF objects
//! are available and copies them into `OUT_DIR` for `include_bytes!`.
//! Missing or stale objects are built together using the nightly toolchain.

fn main() {
    emit_version();

    #[cfg(feature = "ebpf")]
    embed_ebpf_object();

    #[cfg(feature = "native-ui")]
    embed_native_ui().expect("failed to embed native UI assets");
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    output.status.success().then_some(())?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn emit_version() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GITHUB_REF");
    if let Some(paths) = git_output(&[
        "rev-parse",
        "--git-path",
        "HEAD",
        "--git-path",
        "refs",
        "--git-path",
        "packed-refs",
    ]) {
        // Tracking a missing packed-refs file would force every build to rerun.
        for path in paths
            .lines()
            .filter(|path| std::path::Path::new(path).exists())
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    // A release ref disambiguates multiple tags pointing at the same commit.
    let version = std::env::var("GITHUB_REF")
        .ok()
        .and_then(|reference| reference.strip_prefix("refs/tags/").map(str::to_string))
        .filter(|tag| !tag.is_empty())
        .or_else(|| git_output(&["describe", "--tags", "--always", "--match", "v*"]))
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=HONK_VERSION={version}");
    // The commit and target triple identify a build precisely when the version is a tag.
    let revision = git_output(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=HONK_REVISION={revision}");
    // A source archive has no Git metadata; its packager names the commit explicitly.
    println!("cargo:rerun-if-env-changed=HONK_SOURCE_SHA");
    let source_sha = match std::env::var_os("HONK_SOURCE_SHA") {
        Some(explicit) => {
            let explicit = explicit.to_str().filter(|sha| is_full_sha(sha));
            explicit
                .expect("HONK_SOURCE_SHA must be a full 40-character lowercase hexadecimal commit")
                .to_string()
        }
        None => git_output(&["rev-parse", "--verify", "HEAD^{commit}"])
            .filter(|sha| is_full_sha(sha))
            .unwrap_or_default(),
    };
    println!("cargo:rustc-env=HONK_SOURCE_SHA={source_sha}");
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=HONK_TARGET={target}");
}

fn is_full_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(feature = "native-ui")]
#[path = "src/native_api/hashed_asset.rs"]
mod hashed_asset;

#[cfg(feature = "native-ui")]
fn embed_native_ui() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};

    println!("cargo:rerun-if-env-changed=HONK_DOONA_DIR");
    let root = std::path::PathBuf::from(std::env::var_os("HONK_DOONA_DIR").context(
        "the native-ui feature embeds doona and doona lite from HONK_DOONA_DIR and its -lite sibling; \
         fetch the pinned release with `export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`",
    )?);
    ensure!(
        root.is_absolute(),
        "HONK_DOONA_DIR must be an absolute path: {}",
        root.display()
    );
    let mut lite_name = root
        .file_name()
        .context("HONK_DOONA_DIR must name a directory below its parent")?
        .to_os_string();
    lite_name.push("-lite");
    embed_ui_assets(&root, "native_ui")?;
    embed_ui_assets(&root.with_file_name(lite_name), "native_ui_lite")
}

#[cfg(feature = "native-ui")]
fn embed_ui_assets(root: &std::path::Path, name: &str) -> anyhow::Result<()> {
    use std::{fmt::Write, fs, path::Path};

    use anyhow::{Context, ensure};

    fn collect(root: &Path, path: &Path, files: &mut Vec<String>) -> anyhow::Result<()> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "native UI assets must not contain symlinks: {}",
            path.display()
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                collect(root, &entry?.path(), files)?;
            }
        } else {
            ensure!(
                metadata.is_file(),
                "native UI asset must be a regular file: {}",
                path.display()
            );
            files.push(
                path.strip_prefix(root)?
                    .to_str()
                    .context("native UI asset paths must be UTF-8")?
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        }
        Ok(())
    }

    println!("cargo:rerun-if-changed={}", root.display());
    ensure!(
        fs::symlink_metadata(root)
            .with_context(|| format!("failed to inspect native UI directory {}", root.display()))?
            .is_dir(),
        "native UI path must be a directory: {}",
        root.display()
    );
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort_unstable();
    ensure!(
        files
            .binary_search_by(|path| path.as_str().cmp("index.html"))
            .is_ok(),
        "native UI assets must include index.html: {}",
        root.display()
    );
    let unhashed: Vec<_> = files
        .iter()
        .filter(|path| path.starts_with("assets/") && !hashed_asset::is_hashed_asset(path))
        .collect();
    // The server caches assets/ as immutable, which is only safe for content-hashed names.
    ensure!(
        unhashed.is_empty(),
        "native UI assets/ files must carry a content hash: {unhashed:?}"
    );

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let compressed = out.join(name);
    if compressed.exists() {
        fs::remove_dir_all(&compressed)?;
    }
    fs::create_dir(&compressed)?;
    // Brotli at quality 11 is slow; one worker per core keeps its memory bounded, and
    // Cargo's job count caps it so `-j` still limits the build.
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let workers = std::env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse::<usize>().ok())
        .map_or(workers, |jobs| workers.min(jobs.max(1)));
    let encoded = std::thread::scope(|scope| {
        let tasks: Vec<_> = files
            .chunks(files.len().div_ceil(workers))
            .map(|chunk| {
                scope.spawn(|| {
                    chunk
                        .iter()
                        .map(|path| encode(&root.join(path)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        tasks
            .into_iter()
            .flat_map(|task| task.join().expect("native UI compression panicked"))
            .collect::<anyhow::Result<Vec<_>>>()
    })?;
    let mut generated = String::from("&[\n");
    for (index, (path, encoded)) in files.iter().zip(encoded).enumerate() {
        if let Some(Compressed { br, gzip, len }) = encoded {
            let br_file = compressed.join(format!("{index}.br"));
            let gzip_file = compressed.join(format!("{index}.gz"));
            fs::write(&br_file, br)?;
            fs::write(&gzip_file, gzip)?;
            writeln!(
                generated,
                "    ({path:?}, EmbeddedAsset::Encoded {{ br: include_bytes!({:?}), gzip: include_bytes!({:?}), len: {len} }}),",
                br_file.to_str().context("OUT_DIR must be UTF-8")?,
                gzip_file.to_str().context("OUT_DIR must be UTF-8")?,
            )?;
        } else {
            let file = root.join(path);
            let file = file
                .to_str()
                .context("native UI asset paths must be UTF-8")?;
            writeln!(
                generated,
                "    ({path:?}, EmbeddedAsset::Identity(include_bytes!({file:?}))),"
            )?;
        }
    }
    generated.push_str("]\n");
    fs::write(out.join(format!("{name}_assets.rs")), generated)?;
    Ok(())
}

#[cfg(feature = "native-ui")]
struct Compressed {
    br: Vec<u8>,
    gzip: Vec<u8>,
    len: usize,
}

/// Brotli and gzip variants of a text asset, or `None` to embed the file as is.
#[cfg(feature = "native-ui")]
fn encode(file: &std::path::Path) -> anyhow::Result<Option<Compressed>> {
    use std::io::Write;

    const TEXT: &[&str] = &["css", "html", "js", "json", "svg", "txt", "webmanifest"];
    if !file
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| TEXT.contains(&extension))
    {
        return Ok(None);
    }
    let raw = std::fs::read(file)?;
    let mut br = brotli::CompressorWriter::new(Vec::new(), 4096, 11, 22);
    br.write_all(&raw)?;
    let br = br.into_inner();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gzip.write_all(&raw)?;
    let gzip = gzip.finish()?;
    let len = raw.len();
    Ok((br.len().max(gzip.len()) < len).then_some(Compressed { br, gzip, len }))
}

#[cfg(feature = "ebpf")]
fn embed_ebpf_object() {
    use std::{env, path::PathBuf, process::Command};
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    println!("cargo:rerun-if-env-changed=HONK_EBPF_PREBUILT_DIR");
    let status = Command::new("sh")
        .arg(root.join("ci/ebpf-objects.sh"))
        .args(["embed", "legacy-tc"])
        .arg(env::var_os("OUT_DIR").unwrap())
        .status()
        .expect("prepare eBPF objects");
    assert!(status.success(), "eBPF object preparation failed: {status}");
}
