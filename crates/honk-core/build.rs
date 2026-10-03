//! Build script for honk-core.
//!
//! Embeds the release tag or Git description for the CLI and Clash API.
//!
//! When the `ebpf` feature is enabled, this script ensures the eBPF object
//! file is available and copies it into `OUT_DIR` so `lib.rs` can embed it
//! via `include_bytes!`.  If the object does not exist yet, it is built
//! automatically using the nightly toolchain.

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
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=HONK_TARGET={target}");
}

#[cfg(feature = "native-ui")]
#[path = "src/native_api/hashed_asset.rs"]
mod hashed_asset;

#[cfg(feature = "native-ui")]
fn embed_native_ui() -> anyhow::Result<()> {
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

    println!("cargo:rerun-if-env-changed=HONK_DOONA_DIR");
    let root = std::path::PathBuf::from(std::env::var_os("HONK_DOONA_DIR").context(
        "the native-ui feature embeds a doona build from HONK_DOONA_DIR; \
         fetch the pinned release with `export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`",
    )?);
    ensure!(
        root.is_absolute(),
        "HONK_DOONA_DIR must be an absolute path: {}",
        root.display()
    );
    println!("cargo:rerun-if-changed={}", root.display());
    ensure!(
        fs::symlink_metadata(&root)
            .with_context(|| format!("failed to inspect HONK_DOONA_DIR {}", root.display()))?
            .is_dir(),
        "HONK_DOONA_DIR must be a directory: {}",
        root.display()
    );
    let mut files = Vec::new();
    collect(&root, &root, &mut files)?;
    files.sort_unstable();
    ensure!(
        files
            .binary_search_by(|path| path.as_str().cmp("index.html"))
            .is_ok(),
        "native UI assets must include index.html"
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
    let compressed = out.join("native_ui");
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
                .context("HONK_DOONA_DIR paths must be UTF-8")?;
            writeln!(
                generated,
                "    ({path:?}, EmbeddedAsset::Identity(include_bytes!({file:?}))),"
            )?;
        }
    }
    generated.push_str("]\n");
    fs::write(out.join("native_ui_assets.rs"), generated)?;
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
    use std::path::{Path, PathBuf};
    use std::process::Command;

    // A shared target can reuse a build-script binary compiled in another checkout.
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must provide CARGO_MANIFEST_DIR"),
    );
    let ebpf_crate = manifest_dir.join("../honk-ebpf");
    let ebpf_common_crate = manifest_dir.join("../honk-ebpf-common");
    let ebpf_target = ebpf_crate.join("target/bpfel-unknown-none/release/honk-ebpf");
    let toolchain_file = ebpf_crate.join("rust-toolchain.toml");
    println!("cargo:rerun-if-changed={}", toolchain_file.display());
    let toolchain =
        std::fs::read_to_string(&toolchain_file).expect("failed to read eBPF rust-toolchain.toml");
    let channel = toolchain
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim() == "channel")
        .and_then(|(_, value)| value.trim().strip_prefix('"')?.strip_suffix('"'))
        .filter(|channel| !channel.is_empty())
        .expect("eBPF rust-toolchain.toml must contain a quoted channel");

    /// aya refuses objects without a `.BTF` section ("no BTF parsed for
    /// object"). Cheap guard: section names live verbatim in the section
    /// header string table, so a byte search for the NUL-terminated name is
    /// sufficient.
    fn object_has_btf(path: &Path) -> bool {
        std::fs::read(path)
            .map(|data| {
                data.windows(5).any(|w| w == b".BTF\0") || data.windows(5).any(|w| w == b".BTF.")
            })
            .unwrap_or(false)
    }

    /// Newest mtime under `dir` (recursive). The eBPF object is built by a
    /// separate cargo invocation, so cargo's own change tracking never
    /// rebuilds it — without this check a stale object from hours ago gets
    /// embedded while the sources have moved on (observed twice: missing maps
    /// at runtime while the build looks green).
    fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
        if dir.is_file() {
            return dir.metadata().ok()?.modified().ok();
        }
        let mut newest = None;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = path.metadata()
                    && let Ok(mtime) = meta.modified()
                    && newest.is_none_or(|n| mtime > n)
                {
                    newest = Some(mtime);
                }
            }
        }
        newest
    }

    fn object_stale(obj: &Path, src_dirs: &[&Path]) -> bool {
        let Ok(obj_mtime) = obj.metadata().and_then(|m| m.modified()) else {
            return true;
        };
        src_dirs
            .iter()
            .filter_map(|d| newest_mtime(d))
            .any(|src_mtime| src_mtime > obj_mtime)
    }

    let candidates = [
        ebpf_target.clone(),
        manifest_dir.join("../../target/honk-core.o"),
    ];

    let obj = candidates.iter().find(|p| p.exists()).cloned();
    let src_dirs = [
        ebpf_crate.join("src"),
        ebpf_common_crate.join("src"),
        toolchain_file,
    ];

    let obj = match obj {
        Some(p)
            if object_has_btf(&p)
                // A restored object may have a newer mtime than the changed pin.
                && std::fs::read_to_string(p.with_extension("toolchain"))
                    .is_ok_and(|built_channel| built_channel == channel)
                && !object_stale(
                    &p.with_extension("toolchain"),
                    &[manifest_dir.join("build.rs").as_path()],
                )
                && !object_stale(
                    &p,
                    &src_dirs.iter().map(|d| d.as_path()).collect::<Vec<_>>(),
                ) =>
        {
            println!("cargo:rerun-if-changed={}", p.display());
            p
        }
        stale => {
            if let Some(p) = &stale
                && p.exists()
                && object_has_btf(p)
            {
                println!(
                    "cargo:warning=eBPF object at {} has stale sources or toolchain — rebuilding with {channel}",
                    p.display()
                );
            }
            // Missing, or stale without .BTF (e.g. built while an environment
            // RUSTFLAGS overrode crates/honk-ebpf/.cargo/config.toml): (re)build.
            println!("cargo:warning=Building eBPF object with {channel}...");
            let status = {
                let mut command = Command::new("cargo");
                for (key, _) in std::env::vars_os() {
                    if key.as_encoded_bytes().starts_with(b"CARGO_PROFILE_") {
                        command.env_remove(key);
                    }
                }
                command
            }
            .arg(format!("+{channel}"))
            .args([
                "build",
                "--release",
                "-Zbuild-std=core",
                "--target",
                "bpfel-unknown-none",
            ])
            // Cargo exports its absolute host rustc path to build scripts.
            // Let the selected nightly resolve its own compiler and sysroot.
            .env_remove("RUSTC")
            // An inherited RUSTFLAGS would override the crate's
            // .cargo/config.toml rustflags (--btf, debuginfo) and silently
            // produce a BTF-less object again.
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            // Parent workspace analysis must not turn this separate build into clippy.
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CLIPPY_ARGS")
            .env("CARGO_TARGET_DIR", ebpf_crate.join("target"))
            .current_dir(&ebpf_crate)
            .status()
            .expect("failed to build eBPF object");

            if !status.success() {
                panic!(
                    "eBPF build failed. Build manually:\n  \
                     cd crates/honk-ebpf && cargo +{channel} build --release \
                     -Zbuild-std=core --target bpfel-unknown-none"
                );
            }
            if !object_has_btf(&ebpf_target) {
                panic!(
                    "eBPF object at {} has no .BTF section — aya cannot load it. \
                     Rebuild manually:\n  \
                     cd crates/honk-ebpf && cargo +{channel} build --release \
                     -Zbuild-std=core --target bpfel-unknown-none",
                    ebpf_target.display()
                );
            }
            std::fs::write(ebpf_target.with_extension("toolchain"), channel)
                .expect("failed to record eBPF object toolchain");
            println!("cargo:rerun-if-changed={}", ebpf_target.display());
            ebpf_target
        }
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("honk-ebpf.o");
    std::fs::copy(&obj, &dest)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {}", obj.display(), dest.display(), e));

    println!(
        "cargo:rerun-if-changed={}",
        ebpf_crate.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_common_crate.join("src").display()
    );
    println!("cargo:rustc-env=HONK_EBPF_OBJECT={}", dest.display());
    println!(
        "cargo:warning=eBPF object embedded ({} bytes)",
        obj.metadata().map(|m| m.len()).unwrap_or(0)
    );
}
