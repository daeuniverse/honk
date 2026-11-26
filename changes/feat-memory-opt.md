Changed

- Build static musl binaries natively in Alpine 3.24 (`ci/build-musl.sh`), replacing the Zig wrappers and enabling native `aarch64` release builds and startup checks.
- Shrink expanded TCP copy-relay buffers to 8 KiB after 60–120 seconds idle with writes flushed, and drop them on EOF before draining.
- Share BoringSSL contexts across DoT/DoH DNS and HTTP probes, cap the ECH discovery cache at 256 entries, shrink oversized TCP sniff negative-cache storage on prune, and add the opt-in `jemalloc-stats` Cargo feature.
