### CI / releases

Read with: `AGENTS.md` (Current validation guidance, the workspace gate); `deployment.md` for what the tarballs are for; skill `honk-release` for the tag-to-release sequence.

`.github/workflows/ci.yml` selects lanes once in `changes` and records the decision in `ci-report-selection`. Code pull requests run fmt + clippy, workspace nextest, the `honk-core --features ebpf --tests` compile guard and offline documentation links; prose-only pull requests run links and mechanical review. The eBPF path filter or `ci:ebpf` label adds the floor-kernel VM gate. `ci:full` adds every lane even on prose-only pull requests, including the recent-kernel VM gate, native aarch64 nextest, independent feature checks and the x86_64 musl core/toolbox build with toolbox startup. Failed change detection runs all lanes rather than hiding coverage. Pushes to `main`/`dev` run everything. Manual runs always check code and docs; `ebpf` or `full` enables the floor gate, and `full` enables heavy lanes (both inputs default true).

The `features` lane also runs the outbound `feature_boundary` integration target and the `honk-tool` suite with `cargo test --no-default-features`, each in a separate Cargo invocation so workspace feature unification cannot hide `rprx`-off cases. Exact nonempty test-list checks require both no-backend regressions before execution; this lane uses plain Cargo rather than nextest.

The `parser` lane compares config corpus inputs against the pinned dae Go oracle and replays saved fuzz inputs on stable Rust. Its filter covers `honk-config`, `tools/dae-parse`, `fuzz`, corpus source documents and shared build inputs. Dialect-only PRs select parser and docs without selecting workspace code lanes; `ci:full`, failed change detection, pushes and manual CI runs also select parser. Its timeout is eight minutes, and `ci-report-parser` carries conformance/replay counts and the first failing case/path.

`.github/workflows/report.yml` joins stage-1 lane artefacts and per-attempt job results into one marker-bearing bot comment on each matching open pull request. `.github/ci/report/fixtures/ordinary.md` extends the agreed fork layout with parser metrics and anchors the renderer's eight byte-for-byte fixtures.

Host suites use `.config/nextest.toml`'s `ci` profile with per-test timeouts and failure JUnit artifacts. Each VM job BTF-checks both objects, installs pinned geo assets, runs the eBPF-feature core unit suite, and invokes `.github/ci/run-vm-gate.sh floor` or `recent` with its tuple from `.github/ci/pins.env`. The guest runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test, root-only network tests and exact real SO_MARK socket tests serially without a job container.

`.github/workflows/weekly.yml` runs Monday at 04:23 UTC or manually. It checks floating stable fmt/clippy/nextest and a floating nightly eBPF build, re-downloads every pinned asset without caches to verify its checksum, and runs `cargo audit` for RustSec advisories. Ordinary CI has no weekly schedule; drift failures do not automatically open issues.

Its `public-vless-loopback` job uses the repository-pinned compiler and checksum-pinned official Xray/sing-box executables from `.github/ci/pins.env`. It runs exactly the two public ignored `vless_udp` cases with `rprx` and the nextest CI profile; missing executables or test selections fail. This is an optional weekly/manual lane, not a normal PR requirement or the legacy external-mask matrix. Low-port/IPv6 setup is restricted to the ephemeral GitHub-hosted runner; no lab credentials or live hosts are used.

The independent weekly `fuzz` job uses the nightly channel from `crates/honk-ebpf/rust-toolchain.toml` and `CARGO_FUZZ_VERSION` from `pins.env`. It runs `document`, `share_link`, and `lexer` sequentially with two workers, 480 seconds per target, a 10-second input timeout and a 2048 MiB RSS limit. The job has a 40-minute timeout and uploads `fuzz-inputs` on success or failure. It keeps `contents: read` and opens no issues.

`.github/workflows/release.yml` on `v*` and `debug.*`: `cargo test --workspace --no-fail-fast` (`cmake` + `libclang-dev` required for boring-sys), then `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl`. Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). The host compiler comes from the root `rust-toolchain.toml`; build eBPF once on the host with `crates/honk-ebpf/rust-toolchain.toml` and pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Publish GitHub Release tarballs; formal `alpha`/`beta`/`rc` tags and all Debug builds are prereleases.

Before upload, every x86_64 matrix entry extracts its packaged tarball into a clean temporary directory and runs the nested `honk-core --version`. This covers the loader and early startup for gnu/musl and both allocators, not configuration or datapath behavior. aarch64 artifacts are not executed. Manual release runs keep the same build checks; publication remains restricted to `v*` and `debug.*` tag refs, never branches or the rolling `debug` tag itself.

### Rolling Debug release

- Push a source tag such as `debug.2026.9.19.score.1`; the trigger accepts `debug.*` without prescribing a date or component format. It runs the same tests and eight release-profile builds as formal tags.
- Before moving `debug` or updating the release, `.github/ci/check-debug-artifacts.sh` requires all eight expected tarballs to be regular, nonempty files. Missing or empty inputs fail without changing the current publication. The release test job runs `.github/ci/test-debug-artifacts.sh` against the same check.
- Successful publication force-updates only `refs/tags/debug` to the source commit and creates or updates the release titled `Debug` at `/releases/tag/debug`. Original source tags remain intact. The release is always a prerelease with `make_latest: false`; notes identify the source tag, commit and workflow run.
- Fixed `honk-core-debug-<target>[-stock].tar.gz` names let the existing release action replace attachments rather than accumulate per-tag assets. The release itself is not deleted or recreated. Tag, notes and asset updates are not transactional: a failure after publication starts may leave them inconsistent. Retrying only the release job requires all build artifacts to remain available; if any have expired (one-day retention) or been deleted, use **Re-run all jobs** to rebuild the complete set.
- All Debug workflows share a concurrency group with `cancel-in-progress: false`, so a new push does not interrupt a running publication. GitHub may replace pending runs and does not guarantee queue order. After a complete successful publication, Debug represents that publisher, not necessarily the newest source tag; a subsequent failed publication can leave the partial state described above.
- The rolling tag must permit force updates by the workflow token, and the Debug release must remain mutable. `contents: write` stays confined to the publication job. Updating `debug` cannot retrigger `debug.*`; formal `v*` publication remains independent.

### Release process (standing convention)

- **Tag naming:** `v0.0.1.beta.N` (strictly incrementing; check `git tag -l | sort -V | tail`). Tag the current `main` tip after it is pushed and its branch CI is green.
- **Trigger:** tag push runs the full workflow above and creates the GitHub Release with `generate_release_notes: true` as a base.
- **Release notes (agent-curated, dae `v2.0.0` style):** replace auto notes with this format after Release creation:

    ```markdown
    ## Highlights

    <2-5 bullets: what this release means to a gateway operator>

    ## What's Changed

    ### New Features

    - <subject> by @<github-author> in <short-hash>

    ### Bug Fixes

    - <subject> by @<github-author> in <short-hash>

    ### Performance

    - <subject> by @<github-author> in <short-hash>

    ### Documentation

    - <subject> by @<github-author> in <short-hash>

    **Full Changelog**: https://github.com/daeuniverse/honk/compare/<prev-tag>...<tag>
    ```

    - Attribute commits to GitHub-resolved authors (`gh api repos/daeuniverse/honk/commits/<sha> --jq .author.login`), never raw git `Author:` names: the daeuniverse-org Release must show org-visible identity.
    - Group commits by their `type(scope)` prefix (`feat` → New Features, `fix` → Bug Fixes, `perf` → Performance, `docs`/`bench` → Documentation, `refactor`/`test` → fold into the nearest section or omit).
    - Apply `gh release edit <tag> --repo daeuniverse/honk --notes-file <file>` only after the build and workflow `release` job finish; the Release page does not exist earlier.

- **Deployment:** after tagging, use the canonical musl mimalloc gateway tarball. Note development/manual `scp` deployments in the PR/issue of record when they differ from release artifacts.

