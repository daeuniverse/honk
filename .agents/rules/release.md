### CI / releases

Read with: `AGENTS.md` (Current validation guidance, the workspace gate); `deployment.md` for what the tarballs are for; skill `honk-release` for the tag-to-release sequence.

`.github/workflows/ci.yml` selects lanes once in `changes` and records the decision in `ci-report-selection`. Code pull requests run fmt + clippy, workspace nextest, the `honk-core --features ebpf --tests` compile guard and offline documentation links; prose-only pull requests run links and mechanical review. The eBPF path filter or `ci:ebpf` label adds the floor-kernel VM gate. `ci:full` adds every lane even on prose-only pull requests, including the recent-kernel VM gate, native aarch64 nextest, independent feature checks and the x86_64 musl core/toolbox build with toolbox startup. Failed change detection runs all lanes rather than hiding coverage. The `ci-ok` job aggregates every other job (skipped lanes pass; failed or cancelled lanes and failed change detection fail) and is the single check to require in branch protection; making it required is a repository setting the maintainers apply. Pushes to `main`/`dev` run everything. Manual runs always check code and docs; `ebpf` or `full` enables the floor gate, and `full` enables heavy lanes (both inputs default true).

Every code pull request runs the userspace routing goldens (`routing::golden::*`, including the parsed dae-expression tables) as a named `test`-lane step before workspace nextest, failing if the filter selects nothing. The eBPF path filter also covers the routing compiler (`crates/honk-core/src/routing/**`) and `honk-config`'s routing schema/parser, so rule-semantics changes replay those tables against the real routing-test object in the floor-kernel VM gate.

The `features` lane also runs the outbound `feature_boundary` integration target and the `honk-tool` suite with `cargo test --no-default-features`, each in a separate Cargo invocation so workspace feature unification cannot hide `rprx`-off cases. Exact nonempty test-list checks require both no-backend regressions before execution; this lane uses plain Cargo rather than nextest.

Workspace lint and nextest explicitly enable `honk-core/native-ui` (which includes `native-api`) so ordinary code CI covers the opt-in native API and embedded UI alongside the default-on Clash API feature; workspace lint also enables `honk-core/udp-bench` so the `udp_io` benchmark and its real-I/O harness stay compiled and linted, and the `features` lane checks that bench with default features off. Both API listeners still require configuration. The independent `features` lane checks native-only, native+Clash and native-ui builds, requires nonempty authentication/coexistence/embedded-UI selections, and executes native-only HTTP regressions, cross-token isolation and embedded-UI HTTP coverage separately. Native-api-only coverage retains embedded-UI rejection. Release allocator variants share explicit `clash-api,ebpf,rprx,native-ui` capabilities (`native-ui` includes `native-api`) and differ only by `mimalloc`. Every job that enables `native-ui` first runs `ci/fetch-doona.sh`, which downloads the doona release pinned in `.github/ci/pins.env`, checks its SHA-256 and exports the directory as `HONK_DOONA_DIR`; the repository vendors no doona files.

The `parser` lane compares config corpus inputs against the pinned dae Go oracle and replays saved fuzz inputs on stable Rust. Its filter covers `honk-config`, `tools/dae-parse`, `fuzz`, corpus source documents and shared build inputs. Dialect-only PRs select parser and docs without selecting workspace code lanes; `ci:full`, failed change detection, pushes and manual CI runs also select parser. Its timeout is eight minutes, and `ci-report-parser` carries conformance/replay counts and the first failing case/path.

`.github/workflows/report.yml` joins stage-1 lane artefacts and per-attempt job results into one marker-bearing bot comment on each matching open pull request. `.github/ci/report/fixtures/ordinary.md` extends the agreed fork layout with parser metrics and anchors the renderer's eight byte-for-byte fixtures.

Host suites use `.config/nextest.toml`'s `ci` profile with per-test timeouts and failure JUnit artifacts. Each VM job BTF-checks both objects, installs pinned geo assets, runs the eBPF-feature core unit suite, and invokes `.github/ci/run-vm-gate.sh floor` or `recent` with its tuple from `.github/ci/pins.env`. The guest runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test, root-only network tests and exact real SO_MARK socket tests serially without a job container.
The VM executable build explicitly enables `native-api`; the guest requires the nonempty ignored `control::lifecycle::tests::ordinary_shutdown_preserves_live_tcp_until_graceful_completion` selection and runs the ignored `control::lifecycle::tests` suite serially. That test configures one SOCKS5 peer and checks that ordinary shutdown preserves a live TCP request until its final response; it is not a shared-XUDP cycle. This validates the owned mock command loop separately from real hooks/NFQUEUE/routing tests.

`.github/workflows/weekly.yml` runs Monday at 04:23 UTC or manually. It checks floating stable fmt/clippy/nextest and a floating nightly eBPF build, re-downloads every pinned asset without caches to verify its checksum, and runs `cargo audit` for RustSec advisories. Ordinary CI has no weekly schedule; drift failures do not automatically open issues.

Its `public-vless-loopback` job uses the repository-pinned compiler and checksum-pinned official Xray/sing-box executables from `.github/ci/pins.env`. It runs exactly the two public ignored `vless_udp` cases, the ignored library case `official_vision_peers_switch_inner_tls_to_direct` and the ignored `sing_box_shared_source_eim_eif_and_domain_matrix` of `tests/shared_source_sing_box.rs`, each with `rprx` and the nextest CI profile; missing executables or test selections fail. This is an optional weekly/manual lane, not a normal PR requirement or the legacy external-mask matrix. Low-port/IPv6 setup is restricted to the ephemeral GitHub-hosted runner; no lab credentials or live hosts are used.

Each of those steps runs `ci/run-exact-ignored-tests.sh <target> <test>...`, which fails unless `nextest list` reports exactly the requested tests as ignored and non-empty before running them.

The independent weekly `fuzz` job uses the nightly channel from `crates/honk-ebpf/rust-toolchain.toml` and `CARGO_FUZZ_VERSION` from `pins.env`. It runs `document`, `share_link`, and `lexer` sequentially with two workers, 480 seconds per target, a 10-second input timeout and a 2048 MiB RSS limit. The job has a 40-minute timeout and uploads `fuzz-inputs` on success or failure. It keeps `contents: read` and opens no issues.

`.github/workflows/release.yml` on `v*` and `debug.*`: `cargo test --workspace --no-fail-fast` (`cmake` + `libclang-dev` required for boring-sys), then sixteen release-profile builds. Three variants: full (`clash-api,native-ui`), clash-api-only (`clash-api`) and native-api-only (`native-api`); the full build covers `x86_64`/`aarch64` × `gnu`/`musl`, while the lean variants ship only for the static gateway (`musl`) targets. Every build passes `--no-default-features` plus its exact feature list, so native-api-only really drops the default-on `clash-api`. Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). The host compiler comes from the root `rust-toolchain.toml`; build eBPF once on the host with `crates/honk-ebpf/rust-toolchain.toml` and pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Each full tarball carries doona's `LICENSE`, `LICENSES/`, `NOTICE` and `THIRD-PARTY-NOTICES.txt` under `doona/`; the lean variants embed no UI and carry no `doona/` directory. The release job attaches `doona-source-<version>.tar.gz` from `ci/fetch-doona.sh --source` to every tag release and Debug release (GPL-3.0 section 6). Publish GitHub Release tarballs; formal `alpha`/`beta`/`rc` tags and all Debug builds are prereleases.

Before upload, every x86_64 matrix entry extracts its packaged tarball into a clean temporary directory and runs the nested `honk-core --version`. This covers the loader and early startup for gnu/musl and both allocators, not configuration or datapath behavior. aarch64 artifacts are not executed. Manual release runs keep the same build checks; publication remains restricted to `v*` and `debug.*` tag refs, never branches.

Every publication, formal or Debug, also uploads one `SHA256SUMS` covering all published archives and records a build-provenance attestation for each archive, checked with `gh attestation verify <archive> -R daeuniverse/honk`. The publication job alone holds `id-token: write` and `attestations: write` for that, next to `contents: write`.

### Debug releases

- Push a source tag such as `debug.2026.9.19.score.1`; the trigger accepts `debug.*` without prescribing a date or component format. It runs the same tests and sixteen release-profile builds as formal tags.
- Before publishing, `.github/ci/check-debug-artifacts.sh` requires all sixteen expected tarballs to be regular, nonempty files. Missing or empty inputs fail without publishing. The release test job runs `.github/ci/test-debug-artifacts.sh` against the same check.
- Each source tag gets its own release, titled with the tag, at `/releases/tag/<tag>`. Earlier Debug releases are never moved or overwritten. Every Debug release is a prerelease with `make_latest: false`; notes identify the source tag, commit and workflow run.
- After the tag release, the workflow force-moves `refs/tags/debug` to the same commit and updates the release titled `Debug` at `/releases/tag/debug` with the same tarballs, so that page and `/releases/download/debug/<asset>` always serve the newest published build. Assets the new build does not have, such as the previous `doona-source-<version>.tar.gz`, are deleted. Downstream pins name the per-tag release, never `debug`. Updating `debug` cannot retrigger `debug.*`.
- Assets keep the fixed `honk-core-debug-<target>[-stock]-{full|clash-api|native-api}.tar.gz` names inside each release. Before the variant suffix existed, the unsuffixed name was the full build; older releases keep that spelling. Re-running the same tag replaces that release's attachments only. Retrying only the release job requires all build artifacts to remain available; if any have expired (one-day retention) or been deleted, use **Re-run all jobs** to rebuild the complete set.
- After publishing, the workflow deletes per-tag Debug releases beyond the newest ten. Their source tags remain, so `git` can still check them out, but downloads from an older per-tag release stop working; downstream pins should follow the newest Debug tags.
- A pending intermediate run may be superseded by a newer tag. Publication is not transactional: a failed update can leave the tag, notes and assets inconsistent until the release job is re-run.
- All Debug workflows share a concurrency group with `cancel-in-progress: false`, so a new push does not interrupt a running publication. `contents: write` stays confined to the publication job; formal `v*` publication remains independent.

### Release process (standing convention)

- **Versions:** SemVer, `vMAJOR.MINOR.PATCH` with an optional `-alpha.N`, `-beta.N` or `-rc.N` suffix. `[workspace.package] version` in `Cargo.toml` is the only source: bump it (and `Cargo.lock` and `crates/honk-ebpf/Cargo.lock`) in a pull request, then tag `v<that version>` on the merged `main` tip once its branch CI is green. The test job runs `.github/ci/check-release-version.sh` and fails a tag that is not SemVer or differs from the manifest. A tag with a suffix publishes as a prerelease. Tags from before this scheme (`v0.0.1.beta.N`) stay as they are; never move or delete a published tag.
- **Draft:** the tag creates a draft Release. Nobody outside the repository sees it until the maintainer publishes it.
- **Notes:** `.github/ci/release-notes.sh` writes the draft body from the commits since the previous `v*` tag, followed by the `## Downloads` section from `.github/ci/release-assets.sh`:

    ```markdown
    ## Highlights

    <!-- Maintainer: two to five bullets on what this release means to a gateway operator. -->

    ## What's Changed

    ### New Features

    - <subject> by @<github-author> in <short-hash>

    ### Bug Fixes / ### Performance / ### Documentation

    **Full Changelog**: https://github.com/daeuniverse/honk/compare/<prev-tag>...<tag>

    ## Downloads
    ```

    - Commits are grouped by their `type(scope)` prefix: `feat` → New Features, `fix` → Bug Fixes, `perf` → Performance, `docs`/`bench` → Documentation; other types are counted, not listed.
    - Authors are GitHub logins from `gh api repos/daeuniverse/honk/commits/<sha> --jq .author.login`, never raw git `Author:` names; a commit without a login is listed without one.
- **Publish:** the maintainer replaces the Highlights comment, adjusts entries if needed, checks the assets against the build, then publishes with `gh release edit <tag> --repo daeuniverse/honk --draft=false` or **Publish release** in the web UI.

- **Deployment:** after tagging, use the canonical musl mimalloc gateway tarball. Note development/manual `scp` deployments in the PR/issue of record when they differ from release artifacts.

