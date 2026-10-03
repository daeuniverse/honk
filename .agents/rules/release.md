### CI / releases

Read with: `AGENTS.md` (Current validation guidance, the workspace gate); `deployment.md` for what the tarballs are for; skill `honk-release` for the tag-to-release sequence.

`.github/workflows/ci.yml` selects lanes once in `changes` and records the decision in `ci-report-selection`. Code pull requests run fmt + clippy, workspace nextest, the `honk-core --features ebpf --tests` compile guard and offline documentation links; prose-only pull requests run links and mechanical review. The eBPF path filter or `ci:ebpf` label adds the floor-kernel VM gate. `ci:full` adds every lane even on prose-only pull requests, including the recent-kernel VM gate, native aarch64 nextest, independent feature checks and the x86_64 musl core/toolbox build with toolbox startup. Failed change detection runs all lanes rather than hiding coverage. Pushes to `main`/`dev` run everything. Manual runs always check code and docs; `ebpf` or `full` enables the floor gate, and `full` enables heavy lanes (both inputs default true).

Every code pull request runs the userspace routing goldens (`routing::golden::*`, including the parsed dae-expression tables) as a named `test`-lane step before workspace nextest, failing if the filter selects nothing. The eBPF path filter also covers the routing compiler (`crates/honk-core/src/routing/**`) and `honk-config`'s routing schema/parser, so rule-semantics changes replay those tables against the real routing-test object in the floor-kernel VM gate.

The `features` lane also runs the outbound `feature_boundary` integration target and the `honk-tool` suite with `cargo test --no-default-features`, each in a separate Cargo invocation so workspace feature unification cannot hide `rprx`-off cases. Exact nonempty test-list checks require both no-backend regressions before execution; this lane uses plain Cargo rather than nextest.

Workspace lint and nextest explicitly enable `honk-core/native-ui` (which includes `native-api`) so ordinary code CI covers the opt-in native API and embedded UI alongside the default-on Clash API feature. Both API listeners still require configuration. The independent `features` lane checks native-only, native+Clash and native-ui builds, requires nonempty authentication/coexistence/embedded-UI selections, and executes native-only HTTP regressions, cross-token isolation and embedded-UI HTTP coverage separately. Native-api-only coverage retains embedded-UI rejection. Release allocator variants share explicit `clash-api,ebpf,rprx,native-ui` capabilities (`native-ui` includes `native-api`) and differ only by `mimalloc`. Every job that enables `native-ui` first runs `ci/fetch-doona.sh`, which downloads the doona release pinned in `.github/ci/pins.env`, checks its SHA-256 and exports the directory as `HONK_DOONA_DIR`; the repository vendors no doona files.

The `parser` lane compares config corpus inputs against the pinned dae Go oracle and replays saved fuzz inputs on stable Rust. Its filter covers `honk-config`, `tools/dae-parse`, `fuzz`, corpus source documents and shared build inputs. Dialect-only PRs select parser and docs without selecting workspace code lanes; `ci:full`, failed change detection, pushes and manual CI runs also select parser. Its timeout is eight minutes, and `ci-report-parser` carries conformance/replay counts and the first failing case/path.

`.github/workflows/report.yml` joins stage-1 lane artefacts and per-attempt job results into one marker-bearing bot comment on each matching open pull request. `.github/ci/report/fixtures/ordinary.md` extends the agreed fork layout with parser metrics and anchors the renderer's eight byte-for-byte fixtures.

Host suites use `.config/nextest.toml`'s `ci` profile with per-test timeouts and failure JUnit artifacts. Each VM job BTF-checks both objects, installs pinned geo assets, runs the eBPF-feature core unit suite, and invokes `.github/ci/run-vm-gate.sh floor` or `recent` with its tuple from `.github/ci/pins.env`. The guest runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test, root-only network tests and exact real SO_MARK socket tests serially without a job container.
The VM executable build explicitly enables `native-api`; the guest requires a nonempty shared-XUDP lifecycle selection and runs the ignored native lifecycle suite serially. This validates owned mock-command transport cycles separately from real hooks/NFQUEUE/routing tests.

`.github/workflows/weekly.yml` runs Monday at 04:23 UTC or manually. It checks floating stable fmt/clippy/nextest and a floating nightly eBPF build, re-downloads every pinned asset without caches to verify its checksum, and runs `cargo audit` for RustSec advisories. Ordinary CI has no weekly schedule; drift failures do not automatically open issues.

Its `public-vless-loopback` job uses the repository-pinned compiler and checksum-pinned official Xray/sing-box executables from `.github/ci/pins.env`. It runs exactly the two public ignored `vless_udp` cases and the ignored library case `official_vision_peers_switch_inner_tls_to_direct`, each with `rprx` and the nextest CI profile; missing executables or test selections fail. This is an optional weekly/manual lane, not a normal PR requirement or the legacy external-mask matrix. Low-port/IPv6 setup is restricted to the ephemeral GitHub-hosted runner; no lab credentials or live hosts are used.

The independent weekly `fuzz` job uses the nightly channel from `crates/honk-ebpf/rust-toolchain.toml` and `CARGO_FUZZ_VERSION` from `pins.env`. It runs `document`, `share_link`, and `lexer` sequentially with two workers, 480 seconds per target, a 10-second input timeout and a 2048 MiB RSS limit. The job has a 40-minute timeout and uploads `fuzz-inputs` on success or failure. It keeps `contents: read` and opens no issues.

`.github/workflows/release.yml` on `v*` and `debug.*`: `cargo test --workspace --no-fail-fast` (`cmake` + `libclang-dev` required for boring-sys), then `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl`. Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). The host compiler comes from the root `rust-toolchain.toml`; build eBPF once on the host with `crates/honk-ebpf/rust-toolchain.toml` and pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Each tarball carries doona's `LICENSE`, `LICENSES/`, `NOTICE` and `THIRD-PARTY-NOTICES.txt` under `doona/`, and the release job attaches `doona-source-<version>.tar.gz` from `ci/fetch-doona.sh --source` to every tag release and Debug release (GPL-3.0 section 6). Publish GitHub Release tarballs; formal `alpha`/`beta`/`rc` tags and all Debug builds are prereleases.

Before upload, every x86_64 matrix entry extracts its packaged tarball into a clean temporary directory and runs the nested `honk-core --version`. This covers the loader and early startup for gnu/musl and both allocators, not configuration or datapath behavior. aarch64 artifacts are not executed. Manual release runs keep the same build checks; publication remains restricted to `v*` and `debug.*` tag refs, never branches.

### Debug releases

- Push a source tag such as `debug.2026.9.19.score.1`; the trigger accepts `debug.*` without prescribing a date or component format. It runs the same tests and eight release-profile builds as formal tags.
- Before publishing, `.github/ci/check-debug-artifacts.sh` requires all eight expected tarballs to be regular, nonempty files. Missing or empty inputs fail without publishing. The release test job runs `.github/ci/test-debug-artifacts.sh` against the same check.
- Each source tag gets its own release, titled with the tag, at `/releases/tag/<tag>`. Earlier Debug releases are never moved or overwritten. Every Debug release is a prerelease with `make_latest: false`; notes identify the source tag, commit and workflow run.
- Assets keep the fixed `honk-core-debug-<target>[-stock].tar.gz` names inside each release. Re-running the same tag replaces that release's attachments only. Retrying only the release job requires all build artifacts to remain available; if any have expired (one-day retention) or been deleted, use **Re-run all jobs** to rebuild the complete set.
- All Debug workflows share a concurrency group with `cancel-in-progress: false`, so a new push does not interrupt a running publication. `contents: write` stays confined to the publication job; formal `v*` publication remains independent.

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

