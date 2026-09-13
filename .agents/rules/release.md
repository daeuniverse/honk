### CI / releases

Read with: `AGENTS.md` (Current validation guidance, the workspace gate); `deployment.md` for what the tarballs are for; skill `honk-release` for the tag-to-release sequence.

`.github/workflows/ci.yml` selects lanes once in `changes` and records the decision in `ci-report-selection`. Code pull requests run fmt + clippy, workspace nextest, the `honk-core --features ebpf --tests` compile guard and offline documentation links; prose-only pull requests run links and mechanical review. The eBPF path filter or `ci:ebpf` label adds the floor-kernel VM gate. `ci:full` adds every lane even on prose-only pull requests, including the recent-kernel VM gate, native aarch64 nextest, independent feature checks and the x86_64 musl core/toolbox build with toolbox startup. Failed change detection runs all lanes rather than hiding coverage. Pushes to `main`/`dev` run everything. Manual runs always check code and docs; `ebpf` or `full` enables the floor gate, and `full` enables heavy lanes (both inputs default true).

`.github/workflows/report.yml` joins stage-1 lane artefacts and per-attempt job results into one marker-bearing bot comment on each matching open pull request. `.github/ci/report/fixtures/ordinary.md` preserves the agreed fork comment verbatim and anchors the renderer's eight byte-for-byte fixtures.

Host suites use `.config/nextest.toml`'s `ci` profile with per-test timeouts and failure JUnit artifacts. Each VM job BTF-checks both objects, installs pinned geo assets, runs the eBPF-feature core unit suite, and invokes `.github/ci/run-vm-gate.sh floor` or `recent` with its tuple from `.github/ci/pins.env`. The guest runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test and root-only network tests serially without a job container.

`.github/workflows/weekly.yml` runs Monday at 04:23 UTC or manually. It checks floating stable fmt/clippy/nextest and a floating nightly eBPF build, re-downloads every pinned asset without caches to verify its checksum, and runs `cargo audit` for RustSec advisories. Ordinary CI has no weekly schedule; drift failures do not automatically open issues.

`.github/workflows/release.yml` on `v*`: `cargo test --workspace --no-fail-fast` (`cmake` + `libclang-dev` required for boring-sys), then `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl`. The legacy routing test is ignored in source as described in `AGENTS.md` (Current validation guidance). Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). The host compiler comes from the root `rust-toolchain.toml`; build eBPF once on the host with `crates/honk-ebpf/rust-toolchain.toml` and pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Publish GitHub Release tarballs; `alpha`/`beta`/`rc` tags are prereleases.

Before upload, every x86_64 matrix entry extracts its packaged tarball into a clean temporary directory and runs the nested `honk-core --version`. This covers the loader and early startup for gnu/musl and both allocators, not configuration or datapath behavior. aarch64 artifacts are not executed. Manual release runs keep the same build checks; publication remains restricted to `v*` tag refs.

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

