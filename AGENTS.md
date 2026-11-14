# AGENTS.md — honk

Agent guide to understanding, building, testing, and modifying honk. Repository layout/conventions last verified against the tree on 2026-08-09.

A rule is in force only while it is in context: re-read this file and the routed rules file when a conversation grows long or context is trimmed. Claims rest on current code and command output, not on memory or resemblance.

<!-- task-routing:start -->
## Task routing

| Doing | Read first |
|---|---|
| any change | this file; also `.agents/skills/honk-change/SKILL.md` (the loop every PR here follows) |
| honk-config, honk-tool, `doc/*/reference`, `dialect.md`, or a core/outbound consumer of `Config`, `Node`, `derive_id`, group filters, DNS routing | `.agents/rules/configuration.md`; skill [`honk-config-change`](.agents/skills/honk-config-change/SKILL.md) |
| outbound protocols and transports (gRPC, XHTTP, VLESS runtime, shared UDP sources), TCP/UDP connection establishment | `.agents/rules/outbound.md` |
| group policy, Score, health or traffic feedback into Score | `.agents/rules/score.md` |
| native API server, observation (`crate::observe`), log targets | `.agents/rules/native-api.md` |
| kernel/userspace ABI, marks, netns, NFQUEUE, token states, or any item under Runtime invariants | `.agents/rules/datapath.md` |
| real-kernel or eBPF work, `crates/honk-ebpf*`, `crates/honk-core/src/ebpf/`, mock-eBPF development | `.agents/rules/real-ebpf.md`; skill [`honk-real-ebpf-tests`](.agents/skills/honk-real-ebpf-tests/SKILL.md) |
| placing or finding tests, benchmarks | `.agents/rules/test-locations.md` |
| releases, CI workflows | `.agents/rules/release.md`; skill [`honk-release`](.agents/skills/honk-release/SKILL.md) |
| deployment, security-sensitive paths | `.agents/rules/deployment.md`, `.agents/rules/security.md` |
| reviewing a change | `.agents/rules/review.md` |
| REALITY / xtls interop verification against live servers | `.agents/rules/maintainer-lab.md` (the maintainer's lab; not required for contributions) |
<!-- task-routing:end -->

Maintaining this guide: a rule that binds every change goes in this file; a subsystem's reference goes in its `.agents/rules/` file, in the section it belongs to. A new rules file gets a row in the routing table, and every file the table sends the reader to exists. `.agents/tools/` describes the one-time extraction and is not re-run on later edits. The CI mechanical review drops its documentation reminder when either `AGENTS.md` or `.agents/rules/` changes alongside code. Success signal for an edit here: the CI `docs` job (`lychee --offline --include-fragments` over `*.md`, `.agents/**/*.md`, `doc/**/*.md`, `changes/*.md`) passes.

## Project overview

`honk` is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath and configuration surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API). It is not a line-for-line port of either: the kernel path uses TC hooks with a restricted native-BPF routing policy compiled from userspace, while the userspace outbound/control stack follows sing-box-oriented designs.

- `honk-core` intercepts via TC redirect and userspace proxy relay. Ambiguous LAN UDP uses default-on NFQUEUE 320 when prerequisites pass (`global.nfqueue_enable: false` disables; see `.agents/rules/configuration.md`). Its owned nftables table/chain installs no global `iptables` TPROXY rules.
- `honk-config` provides shared types/parsers for original dae `{ section { ... } }`, the primary and only documented config syntax.
- Status: **experimental alpha**. Expect breaking changes.
- License: **GPL-3.0-only**. Repository: <https://github.com/daeuniverse/honk>
- Docs: `README.md` / `README.zh.md` (bilingual overview, feature checklist, TODO list); matching `doc/en/` / `doc/zh/` / `doc/zh-TW/` trees under `doc/`, indexed by `doc/README.md`. Each has `configuration.md`, `design/` (overview/datapath/routing/nfqueue/control-plane/dns/outbound/groups), `reference/` (global/nodes/groups/routing/dns/subscription/assets/experimental/api/cli), and `operations/` runbooks; per-release configuration changes that affect an existing configuration live in `doc/migration/{en,zh}/<tag>.md` (one file per release tag). Lab benchmark tooling, evidence, and bilingual docs live only on `bench`.

## Repository layout

```text
.
├── Cargo.toml / Cargo.lock   # Workspace manifest (release + release-musl profiles)
├── Justfile                  # Day-to-day dev tasks (build, test, run, debug via clash API, cleanup)
├── README.md / README.zh.md  # Bilingual project overview
├── AGENTS.md                 # This file
├── .agents/                  # rules/ (subsystem reference), skills/ (task skills), tools/ (the split scripts); see Task routing
├── LICENSE                   # GPL-3.0-only
├── config.dae                # Full-featured example config (production-leaning)
├── config.min.dae            # Minimal example (good for --mock-ebpf dev)
├── example.dae               # Annotated example (Chinese comments)
├── doc/                      # en/ + zh/ doc trees: guide, design/, reference/, operations/; migration/{en,zh}/<tag>.md
├── ci/                       # zigcc/zigcxx: zig cc/c++ wrappers for cross builds (strip CMake's clang-style --target from boring-sys ASM rules + rustc's aarch64 errata linker args; used by build-musl and the release workflow); zig-bindgen-env: derive BINDGEN_EXTRA_CLANG_ARGS from `zig cc -E -v` for cross bindgen
├── .github/workflows/        # release.yml: tag-triggered test + cross-build + GitHub Release
└── crates/
    ├── honk-config           # Config schema + dae-syntax parser + share links (workspace member)
    ├── honk-ebpf-common      # no_std shared eBPF/userspace types (workspace member)
    ├── honk-nfqueue          # Raw-netlink NFQUEUE 320 + owned nftables table/chain (workspace member)
    ├── honk-outbound         # Proxy handlers, groups, health checks (workspace member)
    ├── honk-core             # eBPF proxy engine, library + `honk-core` binary (workspace member)
    ├── honk-tool             # `honk-tool` CLI toolbox: `sub` subscription/node probing (workspace member)
    └── honk-ebpf             # Kernel eBPF programs (EXCLUDED from workspace, own Cargo.lock)
```

Notable absences (referenced by older docs but **not in this tree**): `Makefile`, `scripts/`, `plan.md`, `run_tests.sh`, `test-honk.sh`, `log/`, and the vendored reference checkouts (`honk/`, `outbound/`, `sing-box/`; these paths are `.gitignore`d). The old `run` / `deploy` / `docker*` recipes were removed with those missing files; use `run-debug`, `run-dae`, and `deploy-vyos`. Those recipes called `scripts/debug-local.sh` / `scripts/deploy-gateway.sh` and an earlier `Dockerfile` / `docker-compose.yml`; today's root `Dockerfile` repackages a published release (`.agents/rules/deployment.md`). `test-routing` and its dependent `test-netns` share one complete disposable-VM gate; prepare its toolchain, objects and environment through `honk-real-ebpf-tests`, which keeps root-cgroup hooks inside the VM.

## Technology stack

- **Language:** Rust, edition 2024 (workspace-wide, including the eBPF crate).
- **Async runtime:** Tokio (`full`).
- **Allocator:** default-on `jemalloc` feature makes **jemalloc** global in shipped `honk-core`; musl malloc is slow under contention. `tikv-jemallocator` builds jemalloc from C source through the `cc` crate, so the musl cross builds use the same `ci/zigcc`/`ci/zigcxx` wrappers as boring-sys and need no CMake. Linux `main.rs` disables process transparent huge pages before Tokio, builds the runtime explicitly, and dispatches the top-level future onto a worker. jemalloc returns unused pages on its own decay schedule, so there is no worker park hook, idle sweep or allocator environment variable. `MALLOC_CONF` is ignored because the crate prefixes jemalloc symbols and the environment variable with `_rjem_`; use `_RJEM_MALLOC_CONF` for runtime tuning.
- **eBPF:** userspace [aya](https://github.com/aya-rs/aya) 0.16 (optional `ebpf` feature in `honk-core`); kernel side `aya-ebpf` 0.3 targeting `bpfel-unknown-none` (nightly + `-Zbuild-std=core` + `bpf-linker`).
- **NFQUEUE:** `honk-nfqueue` uses raw `NETLINK_NETFILTER` for one fixed queue and its nftables transaction; no libnetfilter_queue/libmnl/libnftnl or firewall subprocess.
- **HTTP APIs:** axum 0.8 + tower-http 0.7. Default-on `clash-api` enables WebSockets; independent opt-in `native-api` (build with `--features native-api` or `native-ui`; release builds include it) owns Hyper HTTP/1.1 and observation, config, probe, DNS, lifecycle and source-owned management, with its listener disabled until configured. Limits, ownership, observation and the embedded UI: `.agents/rules/native-api.md`. Config/auth: `.agents/rules/configuration.md`, `.agents/rules/security.md`.
- **QUIC:** quinn 0.11 (TUIC/Juicity/Hysteria2 outbounds, DoQ/DoH3 DNS); congestion `bbr` builds the fork's BBRv3 or quinn's original BBR per `HONK_QUIC_BBR` (`quic.rs::congestion_factory`), and Brutal drives the fork's rate pacer through `pacer_rate`; `h3`/`h3-quinn` for DoH3 only — Hysteria2 ships its own minimal HTTP/3+QPACK layer. Core opts into h3's third-party-backend error visibility so DNS can distinguish typed endpoint loss from deterministic H3 response errors without parsing text. Keep that version-sensitive inspection private in `dns/transport/quic.rs`; upgrades must retain its failure-scope regression.
- **TLS:** [boring](https://github.com/cloudflare/boring) 5.2.0 + tokio-boring 5.2.0 for proxy/DNS TCP TLS and QUIC via custom `quinn_proto::crypto` in `honk-outbound/src/quic/boring.rs`; webpki-root-certs CA roots. rustls supplies loopback wire interop tests and preserves the existing platform-verifier policy for HTTP downloads only. boring-sys builds BoringSSL from source with `cmake`, C compiler, `libclang` (bindgen). Pin all three Boring crates to 5.2.0; patch boring-sys to `https://github.com/Glassyiris/boring-sys`, revision `3beb573b65ecaa69b7eefe3c2fecd074b97facd2`, branch `boring-sys-5.2`. The fork adds REALITY-required `SSL_set1_client_x25519_private_key` and `SSL_set_client_hello_fixup_cb`. Rebase it before upgrading the stack.
- **Persistence:** rusqlite 0.40 (`bundled`) for the state db (`state.rs`, `<data_dir>/state/honk.db`): the `--store db` revisions (`native_api/store/db.rs`), the runtime-state cache tables (`state/cache.rs`), subscription bodies (`subscription/store.rs`), the password-mode administrator (`native_api/auth.rs`) and the geodata sources (`native_api/geodata/sources.rs`); each except the revisions and the geodata sources imports its pre-state-db file once.
- **Serialization:** serde, toml 1, serde_json, serde_yaml.
- **Logging:** tracing + tracing-subscriber (`env-filter`, `json`); also `log`. Levels: Code style guidelines; quiet targets and `RUST_LOG` precedence: `.agents/rules/native-api.md` (Logs).
- **HTTP downloads:** marked TCP or a routed tunnel + Hyper HTTP/1 + tokio-rustls/platform verifier for subscriptions, geodata and external UI downloads (one GET in `marked_http`); reqwest 0.13 supplies URL types and API test clients. Keep platform CA roots and SAN validation, redirect credential stripping, proxy authentication precedence, body caps and cancellation-owned connection drivers.
- **Error handling:** anyhow + thiserror 2.
- **Misc:** socket2, ipnet, aho-corasick, lru, dashmap, parking_lot, h2 0.4 (urltest probes + DoH), tokio-tungstenite (WS transport), zip (external-UI download only), libsystemd (only `sd_notify`), nix (POSIX/Linux syscall wrappers), aes-gcm/chacha20poly1305/blake3/sha1/sha2/hmac/hkdf/md-5.
- **Dev/test:** tempfile, tokio-test, rcgen 0.14, tokio-tungstenite, criterion 0.8 (DNS and UDP benchmarks).

See [design docs](doc/en/design/overview.md).

## Build and test commands

### Rust workspace

```bash
cargo check
cargo build --release                 # whole workspace (needs cmake + C compiler + libclang for boring-sys)
cargo build --release -p honk-core    # engine (default features: clash-api, jemalloc, rprx; mock eBPF)
cargo test --all                      # full suite (see current validation guidance below)
```

The root `rust-toolchain.toml` pins the host compiler; `crates/honk-ebpf/rust-toolchain.toml` pins the eBPF compiler and components. Real-eBPF and standalone eBPF builds: `.agents/rules/real-ebpf.md`. CI and releases consume the same files: `.agents/rules/release.md`.

### Justfile (preferred for day-to-day dev)

| Recipe                                                                          | Purpose                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build` / `check` / `lint` / `fmt` / `fmt-check`                                              | `cargo build --release` / `check` / `clippy --all --all-targets --features honk-core/native-ui,honk-core/dns-syslog,honk-core/udp-bench,honk-core/dns-bench -- -D warnings` / `fmt --all` / `fmt --all -- --check`                                                                                                                                  |
| `test-routing` | Complete pre-provisioned floor-kernel VM gate, including compiled routing goldens and failed-publication preservation; prerequisites in `honk-real-ebpf-tests` |
| `test` / `test-ci` / `test-core` / `test-config` / `test-ebpf` | Test suites (`test` = full workspace; `test-ci` = nextest CI profile with `honk-core/native-ui,honk-core/dns-syslog`, per-test timeouts and JUnit; `test-core` = core + outbound unit/integration tests; `test-config` = config unit/integration tests; `test-ebpf` = honk-ebpf-common only) |
| `test-netns` | Depends on `test-routing`, sharing its single disposable-VM run of routing, real NFQUEUE/eBPF, ownership, lifecycle and exact SO_MARK tests |
| `outbound-ci` / `outbound-ci-e2e`                                               | honk-outbound gate (`ci/outbound-ci.sh`: fmt + clippy + honk-config & honk-outbound suites; `...-e2e` adds live hy2 e2e via `HONK_HY2_SERVER=`) — run after every outbound change                                                            |
| `dns-ci`                                                                        | DNS subsystem gate (`ci/dns-ci.sh`: fmt + clippy + honk-config + honk-core dns/control + honk-outbound suites) — run after every DNS-path change                                                                                             |
| `build-core` / `build-core-ebpf`                                                | honk-core with `ebpf` feature                                                                                                                                                                                                                |
| `build-musl` / `build-musl-embedded-ui`                                         | Static musl build (`x86_64-unknown-linux-musl`, for VyOS/Debian) via the `ci/zigcc`/`ci/zigcxx` zig wrappers + `link-self-contained=no` (needs zig 0.14+); takes a `features` argument (default `ebpf,native-api`); `-embedded-ui` fetches the pinned doona unless `HONK_DOONA_DIR` is set and builds `ebpf,native-ui` |
| `build-ebpf`                                                                    | eBPF object standalone (nightly, `bpfel-unknown-none`) — warns when `RUSTFLAGS` is set (it overrides the crate's `--btf` rustflags) and verifies the object actually has `.BTF` (aya refuses BTF-less objects)                               |
| `run-debug`                                                                     | Build with ebpf, clean previous state, run with `config.dae` + external object                                                                                                                                                               |
| `run-dae`                                                                       | Run with `config.dae` + `--mock-ebpf`                                                                                                                                                                                                        |
| `debug-status` / `debug-config` / `debug-alive` / `debug-stats` / `watch-debug` | Query the clash HTTP API on :9090 (`/version`, `/configs`, `/proxies`, `/group/{n}/delay`, `/stats`, `/connections`)                                                                                                                         |
| `bpf-progs` / `bpf-maps`                                                        | Inspect loaded BPF programs and pinned maps                                                                                                                                                                                                  |
| `deploy-vyos HOST=...`                                                          | musl build + scp to a VyOS router                                                                                                                                                                                                            |
| `clean` / `clean-all`                                                           | `cargo clean` / stop honk-core, remove `dae0`/`daens`, ephemeral BPF pins and policy routes while preserving `UDP_DECISION_SEQUENCE`                                                                                                         |
| `cycle`                                                                         | `clean-all` + `build-core`                                                                                                                                                                                                                   |
| `watch-core`                                                                    | `cargo watch` rebuild                                                                                                                                                                                                                        |

`outbound-ci` runs all-target Clippy and crate test suites in separate `rprx`-off and `rprx`-on invocations; the config suite runs once. The weekly/manual `public-vless-loopback` lane separately runs the two public ignored `vless_udp` official-peer cases, the ignored official Vision uplink Direct case and the ignored shared-source sing-box matrix with pinned executables, not the legacy external-mask test.

## Current validation guidance

Repository status is current command output and CI; dated pass counts are history. `just test-routing` and `just test-netns` use the same complete pre-provisioned disposable-VM gate. Prepare the `routing-test` object, toolchain and VM environment as `honk-real-ebpf-tests` documents; that skill also names the host shortcuts that do not count as running the gate.

DNS syslog auditing is a default-off `dns-syslog` feature, independent of API
features. Builds without it use zero-sized audit hooks and reject enabled audit
at startup. Wire contract: `doc/en/design/dns-syslog.md`; implementation rules: `.agents/rules/configuration.md`.

`just test-ci` requires `cargo-nextest` and selects `.config/nextest.toml`'s `ci` profile: no retries, a three-minute per-test timeout and no fail-fast. JUnit is written to `target/nextest/ci/junit.xml`; CI uploads it on failure. Plain `cargo test` remains supported.

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets --features honk-core/udp-bench,honk-core/dns-bench -- -D warnings
```

Group-policy/scorer changes should run `cargo test -p honk-config group_policy`, `cargo test -p honk-outbound group::score`, and focused core Score/Clash tests before the workspace gate (Score needs no feature flag).

For UDP, run focused `honk-outbound` SOCKS5/group, `honk-nfqueue` parser/verdict/rule,
and `honk-core` control/NFQUEUE/token-transition/endpoint/reload/warm-up/Clash `/stats`
tests before the workspace gate. Held-packet changes also require `just test-netns`:
only the ignored root NFQUEUE test proves real nftables/queue/verdict semantics,
not the unprivileged suite. Deployment A/B needs real eBPF/netns/upstreams and the
`bench` lab harness. TLS backends and the HTTP-download exception: Technology stack.

`routing::tests::test_geosite_*` need `geosite.dat`/`geoip.dat`. Both tests call `use_repo_geo_assets()`, which points `DAE_LOCATION_ASSET` at the checkout root, so files at the top of the checkout are the quickest local setup; otherwise the loader falls through the documented geo asset search order, which is how CI's `/etc/dae` install works, and the tests fail for a reason unrelated to the change under test.
Unset `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` so HTTP clients fetch loopback addresses directly.
The maintainer's REALITY interop lab: `.agents/rules/maintainer-lab.md` (not required for contributions); it also records the REALITY lab peer's target-record limit.

## Change workflow

The steps live in skill `honk-change`; this section sets how deep each step goes.

### Risk classes

| Class | Covers | Plan | Proof | Review |
|---|---|---|---|---|
| Low | docs, tests only | the commit message | the checks of the touched area (link check, the changed tests run) | read your own diff |
| Medium | config, features a human assigns, and the refactors and tests `CONTRIBUTING.md` §3 allows an agent to originate, all outside §2 | a short plan, reviewed before code | tests for the changed behaviour, plus the impact inventory | a reviewer with fresh context |
| High | `CONTRIBUTING.md` §2 areas, any invariant named in this file (Runtime invariants and the sections it links), hot-path performance | a written plan, reviewed before code | a test that fails without the fix, every behaviour hunk ablated, and the VM gate (`just test-netns`) when the change reaches eBPF, NFQUEUE, held packets or routing | `CONTRIBUTING.md` §6 deep review |

When unsure, take the higher class. `CONTRIBUTING.md` §2 changes must be originated by a human, unless the §11 domain-expert exception applies; an agent may analyze, review and suggest there. Signal: the plan and the PR's Verified section name the class and the proof that ran.

### Diagnosis

- **Read to the end of the path before describing a defect.** The trigger, the consequence, and the absence of a thing are each bounded by code you have not opened yet: the callee, the caller, the consumer that clamps the value, the search that would have settled it.
- **Fix where the paths converge**, not where you first saw the failure: a guard on one loader leaves its siblings failing open.

### Ablation

A multi-hunk change proves each behaviour hunk: revert that hunk alone, run the covering tests and watch one fail. High ablates every behaviour hunk. Low and Medium ablate each one or list the unablated hunks in the PR's Verified section. Docs, comments and pure moves have no behaviour hunk; say so instead.

### Flaky tests

A flaky test is red. Fix it, or quarantine it (ignored, with a reason naming an owner and a date) in the PR that found it. CI does not retry: `.config/nextest.toml`'s `ci` profile has no retries, and it stays that way.

### Checks and gates

- **A check that could not run did not pass.** If a gate is missing, errors, or produces no output, say so; empty output reads exactly like a clean run.
- A new check or gate script proves itself before it guards anything: it fails on a planted violation and fails when its selection scans nothing, as `ci/run-exact-ignored-tests.sh` and the routing-golden CI step do. Exit codes: 0 clean, 1 violation found, 2 could not run.

### Performance baselines

Hot-path changes (dial, relay, Shadowsocks/VLESS streams, DNS, reload) carry a before/after measurement on the same host with its load recorded. Repeat the runs before calling a difference real. Harnesses and their run rules: `.agents/rules/test-locations.md` (Benchmarks); lab and deployment harnesses live on branch `bench`.

### Stop points

Stop and ask before touching an area `CONTRIBUTING.md` §2 reserves, before anything leaves the machine, and before discarding work someone else may want; otherwise continue.

## Code style guidelines

- Rust source files carry no SPDX/copyright headers; licensing and attribution live in the root `README.md`/`LICENSE`.
- Prefer `anyhow::Result` for application/binary code and `thiserror` for library error types.
- Use `tracing` macros for logging; prefer structured fields (`info!(network = "tcp", outbound = %name, ...)`). Levels follow frequency × actionability: ERROR only when configured function is lost until an operator acts (committed-degraded activation, process exit, permanent subsystem death, invariant breach); WARN once per entered degraded state (fallback, ceiling, node/group unavailable, rejected candidate with the old config intact); INFO for low-rate lifecycle, operator outcomes and recovery; DEBUG for single connection/request/query outcomes and periodic maintenance. Log a failure once, at the layer that owns its stats/Score/recovery; repeat a persisting state at DEBUG, not per tick. A failure that repeats per query with no episode boundary (DNS SERVFAIL, singleflight saturation) uses `logging::warn_throttled!`: WARN at most every 10 s per site. Native `/api/v1/logs`, Clash `/logs` and the console all receive these levels.
- Use `tokio` async/await and `tokio::select!` for long-lived loops.
- Kernel/userspace structs belong in `honk-ebpf-common`; follow its stable `#[repr(C)]` layout and coordinated `honk-ebpf`/`honk-core` map-writer change rules.
- Follow `cargo fmt --all` and keep `just lint` (all targets with `honk-core/native-ui,honk-core/udp-bench,honk-core/dns-bench`) and `cargo clippy --workspace --all-targets --no-default-features --features honk-core/udp-bench,honk-core/dns-bench -- -D warnings` clean.
- Match the surrounding file's idioms; make minimal, scoped changes (no opportunistic cleanups).

## Commits and pull requests

- **Commits:** `type(scope): one short imperative line`: `feat|fix|refactor|perf|test|docs|style|bench(<area>)`, no body, no markdown. Each commit stands alone and leaves the tree building; multi-part work is more commits, and fixups are squashed before pushing rather than pushed.
- **Changelog:** a PR touching `crates/`, `Cargo.toml`, `Cargo.lock`, `ci/fetch-doona.sh` or `.github/ci/pins.env` adds `changes/<branch-slug>.md`; format and exemptions are in [changes/README.md](changes/README.md). CI fails without it unless a maintainer applies the `no-changelog` label.
- **PR bodies:** English or Simplified Chinese, one short paragraph under each of `## Problem / 问题`, `## How I fixed it / 解决方法` and `## Verified / 验证`, in that order: what is wrong, what changed, what was checked. Follow the single bilingual `.github/pull_request_template.md` and link long evidence instead of pasting it. Start the pull request body from that template, also when you open it with `gh pr create --body` or the API, which leave it empty. Keep its checklist, check only true boxes, and check exactly one of its two AI-disclosure boxes (`CONTRIBUTING.md` §5). For an outside contributor, `template-check` closes a pull request that drops a required box, does not check exactly one of the two AI boxes, or checks the unread or AI-agent box, and reopens it once the body is fixed.

## Writing

Applies to code comments, docs, PR and issue text.

- **Lead with the result.** One point per sentence; no introduction or recap paragraphs.
- **Claims need their line.** A consequence stated in a PR or an issue names the code producing it, or is narrowed until it can; say what you did not check. Line numbers come from `origin/main`, not your working tree.
- **Label the unverified.** Mark anything not run or not read as such (for example `not run:` in Verified) rather than leaving it implied.
- **Comment discipline: readable code; comments explain "why", the code says "what".** Allow module `//!` purpose/non-obvious architecture, public-item `///`, and short rationale/invariant/wire-format/upstream-parity/past-bug comments. Narrating/restating code is a defect. Ordinary logic should have near-zero comments (see `crates/honk-core/src/dns/runtime.rs`); prefer descriptive names/small functions. **Before closing each work phase, review touched comments and delete/rewrite stale behavior descriptions**; stale comments are defects.
- **Language:** code comments and `doc/en/` docs are English; user docs are bilingual (`README.zh.md`, `doc/zh/`); update both when you change documented behavior. Chinese docs use Simplified Chinese, one script per document, with a space between Chinese and Latin letters or digits. `doc/zh-TW/` is the Traditional Chinese (Taiwan) copy of `doc/zh/` that daeuniverse.org serves; after changing `doc/zh/`, carry the same change into `doc/zh-TW/` with Taiwan wording.

## Testing instructions

- **A new test must fail without the change.** Remove the production hunk, run it, read the failure; a test that passes either way is not evidence. Read what already covers the behaviour first; several deliberate oddities here are pinned by one test (see Intentional designs). A deletion needs no test of its own. Multi-hunk changes: Change workflow, Ablation.
- **Say which gates you ran and which you did not.** Running a subset is fine; reporting no limits after running a subset is not.
- A flaky test counts as a failure: Change workflow, Flaky tests.
- `cargo test --all`: unprivileged default workspace unit/integration suites using mock eBPF/loopback where appropriate. `just test-routing` and dependent `just test-netns` share the full isolated floor-kernel VM gate, including routing goldens, failed-publication preservation, real NFQUEUE/eBPF and guarded root-cgroup fixtures.
- Test locations: `.agents/rules/test-locations.md`.
- Older standalone netns/podman scripts mentioned in stale docs are absent; use the supported `just test-netns` gate above.

## Intentional designs

Behaviour that looks like a defect but is deliberate. Reviewers skip these unless the change alters them; a change that does alter one says so in its plan.

| Behaviour | Reason | Ruling source |
|---|---|---|
| Direct eBPF offload traffic is not counted in stats | performance | maintainer, 2026-10-04 |
| VLESS permits UDP/443 by default, including base Vision | users block QUIC through routing | `.agents/rules/configuration.md` |
| VLESS Auto keeps native UDP on 53/443 without Vision instead of Single XUDP | Single XUDP measured about half the goodput and 1.9-3.3× the CPU per MB | `.agents/rules/outbound.md` (UDP transport invariant) |
| A dead outbound drops new flows; there is no implicit `direct` fallback | fail-closed | Runtime invariants: Fail-closed on dead outbounds |
| Real LAN self-protection only warns; it rejects no configuration and synthesizes no rules | advisory, not a connectivity guarantee | `.agents/rules/configuration.md` (Interface modes) |
| Native probes, geodata and shared downloads have no address or port allowlist | whoever writes the configuration or controls subscription content decides those targets; provider content is trusted configuration | `.agents/rules/configuration.md`, `.agents/rules/security.md` |
| Listener-secret values shorter than eight bytes are neither masked nor refused | not recorded | `.agents/rules/security.md` (Native source writes) |
| A partial multi-asset geodata replacement is reported, not rolled back | after rename the new bytes are visible, so no rollback is claimed | `.agents/rules/security.md` (Native entry management) |
| `MALLOC_CONF` has no effect; `_RJEM_MALLOC_CONF` tunes jemalloc | the crate prefixes jemalloc symbols and the variable | Technology stack |
| Default logs silence `quinn::endpoint` | its driver-death ERROR duplicates the failure honk reports with context | `.agents/rules/native-api.md` (Logs) |
| `honk-core proxy <group> <node>` persists nothing; `delay` times raw TCP | local-only commands that do not talk to the running engine | `.agents/rules/configuration.md` (CLI) |
| `just test-routing` runs the complete VM gate, same as `test-netns` | routing contains root-cgroup cases | `.agents/skills/honk-real-ebpf-tests/SKILL.md` |

## Notes for agents

Configuration contracts (settings, dialect, `honk-tool`): `.agents/rules/configuration.md`. Deployment and security-sensitive paths: `.agents/rules/deployment.md`, `.agents/rules/security.md`.

- Choose commands for the owning crate: workspace `cargo` skips `honk-ebpf`, which has separate `Cargo.lock` and nightly-only target.
- Before behavior changes, read `doc/en/design/overview.md` and subsystem siblings in `doc/en/design/`, plus config guide/reference `doc/en/configuration.md` / `doc/en/reference/`. Update both `doc/en/` and `doc/zh/` for behavior changes.
- If you add or remove workspace crates, update this file and the root `Cargo.toml` `[workspace] members` list.
- README authorship disclosure: the maintainer focuses on eBPF; most userspace subsystems were largely AI-authored with partial review. Review userspace changes accordingly.

### Runtime invariants

Each item is an invariant named in this file for the High risk class and `CONTRIBUTING.md` §6. Its full contract lives in the linked section, which carries the same status as text in this file; a change to any of them is High.

- Datapath, full text in [`.agents/rules/datapath.md`](.agents/rules/datapath.md#runtime-invariants):
  - **Kernel/userspace ABI:** layouts, map key sizes, marks, state transitions and statistics keys change together across `honk-ebpf-common`, `honk-ebpf`, `honk-core` and their consumers ([Kernel and userspace ABI](.agents/rules/datapath.md#kernel-and-userspace-abi)).
  - **Bypass mark:** originated sockets and transparent listeners carry the exact effective `global.so_mark_from_dae`.
  - **Anyfrom UDP replies:** replies keep original-destination addressing and leave transparent TPROXY listeners out of the reply path.
  - **Netns discipline:** `daens` is entered only through scoped synchronous `daens::with_daens_netns`, with no `.await` inside.
  - **Datapath admission:** admission opens after every internal hook, listener and queue is ready, and closes before listener teardown.
  - **NFQUEUE readiness and ownership**, **Fragmented LAN UDP53**, **Token-checked terminal state**, **NFQUEUE lifecycle.**
  - **must/block are final:** Clash mode override leaves `block` and `must` results in force.
  - **Fail-closed on dead outbounds** and **group-OR connectivity pushes** with the sole-TCP-leaf exception.
  - **Internal traffic is never proxied; broadcast/multicast passes through eBPF.**
  - **Reserved outbound indices:** `0 Direct | 1 Block | 2+ user groups | 0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND`.
- **UDP transport invariant** and VLESS carrier ownership: [`.agents/rules/outbound.md`](.agents/rules/outbound.md#udp-transport-invariant); gRPC and XHTTP replay no application bytes ([gRPC and XHTTP](.agents/rules/outbound.md#grpc-and-xhttp)).
- **Node identity and group filters:** `Node::derive_id()` is the sole identity source ([configuration](.agents/rules/configuration.md#node-identity-and-group-filters)).
- **Score** evidence, serving pool and currency: [`.agents/rules/score.md`](.agents/rules/score.md).
- **Native observation evidence** is source evidence of what executed, not a reconstruction from current state: [`.agents/rules/native-api.md`](.agents/rules/native-api.md#observation).
