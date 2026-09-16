# AGENTS.md — honk

Agent guide to understanding, building, testing, and modifying honk. Repository layout/conventions last verified against the tree on 2026-08-09.

Re-read it when a conversation grows long or context is trimmed: a rule read once is not a rule in force. Never substitute memory or resemblance for evidence.

<!-- task-routing:start -->
## Task routing

| Doing | Read first |
|---|---|
| any change | this file; also `.agents/skills/honk-change/SKILL.md` (the loop every PR here follows) |
| honk-config, honk-tool, `doc/*/reference`, `dialect.md`, or a core/outbound consumer of `Config`, `Node`, `derive_id`, group filters, DNS routing | `.agents/rules/configuration.md`; skill [`honk-config-change`](.agents/skills/honk-config-change/SKILL.md) |
| real-kernel or eBPF work, `crates/honk-ebpf*`, `crates/honk-core/src/ebpf/`, mock-eBPF development | `.agents/rules/real-ebpf.md`; skill [`honk-real-ebpf-tests`](.agents/skills/honk-real-ebpf-tests/SKILL.md) |
| placing or finding tests, benchmarks | `.agents/rules/test-locations.md` |
| releases, CI workflows | `.agents/rules/release.md`; skill [`honk-release`](.agents/skills/honk-release/SKILL.md) |
| deployment, security-sensitive paths | `.agents/rules/deployment.md`, `.agents/rules/security.md` |
| REALITY / xtls interop verification against live servers | `.agents/rules/maintainer-lab.md` (the maintainer's lab; not required for contributions) |
<!-- task-routing:end -->

Maintaining this guide: a rule that binds every change goes in this file; a subsystem's reference goes in its `.agents/rules/` file, in the section it belongs to. A new rules file gets a row in the routing table, and every file the table sends the reader to must exist. `.agents/tools/` describes the one-time extraction and is not re-run on later edits. The CI mechanical review drops its documentation reminder when either `AGENTS.md` or `.agents/rules/` changes alongside code.

## Project overview

`honk` is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath and configuration surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API). It is not a line-for-line port of either: the kernel path uses TC hooks with a restricted native-BPF routing policy compiled from userspace, while the userspace outbound/control stack follows sing-box-oriented designs.

- `honk-core` intercepts via TC redirect and userspace proxy relay. Ambiguous LAN UDP uses default-on NFQUEUE 320 when prerequisites pass (`global.nfqueue_enable: false` disables; see `.agents/rules/configuration.md`). Its owned nftables table/chain installs no global `iptables` TPROXY rules.
- `honk-config` provides shared types/parsers for original dae `{ section { ... } }`, the primary and only documented config syntax.
- Status: **experimental alpha** (`v0.0.1-alpha`). Expect breaking changes.
- License: **GPL-3.0-only**. Repository: <https://github.com/daeuniverse/honk>
- Docs: `README.md` / `README.zh.md` (bilingual overview, feature checklist, TODO list); matching `doc/en/` / `doc/zh/` trees under `doc/`, indexed by bilingual `doc/README.md`. Each has `configuration.md`, `design/` (overview/datapath/routing/nfqueue/control-plane/dns/outbound/groups), `reference/` (global/nodes/groups/routing/dns/subscription/experimental/api/cli), and `operations/` runbooks. Lab benchmark tooling, evidence, and bilingual docs live only on `bench`.

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
├── doc/                      # en/ + zh/ doc trees: guide, design/, reference/, operations/
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

Notable absences (referenced by older docs but **not in this tree**): `Makefile`, `scripts/`, `Dockerfile`, `docker-compose.yml`, `plan.md`, `run_tests.sh`, `test-honk.sh`, `log/`, and the vendored reference checkouts (`honk/`, `outbound/`, `sing-box/` — these paths are `.gitignore`d). The old `run` / `deploy` / `docker*` recipes were removed with those missing files; use `run-debug`, `run-dae`, and `deploy-vyos`. Root-gated real-kernel checks are split between `test-routing` for compiled routing and `test-netns`, which depends on it for the remaining integration tests.

## Technology stack

- **Language:** Rust, edition 2024 (workspace-wide, including the eBPF crate).
- **Async runtime:** Tokio (`full`).
- **Allocator:** default-on `mimalloc` feature makes **mimalloc** global in shipped `honk-core`; musl malloc is slow under contention. Aligned 1 GiB arenas decommit purged pages, but fragment-pinned worker heaps linger. Linux `main.rs` disables process transparent huge pages before Tokio, builds the runtime explicitly, and dispatches the top-level future onto a worker. Each owning worker's park callback runs `mi_collect(true)`: OS-thread-local 60s cooldown, delayed first collection. A bounded periodic rendezvous, only when every other worker is idle, wakes owners parked after cross-thread frees so that callback can purge their heaps. `HONK_MI_COLLECT_SECS=0` installs neither hook nor rendezvous.
  Clash `/logs` (`clash_api/logs.rs`) skips formatting without subscribers; its unfiltered tracing layer would otherwise allocate a `String` per sub-level datapath event. Default logs silence `quinn::endpoint`: ERROR-on-driver-death accompanies every retired probe/warm transport (e.g. SYNACK-watchdog kills), so it is lifecycle noise. Valid `RUST_LOG` overrides console/file filtering; Clash `/logs` always excludes this target.
- **eBPF:** userspace [aya](https://github.com/aya-rs/aya) 0.14 (optional `ebpf` feature in `honk-core`); kernel side `aya-ebpf` 0.2 targeting `bpfel-unknown-none` (nightly + `-Zbuild-std=core` + `bpf-linker`).
- **NFQUEUE:** `honk-nfqueue` uses raw `NETLINK_NETFILTER` for one fixed queue and its nftables transaction; no libnetfilter_queue/libmnl/libnftnl or firewall subprocess.
- **HTTP API:** axum 0.8 (with `ws`) + tower-http 0.7 (optional `clash-api` feature of `honk-core`, on by default).
- **QUIC:** quinn 0.11 (TUIC/Juicity/Hysteria2 outbounds, DoQ/DoH3 DNS); `h3`/`h3-quinn` for DoH3 only — Hysteria2 ships its own minimal HTTP/3+QPACK layer.
- **TLS:** [boring](https://github.com/cloudflare/boring) 5.2.0 + tokio-boring 5.2.0 for TCP TLS and QUIC via custom `quinn_proto::crypto` in `honk-outbound/src/quic/boring.rs`; webpki-root-certs CA roots. rustls is **dev/test-only** for loopback wire interop. boring-sys builds BoringSSL from source with `cmake`, C compiler, `libclang` (bindgen). Pin all three Boring crates to 5.2.0; patch boring-sys to `https://github.com/Glassyiris/boring-sys`, revision `3beb573b65ecaa69b7eefe3c2fecd074b97facd2`, branch `boring-sys-5.2`. The fork adds REALITY-required `SSL_set1_client_x25519_private_key` and `SSL_set_client_hello_fixup_cb`. Rebase it before upgrading the stack.
- **Persistence:** rusqlite 0.40 (`bundled`) for the `cachedb` SQLite cache.
- **Serialization:** serde, toml 1, serde_json, serde_yaml.
- **Logging:** tracing + tracing-subscriber (`env-filter`, `json`); also `log`.
- **HTTP client:** reqwest 0.13 (rustls, no default features) — subscriptions.
- **Error handling:** anyhow + thiserror 2.
- **Misc:** socket2, ipnet, aho-corasick, lru, dashmap, parking_lot, h2 0.4 (urltest probes + DoH), tokio-tungstenite (WS transport), zip (external-UI download only), libsystemd (only `sd_notify`), nix (POSIX/Linux syscall wrappers), aes-gcm/chacha20poly1305/blake3/sha1/sha2/hmac/hkdf/md-5.
- **Dev/test:** tempfile, tokio-test, rcgen 0.14, tokio-tungstenite, criterion 0.8 (DNS and UDP benchmarks).

See [design docs](doc/en/design/overview.md).

Outbound source ownership: `proxy/{error,packet,outbound,registry}.rs` retain the public proxy facade; Shadowsocks owns `aead2022`/`stream`, and VLESS owns feature-only `handler`/`encryption` plus `cool`/`mux` backends. Shared UoT, transport and REALITY stay outside VLESS. QUIC owns `path_health`, `flow_control`, `metrics`, `endpoint`, `client`, `stream` and `boring`; the public `quic_boring` facade remains supported. AnyTLS uses `padding`/`writer`/`overflow`, Score uses `evidence`/`ranking`/`feedback`, alive uses `health`/`urltest`, and SessionPool uses `maintenance`/`speculative`; common state stays at each ancestor to avoid widening fields. Normal builds without `rprx` allocate no VLESS pools/carrier semaphores; `cfg(test)` retains backend-only unit coverage, never handler registration.

## Build and test commands

### Rust workspace

```bash
cargo check
cargo build --release                 # whole workspace (needs cmake + C compiler + libclang for boring-sys)
cargo build --release -p honk-core    # engine (default features: clash-api, mock eBPF)
cargo test --all                      # full suite (see current validation guidance below)
```

The root `rust-toolchain.toml` pins the host compiler; `crates/honk-ebpf/rust-toolchain.toml` pins the eBPF compiler and components. Real-eBPF and standalone eBPF builds: `.agents/rules/real-ebpf.md`. CI and releases consume the same files: `.agents/rules/release.md`.

### Justfile (preferred for day-to-day dev)

| Recipe                                                                          | Purpose                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build` / `check` / `lint` / `fmt` / `fmt-check`                                              | `cargo build --release` / `check` / `clippy --all --all-targets -- -D warnings` / `fmt --all` / `fmt --all -- --check`                                                                                                                                                                 |
| `test-routing` | Root-gated compiled-policy check: builds the `routing-test` eBPF object and exercises the real object against independent goldens plus failed root-publication preservation (Linux 6.12+) |
| `test` / `test-ci` / `test-core` / `test-config` / `test-ebpf` | Test suites (`test` = full workspace; `test-ci` = nextest CI profile with per-test timeouts and JUnit; `test-core` = core + outbound unit/integration tests; `test-config` = config unit/integration tests; `test-ebpf` = honk-ebpf-common only) |
| `test-netns`                                                                    | Depends on `test-routing`; root-gated real-kernel tests for production NFQUEUE/nftables IPv4+IPv6 held-verdict contract, eBPF netlink/netns roundtrips, link ownership/rebind lifecycle, and pinned allocator rollback compatibility (`--features ebpf --ignored`, serial) |
| `outbound-ci` / `outbound-ci-e2e`                                               | honk-outbound gate (`ci/outbound-ci.sh`: fmt + clippy + honk-config & honk-outbound suites; `...-e2e` adds live hy2 e2e via `HONK_HY2_SERVER=`) — run after every outbound change                                                            |
| `dns-ci`                                                                        | DNS subsystem gate (`ci/dns-ci.sh`: fmt + clippy + honk-config + honk-core dns/control + honk-outbound suites) — run after every DNS-path change                                                                                             |
| `build-core` / `build-core-ebpf`                                                | honk-core with `ebpf` feature                                                                                                                                                                                                                |
| `build-musl`                                                                    | Static musl build (`x86_64-unknown-linux-musl`, for VyOS/Debian) via the `ci/zigcc`/`ci/zigcxx` zig wrappers + `link-self-contained=no` (needs zig 0.14+)                                                                                    |
| `build-ebpf`                                                                    | eBPF object standalone (nightly, `bpfel-unknown-none`) — warns when `RUSTFLAGS` is set (it overrides the crate's `--btf` rustflags) and verifies the object actually has `.BTF` (aya refuses BTF-less objects)                               |
| `run-debug`                                                                     | Build with ebpf, clean previous state, run with `config.dae` + external object                                                                                                                                                               |
| `run-dae`                                                                       | Run with `config.dae` + `--mock-ebpf`                                                                                                                                                                                                        |
| `debug-status` / `debug-config` / `debug-alive` / `debug-stats` / `watch-debug` | Query the clash HTTP API on :9090 (`/version`, `/configs`, `/proxies`, `/group/{n}/delay`, `/stats`, `/connections`)                                                                                                                         |
| `bpf-progs` / `bpf-maps`                                                        | Inspect loaded BPF programs and pinned maps                                                                                                                                                                                                  |
| `deploy-vyos HOST=...`                                                          | musl build + scp to a VyOS router                                                                                                                                                                                                            |
| `clean` / `clean-all`                                                           | `cargo clean` / stop honk-core, remove `dae0`/`daens`, ephemeral BPF pins and policy routes while preserving `UDP_DECISION_SEQUENCE`                                                                                                         |
| `cycle`                                                                         | `clean-all` + `build-core`                                                                                                                                                                                                                   |
| `watch-core`                                                                    | `cargo watch` rebuild                                                                                                                                                                                                                        |

Removed `run` / `deploy` / `docker*` recipes called absent `scripts/debug-local.sh` / `scripts/deploy-gateway.sh` / `Dockerfile` / `docker-compose.yml` (Repository layout).

`outbound-ci` runs all-target Clippy and crate test suites in separate `rprx`-off and `rprx`-on invocations; the config suite runs once. The weekly/manual `public-vless-loopback` lane separately runs the two public ignored official-peer cases with pinned executables, not the legacy external-mask test.

## Current validation guidance

Do not treat dated pass counts as repository status; use the current command output and CI for that evidence. The compiled-routing gate is `just test-routing`: it builds a real `routing-test` eBPF object and exercises independent policy goldens plus preservation of the active root when publication fails.

`just test-ci` requires `cargo-nextest` and selects `.config/nextest.toml`'s `ci` profile: no retries, a three-minute per-test timeout and no fail-fast. JUnit is written to `target/nextest/ci/junit.xml`; CI uploads it on failure. Plain `cargo test` remains supported.

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
```

Group-policy/scorer changes should run `cargo test -p honk-config group_policy`, `cargo test -p honk-outbound group::score`, and focused core Score/Clash tests before the workspace gate (Score needs no feature flag).

For UDP, run focused `honk-outbound` SOCKS5/group, `honk-nfqueue` parser/verdict/rule,
and `honk-core` control/NFQUEUE/token-transition/endpoint/reload/warm-up/Clash `/stats`
tests before the workspace gate. Held-packet changes also require `just test-netns`:
only the ignored root NFQUEUE test proves real nftables/queue/verdict semantics,
not the unprivileged suite. Deployment A/B needs real eBPF/netns/upstreams and the
`bench` lab harness. Production BoringSSL versus test rustls: Technology stack.

`routing::tests::test_geosite_*` need `geosite.dat`/`geoip.dat`. Both tests call `use_repo_geo_assets()`, which points `DAE_LOCATION_ASSET` at the checkout root, so files at the top of the checkout are the quickest local setup; otherwise the loader falls through the documented geo asset search order, which is how CI's `/etc/dae` install works, and the tests fail for a reason unrelated to the change under test.
Unset `HTTP_PROXY`/`HTTPS_PROXY` so reqwest does not proxy Clash UI loopback fetches.
The maintainer's REALITY interop lab: `.agents/rules/maintainer-lab.md` (not required for contributions).

The documented sing-box 1.12 / MetaCubeX-uTLS 1.8.0 REALITY lab peer buffers
8192 bytes of target TLS records including framing; this is server-version-specific,
not a universal honk certificate limit. Earlier `dl.google.com` / `www.microsoft.com`
size observations are historical, not a maintained target allowlist.

## Code style guidelines

- Rust source files do **not** carry SPDX/copyright headers; licensing and attribution live in the root `README.md`/`LICENSE`.
- **Comment discipline (feat/analyze-dns): readable code; comments explain "why", never "what".** Allow module `//!` purpose/non-obvious architecture, public-item `///`, and short rationale/invariant/wire-format/upstream-parity/past-bug comments. Narrating/restating code is a defect. Ordinary logic should have near-zero comments (see `crates/honk-core/src/dns/runtime.rs`); prefer descriptive names/small functions. **Before closing each work phase, review touched comments and delete/rewrite stale behavior descriptions**; stale comments are defects.
- **Commits:** `type(scope): one short imperative line` — `feat|fix|refactor|perf|test|docs|style|bench(<area>)`, no body, no markdown. Each commit stands alone and leaves the tree building; multi-part work is more commits, and fixups are squashed before pushing rather than pushed.
- **PR bodies:** English, one short paragraph under each of `## Problem`, `## How I fixed it` and `## Verified`, in that order: what is wrong, what changed, what was checked — not the reasoning that led there. Link long evidence; do not paste it.
- Prefer `anyhow::Result` for application/binary code and `thiserror` for library error types.
- Use `tracing` macros for logging; prefer structured fields (`info!(network = "tcp", outbound = %name, ...)`).
- Use `tokio` async/await and `tokio::select!` for long-lived loops.
- Kernel/userspace structs belong in `honk-ebpf-common`; follow its stable `#[repr(C)]` layout and coordinated `honk-ebpf`/`honk-core` map-writer change rules.
- Follow `cargo fmt --all` and keep `cargo clippy --all --all-targets -- -D warnings` clean.
- **Claims need their line.** A consequence stated in a PR or an issue names the code producing it, or is narrowed until it can; say what you did not check. Line numbers come from `origin/main`, not your working tree.
- **Read to the end of the path before describing a defect.** The trigger, the consequence, and the absence of a thing are each bounded by code you have not opened yet: the callee, the caller, the consumer that clamps the value, the search that would have settled it.
- **Fix where the paths converge**, not where you first saw the failure: a guard on one loader leaves its siblings failing open.
- **A check that could not run did not pass.** If a gate is missing, errors, or produces no output, say so; empty output reads exactly like a clean run.
- Stop before touching an area `CONTRIBUTING.md` reserves, before anything leaves the machine, and before discarding work someone else may want; otherwise continue.
- Match the surrounding file's idioms; make minimal, scoped changes (no opportunistic cleanups).
- Documentation language: code comments and `doc/en/` docs are English; user docs are bilingual (`README.zh.md`, `doc/zh/`) — update both when you change documented behavior.

## Testing instructions

- **A new test must fail without the change.** Remove the production hunk, run it, read the failure; a test that passes either way is not evidence. Read what already covers the behaviour first — several deliberate oddities here are pinned by one test. A deletion needs no test of its own.
- **Say which gates you ran and which you did not.** Running a subset is fine; reporting no limits after running a subset is not.
- `cargo test --all`: unprivileged default workspace unit/integration suites, using mock eBPF/loopback where appropriate. `just test-routing` runs the root-only compiled-policy goldens and failed-publication checks on Linux 6.12+; `just test-netns` depends on it and runs the remaining real NFQUEUE/eBPF integration checks.
- Test locations: `.agents/rules/test-locations.md`.
- Older standalone netns/podman scripts mentioned in stale docs are absent; use the supported `just test-netns` gate above.

## Notes for agents

Configuration contracts (settings, dialect, `honk-tool`): `.agents/rules/configuration.md`. Deployment and security-sensitive paths: `.agents/rules/deployment.md`, `.agents/rules/security.md`.

Shared eBPF/`honk-core` constants and `#[repr(C)]` structs in `#![no_std]`; `aya` is non-BPF-only for `Pod` impls. **Layouts and map key sizes must agree**: change types/constants together in [this crate](crates/honk-ebpf-common), `honk-ebpf`, and `honk-core` map writers.

- Choose commands for the owning crate: workspace `cargo` skips `honk-ebpf`, which has separate `Cargo.lock` and nightly-only target.
- Change eBPF map types/state transitions/marks/constants together in `honk-ebpf-common`, `honk-ebpf`, `honk-core` backend writers/readers, and relevant `honk-nfqueue` mark/verdict assumptions. Preserve `UDP_DECISION_SEQUENCE` ABI and cross-restart token uniqueness.
- Invariants: IPv4 flows are stored as `::ffff:<ipv4>` (network byte order) everywhere; all wire structs are `#[repr(C)]`. `DnsCacheEntry` and `DomainKey` do **not** exist (domain routing uses `DomainRouting`; DNS caching is purely userspace). ABI assertions and focused token/state tests protect the live layouts. Userspace has no `PARAM` static; only the kernel's `Global<DaeParam>` is configured through `EbpfLoader::override_global`.
  Preserve the legacy 12-byte raw-token ABI across cleanup/restart; startup validates without rewriting. At generation boundaries, eBPF stays sticky-exhausted until fenced userspace rotation. Ring events prompt detection; locked periodic reads are the lossless backstop. Epochs wait only pre-fence readers; tuple fences block new claims during exact-token revalidation/removal. Rotation requires an empty candidate-through-3 suffix across all four token-bearing maps; see `honk-core`'s `src/ebpf/` for rollback and complete-scan rules.
  `ArmDirect` requires Pending and retains token; marked verdicts precede `ActivateDirect`. `ActivateProxy` publishes final outbound/mark, retaining provisional track. Block/abort clean only matching incarnations. Real retirement: install `BPF_NOEXIST` tuple fence → flip reader epoch → wait pre-fence readers → revalidate → delete. Complete scans run to terminal `ENOENT`, never just a short successful batch.
- **UDP transport invariant:** ordinary production endpoints use `PacketTransport`; source-shared VLESS XUDP/Mux.Cool instead uses one core-owned source transport with endpoint send views and one receiver. Tunnel handlers frame datagrams directly: Trojan, native VLESS UDP, AnyTLS/VLESS UoT v2, VLESS H2MUX native connected UDP, VLESS XUDP/Mux.Cool, Shadowsocks, TUIC/Hysteria2, and Juicity. Direct and SOCKS5 hide raw sockets behind the same contract; no loopback bridges remain. `UdpEndpointPool` retires dead transports rather than black-holing flows.
  The core source index is keyed by reused runtime identity, normalized client, VLESS UDP path, and `ActualPeer` or `RewriteTo(original destination)`. It owns one XUDP session, one receiver, and multiple endpoint send views per scope; the full `(client, destination)` endpoint map remains authoritative for routing, decision token, and per-flow Score. An occupied wrong-owner, `Initializing`, or `Retiring` entry is a drop, never a foreign reply. Only an absent `ActualPeer` key may use foreign-reply delivery, without per-flow Score; domain rewrites stay pinned to their original destination.
  The source ID is a runtime-lazy private keyed hash. Reusing a runtime and replacing only a carrier preserves it; replacing/restarting the runtime changes it. This preserves honk's per-source semantics, not Xray's global-ID identity or collision-free NAT. Late local callbacks are owner/token fenced, and no cancelled or ambiguous packet is replayed automatically.
  UDP drivers capture the terminal per-flow Score outcome before their own synchronous health-death callback can retire an endpoint. A shared source owns DataUdp transport health and fans terminal outcomes to its bound flows. Terminal transport errors and no-reply idle expiry affect health; typed policy/size/capacity rejection, packet-local congestion, idle-after-reply, intentional retirement, and shutdown do not. Preserve `PacketRejection::Capacity` as a terminal local refusal through wrappers and DNS retries; CLI callers receive the error rather than `NotApplicable`.
  `SharedError` preserves the causal chain for all waiters on DNS and reusable-session initialization. Terminal packet refusal must survive outer route retries, name-family aggregation, and fallible health/URLTest resolver hooks; never replace it with system/bootstrap DNS or a default probe target. Preserve ordinary-error and configured-literal fallback behavior.
  Authoritative and cold URLTest UDP preparation return generic `PreparedUdpTransport<T>` values. Only the selected value's fallible commit may publish and return its `Arc<T>`; losing/dropped preparations roll back. They share one absolute `max(10s, 4 × connect_timeout)` deadline, including winner commit. Policy is checked at actual candidate admission; rejection terminates and drains without sibling/direct fallback. Deadline expiry drains started preparations; cancellation and never-started candidates are health-neutral, while completed transport failures still count. Endpoint publication and the separately bounded first send follow successful commit.
- `resolve_group_filters`: case-sensitive `name(...)` and dae-compatible `subtag(...)`, supporting exact/`keyword:`/`regex:`. `&&` ANDs predicates with `!` negation; separate `filter:` lines OR them. `subtag` maps `Node.subscription_id` to current subscription tag. Rebuild filtered membership after refresh so stable IDs cannot retain stale provenance. Include all nodes **only** with neither node filters nor sub-groups.
- [`src/node.rs`](crates/honk-config/src/node.rs) — `Node` has only shared identity/endpoint/provenance plus typed `OutboundConfig`; use variant accessors for protocols. [`src/node/vless.rs`](crates/honk-config/src/node/vless.rs) exclusively owns `VlessConfig`, `VlessUdpEncoding`, `VlessMultiplex`, `VlessUdpMux`, `Udp443Policy`, normalization, path selection, and combination validation. `src/node/protocol.rs` owns the other protocol configs and shared TLS/stream/QUIC options. `src/node/validation.rs` owns intrinsic and collection admission. Sole serde adapter `src/node/wire.rs` preserves the compatibility flat TOML/YAML/JSON shape without becoming a second VLESS model.
  `parser/diagnostics.rs` attaches current node-entry source, line and ordinal to both share-link warnings and returned typed errors. Node tags must not be used as schema-field locations for these diagnostics.
  `Node::derive_id()` is the sole identity source: UUID v5 over normalized protocol credentials and dial shape. VLESS identity includes `network`, UDP encoding, multiplex policy/concurrency, UDP/443 policy, transport, REALITY/flow, and encryption; changing these may change the ID. Assign after normalization at every construction entry. `Node::default()` returns **nil**, rejected by the runtime registry; `Config::validate` rejects ID collisions and unsupported protocol combinations.
  VLESS UDP permission comes only from `network`; encoding (`Auto|Native|Xudp|UotV2`) and multiplexing (`Off|H2|Xray`) are independent. Xray TCP and UDP concurrency normalize to `1..=128`; zero TCP means 8, negative disables TCP mux, zero XUDP follows TCP, negative uses the protocol UDP path, and positive XUDP uses a separate pool. Its UDP/443 policy is `Reject|Skip|Allow`: reject applies even when no mux pool exists, skip returns to protocol framing and the Vision gate, and allow bypasses Vision's port-443 denial only for an actual UDP mux path. H2 padding is an H2 property.
  Vision always rejects TCP multiplexing, including with Encryption; UDP-only Xray multiplexing is legal. Without Encryption, Vision requires raw TCP with TLS 1.3 or REALITY. With Encryption, a direct-copy response removes only the AEAD read layer and preserves the outer transport and random-XOR layer. Encryption may use direct or Xray-mux paths but not H2 or UoT framing. Never infer a retry or replay from a failed combination.
  Vision currently implements downstream unpadding and Direct only: uplink padding and uplink Direct are not implemented. Uploads retain their selected outer transport; do not claim full Vision shaping or bidirectional optimization.
  Shared REALITY intent/key presence is resolved by `TlsOptions::effective_reality_public_key`; node admission and outbound parsing must not turn missing or blank keys with REALITY intent into ordinary TLS/plaintext.
- VLESS runtime/pool ownership lives in `honk-outbound/src/runtime/vless.rs` and `proxy/vless/{handler,mux,cool}.rs`; the control plane owns source sharing in `honk-core/src/control/udp_endpoint/source.rs`. One process VLESS-carrier semaphore, carved from the startup FD partition before UDP endpoints and shared across reload and DNS forks, is authoritative. Its permits cover actual carrier I/O through active, provisional, draining, and idle task teardown. H2 keeps its own two-carrier/128-concurrent-stream bound and has no 128-open lifetime; Mux.Cool has no per-node two-carrier cap, admits at most the configured positive concurrency capped at 128 per carrier, and rolls a carrier after 128 issued IDs. The existing maintenance pass reaps unretained idle VLESS carriers; do not add a protocol timer.
  Resolve warm retention and runtime reuse by `WarmRequirement::Session` or `WarmRequirement::Udp`; a runtime selected only by UDP Xray mux remains eligible for bare TCP use.
  Pool waiters register capacity notifications before checking availability. Detached attachment returns its first pool-owned stream permit; all releases, carrier publications, backend close/drain transitions and closed-carrier pruning notify waiters, including non-reserving warm offers. Bind each backend to its owning pool notification before publication or detached attachment.
  Source send start/completion, matching retirement intent, and endpoint/source-view retirement publication share the existing source-state mutex. Release transition guards before pool retirement or unavailable-health callbacks; never hold them across await. Positive availability reports retain their admission fence.
  Source retirement publishes its Score disposition with admission closure. The common endpoint Score finalizer preserves that disposition for bound views; never-bound or previously retired views retain their local result. Snapshot source state before reporting, without holding it across Score callbacks.
- Before behavior changes, read `doc/en/design/overview.md` and subsystem siblings in `doc/en/design/`, plus config guide/reference `doc/en/configuration.md` / `doc/en/reference/`. Update both `doc/en/` and `doc/zh/` for behavior changes.
- If you add or remove workspace crates, update this file and the root `Cargo.toml` `[workspace] members` list.
- README authorship disclosure: the maintainer focuses on eBPF; most userspace subsystems were largely AI-authored with partial review. Review userspace changes accordingly.

### Runtime invariants (do not break)

- **Bypass mark:** control-plane egress (dials/probes/DNS upstreams/QUIC endpoints) must carry `DAE_BYPASS_MARK` (`0x100`) or be loopback, preventing self-routing into `daens`. TPROXY TCP/UDP listeners need the same mark; clear it on accepted TCP sockets in the accept loop. Non-DNS local-socket probing recognizes honk via `mark == PARAM.dae_socket_mark`; unmarked transparent listeners look like local services. Host-netns `dns.bind` ingress is an ordinary unmarked local service, not an exemption from LAN port-53 policy. Parsed destination-53 backend requests retain native LAN delivery only on a nonzero exact configured mark; their replies retain existing non-53 policy.
- **Anyfrom UDP replies:** proxied UDP/transparent port-53 DNS replies use transparent sockets bound to original destination, created in `daens`, cached per endpoint. TPROXY-listener replies die in host `dae0` with source `169.254.0.11:<tproxy_port>`. Standalone TCP uses its accepted host-netns socket; UDP uses its ordinary bound socket + `IP_PKTINFO`/`IPV6_PKTINFO`, replying from the exact targeted local address even on wildcard binds.
- **Netns discipline:** stay in host netns, creating/serving `dns.bind` there. Enter `daens` only via scoped synchronous `with_daens_netns`; **never `.await` inside** because setns is per-thread. Save `/proc/thread-self/ns/net` under a process-wide mutex; restore on every exit; failed restore **aborts**, preventing stranded workers originating dials in daens. Socket creation tests `DAENS_READY` set by `setup_daens_namespace`, never compat bind-mount existence. Unmount only this instance's tmpfs/bind-mount; delete `dae0` by creation-recorded ifindex, leaving same-named replacements alone.
- **Datapath admission:** `DATAPATH_STATE_MAP[0]` remains closed while hooks attach. The control plane publishes every listener FD and starts all receive loops before opening it; shutdown closes it before listener teardown. TC passes traffic untouched while closed, so a partial listener generation cannot black-hole startup UDP.
- **NFQUEUE readiness and ownership:** ordinary UDP staging and fragmented LAN UDP53 controller/raw delivery require ready queue ownership. Clear readiness → flip `UDP_DECISION_EPOCH` → wait old per-CPU readers → remove Preparing/Pending → publish a fresh routing descriptor generation. Failed quiescence forbids READY until a complete fence succeeds. `ROUTING_GENERATION_SEQUENCE` is a core-owned single-value persistent pin, separate from unchanged `UDP_DECISION_SEQUENCE`; reserve nonwrapping 20-bit values before publication/fences and preserve across cleanup/restart. Never reset it while host fragment queues may retain old carriers. No recompilation for descriptor-only fences.
- **Fragmented LAN UDP53:** only first fragments needing controller/raw delivery defer to host native reassembly and queue 320; native direct-must/block/exact bypass retain their actions. Disabled/unready queues drop required fragments. DNS queue events use route/generation carriers, never ordinary token cleanup or conn-state. Admission epoch, receipt deadline and generation checks precede confirmed `NF_DROP`; publish DNS/raw work only afterward. Validate UDP checksums with kernel partial-checksum metadata, reject identified bad payloads per packet, and retain fatal queue/envelope/verdict errors. Existing redirect tracking supplies anyfrom replies. TCP fragments are outside this path.
- **Token-checked terminal state:** require token agreement across skb mark, conn state, handoff, redirect track, verdict cell, lease, endpoint/tombstone, backend transition. Direct marked `NF_ACCEPT` follows `ArmDirect`, which requires `Pending` and retains the token through activation; activate only after every verdict succeeds. `ActivateProxy` publishes the final outbound and mark while retaining the provisional redirect track. Armed followers append only verdict guards, discarding payload without slow/endpoint admission. Proxy publishes before canonical dial/send. Stale cleanup fences the exact tuple, waits pre-fence readers, then revalidates; never overwrite/delete newer incarnations.
- **NFQUEUE lifecycle is fatal/fenced after admission:** listener/queue/verdict/watchdog/cleanup/retirement ambiguity terminates the control plane. Reload/shutdown: clear ready → quiesce kernel stagers → reject ingress → cancel/drain guards/leases/retirements/scheduled token cleanups → detach producers → close queue → delete owned table last. Preserve raw rollback-compatible `UDP_DECISION_SEQUENCE` during ordinary cleanup. Exhaustion uses the same fence/drain and empty-generation-suffix rule in `honk-core`'s `src/ebpf/`. If no suffix is clear, retry with staging fenced; never collide or require reboot.
- **must/block are final:** a matching configured `must` rule is terminal; Clash mode override never overrides `block` or `must` results.
- **Fail-closed on dead outbounds:** `lan_ingress` normally drops new dead-outbound flows (`TC_ACT_SHOT`). Exception: exactly one unique TCP leaf and no `final` keeps the eBPF slot open; userspace may attempt that same leaf only through the current Selector member paths, never bypassing a chosen empty sub-group. Selector TCP/UDP never replace a valid choice with a sibling for health. Real success can revive the leaf without leaking to `direct`; UDP/all-dead multi-leaf groups remain closed. Built-in `direct`/`block` never die, keeping containing groups' OR slots alive. Port 53 TCP+UDP is always exempt (dae parity).
  Ordinary LAN TCP/UDP `:53` evaluates traffic policy even when an exact or wildcard local DNS listener exists; local-socket precedence applies only to non-53 destinations. `must` suppresses sniff-driven rerouting and preserves the selected direct/block/group action, not a blanket bypass. Do not synthesize interface-address routing rules or a replacement kernel allowlist; retain interface observation for topology/ECS/health. Gateway-native routing is [explicit user configuration](doc/en/reference/routing.md#explicit-local-rules). Network events clear stale probe cooldowns and schedule immediate checks; other dead nodes stay closed until fresh success verifies recovery.
- **eBPF connectivity pushes are group-OR plus the sole-TCP-leaf exception:** publish OR of reachable leaf states, including explicit nested `final` edges, into every affected ancestor group alive slot, with the last-resort exception above. One dead member must never `TC_ACT_SHOT` an entire multi-leaf group. GroupManager owns nested final resolution; ordinary member lists remain separate from final-aware health, warm and Score reachability. Never substitute an unchosen Selector sibling or bypass a terminal protocol refusal.
- **Internal traffic is never proxied:** own-link `169.254.0.0/16`, `fd00:686f:6e6b::/64`. **Broadcast/multicast passes through eBPF:** `dst_is_special()` (crates/honk-ebpf/src/transport.rs) early-exits L2 broadcast/multicast MAC, 255.255.255.255, 224.0.0.0/4, 0.0.0.0, ff00::/8 in lan_ingress/lan_egress/wan_egress. DHCP/mDNS/SSDP never enter routing/conntrack; otherwise OpenWrt LAN DHCP breaks. Preserve non-DNS LAN local-socket precedence, including the TCP pure-SYN probe skip; destination 53 must not take that early return.
- Reserved outbound indices: `0 Direct | 1 Block | 2+ user groups | 0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND`.
