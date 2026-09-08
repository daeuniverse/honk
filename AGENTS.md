# AGENTS.md — honk

Agent guide to understanding, building, testing, and modifying honk. Repository layout/conventions last verified against the tree on 2026-08-09.

Re-read it when a conversation grows long or context is trimmed: a rule read once is not a rule in force. Never substitute memory or resemblance for evidence.

## Project overview

`honk` is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath and configuration surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API). It is not a line-for-line port of either: the kernel path uses TC hooks with a restricted native-BPF routing policy compiled from userspace, while the userspace outbound/control stack follows sing-box-oriented designs.

- `honk-core` intercepts via TC redirect and userspace proxy relay. Ambiguous LAN UDP uses default-on NFQUEUE 320 when prerequisites pass (`global.nfqueue_enable: false` disables; see Configuration). Its owned nftables table/chain installs no global `iptables` TPROXY rules.
- `honk-config` provides shared types/parsers for original dae `{ section { ... } }`, the primary and only documented config syntax.
- Status: **experimental alpha** (`v0.0.1-alpha`). Expect breaking changes.
- License: **GPL-3.0-only**. Repository: <https://github.com/daeuniverse/honk>
- Docs: `README.md` / `README_CN.md` (bilingual overview, feature checklist, TODO list); matching `doc/en/` / `doc/zh/` trees under `doc/`, indexed by bilingual `doc/README.md`. Each has `configuration.md`, `design/` (overview/datapath/routing/nfqueue/control-plane/dns/outbound/groups), `reference/` (global/nodes/groups/routing/dns/subscription/experimental/api/cli), and `operations/` runbooks. Lab benchmark tooling, evidence, and bilingual docs live only on `bench`.

## Repository layout

```text
.
├── Cargo.toml / Cargo.lock   # Workspace manifest (release + release-musl profiles)
├── Justfile                  # Day-to-day dev tasks (build, test, run, debug via clash API, cleanup)
├── README.md / README_CN.md  # Bilingual project overview
├── AGENTS.md                 # This file
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
- **TLS:** [boring](https://github.com/cloudflare/boring) 5.2.0 + tokio-boring 5.2.0 for TCP TLS and QUIC via custom `quinn_proto::crypto` in `honk-outbound/src/quic_boring.rs`; webpki-root-certs CA roots. rustls is **dev/test-only** for loopback wire interop. boring-sys builds BoringSSL from source with `cmake`, C compiler, `libclang` (bindgen). Pin all three Boring crates to 5.2.0; patch boring-sys to `https://github.com/Glassyiris/boring-sys`, revision `3beb573b65ecaa69b7eefe3c2fecd074b97facd2`, branch `boring-sys-5.2`. The fork adds REALITY-required `SSL_set1_client_x25519_private_key` and `SSL_set_client_hello_fixup_cb`. Rebase it before upgrading the stack.
- **Persistence:** rusqlite 0.40 (`bundled`) for the `cachedb` SQLite cache.
- **Serialization:** serde, toml 1, serde_json, serde_yaml.
- **Logging:** tracing + tracing-subscriber (`env-filter`, `json`); also `log`.
- **HTTP client:** reqwest 0.13 (rustls, no default features) — subscriptions.
- **Error handling:** anyhow + thiserror 2.
- **Misc:** socket2, ipnet, aho-corasick, lru, dashmap, parking_lot, h2 0.4 (urltest probes + DoH), tokio-tungstenite (WS transport), zip (external-UI download only), libsystemd (only `sd_notify`), nix (only `clock_gettime`), aes-gcm/chacha20poly1305/blake3/sha1/sha2/hmac/hkdf/md-5.
- **Dev/test:** tempfile, tokio-test, rcgen 0.14, tokio-tungstenite, criterion 0.8 (DNS and UDP benchmarks).

See [design docs](doc/en/design/overview.md).

## Build and test commands

### Rust workspace

```bash
cargo check
cargo build --release                 # whole workspace (needs cmake + C compiler + libclang for boring-sys)
cargo build --release -p honk-core    # engine (default features: clash-api, mock eBPF)
cargo test --all                      # full suite (see current validation guidance below)
```

### honk-core with real eBPF

The proxy engine (library `honk_core` + `honk-core` binary). Cargo features:

- `default = ["clash-api", "mimalloc", "rprx"]`
- `ebpf` — aya real backend + `honk-nfqueue`, requires Linux kernel 6.12+; otherwise `MockEbpfBackend`. NFQUEUE activation follows Configuration.
- `clash-api` — Clash-compatible REST/WS API (pulls in optional axum/tower-http).
- `mimalloc` — shipped binary allocates through mimalloc (see Technology stack); build with `--no-default-features --features "clash-api,ebpf,rprx"` for a stock-malloc binary.
- `rprx` — forwards to `honk-outbound/rprx`: registers VLESS (VLESS Encryption and xtls-rprx-vision) and VMess handlers; without it VLESS/VMess nodes parse fine but fail at dial with "No handler for protocol".

Score is always compiled, without a Cargo feature; omitted policy selects Selector.

`build.rs` always emits `HONK_VERSION` from the GitHub release tag, local `git describe`, or Cargo package version without Git metadata. `honk_core::VERSION` supplies both CLIs and Clash `/version`; runtime needs no Git. With `ebpf`, locate `crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf` or `target/honk-core.o` and **verify `.BTF`**. Missing/BTF-less objects trigger `cargo +nightly` rebuild, stripping child `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`: environment flags override `crates/honk-ebpf/.cargo/config.toml`'s `--btf` and silently omit BTF. Copy to `OUT_DIR/honk-ebpf.o`, set `HONK_EBPF_OBJECT`; `lib.rs` embeds with `include_bytes!`. Runtime override: `--bpf-object`.

```bash
# Requires Linux kernel 6.12+, clang/llvm/libbpf headers, nightly + bpf-linker.
# build.rs auto-builds the eBPF object on first build (~30s).
cargo build --release -p honk-core --features ebpf
sudo ./target/release/honk-core --config /etc/honk/config.dae          # embedded object
sudo ./target/release/honk-core --config c.dae --bpf-object /path.o    # external object
```

NFQUEUE activation, mock/preflight fallback, and restart requirements: Configuration.

Dev without kernel eBPF (unprivileged):

```bash
cargo run --release -p honk-core -- --config config.min.dae --mock-ebpf
```

### eBPF program standalone

Kernel eBPF, **excluded from the workspace**, own `Cargo.lock`. Edition 2024, `aya-ebpf` 0.2; release `panic = "abort"`, `lto = true`, `opt-level = 2`. `src/main.rs`: `#![no_std] #![no_main]`, spin-loop panic handler, module declarations. Optional `log` enables `aya-log-ebpf`; otherwise `log_shim.rs` macros are no-ops.

```bash
cd crates/honk-ebpf
cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none
```

`.cargo/config.toml` resolves `bpf-linker` from `PATH`. CI tracks the latest nightly toolchain and pins the prebuilt `bpf-linker` 0.11.0 release.


### Justfile (preferred for day-to-day dev)

| Recipe                                                                          | Purpose                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build` / `check` / `lint` / `fmt`                                              | `cargo build --release` / `check` / `clippy --all -D warnings` / `fmt --all`                                                                                                                                                                 |
| `test-routing` | Root-gated compiled-policy check: builds the `routing-test` eBPF object and exercises the real object against independent goldens plus failed root-publication preservation (Linux 6.12+) |
| `test` / `test-ci` / `test-core` / `test-config` / `test-ebpf`                  | Test suites (`test` = full workspace; `test-ci` = CI gate with the known legacy routing failure skipped; `test-ebpf` = honk-ebpf-common only)                                                                                                |
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

### CI / releases

`.github/workflows/ci.yml` runs fmt + clippy, the workspace gate, and an Ubuntu hosted-VM eBPF job. The VM job boots the pinned Linux 6.12 image, BTF-checks the kernel object, mounts bpffs, installs the geo assets required by eBPF-feature routing tests, runs the full `honk-core --features ebpf --lib` gate, then runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test, and root-only network tests serially without a job container.

`.github/workflows/release.yml` on `v*`: `cargo test --workspace --no-fail-fast` with the temporary routing exclude below (`cmake` + `libclang-dev` required for boring-sys), then `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl`. Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). Build eBPF once on host with latest nightly/pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Publish GitHub Release tarballs; `alpha`/`beta`/`rc` tags are prereleases.

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

## Current validation guidance

Do not treat dated pass counts as repository status; use the current command output and CI for that evidence. The workspace gate below retains the known legacy routing exclude. The current compiled-routing gate is `just test-routing`: it builds a real `routing-test` eBPF object and exercises independent policy goldens plus preservation of the active root when publication fails.

```bash
CARGO_TARGET_DIR=/root/code/honk/target \
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  cargo test --workspace --no-fail-fast -- \
    --skip test_routing_with_config_dae
CARGO_TARGET_DIR=/root/code/honk/target cargo clippy --workspace --all-targets -- -D warnings
```

Group-policy/scorer changes should run `cargo test -p honk-config group_policy`, `cargo test -p honk-outbound group::score`, and focused core Score/Clash tests before the workspace gate (Score needs no feature flag).

For UDP, run focused `honk-outbound` SOCKS5/group, `honk-nfqueue` parser/verdict/rule,
and `honk-core` control/NFQUEUE/token-transition/endpoint/reload/warm-up/Clash `/stats`
tests before the workspace gate. Held-packet changes also require `just test-netns`:
only the ignored root NFQUEUE test proves real nftables/queue/verdict semantics,
not the unprivileged suite. Deployment A/B needs real eBPF/netns/upstreams and the
`bench` lab harness. Production BoringSSL versus test rustls: Technology stack.

`routing::tests::test_geosite_*` needs `/etc/dae/geosite.dat` and `geoip.dat`.
Unset `HTTP_PROXY`/`HTTPS_PROXY` so reqwest does not proxy Clash UI loopback fetches.
Install boring-sys prerequisites (Technology stack) and its REALITY-hooks checkout
at pinned `/root/code/boring-rprx/boring-sys`. Cross-build with `ci/zig*`, not containers.

REALITY / xtls-rprx-vision interop uses two live servers, not the unprivileged suite:
- Lab `10.10.10.70`: sing-box 1.12, systemd `sing-box-rprx`, `/etc/sing-box/rprx.json`.
  Ports: 8443 vless+reality+vision; 8444 vless+reality; 8445 vmess+ws+tls self-signed
  (require `skip_cert_verify`/`insecure=1`); 8446 vmess bare tcp.
  LAN HTTP: `10.10.10.70:18080`, systemd `bench-http18080`.
- Public `103.238.129.118`: Xray 26.3.27, same ports, `xray-rprx.service`, degraded
  ~75 ms / ~15% loss.

REALITY `dest` TLS Certificate messages must stay **under 8 KiB**: sing-box buffers
8192 bytes; `dl.google.com` works, `www.microsoft.com` at 8273 B fails.
JA4 was verified on .70 with `/usr/local/bin/ja4probe` (`ja4probe`, source
`/root/code/ja4probe`). Lab drivers: `honk-outbound/examples/`
(`reality_hook_spike.rs`, `reality_lab59.rs`).

## Code style guidelines

- Rust source files do **not** carry SPDX/copyright headers; licensing and attribution live in the root `README.md`/`LICENSE`.
- **Comment discipline (feat/analyze-dns): readable code; comments explain "why", never "what".** Allow module `//!` purpose/non-obvious architecture, public-item `///`, and short rationale/invariant/wire-format/upstream-parity/past-bug comments. Narrating/restating code is a defect. Ordinary logic should have near-zero comments (see `crates/honk-core/src/dns/runtime.rs`); prefer descriptive names/small functions. **Before closing each work phase, review touched comments and delete/rewrite stale behavior descriptions**; stale comments are defects.
- **Commits:** `type(scope): one short imperative line` — `feat|fix|refactor|perf|test|docs|style|bench(<area>)`, no body, no markdown. Each commit stands alone and leaves the tree building; multi-part work is more commits, and fixups are squashed before pushing rather than pushed.
- **PR bodies:** English, one short paragraph under each of `## Problem`, `## How I fixed it` and `## Verified`, in that order: what is wrong, what changed, what was checked — not the reasoning that led there. Link long evidence; do not paste it.
- Prefer `anyhow::Result` for application/binary code and `thiserror` for library error types.
- Use `tracing` macros for logging; prefer structured fields (`info!(network = "tcp", outbound = %name, ...)`).
- Use `tokio` async/await and `tokio::select!` for long-lived loops.
- Kernel/userspace structs belong in `honk-ebpf-common`; follow its stable `#[repr(C)]` layout and coordinated `honk-ebpf`/`honk-core` map-writer change rules.
- Follow `cargo fmt --all` and keep `cargo clippy --all -- -D warnings` clean.
- **Claims need their line.** A consequence stated in a PR or an issue names the code producing it, or is narrowed until it can; say what you did not check. Line numbers come from `origin/main`, not your working tree.
- **Read to the end of the path before describing a defect.** The trigger, the consequence, and the absence of a thing are each bounded by code you have not opened yet: the callee, the caller, the consumer that clamps the value, the search that would have settled it.
- **Fix where the paths converge**, not where you first saw the failure: a guard on one loader leaves its siblings failing open.
- **A check that could not run did not pass.** If a gate is missing, errors, or produces no output, say so; empty output reads exactly like a clean run.
- Stop before touching an area `CONTRIBUTING.md` reserves, before anything leaves the machine, and before discarding work someone else may want; otherwise continue.
- Match the surrounding file's idioms; make minimal, scoped changes (no opportunistic cleanups).
- Documentation language: code comments and `doc/en/` docs are English; user docs are bilingual (`README_CN.md`, `doc/zh/`) — update both when you change documented behavior.

## Testing instructions

- **A new test must fail without the change.** Remove the production hunk, run it, read the failure; a test that passes either way is not evidence. Read what already covers the behaviour first — several deliberate oddities here are pinned by one test. A deletion needs no test of its own.
- **Say which gates you ran and which you did not.** Running a subset is fine; reporting no limits after running a subset is not.
- `cargo test --all`: unprivileged default workspace unit/integration suites, using mock eBPF/loopback where appropriate. `just test-routing` runs the root-only compiled-policy goldens and failed-publication checks on Linux 6.12+; `just test-netns` depends on it and runs the remaining real NFQUEUE/eBPF integration checks.
- Test locations:
    - `crates/honk-config/src/node.rs`, `src/config.rs`, `src/parser/tests.rs` — GroupPolicy serde, dae policy/default/errors, file loading, parser units: sections, groups, nested filters, DNS upstreams/routing, subscriptions, experimental.
    - `crates/honk-config/tests/example_configs.rs` — keeps `config.dae`, `config.min.dae`, `example.dae` parseable.
    - `crates/honk-config/tests/include.rs` — file-based dae include loading (glob order, nested paths, merge semantics, cycles, directory boundaries, and preservation of policy errors).
    - `crates/honk-config/tests/share_link.rs` — share-link parsing + config format round-trips.
    - `crates/honk-nfqueue/src/*` — NFQA parsing, netlink/nft encoding, exactly-once verdicts; the ignored `kernel_tests.rs` contract exercises the production queue/table in an isolated real netns.
    - `crates/honk-outbound/src/group/tests.rs`, `group/score/tests/`, and `group/udp_selection_repro_tests.rs` — selection semantics (Selector/URLTest/LoadBalance/Fallback/Score, nested groups, UDP exclusion), target attribution, decay and metric qualification, deterministic exploration, reporter lifecycle, reload sharing, and LRU safety.
    - `crates/honk-outbound/src/alive/tests.rs` — health-check state machine, probe semantics, idle suspension.
    - `crates/honk-outbound/src/proxy/hysteria2/tests.rs` + inline `#[cfg(test)]` in `proxy/*`, `urltest.rs`, `bootstrap.rs` — wire vectors and test-only loopback/in-process QUIC interop (`quic::testutil`). Production transport: outbound **UDP transport invariant**.
    - `crates/honk-outbound/src/reality.rs` + `proxy/vless.rs` + `proxy/vless_mux.rs` + `proxy/vless_cool.rs` + `proxy/vless_encryption.rs` (`#[cfg(feature = "rprx")]`) — REALITY vectors; VLESS headers/Vision; UoT v2; sing-mux/H2 flow control; XUDP/Mux.Cool codecs, carrier lifecycle, capacity, speculative publication, warm/reload behavior. The ignored official sing-box/Xray test covers all six cleartext modes, H2MUX TLS/REALITY and padding, plus XUDP Vision.
    - `crates/honk-core/tests/integration_test.rs` — config loading, routing, mock-eBPF workflow, SOCKS5/direct/block, TCP relay + splice, DNS resolver, stats, reload/subscription-merge pipeline.
    - `crates/honk-core/tests/clash_api_test.rs` — Clash API endpoints (auth, proxies, Score representation/current winner/PUT rejection, delay, connections, traffic/logs chunked + WS, `/dns/query`, cache flush, providers, UI hosting, store_dns).
    - `crates/honk-core/tests/config_dae_routing_test.rs` — end-to-end routing assertions against the root `config.dae`.
    - Inline unit tests in `honk-core/src/control/*` (including `nfqueue.rs` held guards, token/generation races, direct/proxy/block/cancel/fatal paths), `ebpf/{mock,real}`, `mode.rs`, `stats.rs`, routing, DNS, and relay; real-backend tests require `ebpf`, and ignored netns tests require root.
    - Benchmarks kept on `main`: `cargo bench -p honk-core --features dns-bench --bench dns`; `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`; and `cargo bench -p honk-outbound --features rprx --bench vless_vision`. Lab/deployment benchmark commands and fixtures live only on branch `bench`; use its `bench/README.md` and `doc/benchmark.en.md` from a separate worktree.
    - Runtime reload benchmark: `cargo bench -p honk-core --bench reload --no-default-features --features reload-alloc-bench`.
- Older standalone netns/podman scripts mentioned in stale docs are absent; use the supported `just test-netns` gate above.

Benchmarks kept on `main`: `benches/dns.rs` (criterion, `harness = false`) covers DNS endpoint parse, cache get/put + 90/10 mix, per-query routing match, framing, forwarder cache-hit, and TcpPool/UpstreamPool exchange; run `cargo bench -p honk-core --features dns-bench --bench dns`. `benches/udp.rs` is the candidate-only UDP Criterion suite; run `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`. Lab/deployment harnesses, raw evidence, and their documentation live only on branch `bench`; use `git worktree add ../honk-bench bench` when benchmarking so they never enter the `main` worktree.

`benches/reload.rs` measures an unchanged-effective-config runtime reload's wall/CPU time, allocations, and mock eBPF writes; run `cargo bench -p honk-core --bench reload --no-default-features --features reload-alloc-bench`.

## Configuration

Only documented format: original **dae syntax**, `{ include { ... } global { ... } node { ... } group { ... } routing { ... } dns { ... } subscription { ... } experimental { ... } }`, parsed by `honk-config/src/parser/mod.rs`. `include` accepts bare/quoted `.dae` globs, entry-relative; merge entry sections first, reject repeated/cyclic/escaping files. Examples: `config.dae` (full), `config.min.dae` (minimal), `example.dae` (annotated). Reference: `doc/en/reference/`; guide: `doc/en/configuration.md`.

Held-first-packet UDP has exactly one `global` key:

```dae
global {
    nfqueue_enable: true
}
```

Legacy `experimental { udp_nfqueue { enabled: ... } }` warns and migrates to `global.nfqueue_enable`; never serialize the removed section.

Default on; restart-required. Activation requires the real eBPF backend and an `ebpf` build.
Mock/no-`ebpf` startup or failed fixed-queue preflight warns and disables staging
for this process, never rewriting config. Set `false` for unprivileged mock development.
Only LAN-forwarded UDP: `inet prerouting` follows LAN TC; host WAN egress stays TPROXY.
Exclude DNS 53, internal/special, reverse, `must`, `block`, and already-safe direct.
No queue/worker/timeout/failure knobs: queue `320` and fail-closed behavior are fixed.
Owned nftables names and firewall restrictions: `crates/honk-nfqueue`.

- Group policy: omitting `policy` selects `Selector`; `policy: score` selects the always-compiled `Score` policy. Legacy `honk` is invalid. Score has no configuration knobs.
- Built-ins: `honk-core` injects `direct`/`block`, not the parser (see `honk-config`'s `ensure_builtin_nodes()`). User nodes using those names or `NodeProtocol::Direct`/`Block` fail validation. `block` drops traffic.
- `src/config.rs` — `Config` / `GlobalConfig` (~40 global fields), `from_file` / `to_file` / `validate`, JSON helpers. Idempotent `ensure_builtin_nodes()` injects `direct`/`block` with reserved `NodeProtocol::Direct`/`Block` and stable `DIRECT_NODE_ID`/`BLOCK_NODE_ID` UUIDs. **The crate never calls it**: `honk-core/src/lib.rs` calls at startup/SIGHUP; other consumers must call explicitly.
- Interface modes: absent `global.lan_interface` means no LAN hooks, never implicit `lo`; configured `wan_interface` hooks still proxy host TCP/UDP. Unresolved `auto` stays pending/fail-open until an IPv4 default route appears. On link/address/route events, `IfaceWatcher` attaches single-/dual-homed programs without restart, refreshes gateway-address must-direct rules through runtime configuration, immediately re-probes health-backed outbounds, and follows WAN bond slaves. WAN-only still requires `dae0`/`daens`, transparent listeners, cgroup hooks, bypass marks.
- Health: `global { tcp_check_url, udp_check_dns, check_interval, check_tolerance }`. Selector leaves stay warm as specified under **Selector warm ownership**. `udp_warm_node_count: 0` disables the separate UDP warm set; positive values warm each group's top-N (≤3) reusable UDP leaves after every probe cycle. Dial modes: `ip` / `domain` / `domain+` / `domain++`.
- Subscription recovery: `global.store_subscribe` defaults `true`, retaining the last valid raw response per request identity. Storage/fallback order and restore-before-refresh: `honk-core`'s `src/subscription.rs`. Process-scoped; reject SIGHUP changes as restart-required.
- DNS bind: absent/empty disables only standalone listening, not transparent TCP/UDP port-53 interception. Bare numeric `IP:port` is UDP-only; `udp://host:port`, `tcp://host:port`, `tcp+udp://host:port` select transports. Accept schemed hostnames, bracketed IPv6, empty wildcard hosts; require port. Bind host-netns sockets all-or-nothing; semantic SIGHUP changes require restart.
- DNS hosts: repeatable `dns.use_host`, default no sources. `true` adds standard `/etc/hosts`; paths add OxiDNS-compatible exact/domain/regexp/keyword rules. Merge in declaration order, later duplicates win. Relative files select the first existing copy under configured `global.data_dir`, then `/var/share/honk`, then CWD; missing files stay under `global.data_dir`. Known IN A/AAAA names precede request rules/cache; missing families return NODATA without upstream I/O. SIGHUP transactionally reloads every source; load failure leaves the active generation untouched.
- DNS projection (`honk-core/src/dns/projection/`): retain at most 10,000 domain owners; admit at most 49,152 canonical IP keys into the 65,536-entry domain map, with at most 32,768 zero bitmaps selected for desired/reload state. Obsolete zero facts awaiting deletion may exceed that sub-limit within the applied total. Shared incremental/reload admission evicts zero facts first, then the highest IP; IPv4/mapped-IPv6 owners OR into one key. Keep 16,384 slots outside DNS projection for sniff writes. At the applied ceiling, new keys wait for confirmed removal, including on retry; the worker drains ready 256-entry batches without another observation. Omitted facts retain existing dial-mode/must/block cache-miss semantics, not blanket unknown-to-punt behavior. See bilingual DNS design docs for headroom limits.
  Reload acknowledges the exact installed IP slice before owner reconciliation; skipped map publication preserves applied state. Worker writes and acknowledgements share the generation fence. Retry wakeups and batch admission use the same capacity-aware per-IP deadline; no separate retry heap can wake blocked insertions.
- DNS upstream URI schemes: `udp://` (bare default), `tcp://`, `tcp+udp://`, `tls://` (DoT), `https://` (DoH), `h3://`/`http3://` (DoH3), `quic://` (DoQ); optional dial-path proxy `name: 'uri' -> <node|group>` (or legacy `outbound:` key).
- Clash UI: `experimental.clash_api.external_ui_download_url` selects HTTP(S) dashboard ZIP; empty uses built-in zashboard. `HONK_UI_DOWNLOAD_URL` overrides both. Nonempty `external_ui_download_detour` forces the initial download and every redirect through its node/group; empty uses per-URL traffic routing. Both config fields require restart.
- Geo assets: `geoip.dat` / `geosite.dat` are selected only from regular files, in order `$DAE_LOCATION_ASSET`, configured `global.data_dir`, `/var/share/honk`, CWD, `/usr/local/share/honk`, `/usr/share/honk`, `/usr/local/share/dae`, `/usr/share/dae`, then `/etc/dae`.
- Environment variables: `RUST_LOG`; `HONK_UI_DOWNLOAD_URL` (highest-precedence UI ZIP URL override); `HONK_POOL_DISABLE=1` (bypass pool); `HONK_MI_COLLECT_SECS` (mimalloc-only per-owner park/sweep interval, default 60s, `0` disables).
  `HONK_VMLINUX_BTF` overrides real-eBPF raw kernel BTF for `pname` offsets; otherwise search `/sys/kernel/btf/vmlinux`, then `/usr/lib/debug/boot/vmlinux`. Unavailable kernel argv capture synchronously falls back to thread `comm` in the cgroup hook. Configure UDP NFQUEUE only via `global.nfqueue_enable`, never environment variables.
- Default runtime paths: config `/etc/honk/config.dae`, BPF pin root `/sys/fs/bpf`, embedded BPF object unless `--bpf-object`.

CLI (`honk-core` binary):

- Flags: `--config/-c` (default `/etc/honk/config.dae`), `--log-file` (process-local override of `global.log_file`), `--bpf-object/-b`, `--bpf-pin-root` (default `/sys/fs/bpf`), `--debug/-d`, `--mock-ebpf`. Log-level order: a valid `RUST_LOG` wins (`EnvFilter::try_from_default_env`), else `--debug` → `debug`, else `global.log_level`, else `info`.
- Subcommands: `reload` sends SIGHUP to the real-datapath PID published in `/run/honk-core.lock`; `mode <rule|global|direct>` rewrites `global.dial_mode` in the config file; `proxy <group> <node>` validates existence and prints but persists nothing; `delay <node> [--url HOST:PORT]` performs raw TCP timing rather than a proxied urltest. The latter three are local-only and do not talk to the running engine.

### `crates/honk-tool`

The `honk-tool` CLI toolbox (bin crate, diagnostics that don't belong in the engine binary). Deps are honk-config + honk-outbound + honk-core (`default-features = false`, so no axum/aya). Subcommands:

- `sub <url|file|-> [--target HOST:PORT] [--url TEST_URL] [--timeout SECS] [--concurrency N] [--limit N] [--ua UA] [--tls-implementation tls|utls] [--utls-imitate chrome_auto]` — fetch a subscription (or parse a share-link file/stdin URL) and probe TCP families, URLTest, and supported UDP paths. VMess, legacy VLESS, and nodes whose `network` excludes UDP render UDP as `n/a`; all other VLESS modes probe through their packet handler. VLESS output exposes only display name, fixed carrier/transport/wire shape, and fixed result codes; endpoint credentials and raw errors are never rendered.
- `bpf show <conn-state|redirect-track|domain-routing|routing-handoff> [--ip IP] [--limit N]` and `bpf stats` — quick reads of the running engine's maps under `/sys/fs/bpf` (raw `bpf(2)`; no aya, no program load). `domain-routing` follows the active `ROUTING_POLICY_ROOT` descriptor's domain-map ID. `stats` prints overflow counters, the `CONN_STATE_OCCUPANCY` gauge, and non-zero per-outbound tx/rx counters.
- `diagnose [--api URL] [--pin-root PATH]` — one-shot read-only health check: engine process, `daens`/`dae0` presence, daens fwmark rule, pinned maps present, occupancy/overflow, clash API reachability. Exit summary `all checks passed` / `N issue(s) found`.
- `geosite list [FILTER] | show <category> [--attr ATTR] | find <domain>` and `geoip list [FILTER] | show <code> | lookup <ip>` — offline content search of geosite.dat/geoip.dat (one record per line, `--file PATH` overrides the default search). Without `--file`, honk-tool selects the first regular file from `$DAE_LOCATION_ASSET`, `/var/lib/honk`, legacy `/var/share/honk`, CWD, honk share directories, then dae asset locations; it does not load a config to discover a custom `global.data_dir`. Backed by the read-only scan API in `honk-core::routing` (`GeositeScan`/`GeoipScan`, including `@attr` decoding); `lookup` is longest-prefix. `--attr` uses the same key-presence predicate as routing's `category@attr` filter, so tool output and expansion agree.
- honk-tool is a **static musl binary** for gateway deployment: build with the `build-musl` zig env (`ZIGCC_TARGET=x86_64-linux-musl` + ci wrappers) and scp — a gnu build fails to exec on VyOS.

## Deployment

- **Native:** root `honk-core` handles eBPF load, netns/link creation, transparent TPROXY sockets, sysctl. Self-contained: one config, embedded eBPF, optional `experimental.clash_api`.
- **Gateway / VyOS:** copy a `just build-core` binary or static `build-musl` (`x86_64-unknown-linux-musl`, workspace `release-musl` profile). `just deploy-vyos HOST=...` builds musl, scps, and smoke-runs; `just deploy` is absent.
- **Releases:** `v*` tags → GitHub Actions → four target triples × two allocators → eight tarballs (CI / releases).
- **Docker:** README-referenced `Dockerfile` / `docker-compose.yml` are absent. Containers require `--privileged --network=host --pid=host`, mounted `/sys`, and an `ebpf` build or `--bpf-object`/`--mock-ebpf`.
- **Cleanup:** graceful shutdown follows runtime NFQUEUE fencing/table-last order. `just clean-all` removes `dae0`/`daens`, ephemeral BPF pins and policy routes, never rollback-compatible `UDP_DECISION_SEQUENCE`. Never reset/delete it for normal exhaustion; the fenced supervisor rotates to legacy-safe empty suffixes or backs off. For startup-rejected corrupt/incompatible pins: keep staging fenced → stop every honk process → verify queue/token-bound maps gone → remove pin once → restart. **Never start a second real datapath instance:** `/run/honk-core.lock` prevents fixed-name overlap.

## Security considerations

- **Root/privileged execution:** `honk-core` requires root for the operations listed under Deployment.
- **Clash API secret:** when `experimental.clash_api` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — bind to localhost or front it with a reverse proxy.
- **Config trust:** treat config/BPF objects as privileged input. `honk-core` writes `/proc/sys` directly and loads configured/CLI BPF paths. Netns/link/routes/rules use rtnetlink and an FD-owned namespace, requiring no external `ip`/`nsenter`.
- **Bypass mark discipline:** follow runtime **Bypass mark** rules for `DAE_BYPASS_MARK`; missing marks loop gateway traffic.
- **NFQUEUE ownership:** host-netns firewall automation must honor `crates/honk-nfqueue`'s exact-name/no-bypass rules while enabled. Mutation can fail closed or violate held-skb lifecycle assumptions.

## Notes for agents

Shared eBPF/`honk-core` constants and `#[repr(C)]` structs in `#![no_std]`; `aya` is non-BPF-only for `Pod` impls. **Layouts and map key sizes must agree**: change types/constants together in [this crate](crates/honk-ebpf-common), `honk-ebpf`, and `honk-core` map writers.

- Choose commands for the owning crate: workspace `cargo` skips `honk-ebpf`, which has separate `Cargo.lock` and nightly-only target.
- Change eBPF map types/state transitions/marks/constants together in `honk-ebpf-common`, `honk-ebpf`, `honk-core` backend writers/readers, and relevant `honk-nfqueue` mark/verdict assumptions. Preserve `UDP_DECISION_SEQUENCE` ABI and cross-restart token uniqueness.
- Invariants: IPv4 flows are stored as `::ffff:<ipv4>` (network byte order) everywhere; all wire structs are `#[repr(C)]`. `DnsCacheEntry` and `DomainKey` do **not** exist (domain routing uses `DomainRouting`; DNS caching is purely userspace). ABI assertions and focused token/state tests protect the live layouts. Userspace has no `PARAM` static; only the kernel's `Global<DaeParam>` is configured through `EbpfLoader::override_global`.
  Preserve the legacy 12-byte raw-token ABI across cleanup/restart; startup validates without rewriting. At generation boundaries, eBPF stays sticky-exhausted until fenced userspace rotation. Ring events prompt detection; locked periodic reads are the lossless backstop. Epochs wait only pre-fence readers; tuple fences block new claims during exact-token revalidation/removal. Rotation requires an empty candidate-through-3 suffix across all four token-bearing maps; see `honk-core`'s `src/ebpf/` for rollback and complete-scan rules.
  `ArmDirect` requires Pending and retains token; marked verdicts precede `ActivateDirect`. `ActivateProxy` publishes final outbound/mark, retaining provisional track. Block/abort clean only matching incarnations. Real retirement: install `BPF_NOEXIST` tuple fence → flip reader epoch → wait pre-fence readers → revalidate → delete. Complete scans run to terminal `ENOENT`, never just a short successful batch.
- **UDP transport invariant:** production endpoints use `PacketTransport`. Tunnel handlers frame datagrams directly: trojan, AnyTLS/VLESS UoT v2, VLESS H2MUX native connected UDP, VLESS XUDP/Mux.Cool, SS, TUIC/Hy2, and Juicity. Direct and SOCKS5 hide raw sockets behind the same contract; no loopback bridges remain. `UdpEndpointPool` retires dead transports rather than black-holing flows.
  UDP drivers capture the terminal Score outcome before their own synchronous health-death callback can retire the endpoint. Terminal transport errors and no-reply idle expiry affect DataUdp health; packet-local congestion, idle-after-reply, intentional retirement, and shutdown do not.
- `resolve_group_filters`: case-sensitive `name(...)` and dae-compatible `subtag(...)`, supporting exact/`keyword:`/`regex:`. `&&` ANDs predicates with `!` negation; separate `filter:` lines OR them. `subtag` maps `Node.subscription_id` to current subscription tag. Rebuild filtered membership after refresh so stable IDs cannot retain stale provenance. Include all nodes **only** with neither node filters nor sub-groups.
- [`src/node.rs`](crates/honk-config/src/node.rs) — `Node` has only shared identity/endpoint/provenance plus typed `OutboundConfig`; use variant accessors for protocols. Also owns `Group`/`GroupPolicy`. `src/node/protocol.rs`: per-protocol configs, shared TLS/stream/QUIC options, normalized `WireMode::{Legacy,UotV2,H2mux,H2muxPadded,Xudp,MuxCool}`. Sole serde adapter `src/node/wire.rs` preserves legacy flat TOML/YAML/JSON shape/order without leaking flat fields into runtime.
  `Node::derive_id()` is the sole identity source: UUID v5 over `protocol|host|port|credential-fingerprint|dial-shape`. Resolve credentials exactly like handlers; dial shape includes SNI/transport/ws/grpc/obfs, REALITY/flow, every non-legacy VLESS mode; legacy IDs stay unchanged. Assign at every construction entry to preserve health/latency/sessions across reload/refresh. `Node::default()` returns **nil**, rejected by the runtime registry. `Config::validate` rejects ID collisions, unsupported flow, non-legacy mode with non-`none` VLESS Encryption, and flow outside `Legacy`/`Xudp`.
- VLESS Encryption lives in `VlessConfig.encryption`: `Node::derive_id()` treats a non-`none` value as credential identity, while legacy plain VLESS IDs remain unchanged. `VlessConfig::validate` rejects combining it with `flow` or any non-legacy mode.
- Before behavior changes, read `doc/en/design/overview.md` and subsystem siblings in `doc/en/design/`, plus config guide/reference `doc/en/configuration.md` / `doc/en/reference/`. Update both `doc/en/` and `doc/zh/` for behavior changes.
- If you add or remove workspace crates, update this file and the root `Cargo.toml` `[workspace] members` list.
- README authorship disclosure: the maintainer focuses on eBPF; most userspace subsystems were largely AI-authored with partial review. Review userspace changes accordingly.

### Runtime invariants (do not break)

- **Bypass mark:** control-plane egress (dials/probes/DNS upstreams/QUIC endpoints) must carry `DAE_BYPASS_MARK` (`0x100`) or be loopback, preventing self-routing into `daens`. TPROXY TCP/UDP listeners need the same mark; clear it on accepted TCP sockets in the accept loop. The NAT-loopback probe recognizes honk via `mark == PARAM.dae_socket_mark`; unmarked listeners look like local services and bypass interception (observed for all proxied UDP). Exception: host-netns `dns.bind` ingress is ordinary, unmarked local service.
- **Anyfrom UDP replies:** proxied UDP/transparent port-53 DNS replies use transparent sockets bound to original destination, created in `daens`, cached per endpoint. TPROXY-listener replies die in host `dae0` with source `169.254.0.11:<tproxy_port>`. Standalone TCP uses its accepted host-netns socket; UDP uses its ordinary bound socket + `IP_PKTINFO`/`IPV6_PKTINFO`, replying from the exact targeted local address even on wildcard binds.
- **Netns discipline:** stay in host netns, creating/serving `dns.bind` there. Enter `daens` only via scoped synchronous `with_daens_netns`; **never `.await` inside** because setns is per-thread. Save `/proc/thread-self/ns/net` under a process-wide mutex; restore on every exit; failed restore **aborts**, preventing stranded workers originating dials in daens. Socket creation tests `DAENS_READY` set by `setup_daens_namespace`, never compat bind-mount existence. Unmount only this instance's tmpfs/bind-mount; delete `dae0` by creation-recorded ifindex, leaving same-named replacements alone.
- **Datapath admission:** `DATAPATH_STATE_MAP[0]` remains closed while hooks attach. The control plane publishes every listener FD and starts all receive loops before opening it; shutdown closes it before listener teardown. TC passes traffic untouched while closed, so a partial listener generation cannot black-hole startup UDP.
- **NFQUEUE readiness and ownership:** `DATAPATH_FLAG_NFQ_ENABLED && !DATAPATH_FLAG_NFQ_READY` drops only new staging-required flows. The serialized flags writer clears readiness → flips `UDP_DECISION_EPOCH` → waits old per-CPU `UDP_DECISION_INFLIGHT` → removes residual Preparing/Pending → completes reload/shutdown fence. Delayed deliveries then fail token lookup. Exclusive queue/table ownership and no-bypass/fanout/fail-open rules: `crates/honk-nfqueue`.
- **Token-checked terminal state:** require token agreement across skb mark, conn state, handoff, redirect track, verdict cell, lease, endpoint/tombstone, backend transition. Direct marked `NF_ACCEPT` follows `ArmDirect`, which requires `Pending` and retains the token through activation; activate only after every verdict succeeds. `ActivateProxy` publishes the final outbound and mark while retaining the provisional redirect track. Armed followers append only verdict guards, discarding payload without slow/endpoint admission. Proxy publishes before canonical dial/send. Stale cleanup fences the exact tuple, waits pre-fence readers, then revalidates; never overwrite/delete newer incarnations.
- **NFQUEUE lifecycle is fatal/fenced after admission:** listener/queue/verdict/watchdog/cleanup/retirement ambiguity terminates the control plane. Reload/shutdown: clear ready → quiesce kernel stagers → reject ingress → cancel/drain guards/leases/retirements/scheduled token cleanups → detach producers → close queue → delete owned table last. Preserve raw rollback-compatible `UDP_DECISION_SEQUENCE` during ordinary cleanup. Exhaustion uses the same fence/drain and empty-generation-suffix rule in `honk-core`'s `src/ebpf/`. If no suffix is clear, retry with staging fenced; never collide or require reboot.
- **must/block are final:** a matching configured `must` rule is terminal; Clash mode override never overrides `block` or `must` results.
- **Fail-closed on dead outbounds:** `lan_ingress` normally drops new dead-outbound flows (`TC_ACT_SHOT`). Exception: exactly one unique TCP leaf and no `final` keeps the eBPF slot open and the same proxy as userspace last resort. Real success can revive it without leaking to `direct`; UDP/all-dead multi-leaf groups remain closed. Built-in `direct`/`block` never die, keeping containing groups' OR slots alive. Port 53 TCP+UDP is always exempt (dae parity).
  LAN-facing specifically bound local `:53` listeners, including `dns.bind`, take precedence for their transport via local-socket probe. Wildcards additionally require full destination FIB `NOT_FWDED`, preventing remote resolvers bypassing transparent DNS. Empty `bind` preserves interception. At startup/reload/interface topology changes, refresh `dip(<every lan/wan iface address>) -> direct(must)` via `Config::ensure_local_direct_rules`; gateway admin/SSH/API must not depend on node health. Network events clear stale probe cooldowns and schedule immediate checks; other dead nodes stay closed until fresh success verifies recovery.
- **eBPF connectivity pushes are group-OR plus the sole-TCP-leaf exception:** publish OR of leaf-member states into the shared group alive slot, with the last-resort exception above. One dead member must never `TC_ACT_SHOT` an entire multi-leaf group.
- **Internal traffic is never proxied:** own-link `169.254.0.0/16`, `fd00:686f:6e6b::/64`. **Broadcast/multicast passes through eBPF:** `dst_is_special()` (crates/honk-ebpf/src/transport.rs) early-exits L2 broadcast/multicast MAC, 255.255.255.255, 224.0.0.0/4, 0.0.0.0, ff00::/8 in lan_ingress/lan_egress/wan_egress. DHCP/mDNS/SSDP never enter routing/conntrack; otherwise OpenWrt LAN DHCP breaks. Keep lan_ingress NAT-loopback local-socket probing unconditional (Go dae parity), detecting local services such as dnsmasq.
- Reserved outbound indices: `0 Direct | 1 Block | 2+ user groups | 0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND`.
