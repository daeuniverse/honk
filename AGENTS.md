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

Real-eBPF and standalone eBPF builds: `.agents/rules/real-ebpf.md`. CI and releases: `.agents/rules/release.md`.

### Justfile (preferred for day-to-day dev)

| Recipe                                                                          | Purpose                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build` / `check` / `lint` / `fmt` / `fmt-check`                                              | `cargo build --release` / `check` / `clippy --all --all-targets -- -D warnings` / `fmt --all` / `fmt --all -- --check`                                                                                                                                                                 |
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

## Current validation guidance

Do not treat dated pass counts as repository status; use the current command output and CI for that evidence. The workspace gate below retains the known legacy routing exclude. The current compiled-routing gate is `just test-routing`: it builds a real `routing-test` eBPF object and exercises independent policy goldens plus preservation of the active root when publication fails.

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  cargo test --workspace --no-fail-fast -- \
    --skip test_routing_with_config_dae
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

REALITY `dest` TLS Certificate messages must stay **under 8 KiB**: sing-box buffers
8192 bytes; `dl.google.com` works, `www.microsoft.com` at 8273 B fails.

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
- **UDP transport invariant:** production endpoints use `PacketTransport`. Tunnel handlers frame datagrams directly: trojan, AnyTLS/VLESS UoT v2, VLESS H2MUX native connected UDP, VLESS XUDP/Mux.Cool, SS, TUIC/Hy2, and Juicity. Direct and SOCKS5 hide raw sockets behind the same contract; no loopback bridges remain. `UdpEndpointPool` retires dead transports rather than black-holing flows.
  UDP drivers capture the terminal Score outcome before their own synchronous health-death callback can retire the endpoint. Terminal transport errors and no-reply idle expiry affect DataUdp health; packet-local congestion, idle-after-reply, intentional retirement, and shutdown do not.
- `resolve_group_filters`: case-sensitive `name(...)` and dae-compatible `subtag(...)`, supporting exact/`keyword:`/`regex:`. `&&` ANDs predicates with `!` negation; separate `filter:` lines OR them. `subtag` maps `Node.subscription_id` to current subscription tag. Rebuild filtered membership after refresh so stable IDs cannot retain stale provenance. Include all nodes **only** with neither node filters nor sub-groups.
- [`src/node.rs`](crates/honk-config/src/node.rs) — `Node` has only shared identity/endpoint/provenance plus typed `OutboundConfig`; use variant accessors for protocols. Also owns `Group`/`GroupPolicy` and normalized `WireMode::{Legacy,UotV2,H2mux,H2muxPadded,Xudp,MuxCool}`. `src/node/protocol.rs` owns per-protocol configs, shared TLS/stream/QUIC options, and canonical VLESS/ALPN checks. `src/node/validation.rs` owns intrinsic and collection admission, attaching typed field/cause diagnostics only on failure. Sole serde adapter `src/node/wire.rs` preserves legacy flat TOML/YAML/JSON shape/order and carries semantic errors without a prose round trip.
  `parser/diagnostics.rs` attaches current node-entry source, line and ordinal to both share-link warnings and returned typed errors. Node tags must not be used as schema-field locations for these diagnostics.
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
- **Fail-closed on dead outbounds:** `lan_ingress` normally drops new dead-outbound flows (`TC_ACT_SHOT`). Exception: exactly one unique TCP leaf and no `final` keeps the eBPF slot open; userspace may attempt that same leaf only through the current Selector member paths, never bypassing a chosen empty sub-group. Selector TCP/UDP never replace a valid choice with a sibling for health. Real success can revive the leaf without leaking to `direct`; UDP/all-dead multi-leaf groups remain closed. Built-in `direct`/`block` never die, keeping containing groups' OR slots alive. Port 53 TCP+UDP is always exempt (dae parity).
  LAN-facing specifically bound local `:53` listeners, including `dns.bind`, take precedence for their transport via local-socket probe. Wildcards additionally require full destination FIB `NOT_FWDED`, preventing remote resolvers bypassing transparent DNS. Empty `bind` preserves interception. At startup/reload/interface topology changes, refresh `dip(<every lan/wan iface address>) -> direct(must)` via `Config::ensure_local_direct_rules`; gateway admin/SSH/API must not depend on node health. Network events clear stale probe cooldowns and schedule immediate checks; other dead nodes stay closed until fresh success verifies recovery.
- **eBPF connectivity pushes are group-OR plus the sole-TCP-leaf exception:** publish OR of leaf-member states into the shared group alive slot, with the last-resort exception above. One dead member must never `TC_ACT_SHOT` an entire multi-leaf group.
- **Internal traffic is never proxied:** own-link `169.254.0.0/16`, `fd00:686f:6e6b::/64`. **Broadcast/multicast passes through eBPF:** `dst_is_special()` (crates/honk-ebpf/src/transport.rs) early-exits L2 broadcast/multicast MAC, 255.255.255.255, 224.0.0.0/4, 0.0.0.0, ff00::/8 in lan_ingress/lan_egress/wan_egress. DHCP/mDNS/SSDP never enter routing/conntrack; otherwise OpenWrt LAN DHCP breaks. Keep lan_ingress NAT-loopback local-socket probing unconditional (Go dae parity), detecting local services such as dnsmasq.
- Reserved outbound indices: `0 Direct | 1 Block | 2+ user groups | 0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND`.
