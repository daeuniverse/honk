### honk-core with real eBPF

Read with: `AGENTS.md` (Technology stack, Current validation guidance, Notes for agents); `configuration.md` for NFQUEUE activation; `test-locations.md` for where the real-kernel tests live; the VM procedure is `.github/workflows/ci.yml` and skill `honk-real-ebpf-tests`.

The proxy engine (library `honk_core` + `honk-core` binary). Cargo features:

- `default = ["clash-api", "mimalloc", "rprx"]`
- `ebpf` — aya real backend + `honk-nfqueue`, requires Linux kernel 6.12+; otherwise `MockEbpfBackend`. NFQUEUE activation follows `configuration.md`.
- `clash-api` — Clash-compatible REST/WS API (pulls in optional axum/tower-http).
- `native-api` — independent, opt-in native HTTP observations/control with a default-off listener; build with `--features native-api` (or `native-ui`); the full and `-native-api` release artifacts include it. It can run with mock or real eBPF and without Clash; real-kernel CI enables it for lifecycle regression coverage.
- `mimalloc` — shipped binary allocates through mimalloc (see Technology stack in `AGENTS.md`); build with `--no-default-features --features "clash-api,ebpf,rprx,native-ui"` for the release capabilities with stock malloc. `native-ui` embeds the pinned doona build and fails without an absolute `HONK_DOONA_DIR` (`export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`); use `native-api` instead only when embedded hosting (`ui: embedded`) is not needed.
- `rprx` — forwards to `honk-outbound/rprx`: registers VLESS (VLESS Encryption and xtls-rprx-vision) and VMess handlers; without it VLESS/VMess nodes parse fine but fail at dial with "No handler for protocol".

Score is always compiled, without a Cargo feature; omitted policy selects Selector.

Preserve [TCX finality](../../doc/en/design/datapath.md#interface-hook-sets): unguarded, mark-preserving passes continue with NEXT; mark writers and existing ownership guards terminate with PASS, never PIPE as continuation.

`RoutingInput.flags` reuses the final 32-bit word for independent MAC presence
and direct-finality permission captured from the caller's Rule-mode flags.
Only domain-independent live prefixes may use that permission; Global retains
its previous handoff/sniff authority. Keep the 128-byte input/328-byte witness
sizes and reject old `mac_present` objects through nested-input BTF validation.

Native routing keeps domain resolution in the prologue for `domain_final`.
Complete positive/negative port conditions precede the other conditions within
each rule; non-domain facts use per-invocation READY-guarded bitmap copy/zero-fill.
Missing facts count as resolved. The READY mask is loaded back from the
decision's zeroed `mark`, the unresolved areas are pre-filled from independent
loads of that field, and each guard is a `jset` on the mask register itself; a
constant mask, an area spilled from the mask register, or a guard on a copy of
the mask each split verifier states per resolution history and multiply the walk
of the later process-name chains (measured on Linux 6.12.107, roughly 3× for the
#280 policy; `doc/en/design/routing.md`).
Keep the emitter's private tests in `control/routing_matcher/codegen/tests.rs`;
real decision/load goldens remain in `ebpf/real/routing/tests/`.

Never infer token-zero WAN userspace ownership from `must`: keep its ownership bit distinct from OFFLOAD and check tuple fences before borrowing state. Retirement and initial staged commits follow the [fence/grace protocol](../../doc/en/design/nfqueue.md#exact-tuple-retirement), preserving the locked `DirectArmed` activation exception and frozen staged timestamps.

Use coherent locked conn snapshots; a refused UDP lookup is not a publication miss, and auxiliary ownership/freshness checks remain independent. Capture WAN UDP socket identity before cached-route lookup so tuple reuse cannot bypass the control-plane identity check.

Reserve UDP `cb[4]` for its listener marker without disturbing the TCP SYN incarnation carrier; every listener-selection path must use the shared host-byte-order tuple hash. Layout and admission contracts live in [datapath](../../doc/en/design/datapath.md), not duplicated constants here.

TCP cached-SYN classification queries the FD-owned daens by its explicit
host-relative namespace ID, never the packet namespace or an assumed ID zero.
ABI sizes: ConnState 72 bytes (80 with its lock wrapper), TcpSocketBinding 120
with syn_isn at offset 116, DaeParam 44. The sock_ops child proof compares the
owned daens netns cookie and reads no kernel structure. Proof selection, IPv6
and sysctl rules live in `AGENTS.md` (Notes for agents).

Socket process identity is native non-cloned `SK_STORAGE`, captured once by
create/connect/sendmsg and reclaimed only with the actual socket object. The
hooks sit on the root cgroup, so capture failure is counted and the operation
proceeds without identity; no cookie hash, release hook or janitor remains.
Required cgroup attachment failure aborts startup. Discover cgroup mounts through
`/proc/thread-self/mounts`; root-cgroup tests require a disposable VM, because
private mount/network namespaces do not isolate cgroup BPF attachment.

`just test-routing` and `just test-netns` both use the existing disposable VM
gate (`.github/ci/run-vm-gate.sh floor`); `test-netns` retains `test-routing` as
its dependency and boots only one guest. The complete routing suite also has
root-cgroup cases, so neither recipe executes ignored tests on the host.
The VM gate includes compiled routing, real backend/datapath, NFQUEUE/netns,
TCP accepted-FD child-proof and tuple-reuse ownership, UDP fullcone source ownership,
native lifecycle, route-only watcher and SO_MARK socket checks. Exact nonempty
selections in the guest gate must remain intact.

Use skill `honk-real-ebpf-tests` for the prerequisite sequence from CI: an
x86_64 Ubuntu 24.04 host, repository-pinned Rust toolchains, build/VM packages,
checksum-pinned virtme-ng and bpf-linker, geo assets, both BTF-bearing objects,
and the runner's workspace/temp/summary environment. Host dependency setup
requires root; the guest runs as root. KVM access is optional with explicit TCG
fallback. The recipes do not install host packages or change shared-host KVM
permissions. Non-x86_64/non-Linux hosts and restricted containers without these
prerequisites cannot run this runner; report the gate as not run and use CI.
Native builds and unprivileged tests remain supported, but Linux 6.12+ and root
are not sufficient isolation for direct protected-suite execution. Never invoke
the guest script directly on a host or export its VM identity markers to bypass
the fixture guard.

`build.rs` always emits `HONK_VERSION` from the GitHub release tag, local `git describe`, or Cargo package version without Git metadata. `honk_core::VERSION` supplies both CLIs and Clash `/version`; runtime needs no Git. With `ebpf`, locate `crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf` or `target/honk-core.o` and **verify `.BTF`**. Missing, BTF-less or stale objects trigger a rebuild with the channel read from `crates/honk-ebpf/rust-toolchain.toml`, stripping child `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`: environment flags override `crates/honk-ebpf/.cargo/config.toml`'s `--btf` and silently omit BTF. The child also strips inherited `CARGO_PROFILE_*` overrides so host profiling cannot replace the standalone kernel crate's release policy. The object records its compiler channel in a `.toolchain` sidecar; source or pin changes invalidate it, and a sidecar older than core's `build.rs` triggers a rebuild after embedding-policy changes. Copy to `OUT_DIR/honk-ebpf.o`, set `HONK_EBPF_OBJECT`; `lib.rs` embeds with `include_bytes!`. Runtime override: `--bpf-object`; manually built or supplied objects remain the caller's responsibility.

```bash
# Requires Linux kernel 6.12+, clang/llvm/libbpf headers, nightly + bpf-linker.
# build.rs auto-builds the eBPF object on first build (~30s).
cargo build --release -p honk-core --features ebpf
sudo ./target/release/honk-core --config /etc/honk/config.dae          # embedded object
sudo ./target/release/honk-core --config c.dae --bpf-object /path.o    # external object
```

NFQUEUE activation, mock/preflight fallback, and restart requirements: `configuration.md`.

Dev without kernel eBPF (unprivileged):

```bash
cargo run --release -p honk-core -- --config config.min.dae --mock-ebpf
```

### eBPF program standalone

Kernel eBPF, **excluded from the workspace**, own `Cargo.lock`. Edition 2024, `aya-ebpf` 0.2; release `panic = "abort"`, `lto = true`, `opt-level = 2`. `src/main.rs`: `#![no_std] #![no_main]`, spin-loop panic handler, module declarations. Optional `log` enables `aya-log-ebpf`; otherwise `log_shim.rs` macros are no-ops.

```bash
cd crates/honk-ebpf
cargo build --release -Zbuild-std=core --target bpfel-unknown-none
```

`.cargo/config.toml` resolves `bpf-linker` from `PATH`. The root `rust-toolchain.toml` pins the host compiler; `crates/honk-ebpf/rust-toolchain.toml` pins the eBPF compiler and components for local builds and CI. CI pins the prebuilt `bpf-linker` 0.11.0 release.


