### honk-core with real eBPF

Read with: `AGENTS.md` (Technology stack, Current validation guidance, Notes for agents); `configuration.md` for NFQUEUE activation; `test-locations.md` for where the real-kernel tests live; the VM procedure is `.github/workflows/ci.yml` and skill `honk-real-ebpf-tests`.

The proxy engine (library `honk_core` + `honk-core` binary). Cargo features:

- `default = ["clash-api", "mimalloc", "rprx"]`
- `ebpf` — aya real backend + `honk-nfqueue`, requires Linux kernel 6.12+; otherwise `MockEbpfBackend`. NFQUEUE activation follows `configuration.md`.
- `clash-api` — Clash-compatible REST/WS API (pulls in optional axum/tower-http).
- `mimalloc` — shipped binary allocates through mimalloc (see Technology stack in `AGENTS.md`); build with `--no-default-features --features "clash-api,ebpf,rprx"` for a stock-malloc binary.
- `rprx` — forwards to `honk-outbound/rprx`: registers VLESS (VLESS Encryption and xtls-rprx-vision) and VMess handlers; without it VLESS/VMess nodes parse fine but fail at dial with "No handler for protocol".

Score is always compiled, without a Cargo feature; omitted policy selects Selector.

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

Token-zero WAN UDP publishes explicit userspace ownership in RoutingMeta bit 58;
native unmarked WAN direct instead publishes OFFLOAD. WAN cached and fresh writers
must join the UDP reader epoch and honor the tuple retirement fence. Retire owned
conn-state, handoff and redirect metadata together only after checking auxiliary
tokens; preserve native/offloaded, missing and newer-token authority. Never infer
WAN ownership from `must` alone or change the persistent 12-byte allocator ABI.

`build.rs` always emits `HONK_VERSION` from the GitHub release tag, local `git describe`, or Cargo package version without Git metadata. `honk_core::VERSION` supplies both CLIs and Clash `/version`; runtime needs no Git. With `ebpf`, locate `crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf` or `target/honk-core.o` and **verify `.BTF`**. Missing, BTF-less or stale objects trigger a rebuild with the channel read from `crates/honk-ebpf/rust-toolchain.toml`, stripping child `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`: environment flags override `crates/honk-ebpf/.cargo/config.toml`'s `--btf` and silently omit BTF. The object records its compiler channel in a `.toolchain` sidecar; source or pin changes invalidate it. Copy to `OUT_DIR/honk-ebpf.o`, set `HONK_EBPF_OBJECT`; `lib.rs` embeds with `include_bytes!`. Runtime override: `--bpf-object`.

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


