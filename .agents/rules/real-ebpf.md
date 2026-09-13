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


