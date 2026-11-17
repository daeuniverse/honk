### honk-core with real eBPF

Read with: `AGENTS.md` (Technology stack, Current validation guidance, Notes for agents); `configuration.md` for NFQUEUE activation; `test-locations.md` for where the real-kernel tests live; the VM procedure is `.github/workflows/ci.yml` and skill `honk-real-ebpf-tests`.

The proxy engine (library `honk_core` + `honk-core` binary). Cargo features:

- `default = ["clash-api", "jemalloc", "rprx"]`
- `ebpf` — aya real TC backend + `honk-nfqueue`, requires Linux kernel 6.12+; default TC otherwise uses `MockEbpfBackend`. Physical XDP and TUN use the shared userspace policy backend. Explicit XDP Host and TUN `host_facts: true` require the feature and real source admission; TUN false remains independently buildable. TUN requires `/dev/net/tun`, device/route and SO_MARK privileges, rejects mock and requires NFQUEUE off. It provides no Native or captured-return capability. NFQUEUE activation follows `configuration.md`.
- Explicit XDP `datapath.host` additionally requires the built `ebpf` feature and actual one-shot Host runtime admission: x86-64 little endian, exact running-kernel BTF/layout, current/worker/children time namespaces agreeing with zero MONOTONIC offset, active BPF LSM with final socket-retirement canary, exact effective root-cgroup hooks/descendants, ready private Copy XSK/consumer, plain namespace-wide custody and create-new receipt. Ordinary operator veths, stacked/mastered/tunnel links and foreign TC/XDP/netfilter/XFRM reinjection compositions currently refuse; only the exact owned private pair is excepted from the link restrictions. The sole nonempty netfilter exception is active AppArmor's native kernel-reported built-in `apparmor_ip_postroute` at IPv4/IPv6 POSTROUTING priority -225, at most one per family, with no device/module/NFT/BPF-chain, duplicate/missing/unknown/flagged or malformed metadata. The callback symbol derives from the actual registered pointer under the trusted-stock-kernel contract; `%ps` is not offset/code attestation. Full inventories retain observed counts/raw records and reject drift; fast RTNL checks may skip netfilter queries. Original security denials remain before source capture; generated replies retain ordinary ingress/security processing without original socket-label/secmark or identical-decision equivalence. Privileged concurrent topology/hook/code mutation is excluded by contract, not atomically fenced by notifications. Stale receipts refuse restart without adoption; confirmed guarded-retained stop is not full removal. Native/TUN S-b/c/d and full V7/E6/E7/physical/13-size acceptance remain separate obligations; native compilation or primitive tests cannot certify them.
- XDP Host's admission does not establish TUN S-b or Native capability. TUN `host_facts: true` needs its own actual socket-source/read admission and lifecycle evidence; no Native/captured-return acceptance follows.
- `clash-api` — Clash-compatible REST/WS API (pulls in optional axum/tower-http).
- `native-api` — independent, opt-in native HTTP observations/control with a default-off listener; build with `--features native-api` (or `native-ui`); the full and `-native-api` release artifacts include it. It can run with mock or real eBPF and without Clash; real-kernel CI enables it for lifecycle regression coverage.
- `jemalloc` — shipped binary allocates through jemalloc (see Technology stack in `AGENTS.md`); build with `--no-default-features --features "clash-api,ebpf,rprx,native-ui"` for the release capabilities with stock malloc. `native-ui` embeds both pinned doona editions and requires the absolute standard directory `HONK_DOONA_DIR` plus its `-lite` sibling (`export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`); use `native-api` instead only when embedded hosting (`ui: embedded` or `ui: embedded-lite`, the lighter doona lite preview edition; both need `native-ui`) is not needed.
- `rprx` — forwards to `honk-outbound/rprx`: registers VLESS (VLESS Encryption and xtls-rprx-vision) and VMess handlers; without it VLESS/VMess nodes parse fine but fail at dial with "No handler for protocol".

Score is always compiled, without a Cargo feature; omitted policy selects Selector.

Native XDP is an additional consumer of `UserspaceBackend`, not the TC backend. Require `direct: native`, the real `ebpf` build, `dial_mode: ip`, disabled NFQUEUE and untagged physical capture. The canonical emitter runs through real XDP/TCX wrappers; an emitted `RoutingInput` function body is never an XDP entry. XDP admits before packet taps, and the required pinned `honk_nat_gate` ingress TCX dispatcher fails closed without a current candidate. Native root odd epochs are open, even/zero epochs closed. Runtime readiness follows all target/topology and packet-supervisor readiness; mode/reload/DNS writers use counted closure and fresh reader grace. Keep the actual module-BTF/kfunc loader and floor/recent verifier outcomes explicit.

Native imports carry 64 bytes of metadata: the existing 32-byte envelope plus a 32-byte import containing producing epoch, owner incarnation, original BOOTTIME expiry and COUNTED flag. The non-LRU claim map uses 56-byte keys and 72-byte values; the single private operation is 264 bytes. A joined cold restart replaces maps, programs and metadata together: reject old 40-byte key/value maps, 48-byte metadata and old readers, with no adoption. Transit requires zero Host owner fields and Keep/0 mark. Only Kernel/Active with zero outstanding uses ordinary non-53 UDP cached Direct; activity refreshes only after >1s, and an idle >120s hit refuses without revival. Under the existing closed writer, reader grace and RX/CQ drain, retire only the exact unchanged expired cache when the real gate query confirms no CT/socket and `PacketEndpoints::retains` is false. Live/unknown owners retain exclusion; query/test-run through the marked query branch does not refresh activity. Capture claims retain actual Endpoint/protocol/TIME_WAIT/source/output/CQ owners. Cache retirement is not skb finalization or transfer evidence. Host Native, late TCP sniff original consumption, fragments, TCP lifecycle alignment and arbitrary CT-zone/NOTRACK compositions have no implied acceptance.

The Transit first consumer chooses before protocol/Core mutation. A Pending original is committed to Capture before Endpoint admission or retained as a whole chain for one TAP write, during which the same-generation canonical gate decides admission. Target `_one_core` entry followed by a newly started same-publication Grace proves transfer; write results alone do not. Followers remain ordered and Active requires the exact outstanding count to reach zero with no held original or private flight. Unknown transfer or failed joins retain the bounded owner, operation, charge and guards; no timeout refund or replay. See [datapath](../../doc/en/design/datapath.md) for TAP prerequisites and recovery. The all65 matrix and real-kernel gates remain unverified by this description.

Native terminal capture intent is not release proof: require successful guards/XSK withdrawal/private seal and fresh post-guard Grace before disposing any original or acknowledging Port completion. Close failures remain sticky, including after a restored private operation record; no repeated close may manufacture joined custody. Keep the original topology authority live through exact owned TAP seal/detach/last-FD-close transactions and late guard checks; never whitelist ifindices, reset invalidation or adopt a new watcher during teardown. Failed recording-hook withdrawal still attempts terminal reader Grace but cannot seal counters or complete collection. Real watcher tests live under `bpf::general::tests::native_watch::kernel_` and require explicit nonempty VM selection; the parent `tests::kernel_` filter does not include them.

Private preparation reserves from the same 384 MiB `CAPTURE_MEMORY` budget, then admits running BTF once with `/dev/net/tun` held, then creates TAP; the loader admits at most 480 captured targets. Port retained slots reserve `R * 1024` and Runtime metadata `R * 192`, where `R = min(rx_frames, ring_size)` per queue. Reply/NAT-translated originals with wire key different from CT ORIGINAL and cross-realm Pending/Armed/Draining inputs drop before reservation/redirect, without a separate drop counter; replies in Draining need retransmission. Those lanes and negative `writev` after admission remain NOT_RUN. Recovery requires the durable joined file, matching `CAPTURED_JOINED_ACK` digest and exact live kernel inventory; an unacknowledged filename is insufficient. See `honk-xsk/src/bpf/native/captured.rs`, `honk-xsk/src/bpf/native.rs`, `honk-core/src/xdp/native/captured.rs` and the bilingual design pages. All65/E7 remain NOT_RUN.

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
The VM gate includes compiled routing (its exact-name-guarded `dns_ownership::tcx::unsupported_lan_ingress_frames_continue_tcx_without_marking`), real backend/datapath, NFQUEUE/netns,
TCP accepted-FD child-proof and tuple-reuse ownership, UDP fullcone source ownership, real VLAN/macsec frame cases,
bond binding, native lifecycle, UDP receive tracing (including per-family attachment failure), route-only watcher,
lazy interface binding and SO_MARK socket checks. Exact nonempty
selections in the guest gate must remain intact. The same guest gate then runs the matching real daemon's XDP/native-control/guard smoke and omitted-datapath TC startup/reload, with Core/XSK ignored cases restricted to its owned private namespace.

TUN S-a real-FD validation belongs to `.github/ci/tun-daemon-smoke.sh`, restricted to the same disposable floor/recent guest and its private namespaces with a matching daemon. The fixture owns operator forwarding/firewall/main-route prerequisites; the daemon must own TUN/address/table/five-rule/receipt setup. The complete gate must retain TC/XDP selections and exercise all twelve A Host/Transit × IPv4/IPv6 × TCP/connected/unconnected UDP rows, actual proxy and Endpoint Direct exchanges, FD/read-write/mark/DNS/reload/failure/representation subrows and confirmed stop versus crash guards. Socketpair/unit tests are not TUN evidence; record missing rows as NOT_RUN, never HostFacts/Native or E6.4 acceptance. This location/required matrix is not a claim that the gate has run.

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

Keep every object map unpinned, including allocator maps; core owns explicit pin paths (see [object admission](../../doc/en/design/control-plane.md#startup-and-shutdown)).

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

Kernel eBPF, **excluded from the workspace**, own `Cargo.lock`. Edition 2024, `aya-ebpf` 0.3; release `panic = "abort"`, `lto = true`, `opt-level = 2`. `src/main.rs`: `#![no_std] #![no_main]`, spin-loop panic handler, module declarations. Optional `log` enables `aya-log-ebpf`; otherwise `log_shim.rs` macros are no-ops.

```bash
cd crates/honk-ebpf
cargo build --release -Zbuild-std=core --target bpfel-unknown-none
```

`.cargo/config.toml` resolves `bpf-linker` from `PATH`. The root `rust-toolchain.toml` pins the host compiler; `crates/honk-ebpf/rust-toolchain.toml` pins the eBPF compiler and components for local builds and CI. CI pins the prebuilt `bpf-linker` 0.11.0 release.


