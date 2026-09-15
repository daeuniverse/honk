## Test locations

Read with: `AGENTS.md` (Testing instructions); `real-ebpf.md` for the root-gated real-kernel tests; `configuration.md` for what the honk-config tests cover.

### Placement convention

- Keep small private unit suites inline. Use `src/<owner>/tests.rs` when extraction improves readability; only sizeable, distinct topics need `src/<owner>/tests/<topic>.rs` children, loaded with ordinary `mod`, not textual `include!`.
- Public integration suites belong in `crates/<crate>/tests/<subsystem>.rs`. Each top-level file is a separate Cargo executable: combine related regressions rather than adding an executable per bug or PR, but split by ownership before a new suite grows past 1000 lines.
- Name test modules and fixture directories for behavior, not PR numbers or investigation IDs. Keep byte-sensitive/file-loading fixtures in `tests/fixtures/<subsystem>/`; preserve their contents when moving them.
- Put shared helpers at the nearest common test-module owner. Do not import fixtures from another test-case suite; keep single-suite helpers with that suite.
- Preserve process isolation where global tracing, environment, or allocator state requires it. `honk-config/tests/logging.rs` contains only scoped-subscriber logging checks with independent capture buffers; data-only tests stay in other executables so `NoSubscriber` cannot poison shared callsite interest.

### Suite map

- Configuration:
    - `crates/honk-config/src/node.rs`, `src/node/vless.rs`, `src/config.rs`, `src/types.rs`, `src/parser/tests.rs` — canonical VLESS UDP/multiplex normalization and validation, GroupPolicy serde, protocol durations, dae defaults/errors, file loading and private parser units.
    - `crates/honk-config/tests/parser_syntax.rs`, `entries.rs`, `dns_parser.rs` — scalar/routing/section grammar, named node/subscription/group entries, and DNS grammar respectively.
    - `crates/honk-config/tests/diagnostics.rs`, `validation.rs` — safe diagnostics across loaders/serde and shared admission boundaries.
    - `crates/honk-config/tests/example_configs.rs` — keeps `config.dae`, `config.min.dae`, `example.dae` parseable.
    - `crates/honk-config/tests/include.rs` — file-based dae include loading (glob order, nested paths, merge semantics, cycles, directory boundaries, and preservation of policy errors).
    - `crates/honk-config/tests/dns_validation.rs` — named upstream references, original diagnostic paths, complete rule traversal, and shared effective-request precedence.
    - `crates/honk-config/tests/share_link.rs` — share-link parsing + config format round-trips.
    - `crates/honk-core/src/subscription/tests/admission.rs` — subscription admission, original diagnostic provenance, valid-sibling salvage and bounded diagnostic retention; fetch/store tests and shared body fixtures remain with `subscription/tests.rs`.
- Runtime and transport:
    - `crates/honk-nfqueue/src/*` — NFQA parsing, netlink/nft encoding, exactly-once verdicts; the ignored `kernel_tests.rs` contract exercises the production queue/table in an isolated real netns.
    - `crates/honk-outbound/src/group/tests.rs`, `group/tests/udp_selection.rs`, and `group/score/tests/` — selection semantics (Selector/URLTest/LoadBalance/Fallback/Score, nested groups, UDP exclusion), target attribution, decay and metric qualification, deterministic exploration, reporter lifecycle, reload sharing, and LRU safety.
    - `crates/honk-outbound/src/alive/tests.rs` — health-check state machine, probe semantics, idle suspension.
    - `crates/honk-outbound/src/proxy/hysteria2/tests.rs`, `src/urltest/tests/http2.rs`, and inline `#[cfg(test)]` in `proxy/*`, `urltest.rs`, `bootstrap.rs` — wire vectors and test-only loopback/in-process QUIC interop (`quic::testutil`). Production transport: the **UDP transport invariant** in `AGENTS.md` (Notes for agents).
    - `crates/honk-outbound/src/reality.rs` and `reality/wire_tests.rs`; `proxy/vless.rs`, `proxy/vless/{carrier,packet,stream}.rs`, and `proxy/vless/tests/{pools,udp,stream_tests,protocol,interop}.rs`; `proxy/vless_cool.rs`, `proxy/vless_cool/{codec,child}.rs`, and `proxy/vless_cool/tests/{cancellation,session,codec_tests}.rs`; `proxy/vless_mux.rs` and `proxy/vless_mux/tests.rs`; `runtime/vless.rs` and `runtime/tests/vless_runtime.rs` (`#[cfg(feature = "rprx")]`) — REALITY byte/auth and first-flow behavior; VLESS framing/Vision/encryption; source-capable XUDP, H2MUX, Mux.Cool carrier lifecycle/capacity, speculative publication, warm/reload behavior, and official interop.
    - `crates/honk-core/tests/integration_test.rs` — loaded config-to-Router decisions, routing, stats, reload/subscription-merge pipeline, and daemon/CLI behavior. Direct/block and splice payload/accounting coverage stay in their owning unit suites.
    - `crates/honk-core/tests/clash_api_test.rs` — Clash API endpoints (auth, proxies, Score representation/current winner/PUT rejection, delay, connections, traffic/logs chunked + WS, `/dns/query`, cache flush, providers, UI hosting, store_dns).
    - `crates/honk-core/tests/dns_runtime_test.rs` — public reload, hosts, DNS policy/transport replacement and cache boundaries; loopback support stays in the suite.
    - `crates/honk-core/src/control/tests.rs` and `tests/` — control-plane behavior, admission, diagnostics and health; shared fixtures live in `tests/support.rs`. Owner-specific connection/prober/DNS/NFQUEUE suites remain with their modules.
    - `crates/honk-core/src/control/udp_endpoint/source.rs`, `source/reply.rs`, `source_tests.rs`, and `source_tests/{cross_source,regressions}.rs` — VLESS source-scope reuse, cross-source carrier isolation, original-address reply delivery, queue-versus-I/O admission, capacity, Score/health separation, and retirement fencing.
    - `control/sockets/tests.rs` owns socket options, receive batching and ancillary decoding; `control/udp_ingress/tests.rs` owns destination provenance. Shared control fixtures stay in `control/tests/support.rs`.
    - `crates/honk-core/src/dns/<owner>/tests.rs` and topic children — resolver/cache/engine/forwarder/policy/runtime tests, using native Rust modules.
    - Inline unit tests in the other owning modules cover mode, stats, routing, relay and transports. Real-backend tests require `ebpf`; ignored netns tests require root. `honk-core/tests/ebpf_datapath_test.rs` remains a separate root-gated target for `just test-netns` and CI.
    - `crates/honk-core/src/routing/lan_protection.rs` — conservative advisory coverage: ordered terminal ownership, unknown predicates, address families and non-DNS port/protocol boundaries.
    - `crates/honk-tool/tests/{geo_cli,diagnose_cli}.rs` — toolbox process-level contracts; command internals stay in their owning unit modules.

### Benchmarks

Benchmarks kept on `main`: `benches/dns.rs` (criterion, `harness = false`) covers DNS endpoint parse, cache get/put + 90/10 mix, per-query routing match, framing, forwarder cache-hit, and TcpPool/UpstreamPool exchange; run `cargo bench -p honk-core --features dns-bench --bench dns`. `benches/udp.rs` is the candidate-only UDP Criterion suite; run `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`. Lab/deployment harnesses, raw evidence, and their documentation live only on branch `bench`; use `git worktree add ../honk-bench bench` when benchmarking so they never enter the `main` worktree.

`benches/reload.rs` measures an unchanged-effective-config runtime reload's wall/CPU time, allocations, and mock eBPF writes; run `cargo bench -p honk-core --bench reload --no-default-features --features reload-alloc-bench`.

`cargo bench -p honk-outbound --features rprx --bench vless_vision` covers the Vision transport.

`just test-config` and `just test-core` include their crates' unit and integration suites. `just test-routing` and `just test-netns` retain the real-kernel gates, including the route-only network watcher selected by exact name with a nonempty-list check; moving test files must not alter their feature or ignore requirements. Native kernel gates may attach to loopback/root cgroups and mutate test links/routes in the current namespace; use the CI VM gate on a shared host rather than assuming every native test is isolated.
