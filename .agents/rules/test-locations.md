## Test locations

Read with: `AGENTS.md` (Testing instructions); `real-ebpf.md` for the root-gated real-kernel tests; `configuration.md` for what the honk-config tests cover.

- Test locations:
    - `crates/honk-config/src/node.rs`, `src/config.rs`, `src/parser/tests.rs` — GroupPolicy serde, dae policy/default/errors, file loading, parser units: sections, groups, nested filters, DNS upstreams/routing, subscriptions, experimental.
    - `crates/honk-config/tests/example_configs.rs` — keeps `config.dae`, `config.min.dae`, `example.dae` parseable.
    - `crates/honk-config/tests/include.rs` — file-based dae include loading (glob order, nested paths, merge semantics, cycles, directory boundaries, and preservation of policy errors).
    - `crates/honk-config/tests/dns_validation.rs` — named upstream references, original diagnostic paths, complete rule traversal, and shared effective-request precedence.
    - `crates/honk-config/tests/share_link.rs` — share-link parsing + config format round-trips.
    - `crates/honk-nfqueue/src/*` — NFQA parsing, netlink/nft encoding, exactly-once verdicts; the ignored `kernel_tests.rs` contract exercises the production queue/table in an isolated real netns.
    - `crates/honk-outbound/src/group/tests.rs`, `group/score/tests/`, and `group/udp_selection_repro_tests.rs` — selection semantics (Selector/URLTest/LoadBalance/Fallback/Score, nested groups, UDP exclusion), target attribution, decay and metric qualification, deterministic exploration, reporter lifecycle, reload sharing, and LRU safety.
    - `crates/honk-outbound/src/alive/tests.rs` — health-check state machine, probe semantics, idle suspension.
    - `crates/honk-outbound/src/proxy/hysteria2/tests.rs` + inline `#[cfg(test)]` in `proxy/*`, `urltest.rs`, `bootstrap.rs` — wire vectors and test-only loopback/in-process QUIC interop (`quic::testutil`). Production transport: the **UDP transport invariant** in `AGENTS.md` (Notes for agents).
    - `crates/honk-outbound/src/reality.rs` + `proxy/vless.rs` + `proxy/vless_mux.rs` + `proxy/vless_cool.rs` + `proxy/vless_encryption.rs` (`#[cfg(feature = "rprx")]`) — REALITY vectors; VLESS headers/Vision; UoT v2; sing-mux/H2 flow control; XUDP/Mux.Cool codecs, carrier lifecycle, capacity, speculative publication, warm/reload behavior. The ignored official sing-box/Xray test covers all six cleartext modes, H2MUX TLS/REALITY and padding, plus XUDP Vision.
    - `crates/honk-core/tests/integration_test.rs` — config loading, routing, mock-eBPF workflow, SOCKS5/direct/block, TCP relay + splice, DNS resolver, stats, reload/subscription-merge pipeline.
    - `crates/honk-core/tests/clash_api_test.rs` — Clash API endpoints (auth, proxies, Score representation/current winner/PUT rejection, delay, connections, traffic/logs chunked + WS, `/dns/query`, cache flush, providers, UI hosting, store_dns).
    - `crates/honk-core/tests/config_dae_routing_test.rs` — end-to-end routing assertions against the root `config.dae`.
    - Inline unit tests in `honk-core/src/control/*` (including `nfqueue.rs` held guards, token/generation races, direct/proxy/block/cancel/fatal paths), `ebpf/{mock,real}`, `mode.rs`, `stats.rs`, routing, DNS, and relay; real-backend tests require `ebpf`, and ignored netns tests require root.
    - Benchmarks kept on `main`: `cargo bench -p honk-core --features dns-bench --bench dns`; `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`; and `cargo bench -p honk-outbound --features rprx --bench vless_vision`. Lab/deployment benchmark commands and fixtures live only on branch `bench`; use its `bench/README.md` and `doc/benchmark.en.md` from a separate worktree.
    - Runtime reload benchmark: `cargo bench -p honk-core --bench reload --no-default-features --features reload-alloc-bench`.

Benchmarks kept on `main`: `benches/dns.rs` (criterion, `harness = false`) covers DNS endpoint parse, cache get/put + 90/10 mix, per-query routing match, framing, forwarder cache-hit, and TcpPool/UpstreamPool exchange; run `cargo bench -p honk-core --features dns-bench --bench dns`. `benches/udp.rs` is the candidate-only UDP Criterion suite; run `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`. Lab/deployment harnesses, raw evidence, and their documentation live only on branch `bench`; use `git worktree add ../honk-bench bench` when benchmarking so they never enter the `main` worktree.

`benches/reload.rs` measures an unchanged-effective-config runtime reload's wall/CPU time, allocations, and mock eBPF writes; run `cargo bench -p honk-core --bench reload --no-default-features --features reload-alloc-bench`.
