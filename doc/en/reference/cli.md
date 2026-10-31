# Command-Line Reference

`honk-core` runs the engine; `honk-tool` provides diagnostics.

## `honk-core`

`honk-core` loads the configuration, initializes the control plane, and selects either the real eBPF backend or the mock backend.

### Invocation

```text
honk-core [OPTIONS] [COMMAND]
```

| Option | Default | Effect |
| --- | --- | --- |
| `-c`, `--config PATH` | `/etc/honk/config.dae` | Configuration entry file. With `--store db` it is read only while the db is empty, or by an API import. `mode`, `proxy`, and `delay` also read this path in file mode. `reload` ignores it and signals the running instance, which reloads its own startup path. |
| `--log-file PATH` | Unset | Override `global.log_file` for this engine process without rewriting the configuration. Relative paths resolve below `global.data_dir`; console logging remains enabled. While set, SIGHUP ignores changes to the shadowed config value unless the effective destination changes. |
| `-b`, `--bpf-object PATH` | Embedded object | Override the object embedded by an `ebpf` build. Used only by the real backend. |
| `--bpf-pin-root PATH` | `/sys/fs/bpf` | Root for pinned eBPF maps. |
| `--disable-timestamp` | Off | Omit the timestamp from console log lines. Use it under systemd or another logger that stamps each line itself; the file selected by `--log-file` or `global.log_file` keeps its timestamps. |
| `-d`, `--debug` | Off | Select `debug` as the default console filter when `RUST_LOG` does not provide a valid filter. |
| `--mock-ebpf` | Off | Use `MockEbpfBackend` instead of loading kernel eBPF. If `global.nfqueue_enable: true` is requested, honk logs a warning and disables NFQUEUE staging for this process. |
| `--store file\|db` | `file` | `db` runs from the revisions in `<data-dir>/state/honk.db` and imports `-c` into an empty db. See the [configuration db](./api.md#configuration-db---store-db). |
| `--data-dir PATH` | `/var/lib/honk` | Data directory holding the state db, `state/honk.db`. It must equal `global.data_dir`. Used by `--store db`, `config export` and `admin reset`. |

Both binaries provide `-h`/`--help` and `-v`/`--version`.

The CLI and Clash API share a build-time version: release builds use the GitHub tag name. Local Git builds use `git describe --tags --always --match 'v*'` (the tag, or the nearest tag plus commit distance and hash). Without usable Git metadata, the Cargo package version is used. Git is not required at runtime.

Use matching `honk-core`, `honk-tool`, and BPF object versions; incompatible objects and pinned handoff layouts are rejected under the [datapath ABI contract](../design/datapath.md#map-inventory).

### Log-level precedence

A valid `RUST_LOG` currently wins over the other log-level settings. The executable chooses the debug/config default, then calls `EnvFilter::try_from_default_env()`. The source comment instead describes the intended order as `--debug` → `RUST_LOG` → `global.log_level` → `info`:

| Current priority | Source | Behavior |
| --- | --- | --- |
| 1 | `RUST_LOG` | A valid tracing filter overrides every default, including `--debug`. |
| 2 | `--debug` | Uses `debug` when `RUST_LOG` is absent or invalid. |
| 3 | `global.log_level` | Used without `--debug` and without a valid `RUST_LOG`. |
| 4 | `info` | Used when `global.log_level` is empty. |

See the [global configuration reference](./global.md) for `log_level`.

Levels carry fixed meanings, so the default `info` stays low-rate:

| Level | Meaning |
| --- | --- |
| `error` | Configured function is lost until an operator acts: activation committed degraded, the process stops, a subsystem stops permanently, or an internal invariant breaks. |
| `warn` | Degraded but running, logged once when the state is entered: a fallback, a resource ceiling, a node or group becoming unavailable, a rejected configuration while the previous one keeps running. A failure repeated per DNS query (SERVFAIL, singleflight saturation) warns at most every 10 seconds. |
| `info` | Start, stop, activation, operator actions and recovery from a warned state. |
| `debug` | Single connection, request and DNS query outcomes, including individual dial and relay failures, and periodic maintenance results. Native flows record the same per-flow outcomes. |

### Subcommands

| Command | Current behavior | Persistence / runtime effect |
| --- | --- | --- |
| `reload` | Reads the PID from the locked `/run/honk-core.lock` and sends `SIGHUP`. | Reports successful signal delivery only. The running process later logs `applied` or `rejected`. Mock instances do not own the lock. |
| `mode <rule\|global\|direct>` | Loads `--config`, assigns the supplied string to `experimental.clash_api.default_mode`, and validates before rewriting structured-format files. `.dae` files are rejected unchanged because the writer cannot preserve dae syntax, comments, or includes; edit those sources directly or use `.toml`, `.yaml`, or `.json`. | File-only; it does not contact the running engine or change dial mode. The accepted strings differ from the normal dial-mode values `ip`, `domain`, `domain+`, and `domain++`. |
| `proxy <group> <node>` | Checks that the group and node names each exist, then prints the requested selection. It does not check membership. | Nothing is written and no running engine is contacted. |
| `config export --out PATH [--without-secrets]` | Writes the active revision of the configuration db as one `.dae` file, with listener secrets restored unless `--without-secrets`. It reads the db through a query-only connection that opens read-write, whether or not a daemon runs. Closing it never checkpoints or deletes `honk.db-wal`; apart from the `-shm` index SQLite may create, the only write it can cause is rolling back a journal a crash left. It publishes the file only once it is complete. | Creates `PATH` with mode 0600 and refuses an existing file. |
| `admin reset` | Deletes the password-mode administrator from the state db under `--data-dir`, so the next start opens setup again. | Refused while any honk-core, mock mode included, has that state db open. |
| `delay <node> [-u\|--url HOST:PORT]` | Opens one raw TCP connection with a five-second timeout and prints elapsed milliseconds. Without `--url`, it uses the node server address. | Not proxied, not an HTTP URLTest, and no running engine is contacted. |

With `--store db`, `proxy` and `delay` read the active revision and `mode` refuses.

A real-datapath process holds the lock for its lifetime. `reload` verifies that the file is still locked before trusting its PID; successful `kill(2)` delivery does not mean the candidate configuration passed validation or restart-required checks.

An exhausted [compiled-routing publication counter](../design/routing.md#synchronous-slots-and-atomic-publication) requires restart; this is separate from ordinary SIGHUP and DNS runtime reloads.

## Environment variables

| Variable | Scope | Current behavior |
| --- | --- | --- |
| `RUST_LOG` | Both binaries | Tracing filter. It has the effective `honk-core` precedence described above; `honk-tool` otherwise defaults to `warn`. |
| `HONK_UI_DOWNLOAD_URL` | `honk-core` with `clash-api` | Highest-precedence dashboard ZIP URL; overrides `assets.ui.url` when a configured external-UI directory needs downloading. |
| `HONK_POOL_DISABLE=1` | `honk-core` | Bypasses both ready-stream and bare-TCP pools and performs fresh dials. The code also accepts case-insensitive `true`; the value is cached on first use. |
| `HONK_QUIC_GSO=0\|1` | QUIC outbounds | Forces UDP GSO off/on. Without an override, the conservative 1252-byte MTU keeps GSO off, while an explicit larger `mtu` enables batches capped at 16 segments. |
| `HONK_QUIC_BBR=v1\|v3` | QUIC outbounds | Selects the controller behind the `bbr` congestion setting: TUIC `congestion_control: bbr`, Juicity, and Hysteria2 without an upload rate. `v3` is BBRv3. `v1` is quinn's original BBR, which ignores loss; quinn-proto 0.11.16+ receivers can abort its uploads on high-BDP paths with `too many gaps in stream buffer`. The default is `v3`; other values warn and keep the default. |
| `HONK_MI_COLLECT_SECS` | `honk-core` with `mimalloc` | Per-owner idle collection interval. A periodic rendezvous wakes persistently parked owners only while every other worker is idle; forced collection remains in each owner's park hook. Default `60`; `0` disables both the hook and rendezvous; an invalid value falls back to `60`. |
| `MIMALLOC_PURGE_DELAY` | `honk-core` with `mimalloc` | mimalloc's own purge delay in milliseconds: how long freed pages stay committed before they are returned to the OS. honk starts with `100` (mimalloc v3's default is `1000`), which lowers RSS under connection, probe and DNS churn without a measurable bulk-relay throughput or CPU change. Any environment value takes precedence. An unparsable value leaves mimalloc's `1000`. `0` purges immediately (lowest RSS, slightly more CPU) and `-1` never purges. |
| `TOKIO_WORKER_THREADS` | `honk-core` | Tokio's own worker count. `honk-core` builds a default multi-thread runtime, so it follows the core count. It must be a positive integer: `0` or a non-number makes Tokio panic at startup. Every worker keeps its own allocator heap, so a lower value reduces RSS on many-core gateways. In a lab measurement with 120 connections plus DNS on a 4-core host, RSS was about 85 MiB with 16 workers, 66 MiB with 8, and 60 MiB with 4. CPU differences were within noise. The relay path runs on these workers; size the value to the traffic. |
| `HONK_VMLINUX_BTF` | `honk-core` with `ebpf` | Overrides the raw kernel BTF shared by process-name routing and native UDP receive tracing. The file must match the running kernel. An explicit unreadable or invalid override refuses real-backend startup rather than falling back to another file. TCP ownership proof reads no kernel structures and does not depend on it. |
| `DAE_LOCATION_ASSET` | Geo loading in both binaries | Directory checked first for `geoip.dat` and `geosite.dat`. |

UDP NFQUEUE has no environment-variable switch. It is enabled by default through `global.nfqueue_enable`; set that key to `false` to disable it. See the [global configuration reference](./global.md) and [NFQUEUE design](../design/nfqueue.md).

## eBPF and runtime paths

| Item | Control | Current invariant |
| --- | --- | --- |
| eBPF object | Embedded object or `--bpf-object PATH` | With the `ebpf` feature, `build.rs` supplies the object embedded by `include_bytes!`; the option replaces those bytes at runtime. Object-declared `ByName` pinning is refused before probe/loading: rebuild with unpinned maps, leaving pin paths to core. Builds without `ebpf` use the mock backend. |
| Kernel BTF | `HONK_VMLINUX_BTF`, `/sys/kernel/btf/vmlinux` or `/usr/lib/debug/boot/vmlinux` | Without an override, reads `/sys/kernel/btf/vmlinux`, then `/usr/lib/debug/boot/vmlinux` (OpenWrt's `vmlinux-btf` package) if the former is unreadable. Only raw BTF is accepted; for an ELF debug vmlinux, extract its `.BTF` section and point the override at it. The selected BTF supplies kernel-field offsets, the Aya loader target and receive-trace function signatures. Missing or invalid BTF refuses startup. Unavailable kernel argv capture can still fall back to thread `comm`. Native UDP receive tracing additionally needs the in-kernel BTF and ftrace, and degrades without them; an external file does not replace them. |
| Pin root | `--bpf-pin-root PATH` | Defaults to `/sys/fs/bpf` and is passed to the real backend for pinned maps. |
| Bypass mark | `global.so_mark_from_dae` | Exact socket mark for dials, probes, DNS and downloads; zero selects the default `0x100`. Changes require restart. See [socket marks](./global.md#socket-marks). |
| TPROXY mark | Compiled constant plus validated config | `TPROXY_MARK = 0x08000000`; `global.tproxy_mark` must equal this value. |
| Geo assets | Runtime path search | `DAE_LOCATION_ASSET` first, then `global.data_dir`, legacy `/var/share/honk`, the working directory, `/usr/local/share/honk`, `/usr/share/honk`, `/usr/local/share/dae`, `/usr/share/dae`, and `/etc/dae`; each candidate must be a regular file. See the [global configuration reference](./global.md). |

## `honk-tool`

`honk-tool` is a diagnostics toolbox for subscription probing, pinned-map inspection, engine health checks, and offline Geo asset searches. It does not load or attach eBPF programs.

### Build and deployment

Build for development:

```bash
cargo build --release -p honk-tool
```

For a gateway, build the static musl target with the repository's Zig wrappers and copy the single binary:

```bash
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl=$PWD/ci/zigcc \
CXX_x86_64_unknown_linux_musl=$PWD/ci/zigcxx \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$PWD/ci/zigcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$(ci/zig-bindgen-env x86_64-linux-musl)" \
cargo build --release -p honk-tool --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/honk-tool root@GATEWAY:/tmp/
```

The current `just build-musl` and `just deploy-vyos` recipes build and deploy only `honk-core`; they do not include `honk-tool`. A GNU-linked build may not execute on a musl-only gateway.

### Command families

| Family | Purpose |
| --- | --- |
| `sub` | Fetch or parse nodes and probe TCP-family, URLTest, and supported UDP paths. |
| `bpf` | Inspect pinned maps and collect opt-in WAN diagnostics. |
| `diagnose` | Run a read-only engine, network-plumbing, map, and API health check. |
| `geosite` | List, inspect, and reverse-search `geosite.dat`. |
| `geoip` | List, inspect, and longest-prefix search `geoip.dat`. |

The binary provides `-h`/`--help` and `-v`/`--version`. Each command family and action has its own help. The build version matches `honk-core`.

### `sub`

```text
honk-tool sub <url|file|-> [--target HOST:PORT] [--url TEST_URL]
              [--udp-check HOST[:PORT]]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--tls-implementation tls|utls] [--utls-imitate PROFILE]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

| Argument / option | Default | Meaning |
| --- | --- | --- |
| `<url\|file\|->` | Required | HTTP(S) subscription URL, an existing local subscription file, or `-`. `-` reads exactly one HTTP(S) subscription URL from stdin; it does not read a subscription body from stdin. |
| `--target HOST:PORT` | `cp.cloudflare.com:443` | Host for the family probes' HTTPS request URL (TLS SNI and Host header), and host and port for QUIC. Without `--v4-target`/`--v6-target` address overrides, family probes resolve this host and use this port. `--udp-check` selects the UDP DNS probe target separately. |
| `--udp-check HOST[:PORT]` | `dns.google:53`, `8.8.8.8`, `2001:4860:4860::8888` | UDP DNS check targets, defaulting to the engine list in `honk-config`. Repeat the flag or use commas. The first IP/socket-address literal is used; otherwise the first entry is resolved only for eligible UDP DNS probes. An omitted port means `53`. |
| `--url TEST_URL` | `https://www.gstatic.com/generate_204` | Proxied URLTest target. |
| `--timeout SECS` | `5` | Per-probe timeout. |
| `--concurrency N` | `10` | Maximum node probe tasks in flight. |
| `--limit N` | `0` | Probe only the first `N` nodes; `0` means all. |
| `--ua UA` | Unset | `User-Agent` for a remote subscription fetch. |
| `--tls-implementation tls\|utls` | `tls` | Process-wide TLS ClientHello implementation for probes. |
| `--utls-imitate PROFILE` | `chrome_auto` | Fingerprint profile used with `utls`; the current validator accepts only names beginning with `chrome`. |
| `--v4-target IP:PORT` | `1.1.1.1:443` | Explicit IPv4 address for the v4 connectivity probe. |
| `--v6-target [IP]:PORT` | `[2606:4700:4700::1111]:443` | Explicit IPv6 address for the v6 connectivity probe. |

Remote subscriptions and local files share the engine's automatic format detection:

- Encoded or raw share links.
- Clash YAML/JSON, SIP008, and sing-box JSON.
- Supported Surge/Surfboard/Loon/Quantumult X records.

Unsupported nodes are skipped without printing their raw input. Source `-` keeps a credential-bearing provider URL out of argv and process listings.

For each node, the command reports:

- Server address families.
- Full proxied IPv4 and IPv6 exchanges.
- Proxied URLTest latency.
- A DNS query through the packet handler.
- A real QUIC handshake through that handler.

VLESS rows use this redacted format, without the endpoint, UUID, REALITY key, SNI, or URL query:

```text
vless/{plain|tls|reality}/{tcp|ws|grpc|xhttp}[/vision]/tcp={plain|h2mux|mux-cool}/{udp-fallback=auto|native|xudp|uot-v2|udp=disabled}[/padding=true|false][/mux=TCP:UDP:POLICY]
```

| VLESS output field | Meaning |
| --- | --- |
| `tcp=` | Effective TCP path. |
| `udp-fallback=` | Normalized fallback, even when H2MUX or Xray mux owns the target UDP path. |
| `udp=disabled` | Packet dialing is forbidden. |
| `padding=` | Present only for H2MUX. |
| Xray mux `TCP` | Effective logical-child concurrency per TCP carrier; `0` means disabled. |
| Xray mux `UDP` | `protocol`, `shared`, or the logical-child concurrency per carrier in a separate UDP pool. |
| Xray mux `POLICY` | UDP/443 policy: `reject`, `skip`, or `allow`. |

Example shapes:

- `vless/tls/tcp/tcp=plain/udp-fallback=native`
- `vless/reality/grpc/tcp=h2mux/udp-fallback=auto/padding=true`
- `vless/tls/tcp/vision/tcp=plain/udp-fallback=auto/mux=0:8:allow`

`xhttp` identifies the H2 XHTTP transport; the row does not expose its path, HTTP host, extra headers or padding contents. The transport's mode and supported parameter profile are documented in the [node reference](./nodes.md#xhttp-over-h2).

| Probe eligibility | Network work |
| --- | --- |
| `supported` | Eligible for probes. |
| `invalid-uuid`, `invalid-reality`, `invalid-config` | Entry remains visible but performs no network work. |
| `unsupported-transport`, `unsupported-flow`, `vision-without-tls`, `vision-non-tcp` | Entry remains visible but performs no network work. |

Vision TCP requires an eligible direct carrier; UDP-only Xray mux remains valid. VLESS Encryption can combine with Vision. Only unencrypted Vision additionally requires TLS 1.3 or REALITY on raw TCP.

`n/a` means a probe was not applicable, for example because packet dialing is disabled or UDP/443 policy rejects that target. A local carrier-capacity refusal is an attempted terminal failure and appears as `FAIL(...)`, not `n/a`; it remains neutral to remote endpoint health. The shared global file-descriptor budget can admit fewer physical VLESS carriers than the per-node mux limits request.

UDP DNS target resolution, packet-transport setup, send, and receive share one `--timeout` budget. A resolution failure or timeout is reported only in the DNS column; TCP, URLTest, and QUIC probes continue. Unsupported UDP nodes skip this resolution, and a failed hostname is never replaced with another target.

| Probe column | Time limit |
| --- | --- |
| Each non-QUIC column | `--timeout` plus one second, independently per column. |
| QUIC | Two additional seconds for joined teardown. Cleanup time is not a latency sample. |

URLTest and family probes give dial, target TLS, and each exchange their own `--timeout`. Slow cold-carrier setup can therefore reach the column cap. That column reports `timeout`, or `n/a` when UDP policy rejects the target. Other columns retain their results.

UDP DNS hostname targets use a shared asynchronous resolver with the first numeric nameserver in `/etc/resolv.conf` (UDP port `53`) and `/etc/hosts` when present, rather than blocking NSS lookup. This path does not apply NSS plugins or resolver search suffixes. An unavailable resolver is a DNS-column `resolve` failure, not a fallback to a public resolver; literal targets need no resolver.

VLESS carrier/session reuse follows the runtime and normalized wire shape, so changing the canonical UDP/mux queries can change node identity and pool reuse. Shared physical-carrier capacity is global, while XUDP's 8-byte Global ID is scoped by honk's runtime/client/path/destination source identity rather than treated as a process-wide collision-free NAT key. See the [node reference](./nodes.md#vless-udp-and-multiplexing) and canonical [VLESS outbound design](../design/outbound.md#sourcesession-ownership-and-capacity).

Probe failure codes are `resolve`, `timeout`, `exchange`, `handler`, and `admission`. Credentials, endpoint details, SNI, REALITY keys, URL query data, and raw errors are never rendered.

### `bpf`

```text
honk-tool bpf show <conn-state|redirect-track|domain-routing|routing-handoff>
                   [--ip IP] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
honk-tool bpf wan-diag --interface DEV --source-port PORT [--seconds SECS] [--pin-root PATH]
honk-tool bpf wan-diag --interface DEV --disable [--pin-root PATH]
```

| Command / option | Default | Meaning |
| --- | --- | --- |
| `show <map>` | Required | Decode one supported pinned map. |
| `show --ip IP` | Unset | Filter tuple maps by source or destination IP; filter `domain-routing` by its exact IP key. |
| `show --limit N` | `50` | Maximum printed entries; `0` means all. |
| `show --pin-root PATH` | `/sys/fs/bpf` | Pin root for the selected map. |
| `stats --pin-root PATH` | `/sys/fs/bpf` | Pin root for statistics maps. |

| `show` map | Decoded contents |
| --- | --- |
| `conn-state` | Tuple, outbound, mark, must flag, state, and last-seen timestamp. |
| `redirect-track` | Reply-rewrite source/destination, outbound, WAN direction, interface, and last-seen timestamp. |
| `domain-routing` | Learned IP and active-policy domain-predicate bitmap indices, from DNS or sniffed evidence; known-zero entries remain visible. |
| `routing-handoff` | Tuple and pending eBPF-to-control-plane routing result. |

`show` and `stats` read pins through raw `bpf(2)` without loading programs or attaching hooks; reads normally require root or suitable BPF capabilities. `stats` prints each counter below on its own labeled line, the `CONN_STATE_OCCUPANCY` insert/delete gauge, and non-zero per-outbound packet/byte counts. `BPF_STATS_MAP` must have nine slots: mixed tool/engine versions fail with `unexpected map layout for BPF_STATS_MAP: expected max_entries=9 found 7` (reversed for an older tool), rather than mislabelling counters. Upgrade the tool with the engine/object.

| Key | Canonical label | Counts |
| --- | --- | --- |
| `0` | `udp_conn_overflow` | UDP conn-state insertion failures with no existing tuple. |
| `1` | `tcp_conn_overflow` | TCP conn-state insertion failures. |
| `2` | `redirect_track_insert_failure` | Redirect-track publication failures: map insertion or unavailable preparation scratch. |
| `3` | `routing_handoff_insert_failure` | Routing-handoff publication failures: map insertion or unavailable preparation scratch. |
| `4` | `socket_identity_capture_failure` | Failures to capture or store a socket's process identity. |
| `5` | `tcp_child_proof_storage_failure` | Failures to store an accepted TCP child's ownership proof. |
| `6` | `tcp_publisher_claim_failure` | TCP SYN publisher-claim insertion failures, excluding ordinary same-tuple collisions (`EEXIST`). |
| `7` | `new_flow_rate_limited` | LAN flow attempts dropped by the per-source, per-CPU new-flow limit. |
| `8` | `udp_reverse_learning_suspended` | Reverse UDP learning attempts skipped under conn pressure after a conn-state lookup miss. |

`routing-handoff` validates the [handoff ABI](../design/datapath.md#map-inventory) before reading entries; upgrade the tool with the engine/object.

`stats` requires a readable, genuine `/sys/devices/system/cpu/possible` export. It sizes per-CPU buffers from that mask's population, never the present/online CPU count. `CONN_STATE_OCCUPANCY` and `OUTBOUND_STATS` must be per-CPU arrays with 4-byte keys and 8-byte and 32-byte values, respectively. An unreadable or invalid CPU list, or incompatible map metadata, fails before per-CPU lookup; there is no guessed CPU-count fallback.

#### WAN diagnostic capture

The issue #415 diagnostic build adds `wan-diag`, without a bpftool dependency. It validates the diagnostic map names/layouts and their shared TCX egress program/link ownership before enabling the selected interface and source port. Ports are `1..65535`; `--seconds` is `1..300`, default `15`. It disables sampling before emitting JSON `before`/`after` snapshots, including on INT/TERM/HUP. `--disable` is the mutually exclusive, idempotent recovery mode; it cannot be combined with an explicit `--seconds`.

This command writes only `WAN_DIAG_CFG`, not routing or connection state, and never loads or attaches programs. Run one collector at a time and freeze engine configuration. Counts are cumulative packets; rows are latest per-reason/per-CPU-slot samples, not coherent history. Unparsed reasons are interface-wide and cannot be attributed to the selected port. See the [collection and recovery runbook](../operations/wan-diagnostic-415.md) for actual-probe matching and interruption limits.


### `diagnose`

```text
honk-tool diagnose [--api URL] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark VALUE]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--api URL` | `http://127.0.0.1:9090` | Plain-HTTP Clash API base URL. An empty value skips the API check; the built-in client does not support HTTPS. |
| `--secret TOKEN` | `HONK_API_SECRET`, if set | Bearer token for the Clash API. The flag overrides the environment variable. |
| `--pin-root PATH` | `/sys/fs/bpf` | Root used for pinned-map presence and statistics reads. |
| `--tproxy-mark VALUE` | `134217728` (`0x08000000`) | Expected fwmark in the `daens` policy rule. |

The check is read-only and inspects:

- an engine process named `honk-core`, `honk`, or `dae`;
- `/var/run/netns/daens` and `/sys/class/net/dae0`;
- the fwmark rule inside `daens`;
- required pinned maps and readable occupancy/overflow statistics;
- a successful HTTP response from `<api>/version`.

| Result | Output |
| --- | --- |
| API returns 2xx | `[ok]` followed by the response body. |
| API returns non-2xx | `[FAIL]` followed by the status text. |
| All checks pass | Standard output ends with `diagnose: all checks passed`; exit status `0`. |
| A check fails | Standard output ends with `diagnose: N issue(s) found`; exit status `1` and an error message containing the issue count. |

The statistics check has the same possible-CPU file and pinned-map layout prerequisites as `bpf stats`. A preparation failure prints `[FAIL] map stats read`, contributes to the issue count, and causes a nonzero exit.

### `geosite` and `geoip`

```text
honk-tool geosite [--file PATH] list [FILTER]
honk-tool geosite [--file PATH] show <category> [--attr ATTR]
honk-tool geosite [--file PATH] find <domain>
honk-tool geoip [--file PATH] list [FILTER]
honk-tool geoip [--file PATH] show <code>
honk-tool geoip [--file PATH] lookup <ip>
```

| Command | Behavior |
| --- | --- |
| `geosite list [FILTER]` | List category codes and entry counts; optional filter is a case-insensitive substring. |
| `geosite show <category> [--attr ATTR]` | Print entries in one category. `--attr` keeps entries containing that attribute key, case-insensitively, matching routing's `category@attr` predicate. |
| `geosite find <domain>` | Print full, suffix, keyword, and regex entries that match the domain, grouped by category. |
| `geoip list [FILTER]` | List codes and CIDR counts; optional filter is a case-insensitive substring. |
| `geoip show <code>` | Print every CIDR in one code. |
| `geoip lookup <ip>` | Return every code/CIDR tie at the longest matching prefix. |
| `--file PATH` | Global per-family override for the corresponding `.dat` file. |

Without `--file`, the tool selects the first existing regular file in this order:

1. `$DAE_LOCATION_ASSET/<name>.dat`
2. `/var/lib/honk/<name>.dat`
3. `/var/share/honk/<name>.dat` (legacy root)
4. `./<name>.dat`
5. `/usr/local/share/honk/<name>.dat`
6. `/usr/share/honk/<name>.dat`
7. `/usr/local/share/dae/<name>.dat`
8. `/usr/share/dae/<name>.dat`
9. `/etc/dae/<name>.dat`

Unlike `honk-core`, the tool does not load a config to discover a custom `global.data_dir`. Output is one record per line. A closed downstream pipe does not cause a panic.

## Related docs

- [Global configuration reference](./global.md)
- [Experimental configuration reference](./experimental.md)
- [Clash API reference](./api.md)
