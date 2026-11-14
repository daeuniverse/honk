# Command-Line Reference

`honk-core` runs the engine; `honk-tool` provides diagnostics.

## `honk-core`

`honk-core` loads the configuration, initializes the control plane, and selects either the real eBPF backend or the mock backend.

### Invocation

```text
honk-core [OPTIONS] [COMMAND]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `-c`, `--config PATH` | Omitted; `/etc/honk/config.dae` | Configuration entry file. See [`--config`](#--config). |
| `--log-file PATH` | Omitted; unset | Override `global.log_file` for this engine process. See [`--log-file`](#--log-file). |
| `-b`, `--bpf-object PATH` | Omitted; embedded object | Replace the object embedded by an `ebpf` build; only the real backend reads it. |
| `--bpf-pin-root PATH` | Omitted; `/sys/fs/bpf` | Root for pinned eBPF maps, passed to the real backend. |
| `--disable-timestamp` | Omitted; off | Omit the timestamp from console log lines. See [`--disable-timestamp`](#--disable-timestamp). |
| `-d`, `--debug` | Omitted; off | Use `debug` as the default console filter when `RUST_LOG` gives no valid filter. |
| `--mock-ebpf` | Omitted; off | Use `MockEbpfBackend` instead of loading kernel eBPF. See [`--mock-ebpf`](#--mock-ebpf). |
| `--store file\|db` | Omitted; `file` | Run from the revisions in `<data-dir>/state/honk.db`. See [`--store`](#--store). |
| `--data-dir PATH` | Omitted; `/var/lib/honk` | Data directory holding `state/honk.db`. See [`--data-dir`](#--data-dir). |

Both binaries provide `-h`/`--help` and `-v`/`--version`.

### --config

```text
honk-core --config /etc/honk/config.dae
```

Configuration entry file.

With `--store db`, the file is read only while the db is empty, or by an API import. `mode`, `proxy`, and `delay` also read this path in file mode.

`reload` ignores it and signals the running instance, which reloads its own startup path.

### --log-file

```text
honk-core --log-file honk.log
```

Overrides `global.log_file` for this engine process without rewriting the configuration. Relative paths resolve below `global.data_dir`.

Console logging remains enabled.

While set, SIGHUP ignores changes to the overridden config value unless the effective destination changes.

### --disable-timestamp

```text
honk-core --disable-timestamp
```

Omits the timestamp from console log lines. Use it under systemd or another logger that stamps each line itself.

The file selected by `--log-file` or `global.log_file` keeps its timestamps.

### --mock-ebpf

```text
honk-core --mock-ebpf
```

Uses `MockEbpfBackend` instead of loading kernel eBPF.

If the configuration requests `global.nfqueue_enable: true`, honk logs a warning and disables NFQUEUE staging for this process.

### --store

```text
honk-core --store db --data-dir /var/lib/honk
```

`db` runs from the revisions in `<data-dir>/state/honk.db` and imports `-c` into an empty db. It needs a `native-api` build. See the [configuration db](./api.md#configuration-db---store-db).

### --data-dir

```text
honk-core --store db --data-dir /var/lib/honk
```

Data directory holding the state db, `state/honk.db`. Used by `--store db`, `config export`, and `admin reset`.

With `--store db` the value must equal `global.data_dir`. A file-mode start ignores it.

### Log-level precedence

A valid `RUST_LOG` wins over the other log-level settings. The executable chooses the debug or config default, then calls `EnvFilter::try_from_default_env()`.

The source comment describes the intended order as `--debug` → `RUST_LOG` → `global.log_level` → `info`. The current priority is:

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

| Key | Meaning |
| --- | --- |
| `reload` | Send `SIGHUP` to the process that holds the engine lock. See [`reload`](#reload). |
| `mode` | Write the supplied string into `experimental.clash_api.default_mode` in a structured-format file. See [`mode`](#mode). |
| `proxy` | Print the requested selection for a group and a node. See [`proxy`](#proxy). |
| `config export` | Write the active configuration revision as one `.dae` file. See [`config export`](#config-export). |
| `admin reset` | Delete the password-mode administrator from the state db. See [`admin reset`](#admin-reset). |
| `delay` | Time a direct TCP dial to a node. See [`delay`](#delay). |

With `--store db`, `proxy` and `delay` read the active revision and need a `native-api` build; `mode` refuses.

#### reload

```text
honk-core reload
```

Reads the PID from the locked `/run/honk-core.lock` and sends `SIGHUP`.

It reports successful signal delivery only. The running process later logs `applied` or `rejected`. Mock instances do not own the lock.

A real-datapath process holds the lock for its lifetime, and `reload` verifies that the file is still locked before trusting its PID. Successful `kill(2)` delivery does not mean the candidate configuration passed validation or restart-required checks.

#### mode

```text
honk-core mode <rule|global|direct>
```

Loads `--config`, assigns the supplied string to `experimental.clash_api.default_mode`, and validates before rewriting structured-format files.

`.dae` files are rejected unchanged: the writer cannot preserve dae syntax, comments, or includes. Edit those sources directly, or use `.toml`, `.yaml`, or `.json`.

The command is file-only. It does not contact the running engine or change dial mode. The accepted strings differ from the normal dial-mode values `ip`, `domain`, `domain+`, and `domain++`.

#### proxy

```text
honk-core proxy <group> <node>
```

Checks that the group and node names each exist, then prints the requested selection. It does not check membership.

Nothing is written and no running engine is contacted.

#### config export

```text
honk-core config export --out PATH [--without-secrets]
```

Needs a `native-api` build. Writes the active revision of the configuration db as one `.dae` file, with listener secrets restored unless `--without-secrets`.

The command reads the db through a query-only connection that opens read-write, whether or not a daemon runs. Closing the connection never checkpoints or deletes `honk.db-wal`. Apart from the `-shm` index SQLite may create, the only write it can cause is rolling back a journal a crash left.

It publishes the file only once it is complete. It creates `PATH` with mode 0600 and refuses an existing file.

#### admin reset

```text
honk-core admin reset
```

Deletes the password-mode administrator from the state db under `--data-dir`, so the next start opens setup again.

Refused while any honk-core, mock mode included, has that state db open.

#### delay

```text
honk-core delay <node> [-u|--url HOST:PORT]
```

Resolves the address, connects over direct TCP and prints the elapsed milliseconds, resolution included. Without `--url`, it uses the node server address.

Resolved addresses are raced at most two at a time, 250 ms apart, and each attempt times out after five seconds.

The dial is not proxied and is not an HTTP URLTest. No running engine is contacted.

### Restart requirements

An exhausted [compiled-routing publication counter](../design/routing.md#synchronous-slots-and-atomic-publication) requires a restart. This is separate from ordinary SIGHUP and DNS runtime reloads.

## Environment variables

| Key | Default | Meaning |
| --- | --- | --- |
| `RUST_LOG` | Omitted; `warn` in `honk-tool` | Tracing filter for both binaries. See [log-level precedence](#log-level-precedence). |
| `NO_COLOR` | Omitted; unset | `honk-core` console: a nonempty value disables ANSI color. Otherwise color is on only when stdout is a terminal. |
| `HONK_UI_DOWNLOAD_URL` | Omitted; unset | Highest-precedence dashboard ZIP URL; overrides `assets.ui.url`. See [`HONK_UI_DOWNLOAD_URL`](#honk_ui_download_url). |
| `HONK_POOL_DISABLE` | Omitted; unset | Bypass the ready-stream and bare-TCP pools. See [`HONK_POOL_DISABLE`](#honk_pool_disable). |
| `HONK_QUIC_GSO` | Omitted; unset | Force UDP GSO on or off for QUIC outbounds. See [`HONK_QUIC_GSO`](#honk_quic_gso). |
| `HONK_QUIC_BBR` | Omitted; `v3` | Select the BBR implementation behind `congestion_control: bbr`. See [`HONK_QUIC_BBR`](#honk_quic_bbr). |
| `TOKIO_WORKER_THREADS` | Omitted; core count | Tokio worker count for `honk-core`. See [`TOKIO_WORKER_THREADS`](#tokio_worker_threads). |
| `HONK_VMLINUX_BTF` | Omitted; `/sys/kernel/btf/vmlinux`, then `/usr/lib/debug/boot/vmlinux` | Raw kernel BTF override for process-name routing and native UDP receive tracing. See [`HONK_VMLINUX_BTF`](#honk_vmlinux_btf). |
| `DAE_LOCATION_ASSET` | Omitted; unset | Directory that `honk-core` and `honk-tool` check first for `geoip.dat` and `geosite.dat`. |

### HONK_UI_DOWNLOAD_URL

```text
HONK_UI_DOWNLOAD_URL=https://example.org/dashboard.zip honk-core
```

Highest-precedence dashboard ZIP URL for `honk-core` with `clash-api`. It overrides `assets.ui.url` when a configured external-UI directory needs downloading.

### HONK_POOL_DISABLE

```text
HONK_POOL_DISABLE=1 honk-core
```

Bypasses both ready-stream and bare-TCP pools and performs fresh dials.

The value is cached on first use. `1` and case-insensitive `true` enable it.

### HONK_QUIC_GSO

```text
HONK_QUIC_GSO=1 honk-core
```

`1` or case-insensitive `true` forces UDP GSO on. Any other value, empty included, forces it off. The value is cached on first use.

Without an override, the conservative 1252-byte MTU keeps GSO off. An explicit larger `mtu` enables batches capped at 16 segments.

### HONK_QUIC_BBR

```text
HONK_QUIC_BBR=v1 honk-core
```

Selects the controller behind the `bbr` congestion setting: TUIC `congestion_control: bbr`, Juicity, and Hysteria2 without an upload rate.

`v3` is BBRv3. `v1` is quinn's original BBR, which ignores loss; quinn-proto 0.11.16+ receivers can abort its uploads on high-BDP paths with `too many gaps in stream buffer`.

The default is `v3`. Other values warn and keep the default.

### TOKIO_WORKER_THREADS

```text
TOKIO_WORKER_THREADS=4 honk-core
```

Tokio's own worker count for `honk-core`. `honk-core` builds a default multi-thread runtime, so the count follows the core count.

The value must be a positive integer: `0` or a non-number makes Tokio panic at startup.

Every worker keeps its own allocator heap, so a lower value reduces RSS on many-core gateways. In a lab measurement with 120 connections plus DNS on a 4-core host, RSS was about 85 MiB with 16 workers, 66 MiB with 8, and 60 MiB with 4. CPU differences were within noise.

The relay path runs on these workers, so size the value to the traffic.

### HONK_VMLINUX_BTF

```text
HONK_VMLINUX_BTF=/path/to/vmlinux.btf honk-core
```

Overrides the raw kernel BTF shared by process-name routing and native UDP receive tracing. The file must match the running kernel.

An explicit unreadable or invalid override refuses real-backend startup rather than falling back to another file. TCP ownership proof reads no kernel structures and does not depend on it.

### UDP NFQUEUE

UDP NFQUEUE has no environment-variable switch. It is enabled by default through `global.nfqueue_enable`; set that key to `false` to disable it. See the [global configuration reference](./global.md) and [NFQUEUE design](../design/nfqueue.md).

## eBPF and runtime paths

| Key | Meaning |
| --- | --- |
| eBPF object | Object the real backend loads. See [eBPF object](#ebpf-object). |
| Kernel BTF | Kernel type information for routing and receive tracing. See [Kernel BTF](#kernel-btf). |
| Bypass mark | Exact socket mark for dials, probes, DNS and downloads. See [Bypass mark](#bypass-mark). |
| TPROXY mark | `TPROXY_MARK = 0x08000000`; `global.tproxy_mark` must equal this value. |
| Geo assets | `geoip.dat` and `geosite.dat` search order. See [Geo assets](#geo-assets). |

### eBPF object

With the `ebpf` feature, `build.rs` supplies the object embedded by `include_bytes!`. The `--bpf-object` option replaces those bytes at runtime.

Object-declared `ByName` pinning is refused before probe/loading: rebuild with unpinned maps, leaving pin paths to core. Builds without `ebpf` use the mock backend.

### Kernel BTF

Without an override, honk reads `/sys/kernel/btf/vmlinux`. If that file is unreadable, it reads `/usr/lib/debug/boot/vmlinux` (OpenWrt's `vmlinux-btf` package). Only raw BTF is accepted. For an ELF debug vmlinux, extract its `.BTF` section and point the override at it.

The selected BTF supplies kernel-field offsets, the Aya loader target and receive-trace function signatures. Missing or invalid BTF refuses startup. If kernel argv capture is unavailable, honk can still fall back to the thread `comm`.

Native UDP receive tracing additionally needs the in-kernel BTF and ftrace, and degrades without them. An external file does not replace them.

### Bypass mark

`global.so_mark_from_dae` sets the exact socket mark for dials, probes, DNS and downloads. Zero selects the default `0x100`.

Changes require a restart. See [socket marks](./global.md#socket-marks).

### Geo assets

honk searches `DAE_LOCATION_ASSET` first, then `global.data_dir`, legacy `/var/share/honk`, the working directory, `/usr/local/share/honk`, `/usr/share/honk`, `/usr/local/share/dae`, `/usr/share/dae`, and `/etc/dae`. Each candidate must be a regular file.

See the [global configuration reference](./global.md).

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

| Key | Meaning |
| --- | --- |
| `sub` | Fetch or parse nodes and probe TCP-family, URLTest, and supported UDP paths. |
| `bpf` | Read and decode maps already pinned by the running engine. |
| `diagnose` | Run a read-only engine, network-plumbing, map, and API health check. |
| `geosite` | List, inspect, and reverse-search `geosite.dat`. |
| `geoip` | List, inspect, and longest-prefix search `geoip.dat`. |

The binary provides `-h`/`--help` and `-v`/`--version`. Each command family and action has its own help.

### `sub`

```text
honk-tool sub <url|file|-> [--target HOST:PORT] [--url TEST_URL]
              [--udp-check HOST[:PORT]]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--tls-implementation tls|utls] [--utls-imitate PROFILE]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `<url\|file\|->` | Required | HTTP(S) subscription URL, an existing local subscription file, or `-`. `-` reads exactly one HTTP(S) subscription URL from stdin and never a subscription body. |
| `--target HOST:PORT` | Omitted; `cp.cloudflare.com:443` | Probe target host and port. See [`--target`](#--target). |
| `--udp-check HOST[:PORT]` | Omitted; `dns.google:53`, `8.8.8.8`, `2001:4860:4860::8888` | UDP DNS check targets. See [`--udp-check`](#--udp-check). |
| `--url TEST_URL` | Omitted; `https://www.gstatic.com/generate_204` | Proxied URLTest target. |
| `--timeout SECS` | Omitted; `5` | Per-probe timeout. `0` is a zero timeout, not unlimited. |
| `--concurrency N` | Omitted; `10` | Maximum node probe tasks in flight. `0` probes nothing, prints an empty summary, and does not mean unlimited. |
| `--limit N` | Omitted; `0` | Probe only the first `N` nodes; `0` means all. |
| `--ua UA` | Omitted; unset | `User-Agent` for a remote subscription fetch. |
| `--tls-implementation tls\|utls` | Omitted; `tls` | Process-wide TLS ClientHello implementation for probes. |
| `--utls-imitate PROFILE` | Omitted; `chrome_auto` | Fingerprint profile used with `utls`. The current validator accepts only names beginning with `chrome`. |
| `--v4-target IP:PORT` | Omitted; `1.1.1.1:443` | Numeric IPv4 address the v4 probe connects to. The address family is not checked. |
| `--v6-target [IP]:PORT` | Omitted; `[2606:4700:4700::1111]:443` | Numeric IPv6 address the v6 probe connects to. The address family is not checked. |

#### --target

```text
honk-tool sub nodes.txt --target one.one.one.one:443 \
  --v4-target 1.0.0.1:443 --v6-target '[2606:4700:4700::1001]:443'
```

The host forms the family probes' HTTPS request URL, TLS SNI and Host header. Host and port serve QUIC.

The family probes still connect to `--v4-target` and `--v6-target`, so change those with it. `--udp-check` selects the UDP DNS probe target separately.

#### --udp-check

```text
honk-tool sub nodes.txt --udp-check 'dns.google:53,8.8.8.8'
```

UDP DNS check targets, defaulting to the engine list in `honk-config`. Repeat the flag or use commas.

`honk-tool` uses the first IP or socket-address literal in the list. Without a literal, it resolves the first entry, and only for eligible UDP DNS probes. An omitted port means `53`.

#### Source formats

Remote subscriptions and local files share the engine's automatic format detection:

- Encoded or raw share links.
- Clash YAML/JSON, SIP008, and sing-box JSON.
- Supported Surge/Surfboard/Loon/Quantumult X records.

Unsupported nodes are skipped without printing their raw input. Passing `-` as the source keeps a credential-bearing provider URL out of argv and process listings.

#### Exit status

Once the subscription loads, the exit status is `0` even when every probe fails or every node is skipped. A crashed probe task prints `probe task failed` and leaves the exit status `0`. Scripts must read the summary line to judge connectivity.

#### Output

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

#### Probe eligibility

| Probe eligibility | Network work |
| --- | --- |
| `supported` | Eligible for probes. |
| `invalid-uuid`, `invalid-reality`, `invalid-config` | Entry remains visible but performs no network work. |
| `unsupported-transport`, `unsupported-flow`, `vision-without-tls`, `vision-non-tcp` | Entry remains visible but performs no network work. |

Vision TCP requires an eligible direct carrier; UDP-only Xray mux remains valid. VLESS Encryption can combine with Vision. Only unencrypted Vision additionally requires TLS 1.3 or REALITY on raw TCP.

`n/a` means a probe was not applicable, for example because packet dialing is disabled or UDP/443 policy rejects that target. A local carrier-capacity refusal is an attempted terminal failure and appears as `FAIL(...)`, not `n/a`. It does not affect remote endpoint health.

The shared global file-descriptor budget can admit fewer physical VLESS carriers than the per-node mux limits request.

#### Time limits

UDP DNS target resolution, packet-transport setup, send, and receive share one `--timeout` budget. A resolution failure or timeout is reported only in the DNS column. TCP, URLTest, and QUIC probes continue. Unsupported UDP nodes skip this resolution, and a failed hostname is never replaced with another target.

| Probe column | Time limit |
| --- | --- |
| Each non-QUIC column | `--timeout` plus one second, independently per column. |
| QUIC | Two additional seconds for joined teardown. Cleanup time is not a latency sample. |

URLTest and family probes give dial, target TLS, and each exchange their own `--timeout`. Slow cold-carrier setup can therefore reach the column cap. That column reports `timeout`, or `n/a` when UDP policy rejects the target. Other columns retain their results.

#### DNS target resolution

UDP DNS hostname targets use a shared asynchronous resolver, not a blocking NSS lookup. It uses the first numeric nameserver in `/etc/resolv.conf`, on UDP port `53`, plus `/etc/hosts` when present. This path does not apply NSS plugins or resolver search suffixes.

An unavailable resolver is a DNS-column `resolve` failure, not a fallback to a public resolver. Literal targets need no resolver.

#### Reuse and identity

VLESS carrier and session reuse follow the runtime and the normalized wire shape. Changing the canonical UDP or mux queries can therefore change node identity and pool reuse.

Shared physical-carrier capacity is global. XUDP's 8-byte Global ID is scoped by honk's runtime/client/path/destination source identity rather than treated as a process-wide collision-free NAT key.

See the [node reference](./nodes.md#vless-udp-and-multiplexing) and canonical [VLESS outbound design](../design/outbound.md#sourcesession-ownership-and-capacity).

#### Failure codes

Probe failure codes are `resolve`, `timeout`, `exchange`, `handler`, and `admission`.

Probe rows never render credentials, endpoint details, SNI, REALITY keys, URL query data, or raw errors. The one exception is stderr: a failed probe runtime cleanup prints `probe runtime cleanup failed: <error>` with the raw error.

### `bpf`

```text
honk-tool bpf show <conn-state|redirect-track|domain-routing|routing-handoff>
                   [--ip IP] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `show <map>` | Required | Decode one supported pinned map. |
| `show --ip IP` | Omitted; unset | Filter tuple maps by source or destination IP; filter `domain-routing` by its exact IP key. |
| `show --limit N` | Omitted; `50` | Maximum printed entries; `0` means all. |
| `show --pin-root PATH` | Omitted; `/sys/fs/bpf` | Pin root for the selected map. |
| `stats --pin-root PATH` | Omitted; `/sys/fs/bpf` | Pin root for statistics maps. |

| Key | Decoded contents |
| --- | --- |
| `conn-state` | Tuple, outbound, mark, must flag, state, last-seen timestamp, and trace ID. |
| `redirect-track` | Reply-rewrite source/destination, outbound, WAN direction, interface, and last-seen timestamp. |
| `domain-routing` | Learned IP and active-policy domain-predicate bitmap indices, from DNS or sniffed evidence; known-zero entries remain visible. |
| `routing-handoff` | Tuple, pending eBPF-to-control-plane routing result, last-seen timestamp, routing generation, and trace ID. |

#### Snapshot reads

`conn-state`, `redirect-track` and `routing-handoff` are read with `BPF_MAP_LOOKUP_BATCH` and `BPF_F_LOCK`. A kernel without that support fails with `safe external map snapshot requires BPF_MAP_LOOKUP_BATCH ...`. There is no unlocked fallback.

The commands read pins through raw `bpf(2)` without loading programs or attaching hooks. Reads normally require root or suitable BPF capabilities.

`routing-handoff` validates the [handoff ABI](../design/datapath.md#map-inventory) before reading entries. Upgrade the tool with the engine/object.

#### Statistics

`stats` prints each counter below on its own labeled line, the `CONN_STATE_OCCUPANCY` insert/delete gauge, and non-zero per-outbound packet/byte counts.

`BPF_STATS_MAP` must have nine slots. Mixed tool/engine versions fail with `unexpected map layout for BPF_STATS_MAP: expected max_entries=9 found 7` (reversed for an older tool), rather than mislabelling counters. Upgrade the tool with the engine/object.

`stats` requires a readable, genuine `/sys/devices/system/cpu/possible` export. It sizes per-CPU buffers from that mask's population, never the present/online CPU count.

`CONN_STATE_OCCUPANCY` and `OUTBOUND_STATS` must be per-CPU arrays with 4-byte keys and 8-byte and 32-byte values, respectively. An unreadable or invalid CPU list, or incompatible map metadata, fails before per-CPU lookup. There is no guessed CPU-count fallback.

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

### `diagnose`

```text
honk-tool diagnose [--api URL] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark VALUE]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `--api URL` | Omitted; `http://127.0.0.1:9090` | Clash API base URL. See [`--api`](#--api). |
| `--secret TOKEN` | Omitted; `HONK_API_SECRET`, if set | Bearer token for the Clash API. The flag overrides the environment variable. |
| `--pin-root PATH` | Omitted; `/sys/fs/bpf` | Root used for pinned-map presence and statistics reads. |
| `--tproxy-mark VALUE` | Omitted; `134217728` (`0x08000000`) | Expected fwmark in the `daens` policy rule, as a decimal 32-bit integer; hexadecimal input is rejected. |

#### --api

```text
honk-tool diagnose --api http://127.0.0.1:9090
```

Plain-HTTP Clash API base URL. The port is required, as in `http://panel.example:80`; HTTPS is not supported.

An empty value skips the API check.

The API check has no timeout, so a stalled peer can hang the command. Wrap it in `timeout(1)`, or pass `--api ''` if that risk is unacceptable.

#### Checks

`diagnose` runs `ip`. If `ip` cannot be executed, it exits nonzero before the remaining checks and the summary.

The check is read-only and inspects:

- an engine process named `honk-core`, `honk`, or `dae`;
- `/var/run/netns/daens` and `/sys/class/net/dae0`;
- the fwmark rule inside `daens`;
- required pinned maps and readable occupancy/overflow statistics;
- a successful HTTP response from `<api>/version`.

#### Results

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

| Key | Behavior |
| --- | --- |
| `geosite list [FILTER]` | List category codes and entry counts; optional filter is a case-insensitive substring. |
| `geosite show <category> [--attr ATTR]` | Print entries in one category. `--attr` keeps entries containing that attribute key, case-insensitively, matching routing's `category@attr` predicate. |
| `geosite find <domain>` | Print full, suffix, keyword, and regex entries that match the domain, grouped by category. |
| `geoip list [FILTER]` | List codes and CIDR counts; optional filter is a case-insensitive substring. |
| `geoip show <code>` | Print every CIDR in one code. |
| `geoip lookup <ip>` | Return every code/CIDR tie at the longest matching prefix. |
| `--file PATH` | Global per-family override for the corresponding `.dat` file. |

An unknown `show` category or code exits nonzero. A `list`, `find`, or `lookup` that matches nothing prints nothing and exits `0`.

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

| Command | Line format |
| --- | --- |
| `geosite list` | `CATEGORY ENTRY_COUNT` |
| `geosite show`, `geosite find` | `CATEGORY KIND VALUE [@ATTR ...]`, where `KIND` is `domain`, `full`, `keyword`, or `regexp` |
| `geoip list` | `CODE CIDR_COUNT` |
| `geoip show`, `geoip lookup` | `CODE CIDR` |

## Version and compatibility

The CLI and Clash API share a build-time version. Release builds use the GitHub tag name. Local Git builds use `git describe --tags --always --match 'v*'`, which gives the tag, or the nearest tag plus commit distance and hash. Without usable Git metadata, the Cargo package version is used. Git is not required at runtime.

`honk-tool` reports the same build version as `honk-core`. Use matching `honk-core`, `honk-tool`, and BPF object versions; incompatible objects and pinned handoff layouts are rejected under the [datapath ABI contract](../design/datapath.md#map-inventory).

## Related docs

- [Global configuration reference](./global.md)
- [Experimental configuration reference](./experimental.md)
- [Clash API reference](./api.md)
