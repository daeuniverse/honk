# Command-Line Reference

This reference covers the current `honk-core` engine CLI and the `honk-tool` diagnostics toolbox.

## `honk-core`

`honk-core` loads the configuration, initializes the control plane, and selects either the real eBPF backend or the mock backend.

### Invocation

```text
honk-core [OPTIONS] [COMMAND]
```

| Option | Default | Effect |
| --- | --- | --- |
| `-c`, `--config PATH` | `/etc/honk/config.dae` | Configuration entry file. `mode`, `proxy`, and `delay` also read this path. `reload` ignores it and signals the running instance, which reloads its own startup path. |
| `--log-file PATH` | Unset | Override `global.log_file` for this engine process without rewriting the configuration. Relative paths resolve below `global.data_dir`; console logging remains enabled. While set, SIGHUP ignores changes to the shadowed config value unless the effective destination changes. |
| `-b`, `--bpf-object PATH` | Embedded object | Override the object embedded by an `ebpf` build. Used only by the real backend. |
| `--bpf-pin-root PATH` | `/sys/fs/bpf` | Root for pinned eBPF maps. |
| `-d`, `--debug` | Off | Select `debug` as the default console filter when `RUST_LOG` does not provide a valid filter. |
| `--mock-ebpf` | Off | Use `MockEbpfBackend` instead of loading kernel eBPF. If `global.nfqueue_enable: true` is requested, honk logs a warning and disables NFQUEUE staging for this process. |

Clap also provides `-h`/`--help` and `-V`/`--version`.

### Log-level precedence

The source comment records the intended order as `--debug` → `RUST_LOG` → `global.log_level` → `info`. The current executable first chooses the debug/config default and then calls `EnvFilter::try_from_default_env()`, so a valid `RUST_LOG` currently wins:

| Current priority | Source | Behavior |
| --- | --- | --- |
| 1 | `RUST_LOG` | A valid tracing filter overrides every default, including `--debug`. |
| 2 | `--debug` | Uses `debug` when `RUST_LOG` is absent or invalid. |
| 3 | `global.log_level` | Used without `--debug` and without a valid `RUST_LOG`. |
| 4 | `info` | Used when `global.log_level` is empty. |

See the [global configuration reference](./global.md) for `log_level`.

### Subcommands

| Command | Current behavior | Persistence / runtime effect |
| --- | --- | --- |
| `reload` | Reads the PID from the locked `/run/honk-core.lock` and sends `SIGHUP`. | Reports successful signal delivery only. The running process later logs `applied` or `rejected`. Mock instances do not own the lock. |
| `mode <rule\|global\|direct>` | Loads `--config`, assigns the supplied string to `experimental.clash_api.default_mode`, and validates before rewriting structured-format files. `.dae` files are rejected unchanged because the writer cannot preserve dae syntax, comments, or includes; edit those sources directly or use `.toml`, `.yaml`, or `.json`. | File-only; it does not contact the running engine or change dial mode. The accepted strings differ from the normal dial-mode values `ip`, `domain`, `domain+`, and `domain++`. |
| `proxy <group> <node>` | Checks that the group and node names each exist, then prints the requested selection. It does not check membership. | Nothing is written and no running engine is contacted. |
| `delay <node> [-u\|--url HOST:PORT]` | Opens one raw TCP connection with a five-second timeout and prints elapsed milliseconds. Without `--url`, it uses the node server address. | Not proxied, not an HTTP URLTest, and no running engine is contacted. |

A real-datapath process holds the lock for its lifetime. `reload` verifies that the file is still locked before trusting its PID; successful `kill(2)` delivery does not mean the candidate configuration passed validation or restart-required checks.

## Environment variables

| Variable | Scope | Current behavior |
| --- | --- | --- |
| `RUST_LOG` | Both binaries | Tracing filter. It has the effective `honk-core` precedence described above; `honk-tool` otherwise defaults to `warn`. |
| `HONK_UI_DOWNLOAD_URL` | `honk-core` with `clash-api` | Highest-precedence dashboard ZIP URL; overrides `external_ui_download_url` when a configured external-UI directory needs downloading. |
| `HONK_POOL_DISABLE=1` | `honk-core` | Bypasses both ready-stream and bare-TCP pools and performs fresh dials. The code also accepts case-insensitive `true`; the value is cached on first use. |
| `HONK_QUIC_GSO=0|1` | QUIC outbounds | Forces UDP GSO off/on. Without an override, the conservative 1252-byte MTU keeps GSO off, while an explicit larger `mtu` enables batches capped at 16 segments. |
| `HONK_MI_COLLECT_SECS` | `honk-core` with `mimalloc` | Per-owner idle collection interval. A periodic rendezvous wakes persistently parked owners only while every other worker is idle; forced collection remains in each owner's park hook. Default `60`; `0` disables both the hook and rendezvous; an invalid value falls back to `60`. |
| `HONK_VMLINUX_BTF` | `honk-core` with `ebpf` | Overrides the raw kernel BTF file used to resolve process-name offsets. Without it, honk checks `/sys/kernel/btf/vmlinux` and then `/usr/lib/debug/boot/vmlinux`; if runtime BTF offsets or verifier-safe kernel argv access are unavailable, pname synchronously falls back to the calling thread's `comm`. |
| `DAE_LOCATION_ASSET` | Geo loading in both binaries | Directory checked first for `geoip.dat` and `geosite.dat`. |

UDP NFQUEUE has no environment-variable switch. It is enabled by default through `global.nfqueue_enable`; set that key to `false` to disable it. See the [global configuration reference](./global.md) and [NFQUEUE design](../design/nfqueue.md).

## eBPF and runtime paths

| Item | Control | Current invariant |
| --- | --- | --- |
| eBPF object | Embedded object or `--bpf-object PATH` | With the `ebpf` feature, `build.rs` supplies the object embedded by `include_bytes!`; the option replaces those bytes at runtime. Builds without `ebpf` use the mock backend. |
| Kernel BTF | `HONK_VMLINUX_BTF` or common-path search | Used only to resolve `pname` kernel-field offsets. Without an override, honk tries `/sys/kernel/btf/vmlinux` followed by `/usr/lib/debug/boot/vmlinux`. |
| Pin root | `--bpf-pin-root PATH` | Defaults to `/sys/fs/bpf` and is passed to the real backend for pinned maps. |
| Bypass mark | Compiled constant | `DAE_BYPASS_MARK = 0x100`; control-plane dials, probes, and DNS upstream sockets use it to avoid re-interception. |
| TPROXY mark | Compiled constant plus validated config | `TPROXY_MARK = 0x08000000`; `global.tproxy_mark` must equal this value. |
| Geo assets | Runtime path search | `DAE_LOCATION_ASSET` first, then `global.data_dir`, the working directory, `/usr/local/share/honk`, `/usr/share/honk`, `/usr/local/share/dae`, `/usr/share/dae`, and `/etc/dae`. See the [global configuration reference](./global.md). |

## `honk-tool`

`honk-tool` is a diagnostics toolbox for subscription probing, pinned-map inspection, engine health checks, and offline Geo asset searches. It does not load or attach eBPF programs.

### Build and deployment

A normal development build is:

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
| `bpf` | Read and decode maps already pinned by the running engine. |
| `diagnose` | Run a read-only engine, network-plumbing, map, and API health check. |
| `geosite` | List, inspect, and reverse-search `geosite.dat`. |
| `geoip` | List, inspect, and longest-prefix search `geoip.dat`. |

Clap provides `-h`/`--help` and `-V`/`--version` for the binary, with help on every command family and action.

### `sub`

```text
honk-tool sub <url|file|-> [--target HOST:PORT] [--url TEST_URL]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--tls-implementation tls|utls] [--utls-imitate PROFILE]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

| Argument / option | Default | Meaning |
| --- | --- | --- |
| `<url\|file\|->` | Required | HTTP(S) subscription URL, an existing local file containing one share link per line, or `-`. `-` reads exactly one HTTP(S) subscription URL from stdin; it does not read share-link lines from stdin. |
| `--target HOST:PORT` | `cp.cloudflare.com:443` | Host used by the family connectivity probes and QUIC probe. |
| `--url TEST_URL` | `https://www.gstatic.com/generate_204` | Proxied URLTest target. |
| `--timeout SECS` | `5` | Per-probe timeout. |
| `--concurrency N` | `10` | Maximum node probe tasks in flight. |
| `--limit N` | `0` | Probe only the first `N` nodes; `0` means all. |
| `--ua UA` | Unset | `User-Agent` for a remote subscription fetch. |
| `--tls-implementation tls\|utls` | `tls` | Process-wide TLS ClientHello implementation for probes. |
| `--utls-imitate PROFILE` | `chrome_auto` | Fingerprint profile used with `utls`; the current validator accepts only names beginning with `chrome`. |
| `--v4-target IP:PORT` | `1.1.1.1:443` | Explicit IPv4 address for the v4 connectivity probe. |
| `--v6-target [IP]:PORT` | `[2606:4700:4700::1111]:443` | Explicit IPv6 address for the v6 connectivity probe. |

Remote subscriptions use the engine's subscription parser, including supported encoded/raw/Clash feeds. Existing local files are parsed as share links, ignoring blank lines and `#` comments; invalid lines are counted but never printed. Source `-` keeps a credential-bearing provider URL out of argv and process listings.

For each node, the command reports server address families, full proxied IPv4 and IPv6 exchanges, proxied URLTest latency, a DNS query through the packet handler, and a real QUIC handshake through that handler. VMess, legacy VLESS, and nodes whose `network` excludes UDP show `n/a` for UDP; non-legacy VLESS modes use their configured packet transport.

VLESS output is deliberately bounded to the display name and normalized carrier/transport/wire shape. Eligibility codes are `supported`, `invalid-uuid`, `invalid-reality`, `invalid-config`, `unsupported-transport`, `unsupported-flow`, `vision-without-tls`, and `vision-non-tcp`; probe failure codes are only `resolve`, `timeout`, `exchange`, and `handler`. Credentials, endpoint details, SNI, REALITY keys, URL query data, and raw errors are never rendered.

### `bpf`

```text
honk-tool bpf show <conn-state|redirect-track|domain-routing|routing-handoff>
                   [--ip IP] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
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
| `domain-routing` | DNS-learned IP and routing-rule bitmap indices. |
| `routing-handoff` | Tuple and pending eBPF-to-control-plane routing result. |

The implementation opens pins with raw `bpf(2)` operations; it does not use aya, load programs, or attach hooks. `stats` prints conn-state and auxiliary-map overflow/failure counters, the `CONN_STATE_OCCUPANCY` insert/delete gauge, and non-zero per-outbound packet/byte counters. Map reads normally require root or suitable BPF capabilities.

### `diagnose`

```text
honk-tool diagnose [--api URL] [--pin-root PATH] [--tproxy-mark VALUE]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--api URL` | `http://127.0.0.1:9090` | Plain-HTTP Clash API base URL. An empty value skips the API check; the built-in client does not support HTTPS. |
| `--pin-root PATH` | `/sys/fs/bpf` | Root used for pinned-map presence and statistics reads. |
| `--tproxy-mark VALUE` | `134217728` (`0x08000000`) | Expected fwmark in the `daens` policy rule. |

The check is read-only. It looks for an engine process (`honk-core`, `honk`, or `dae`), `/var/run/netns/daens`, `/sys/class/net/dae0`, the fwmark rule inside `daens`, required pinned maps, readable occupancy/overflow statistics, and `<api>/version` reachability. It ends with exactly `diagnose: all checks passed` or `diagnose: N issue(s) found`. Detected failed checks are summarized but do not by themselves change the process exit status.

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

Without `--file`, the tool searches `$DAE_LOCATION_ASSET/<name>.dat`, `/var/share/honk/<name>.dat`, `./<name>.dat`, `/usr/local/share/honk/<name>.dat`, `/usr/share/honk/<name>.dat`, `/usr/local/share/dae/<name>.dat`, `/usr/share/dae/<name>.dat`, then `/etc/dae/<name>.dat`. Unlike `honk-core`, the tool does not load a config to discover a custom `global.data_dir`. Output is one record per line and handles a closed downstream pipe without a panic.

## Related docs

- [Global configuration reference](./global.md)
- [Experimental configuration reference](./experimental.md)
- [Clash API reference](./api.md)
