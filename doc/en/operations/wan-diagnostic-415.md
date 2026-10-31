# Issue #415 WAN diagnostic build

For `diag/issue-415-rawip-wan` only; **not a fix**. Existing routing, marks, forwarding classification and conntrack behavior are retained. Requires root, `bpftool-full` and curl; no tracefs, device compiler or `kernel.bpf_stats_enabled`. Two temporary BTF maps provide opt-in sampling, disabled by default.

## Start safely

Keep the original executable and configuration. Gracefully stop the original honk service, confirm no honk process remains, then start this package's `honk-core --config /etc/honk/config.dae`. Never run two engines or overwrite a running executable. Preserve the existing data directory, configuration, and both `UDP_DECISION_SEQUENCE` and `ROUTING_GENERATION_SEQUENCE` pins. Do not clear bpffs.

This package uses the recorded main revision, not an exact rebuild of the third-party beta.4 APK. Do not mix its BPF object with an older honk-core. Debug logging is unnecessary. Export evidence before shutdown: normal shutdown attempts to remove owned diagnostic pins, but failures can leave stale pins whose presence does not prove a hook is active. Startup creates new maps, while SIGHUP does not reset them.

## Verify program/map identity

```sh
bpftool net
bpftool prog show id PROGRAM_ID
bpftool prog dump xlated id PROGRAM_ID
bpftool map show pinned /sys/fs/bpf/WAN_DIAG_CFG
bpftool map show pinned /sys/fs/bpf/WAN_DIAG
```

`PROGRAM_ID` must be the current TCX egress program on sipa_eth0 with entry point `wan_egress_l3`. Both pinned map IDs must occur in that program's `map_ids`; otherwise stop rather than inspecting/updating stale pins. Adjust paths if using a custom `--bpf-pin-root`.

Expected layouts: `WAN_DIAG_CFG` is an array with 4-byte keys, 8-byte values and one entry. `WAN_DIAG` is a percpu_array with 4-byte keys, 104-byte values and 13 entries. Both need BTF IDs; `bpftool btf dump id BTF_ID format c` shows `Filter { ifindex, source_port }` and the `Sample` fields. Reacquire program/map IDs after restart.

## One IPv4 probe

Pause unnecessary concurrent probes. Use the actual outgoing interface, not the issue's historical ifindex 3. Avoid concurrent LAN traffic using the same source port.

```sh
(
set -eu
umask 077
DEV=sipa_eth0
IFINDEX=$(cat /sys/class/net/$DEV/ifindex)
CFG=/sys/fs/bpf/WAN_DIAG_CFG
DATA=/sys/fs/bpf/WAN_DIAG
le32() { printf '%02x %02x %02x %02x' "$(($1 & 255))" "$(($1 >> 8 & 255))" "$(($1 >> 16 & 255))" "$(($1 >> 24 & 255))"; }
off() { bpftool map update pinned "$CFG" key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00; }
trap 'off' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
off
bpftool -j -p map dump pinned "$DATA" > wan4-before.json
bpftool map update pinned "$CFG" key hex 00 00 00 00 value hex $(le32 "$IFINDEX") $(le32 41500)
date -u
RC=0
curl -q -4 --noproxy '*' --http1.1 --local-port 41500 \
  --connect-timeout 5 --max-time 15 --verbose \
  --write-out '\nlocal=%{local_ip}:%{local_port} remote=%{remote_ip}:%{remote_port}\n' \
  https://api.ip.sb/ip || RC=$?
date -u
off
printf 'curl_exit=%s\n' "$RC"
bpftool -j -p map dump pinned "$DATA" > wan4-after.json
)
```

`-q` must be curl's first option to ignore `.curlrc`; `--noproxy '*'` excludes proxy environment settings. Do not bind the WAN device: that would change socket semantics relative to the report. Save all curl output. A DNS failure cannot establish that TC was skipped. If the actual destination is known, `--resolve api.ip.sb:443:ADDRESS` pins it while retaining TLS hostname validation; bracket IPv6 addresses. Do not use `-k`.

Run IPv6 separately: change `-4` to `-6`, use **41501** for both the filter and curl's source port, and name the dumps `wan6-*`. If a port is occupied, choose another unused port and change both values. Do not use port ranges or concurrent curls. Each probe follows disable → before dump → enable → curl → disable → after dump. The subshell attempts to disable sampling on normal exit or catchable signals; if forcibly terminated or disabling reports an error, repeat the disabling map update manually.

## Interpretation

| key | Existing path |
| --- | --- |
| 0 | Packet scratch unavailable; drop, no tuple evidence |
| 1 | Parser refusal; continue, no tuple evidence |
| 2 | Condemned fragment or local NDP Redirect; drop, no tuple evidence |
| 3 | NFQUEUE DNS carrier drop |
| 4 | VLAN deferred to another device |
| 5 | Datapath not ready; continue |
| 6 | Broadcast/multicast/special destination; continue |
| 7 | Destination matches PARAM.local_ip; continue |
| 8 | Nonzero ingress_ifindex; continue as forwarded traffic |
| 9 | Exact bypass mark or classified mark; PASS |
| 10 | Tuple fence refusal |
| 11 | TCP publication acquisition refusal |
| 12 | Entering TCP/UDP handler—not proof of successful interception/proxying |

Addresses are 16 network-order bytes, using IPv4-mapped IPv6 for IPv4. Ports are host-order integers; `protocol` is host-order EtherType (2048/34525). `first_byte=-1` denotes a failed read; otherwise it is the first byte after the link header. `parse_result` retains the signed parser result. Only `tuple_valid=1` supports five-tuple attribution.

**Keys 0/1/2 contain interface-wide unparsed evidence, not source-port-filtered curl evidence.** Their tuple/L4 fields are zeroed instead of exposing stale parser scratch. Other records match the selected source port, but may include forwarded LAN traffic. Match one whole sample's tuple against curl's actual tuple, family and probe interval. Cookie is auxiliary evidence only: nonzero is not sufficient proof of host origin, and zero does not exclude it. Reading it may lazily assign a socket cookie; it never participates in classification.

Each reason/CPU retains a cumulative packet count and only its latest sample. Counts are not connection counts. Sum counts across CPUs, never combine sample fields across CPUs. Compare before/after; later traffic can overwrite the relevant sample, and empty/unmatched evidence remains inconclusive. `timestamp_ns` is monotonic nanoseconds, not UTC. Freeze configuration throughout a probe, never reset counters while enabled, and do not treat config updates as an atomic publication protocol. Disabling is not a grace barrier for in-flight invocations; dumps can race a final write.

A sample positively matched to the host curl at key 8 with nonzero `ingress_ifindex` confirms that guard passed it through. Key 1 plus inconsistent EtherType/header bytes suggests a separate parser investigation. Key 12 requires following handler/routing outcomes rather than retaining the ifindex hypothesis.

Retain and sanitize: build version/SHA256, startup/binding logs, program/map identity, complete IPv4/IPv6 curl output, before/after JSON, and `ip -details link show dev sipa_eth0`. JSON includes IP addresses, but no payload, domains, configuration or credentials.

## Restore

Standalone disable command, also usable after reconnecting without the earlier subshell's functions (adjust a custom pin root):

```sh
bpftool map update pinned /sys/fs/bpf/WAN_DIAG_CFG \
  key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00
```

Disable sampling, export evidence, gracefully stop the diagnostic instance, restore the original executable, and restart the original service. Preserve persistent allocator pins. A reboot is unnecessary; unpinning is not a reset of a map still referenced by a running program.
