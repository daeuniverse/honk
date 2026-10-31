# Issue #415: collect WAN evidence with honk-tool

This branch adds observation only; routing, marks, conntrack and host/forwarded classification are unchanged. The package includes matching static `honk-core`, `honk-tool` and BPF object builds. **No bpftool, tracefs or device-side compiler is needed.**

Root/BPF permissions, Linux TCX, a readable `/sys/devices/system/cpu/possible`, and an engine with these diagnostic maps are required. Curl below triggers the reported problem; the collector does not depend on it. Do not mix the new tool/object with an older engine.

## Startup and scope

Keep the original executable and configuration. Gracefully stop the original service, confirm no honk process remains, then start the packaged `honk-core --config /etc/honk/config.dae`. Never overwrite a running executable or start a second engine. Preserve the data directory and both `UDP_DECISION_SEQUENCE` and `ROUTING_GENERATION_SEQUENCE`; do not clear bpffs.

`honk-tool bpf wan-diag` reuses the existing raw `bpf(2)` facilities. It loads no programs and attaches no hooks. It only updates `WAN_DIAG_CFG`, not datapath state or counters. It validates actual map names, types, sizes, entry counts and ownership by the same TCX egress program on the selected interface. Program/link identity is checked at capture boundaries; held old map FDs prevent cleanup from writing a restart's replacement map. Boundary checks do not prove no intermediate update occurred: keep engine configuration unchanged during probing.

Sampling defaults off. **Run only one collector per engine; do not race the recovery command against a collector.** Admission is not an atomic ownership claim. A pre-enabled nonzero filter is refused without modification; stop the original collector or explicitly recover first.

## IPv4: two terminals

Terminal A, using the actual WAN interface; add `--pin-root PATH` for a custom pin root:

```sh
umask 077
./honk-tool bpf wan-diag --interface sipa_eth0 \
  --source-port 41500 --seconds 20 > wan4.json
```

Wait for `WAN diagnostic sampling ready:` on stderr, then run in terminal B:

```sh
umask 077
(
  date -u
  RC=0
  curl -q -4 --noproxy '*' --http1.1 --local-port 41500 \
    --connect-timeout 5 --max-time 15 --verbose \
    --write-out '\nlocal=%{local_ip}:%{local_port} remote=%{remote_ip}:%{remote_port}\n' \
    https://api.ip.sb/ip || RC=$?
  date -u
  printf 'curl_exit=%s\n' "$RC"
) > wan4-curl.txt 2>&1
```

At the deadline, the tool disables sampling and writes one JSON document containing `before` and `after`; it does not continuously log packets. Check terminal A's successful exit and a parseable file. An empty file from a failed command is not zero-traffic evidence.

`-q` must be curl's first option to ignore `.curlrc`; `--noproxy '*'` excludes proxy environment settings. Do not bind the WAN device, which would change socket semantics relative to the report. A known target can be pinned with `--resolve api.ip.sb:443:ADDRESS` (bracket IPv6 addresses), retaining TLS hostname validation; do not use `-k`. DNS failure or a probe outside the capture window cannot establish that TC was skipped.

Run IPv6 separately: use **41501** in both commands, change curl to `-6`, and write `wan6.json` / `wan6-curl.txt`. Do not overlap captures. If a port is occupied, choose a new port consistently in both commands and avoid concurrent LAN traffic reusing it.

## Interruption and recovery

`--seconds` accepts 1–300, default 15. INT/TERM/HUP attempt to disable sampling before producing partial output; `end_reason` and `elapsed_ms` distinguish interruption from expiration. The deadline bounds enabled sampling, not process exit when an output pipe is blocked.

Both capture and `--disable` release their map/program FDs after constructing the owned report and before serializing it to stdout. Output backpressure therefore cannot retain a retired engine's production maps; handled cleanup failures are also returned after owners close, and fallback Drop cleanup performs no stdio.

SIGKILL, system failure or a failed disable update can leave the filter enabled. After confirming the original collector stopped, recover with this standalone command, adding a custom pin root if applicable:

```sh
./honk-tool bpf wan-diag --interface sipa_eth0 --disable
```

It is idempotent when already disabled and still checks map/interface ownership. If identity validation fails, do not bypass it with a forced map write: gracefully stop and restart the matching diagnostic engine using the original startup procedure. Never substitute clearing bpffs.

## JSON interpretation

Top-level fields identify the interface/ifindex, program/link/maps, selected source port, requested duration, elapsed time, end reason, and `before` / `after`. The two arrays contain nonzero per-reason/per-CPU-slot records only.

Each row retains cumulative `packets`, monotonic `timestamp_ns`, `socket_cookie`, egress/ingress ifindices, the actual `mark`, host-order EtherType `protocol`, packet length, signed `parse_result` and `first_byte`, `link_h_len`, and a readable `tuple`. `tuple=null` means no tuple attribution; `first_byte=-1` means reading the first header byte failed. IPv4-mapped addresses render as ordinary IPv4; ports are host-order.

| reason_index | reason | Existing path |
| --- | --- | --- |
| 0 | scratch_unavailable | Scratch unavailable; drop |
| 1 | parse_pass | Parser refusal; continue |
| 2 | parse_drop | Condemned fragment or local NDP Redirect |
| 3 | queue_carrier_drop | NFQUEUE DNS carrier drop |
| 4 | vlan_pass | Deferred to another VLAN device |
| 5 | not_ready_pass | Datapath not ready; continue |
| 6 | special_pass | Broadcast/multicast/special destination |
| 7 | local_destination_pass | Destination matches PARAM.local_ip |
| 8 | forwarded_pass | Nonzero ingress_ifindex; continue as forwarded |
| 9 | marked_pass | Exact bypass/classified mark; PASS |
| 10 | tuple_fence_drop | Tuple fence refusal |
| 11 | tcp_acquire_drop | TCP publication acquisition refusal |
| 12 | dispatch | Entering TCP/UDP handler, not proxy success |

Limits:

- **Reasons 0/1/2 are interface-wide unparsed evidence, not source-port-filtered evidence attributable to curl.**
- Counts are cumulative packets; each reason/CPU retains only its latest sample. Historical rows can remain unchanged in a later window. Compare before/after rather than treating an old sample as the new request.
- `cpu_slot` is a position in the possible-CPU buffer, not necessarily a sparse system's OS CPU ID. Counts may be summed, but sample fields must not be combined across slots.
- `coherent_snapshot=false`: disabling is not a grace barrier for admitted writers. A final write can race the dump; samples can be overwritten.
- Matching source ports may include LAN traffic. Match the full tuple, family and window to curl's actual output. Cookie is not host-origin authority; reading it may lazily assign one.
- Only a `forwarded_pass` sample positively matched to that curl confirms this guard's bypass. `dispatch` requires following the handler. Empty or unmatched evidence is inconclusive.

Retain and sanitize both JSON files, both curl outputs, both binary versions, package checksums, startup/binding logs and interface information. JSON includes IP addresses, not application payload, configuration or credentials.

## Finish

Export evidence and confirm sampling is disabled; gracefully stop the diagnostic engine, restore the original executable and restart the original service. Normal shutdown only attempts to remove owned pins; stale pins do not prove an active hook. Restart creates fresh diagnostic maps, while SIGHUP does not clear them. Never compare captures across restarts as a single counter interval. Preserve persistent allocator pins.
