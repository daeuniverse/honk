# Issue #415: collect WAN evidence with honk-tool

This build collects evidence for issue #415 without changing forwarding. **It is not a fix for the SIPA problem.** Use the aarch64 musl archive for this device: it contains matching static `honk-core` and `honk-tool` binaries, with BPF embedded in core. No bpftool, tracefs or device-side compiler is needed.

Root/BPF permissions, Linux TCX and a readable `/sys/devices/system/cpu/possible` are required. Use core/tool from the same diagnostic archive. Curl only generates the test request.

## Startup and scope

Back up the executable and config, stop the old service, and confirm no honk process remains. Start the packaged `honk-core --config /etc/honk/config.dae`. Do not overwrite a running executable or start a second engine. Keep the data directory, `UDP_DECISION_SEQUENCE` and `ROUTING_GENERATION_SEQUENCE`; do not clear bpffs.

The tool loads no programs or hooks. It writes only the diagnostic switch `WAN_DIAG_CFG`, not datapath state or counters. It checks map layouts and their association with the interface's TCX program. Cleanup uses the original map FDs, never replacement maps after a restart. Program/link checks run only at capture boundaries; do not reload or change configuration during capture.

Sampling defaults off. **Run one collector at a time; do not run recovery alongside it.** The initial check is not a concurrency lock. An existing nonzero filter refuses capture: stop the old collector or recover first.

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

At the deadline, sampling stops and stdout receives one JSON document with `before` / `after`, not per-packet logs. Require successful exit and parseable JSON; an empty file after failure does not mean zero traffic.

Keep `-q` first to ignore `.curlrc`; `--noproxy '*'` excludes proxy environment settings. Do not bind the WAN device, which changes socket behavior. For a known target IP, add `--resolve api.ip.sb:443:ADDRESS` (bracket IPv6 addresses); do not skip TLS validation with `-k`. DNS failure or a missed capture window cannot show that TC was skipped.

After IPv4, test IPv6 separately: change both ports to **41501**, curl to `-6`, and output names to `wan6.json` / `wan6-curl.txt`. If the port is busy, change it in both commands; avoid LAN traffic using the same port.

## Interruption and recovery

`--seconds` accepts 1–300, default 15. INT/TERM/HUP attempt to stop sampling and output partial results; `end_reason` and `elapsed_ms` record the reason and duration. The deadline limits sampling, not process exit when output is blocked.

The tool releases map/program FDs before writing JSON or reporting cleanup errors. Blocked output cannot keep an old engine's production maps alive.

SIGKILL, system failure or a failed disable write may leave sampling enabled. Once the old collector has stopped, run this command (add your custom pin root if used):

```sh
./honk-tool bpf wan-diag --interface sipa_eth0 --disable
```

Safe to repeat when already disabled. If the map/interface check fails, do not force a map write: stop and restart the matching diagnostic engine. Do not clear bpffs.

## JSON interpretation

Top-level fields record the interface, program/link/map IDs, source port, duration and end reason. `before` / `after` contain only nonzero reason/CPU-slot rows.

Rows contain cumulative `packets`, monotonic `timestamp_ns`, `socket_cookie`, egress/ingress ifindices, `mark`, EtherType `protocol`, packet length, `parse_result`, `first_byte`, `link_h_len` and `tuple`. `tuple=null` means no tuple; `first_byte=-1` means a failed read. Both result fields are signed; protocol and ports use host byte order, and IPv4-mapped addresses render as IPv4.

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

- **Reasons 0/1/2 cover unparsed packets across the interface. They are not source-port-filtered and cannot be attributed to curl.**
- Counts accumulate; each reason/CPU retains one last sample. Compare before/after: an unchanged old sample is not the new request.
- `cpu_slot` indexes the possible-CPU buffer, not necessarily OS CPU IDs. Sum counts if needed; never combine sample fields across slots.
- `coherent_snapshot=false`: disabling does not wait for in-flight writers. Writes or sample replacement can still race the read.
- The source port may also match LAN traffic. Check the full tuple, family and window against curl. A cookie does not prove host origin; reading it may assign one.
- Only `forwarded_pass` matched to that curl confirms bypass at the ingress_ifindex check. `dispatch` means the TCP/UDP handler was entered, not proxy success. Empty or unmatched samples cannot identify the cause.

Return both JSON files, both curl outputs, both programs' `--version`, package checksums, startup/binding logs and interface details. JSON contains IPs, not application data, configuration or credentials; sanitize before sharing.

## Finish

Export results and confirm sampling is off. Stop the diagnostic engine, restore the original executable and restart the service. Shutdown only attempts to remove owned pins; stale pins do not prove an active hook. Restart creates fresh diagnostic maps; SIGHUP does not clear them. Do not compare counters across restarts. Keep both persistent allocator pins named above.
