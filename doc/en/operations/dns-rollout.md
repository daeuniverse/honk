# DNS Canary and Rollback Runbook

Use this runbook to deploy the DNS subsystem described in [DNS design](../design/dns.md).

This deployment checklist has not been run in the local development environment. The privileged steps need an isolated, explicitly authorized Linux host with root access. They load and attach real eBPF programs, change network namespaces, open transparent sockets, and publish routing maps.

## Prerequisites

- A disposable or isolated authorized host, an out-of-band recovery path, and a maintenance window. Do not use a shared production gateway as the first canary.
- For the privileged canary only: root or passwordless `sudo`; a supported Linux kernel with cgroup v2 and raw BTF (in-kernel, OpenWrt's `/usr/lib/debug/boot/vmlinux`, or an external file through `HONK_VMLINUX_BTF`); and the target interfaces, routes, and DNS clients.
- Rust stable plus the project nightly toolchain, `rust-src`, `bpf-linker`, CMake, a C/C++ compiler, the libclang/bindgen dependencies, and `readelf`.
- Exact paths for the active binary, config, BPF object, and persisted state (`<data_dir>/state/`, or `cache.db` before the state db); enough space for immutable rollback copies; and the previous known-good binary and config checksum.
- A way to observe service logs and host health. DNS counters and structured logs are internal diagnostics; there is no new public DNS metrics endpoint.

## Pre-deployment and backup

1. Record the host, kernel, interfaces, current binary and config checksums, the current routing generation from the logs, the service command, and the UTC time.
2. Run the unprivileged standalone DNS smoke from the exact candidate source:

   ```bash
   just dns-smoke
   ```

   This command builds the debug `honk-core` and runs it with `--mock-ebpf`. It verifies the configured loopback listener over UDP and a persistent TCP connection before and after an unchanged SIGHUP. It stops the process and removes all temporary resources before returning.
3. Quiesce the installed service using its normal service manager. Copy the current binary and config to timestamped, read-only rollback paths.
4. Back up the persisted state (`<data_dir>/state/`, or `cache.db`) while the service is quiesced, and preserve ownership and mode. With `global.store_subscribe`, back up the legacy subscription store as well: the first private `.sub` directory found among `<data_dir>/.sub`, `/var/share/honk/.sub`, and `./.sub`. A candidate with the state db imports and deletes its `*.sub` bodies on the first start. Record checksums for the binary, config, state, and `.sub` backups. Do not delete, rewrite, compact, or migrate the database.
5. Restart the previous version and run its UDP/TCP DNS smoke before you continue. This proves that the rollback bundle works.

## Privileged canary

> Status: **NOT EXECUTED** in the local development environment. Run these steps only on an isolated, explicitly authorized host that meets every prerequisite above.

1. Build and inspect the candidate on the authorized host:

   ```bash
   just build-ebpf
   cargo build --release -p honk-core --features ebpf
   ```

   Confirm that the eBPF object contains `.BTF` and retain the build log.
2. Stop the previous service normally. Install the candidate binary without overwriting the rollback copy, then start it with the retained production config and explicit BPF object through the host's service manager.
3. Confirm load and attach success, interface and policy-route health, and a newly published routing generation. Do not run `just clean-all` or delete pinned maps, namespaces, routes, or cache rows.
4. From an authorized client, issue one UDP and one TCP DNS query through the intercepted path. If enabled, also exercise Clash `/dns/query` and `/cache/dns/flush`; do not enable Clash solely for the canary.
5. Reload the unchanged config through the normal SIGHUP or service-manager path and repeat the queries. Then make one pre-approved reversible policy change, reload, and verify the new coherent routing generation.
6. Observe the internal low-cardinality diagnostics: cache hit, miss and stale; flight saturation, cancel and retry; persistence drop or flush failure; runtime retirement; transport init and reset; projection stale generation, write failure and retry; DNS outcome classes. Any growing failure or retry counter, retirement timeout, map-full condition, DNS answer regression or routing mismatch fails the canary.

## Rollback

1. Stop the candidate normally and retain its logs. Do not clean BPF state or mutate the persisted state.
2. Restore the prior binary and config from the verified rollback copies. Restore the database backup only if the canary corrupted or replaced the database; normally keep the live database. A candidate with the state db imports and deletes `cache.db` on its first start. With `global.store_subscribe`, it also imports and deletes the legacy `.sub` subscription bodies. Rolling back to a binary without the state db therefore means restoring the `cache.db` and `.sub` backups.
3. Start the prior binary with the prior config and BPF object. Trigger its normal config reload once, so that it re-pushes the prior routing generation. Verify the generation commit in the logs before you reopen traffic.
4. Repeat the UDP/TCP DNS and routing smokes, plus the Clash smoke when it was configured. Confirm host health and compare counters and logs with the pre-deployment record.
5. Preserve the candidate logs, checksums, build output, and query results for incident review. Never use destructive cleanup as a rollback mechanism.

## Evidence record

Record every command, exit status, timestamp, checksum, routing generation, query result, and relevant counter or log snapshot in the deployment ticket. Mark the privileged checklist `NOT EXECUTED` unless every prerequisite above is met on an isolated authorized host.

## Related docs

- [DNS design](../design/dns.md)
- [DNS configuration reference](../reference/dns.md)
- [Experimental configuration reference](../reference/experimental.md)
