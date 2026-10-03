# DNS Canary and Rollback Runbook

This deployment runbook is the operational companion to the [DNS design](../design/dns.md).

This checklist is deployment-only. It was not executed in the local
development environment because real eBPF load/attach, network namespace
changes, transparent sockets, and routing-map publication require an isolated,
explicitly authorized Linux host with root access.

## Prerequisites

- A disposable or isolated authorized host, an out-of-band recovery path, and
  a maintenance window. Do not use a shared production gateway as the first
  canary.
- For the privileged canary only: root or passwordless `sudo`, a supported
  Linux kernel with BTF, and the target interfaces, routes, and DNS clients.
- Rust stable plus the project nightly toolchain, `rust-src`, `bpf-linker`,
  CMake, C/C++ compiler, libclang/bindgen dependencies, and `readelf`.
- Exact paths for the active binary, config, BPF object, and persisted state
  (`<data_dir>/state/`, or `cache.db` before the state db);
  enough space for immutable rollback copies; the previous known-good binary
  and config checksum.
- A way to observe service logs and host health. DNS counters and structured
  logs are internal diagnostics; there is no new public DNS metrics endpoint.

## Pre-deployment and backup

1. Record the host, kernel, interfaces, current binary/config checksums,
   current routing generation from logs, service command, and UTC time.
2. Run the unprivileged standalone DNS smoke from the exact candidate source:

   ```bash
   just dns-smoke
   ```

   This command builds the debug `honk-core`, runs it with `--mock-ebpf`, and
   proves the configured loopback listener over UDP and a persistent TCP
   connection before and after an unchanged SIGHUP. It stops the process and
   removes all temporary resources before returning.
3. Quiesce the installed service using its normal service manager. Copy the
   current binary and config to timestamped, read-only rollback paths.
4. Back up the persisted state (`<data_dir>/state/`, or `cache.db`) while the
   service is quiesced, preserving ownership and mode. Record checksums for all three rollback artifacts. Do not delete,
   rewrite, compact, or migrate the database.
5. Restart the previous version and verify its UDP/TCP DNS smoke before
   proceeding. This proves the rollback bundle rather than merely creating it.

## Privileged canary

> Status: **NOT EXECUTED** in the local development environment. Run these
> steps only on an isolated, explicitly authorized host that meets every
> prerequisite above.

1. Build and inspect the candidate on the authorized host:

   ```bash
   just build-ebpf
   cargo build --release -p honk-core --features ebpf
   ```

   Confirm the eBPF object contains `.BTF` and retain the build log.
2. Stop the previous service normally. Install the candidate binary without
   overwriting the rollback copy, then start it with the retained production
   config and explicit BPF object through the host's service manager.
3. Confirm load/attach success, interface and policy-route health, and a newly
   published routing generation. Do not run `just clean-all` or delete pinned
   maps, namespaces, routes, or cache rows.
4. From an authorized client, issue one UDP and one TCP DNS query through the
   intercepted path. If enabled, also exercise Clash `/dns/query` and
   `/cache/dns/flush`; otherwise do not enable Clash solely for the canary.
5. Reload the unchanged config through the normal SIGHUP/service-manager path,
   repeat the queries, then make one pre-approved reversible policy change,
   reload, and verify the new coherent routing generation.
6. Observe the internal low-cardinality diagnostics for cache hit/miss/stale,
   flight saturation/cancel/retry, persistence drop/flush failure, runtime
   retirement, transport init/reset, projection stale-generation/write
   failure/retry, and DNS outcome classes. Any growing failure/retry counter,
   retirement timeout, map-full condition, DNS answer regression, or routing
   mismatch fails the canary.

## Rollback

1. Stop the candidate normally and retain its logs. Do not clean BPF state or
   mutate the persisted state.
2. Restore the prior binary and config from the verified rollback copies.
   Restore the database backup only if the canary corrupted or replaced the
   database; normally keep the live database. A candidate with the state db
   imports and deletes `cache.db` on its first start, so rolling back to a
   binary without it means restoring the `cache.db` backup.
3. Start the prior binary with the prior config and BPF object. Trigger its
   normal config reload once so it re-pushes the prior routing generation;
   verify the generation commit in logs before reopening traffic.
4. Repeat UDP/TCP DNS, routing, and, when already configured, Clash smokes.
   Confirm host health and compare counters/logs with the pre-deployment
   record.
5. Preserve the candidate logs, checksums, build output, and query results for
   incident review. Never use destructive cleanup as a rollback mechanism.

## Evidence record

Record every command, exit status, timestamp, checksum, routing generation,
query result, and relevant counter/log snapshot in the deployment ticket.
Mark the privileged checklist `NOT EXECUTED` unless all prerequisites above
are met on an isolated authorized host.

## Related docs

- [DNS design](../design/dns.md)
- [DNS configuration reference](../reference/dns.md)
- [Experimental configuration reference](../reference/experimental.md)
