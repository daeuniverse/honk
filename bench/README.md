# Lab benchmark harness

`lab-bench.sh` is the single A/B benchmark harness for honk vs dae on the
lab (see `doc/benchmark.en.md` for the topology and the latest results).
It replaces the old `bench.sh` / `bench-cold.sh` / `bench-cpu.sh` /
`bench-honest.sh` script set.

## What it measures

Per engine × protocol:

- **cold** — first-request latency on a freshly restarted engine (3 runs,
  median; health checks are set to 3600s in both lab configs so they don't
  race the measurement)
- **hot p50/p95** — open-stream latency over 15 requests (proxy session
  already warm); only 2xx/3xx responses count, otherwise the row is `invalid`
- **bw** — iperf3 `-R` download, 3 runs, median receiver bitrate
- **cpu** — engine CPU cores during the median bandwidth run
  (`/proc/<pid>/stat` utime+stime delta over wall time)
- **rss** — engine RSS after the bandwidth runs
- **loaded latency stability** — 200 new HTTP streams at a fixed 250 ms
  cadence while one reverse iperf3 stream loads the same outbound; reports
  load, p50/p95/p99/max, and failures, with one JSONL row per attempt
- **direct baseline** — unproxied path through the engine datapath
  (`8080` http, `5300` iperf3)

AnyTLS rows require an engine build and config that expose those routes. Use
the shared four-protocol set when comparing against an ARM dae build without
AnyTLS.

## Usage

The script runs **on an engine host** (`10.10.10.49` x86-64 or
`10.10.10.118` ARM64):

```bash
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.49:/root/
ssh root@10.10.10.49 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# ARM comparison uses the common protocol surface.
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.118:/root/
ssh root@10.10.10.118 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan'"

# The dedicated rprx config maps its three groups onto live target slots 1-3.
ssh root@10.10.10.49 \
  "HONK_CONFIG=/root/honk-rprx.dae VLESS_VISION_INDEX=1 \
   VLESS_REALITY_INDEX=2 VMESS_INDEX=3 bash /root/lab-bench.sh \
   'honk' 'vless-vision vless-reality vmess'"
# args: [engines] [protocols] — both are space lists inside one arg
```

When `LAB_HOLDER_PID` is unset, the harness keeps the client `lab` namespace
alive across engine teardown and recreates its named mount automatically. Set
`LAB_HOLDER_PID` only when an external namespace holder already owns that
lifecycle.

Stdout contains the conventional throughput table followed by the loaded
latency-stability table. Standard rows append to `TSV` (default
`/root/bench-results.tsv`); stability rows append to `STABILITY_TSV`, while
raw samples, summaries, and iperf3 JSON go under `STABILITY_DIR`. The driver
prints host/kernel and honk/dae SHA-256 identities on stderr.

## Requirements on the lab

- Client netns `lab` with the veth pair + NAT (see the doc); set
  `net.ipv4.ip_forward=1` after every host reboot before the direct preflight.
  Standard configs route `5201/8001 → hy2` through `5206/8006 → anytls-go`.
  Dedicated rprx configs reuse target slots 1–3 with `VLESS_VISION_INDEX=1`,
  `VLESS_REALITY_INDEX=2`, and `VMESS_INDEX=3`.
- honk's lab config must expose the clash API on `127.0.0.1:9090` — the
  harness uses the API listener to identify the *active* engine process
  (a second honk instance parked on the singleton flock reports zero CPU
  and would poison the metrics).
- Live targets on 10.10.10.70: HTTP `8001-8006`, iperf3 `5201-5206`,
  direct controls `8080`/`5300`, and UDP echo `53531-53536`; churn/reload
  servers use `18006-18007` (`18007/big.bin` is the throttled long stream).
- `latency_stability.py` must be beside the driver unless
  `STABILITY_COLLECTOR` names another path.

## Paired runtime-memory measurements

`runtime-memory.sh` compares two honk binaries on the engine host. It alternates
arm order by run and validates the measured PID's start time, executable inode,
and binary hash before and after every scenario. Use only an externally generated,
sanitized lab config. The driver snapshots it once before the first arm and runs
every pair from that immutable copy outside the repository; the snapshot hash is
recorded in every row so a mid-run edit cannot mix configurations.

```bash
sudo bench/runtime-memory.sh \
  --baseline-bin /opt/honk/baseline/honk-core \
  --baseline-commit <40-or-64-hex-object-id> \
  --candidate-bin /opt/honk/candidate/honk-core \
  --candidate-commit <40-or-64-hex-object-id> \
  --config /root/honk-memory-lab.dae \
  --target 10.10.10.70 \
  --runs 5 \
  --output /var/tmp/honk-runtime-memory.jsonl
```

Each fresh arm records a 130-second cold curve; rejects a direct-path control
below 8.93 Gbps; measures AnyTLS open latency and reverse throughput; runs
20,000 requests at 64-way concurrency across all six protocol routes in ten
2,000-request batches separated by one second (up to three recorded retries
for transient connection/response timeouts); runs eight stalled readers beside
1,000 fast requests at 16-way concurrency; verifies 20 SIGHUP reloads (the
first while hashing a throttled long stream and checking new TCP plus UDP, the
other 19 with a new TCP flow each); smokes TCP and UDP through all six protocol
routes; and records a 130-second post-drain curve. Every JSONL
row carries source, binary, immutable config-snapshot, and benchmark-code identity;
host policy; RSS/PSS/private-dirty/fault/CPU telemetry; throughput and latency
quantiles; failures/loss, connection counts, and UDP stats. Engine logs remain in
`<output>.runs/`; any TCP workload failure emits no partial arm and leaves
the output suitable only as failure evidence.

Runtime-memory rows use `schema_version: 2`; `direct_control` and
`protocol_smoke` are explicit scenario discriminators, not fields folded into
the proxied throughput row.

For the collector ablation, rerun the same five pairs with both
`--baseline-collect-secs 0` and `--candidate-collect-secs 0`; do not change THP,
worker count, profile, config, or target between arms. The deterministic CLI and
JSONL contract runs unprivileged:

```bash
bash bench/tests/runtime-memory-cli.sh
```

## Known measurement traps

- The lab is shared. Another session restarting engines mid-run corrupts
  numbers — re-run any row that looks off before publishing.
- Historical (fixed): single-stream iperf3 through AnyTLS read 2–3 Mbps
  because honk killed streams on a full demux queue. The bounded per-stream
  overflow now preserves ordering, uses hard byte caps, and resets only an
  offending stream; single-stream AnyTLS numbers are valid and included in the
  table.

## sing-box as a third engine

`lab-bench.sh sing-box '<protos>'` runs sing-box 1.13.14 as a TUN client
**inside** the lab netns (`bench/sb-client.json` → `/root/sb-client.json`,
binary at `/root/sing-box`): client traffic hits the TUN, per-port route
rules pick the outbound, outbounds bind `veth-client`. Because no gateway
engine is running, the host must plain-forward lab traffic — the harness
assumes an idempotent masquerade (`/root/setup-nat.sh`, table `labnat`,
saddr 192.168.222.0/24 oif ens3). After each sing-box run the netns is
rebuilt (its TUN auto_route rewrites the routing table).

## UDP measurements

Each UDP-capable protocol row gets a `<proto>/udp` companion row: echo RTT
(15 pings to `53530+idx`, median — servers on .70 run `udpecho-multi.py` on
53530–53536) and iperf3 `-u -b 10G -l 1200 -R` (receiver bps + loss at a
saturating offered rate). Datagrams are pinned to 1200 B: QUIC datagrams cap
near that — honk's hy2/tuic drop oversized datagrams (protocol-normal;
iperf3's ~1448 B default would measure the cap, not the tunnel). honk's
VLESS/VMess variants have no packet handler, so the harness writes explicit
`n/a` fields and does not accidentally measure a direct fallback.

## Loaded latency stability

This is deliberately not another 15-request hot-latency burst. For each
engine × route, the driver starts one reverse iperf3 stream through that route,
then `latency_stability.py` opens 200 independent HTTP streams at absolute
250 ms deadlines (50 seconds). A bounded worker pool preserves those deadlines
when an earlier request stalls; each raw row records actual start offset and
schedule lag, and the summary keeps the p99/max lag. Quantiles include
successful HTTP 2xx/3xx samples; timeout, connection, and HTTP-status failures
remain in the denominator and are written to the raw JSONL. The paired iperf3
JSON retains the achieved pressure for audit. A non-zero collector/iperf exit,
missing JSON, or a non-positive measured load rejects that arm. Load duration
covers the one-second head start, every absolute deadline, the full configured
request timeout, and a one-second guard. The driver preserves failed artifacts,
retries twice, and emits an explicit `invalid` row rather than valid percentiles
if all three attempts fail.

Defaults can be overridden for a preflight with `STABILITY_SAMPLES`,
`STABILITY_INTERVAL_MS`, `STABILITY_TIMEOUT`, and `STABILITY_RETRIES`; set
`LATENCY_STABILITY=0` only for legacy throughput-only runs. Deterministic
collector tests run with:

```bash
python3 bench/tests/latency_stability_test.py
```
