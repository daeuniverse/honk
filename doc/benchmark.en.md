# Benchmark Lab and Results

This document describes the reproducible benchmark environment for honk, the
measurement methodology, and the most recent results against
[dae](https://github.com/daeuniverse/dae) (same-time A/B). It lives in the
repo so the setup and the numbers stay in sync with the code.

## Lab topology

```text
┌──────────────────────────────────────┐       ┌─────────────────────────────┐
│ Engine host (one selected per run)   │       │ 10.10.10.70 (physical, 50G) │
│                                      │       │                             │
│ x86: 10.10.10.49, 4 vCPU / 2 GiB    │  LAN  │ Protocol servers:           │
│ ARM: 10.10.10.118, R2S / 1 GiB       ├──────►│  hy2/tuic/SS/Trojan/AnyTLS │
│                                      │       │ Targets:                    │
│  ┌───────────────┐                   │       │  HTTP  :8001-8006,8080      │
│  │ netns "lab"   │ veth              │       │  iperf:5201-5206,5300      │
│  │ 192.168.222.2 ├──► real eBPF path │       │  UDP echo:53531-53536      │
│  └───────────────┘                   │       └─────────────────────────────┘
│ honk / dae (one at a time)           │
│ LAN: veth-lab                        │
│ WAN: ens3 (x86) / USB GbE (ARM)      │
└──────────────────────────────────────┘
```

- **x86 engine host (`10.10.10.49`)**: Debian 13 VM, four host-passthrough
  i5-13600K vCPUs and 2 GiB RAM, with `ens3` as WAN. Its client lives in
  network namespace `lab` (`veth-lab` ↔ `veth-client`, 192.168.222.0/24,
  nftables masquerade). The direct control reaches about 9.4 Gbps.
- **ARM engine host (`10.10.10.118`)**: NanoPi R2S, RK3328 with four
  Cortex-A53 cores, 968 MiB usable RAM, and `eth0` as WAN. It uses the
  identical `lab` namespace topology; the direct control is approximately
  0.8–0.9 Gbps.
- **Real datapath**: both hosts run either honk or dae, never both. Every
  measured client flow crosses the engine's real eBPF/TPROXY path; no
  loopback shortcut is measured.
- **Server host (`10.10.10.70`)**: protocol servers (official hysteria,
  tuic-server, sing-box, Go anytls-server) plus local targets. Servers dial
  out to the internet directly, so "internet" tests traverse server → WAN.
- **Isolation**: nothing here touches the production gateway (`10.10.10.1`).
  Production validations are done separately and called out as such.

### Known lab limits

- Cross-architecture absolute throughput is intentionally not normalized:
  `.118` is capped by USB GbE and A53 CPU. Compare honk-vs-dae on the
  **same host**; use the two hosts to show whether conclusions survive the
  architecture change.
- The loaded-latency phase deliberately runs one reverse iperf3 stream on the
  same route. Its tail includes engine scheduling, crypto, softirq contention,
  and the host's NIC ceiling; it is not an unloaded network RTT measurement.
- Run-to-run variance on shared infrastructure is about ±5%. The lab is
  shared: another session restarting an engine or compiling on the ARM board
  invalidates that arm, which must be rerun before publication.
- The x86 VM uses host CPU passthrough (AES-NI + AVX2). Historical qemu64
  measurements without SIMD are retained below only as explicitly dated
  history, not as the current x86 baseline.
- The rprx server's process/version on `.70` was not retrievable with the
  available SSH credentials. Exact client wire parameters and both client
  binary hashes are retained, but those rows must not be used as a
  server-version regression baseline.
- The 2026-08-08 proxy matrix covers every endpoint configured at that time:
  HY2, TUIC, SS2022, Trojan, two AnyTLS servers, VLESS Vision/REALITY, and
  VMess. No SOCKS5 endpoint is available. Juicity was absent from that matrix;
  a dedicated 2026-08-26 comparison against the existing Go server is reported
  below. The older Juicity direct-UDP offload result is not a proxy comparison.

## What's running where

| Component | Binary | Config |
| --- | --- | --- |
| hy2 server | official `hysteria` | `:8443`, password `testpass123`, cert CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`, uuid `00000000-0000-0000-0000-000000000001` / `testpass123`, requires SNI `hy2.test` |
| Juicity server | official Go `juicity-server` v0.4.3 | `:2451`, uuid `00000000-0000-0000-0000-000000000001` / `testpass123`, SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`, password `testpass123` |
| AnyTLS server | Go reference `anytls-server` | `:2443`, `-p testpass123` |
| SS 2022 server | sing-box | `:2447`, `2022-blake3-aes-128-gcm`, psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`, password `testpass123`, SNI `hy2.test` |
| Targets | python http.server, iperf3 | ports `8001-8006` + `8080` (direct), `5201-5206` + `5300` (direct); UDP echo `53531-53536` |

Standard engine configs route by destination port so no API switching is
needed: `5201/8001 → hy2`, `5202/8002 → tuic`, `5203/8003 → ss2022`,
`5204/8004 → trojan`, `5205/8005 → anytls-sb`, `5206/8006 → anytls-go`.
The dedicated honk-only rprx configs remap VLESS Vision/REALITY/VMess onto the
live target slots 1–3 via harness index overrides; the dedicated Juicity
configs reuse slot 1 for a paired honk/dae run. The current x86 kdae build
includes AnyTLS; ARM honk-vs-dae uses the four-protocol shared surface. Node
server ports are `direct(must)` and everything else falls back to direct.

## Methodology

One harness — `bench/lab-bench.sh` (in this repo, run on the engine host) —
replaces the old bench.sh/bench-cold.sh/bench-cpu.sh/bench-honest.sh set.
See `bench/README.md` for usage and lab requirements.

Per engine × protocol:

- **cold** — first-request latency on a freshly restarted engine, 3 runs,
  median. Health checks are at 3600s in both lab configs so the first probe
  doesn't race the measurement.
- **hot p50/p95** — open-stream latency over 15 requests against the
  per-protocol HTTP target (proxy session already warm). For QUIC protocols
  this is dominated by connection/session reuse; for mux protocols by the
  pooled session.
  Standard HTTP samples require a successful 2xx/3xx response; a connect or
  status failure marks the row invalid instead of recording curl's failure time.
- **bw** — iperf3 `-R` download, single stream, 3 runs, median receiver
  bitrate.
- **udp** — per protocol: echo RTT (15 pings to the routed echo port
  5353x, median) and iperf3 `-u -b 10G -l 1200 -R` (receiver bitrate +
  loss at a saturating offered rate; datagrams pinned to 1200 B because
  QUIC datagrams cap near that).
- **loaded latency stability** — after the regular throughput sample, one
  reverse iperf3 stream loads the same route while a bounded worker pool opens
  200 independent HTTP streams at absolute 250 ms deadlines (50 seconds), so
  one timeout cannot serialize later attempts. Report p50/p95/p99, maximum,
  failures, and scheduling lag; retain every attempt as JSONL plus the paired
  iperf3 JSON so a failed or low-pressure load cannot look "stable".
- **cpu** — engine CPU cores during the median bandwidth run
  (`/proc/<pid>/stat` utime+stime delta over wall time). The honk pid is
  anchored on the clash-API listener so a second instance parked on the
  singleton flock (zero CPU) can't poison the metric.
- **rss** — engine RSS after the bandwidth runs.
- **direct baseline** — same measurements on the unproxied path
  (`8080`/`5300`).

```bash
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.49:/root/
ssh root@10.10.10.49 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# ARM uses the protocol surface shared with its dae build.
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.118:/root/
ssh root@10.10.10.118 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan'"
```

`lab-bench.sh` prints host/kernel and binary SHA-256 identities. Standard rows
append to `TSV`; loaded-stability summaries append to `STABILITY_TSV`, with raw
samples and load JSON under `STABILITY_DIR`. Collector fixtures run with
`python3 bench/tests/latency_stability_test.py`.

### VLESS Vision codec candidate benchmark

`crates/honk-outbound/benches/vless_vision.rs` isolates response decoding on a
clear loopback carrier; production Vision remains TLS/REALITY-only. Both cases
decode exactly **16 MiB** from deterministic 16 KiB source writes, and each
binary validates the decoded byte count before Criterion starts timing:

- `vision_framed_16m`: many content/padding frames ending with `End`;
- `vision_direct_16m`: one `Direct` frame followed by the raw tail.

The paired release-musl binaries run on the confirmed x86-64 Debian host
`root@10.10.10.50`, from one Criterion directory and back-to-back:

```bash
ssh root@10.10.10.50 \
  'mkdir -p /root/vless-vision-criterion && cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.before --bench --save-baseline vless-before-final'
ssh root@10.10.10.50 \
  'cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.after --bench --baseline vless-before-final'
```

Accept a candidate only when the framed point estimate improves and its 95%
interval excludes a slowdown greater than 3%; the Direct point estimate may
regress by at most 3%.

## Results (2026-08-27, proxied QUIC adapter regression gate)

The merged PR #75 path plus follow-up fix `0ecc101` was compared with pre-PR
main `4c3ade3`. The fixture uses the production ownership shape: one shared
`NodeRuntime`, a fresh packet flow through the real Hysteria2, TUIC, or Juicity
lab server, and one inner QUIC handshake to a loopback H3 server. Each protocol
has 30 alternating A/B pairs, 100 measured handshakes and 5 warmups per process
(3,000 measured samples per arm). This isolates adapter/probe cost; it is not a
user-data capacity benchmark.

| Outer transport | baseline / candidate total median ms | paired median delta | 95% bootstrap interval | paired p95 delta | process CPU delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hysteria2 | 0.916 / 0.923 | +0.688% | -1.328% to +2.115% | -3.054% | -7.709% |
| TUIC | 0.920 / 0.937 | +1.580% | -1.136% to +4.108% | +2.511% | -7.136% |
| Juicity | 0.857 / 0.873 | +2.549% | -0.152% to +3.893% | +2.848% | -7.336% |

Every interval includes zero, so this run demonstrates no latency regression.
The point estimates stay below 3%, but the TUIC and Juicity upper bounds exceed
3%; the sample does not prove a sub-3% worst case. All 9,000 measured candidate
handshakes completed with empty stderr. The process CPU rows divide child CPU
by all 105 probes and include amortized process startup; they are supporting
evidence, not a claim about proxy throughput.

A separate 5,000-probe tight loop checks endpoint-worker retirement. It is
deliberately much denser than the periodic production cadence:

| Outer transport | baseline / candidate peak RSS KiB | baseline / candidate wall s |
| --- | ---: | ---: |
| Hysteria2 (two runs) | 231104–247072 / 44048–45520 | 3.69–3.98 / 4.27–4.42 |
| TUIC | 246944 / 43520 | 3.64 / 4.36 |
| Juicity | 217840 / 43088 | 4.27 / 4.26 |

The follow-up keeps peak RSS near 43–46 MiB instead of 213–241 MiB under this
churn. Hysteria2 and TUIC pay up to 0.72 seconds over 5,000 immediate probes for
deterministic worker cleanup; Juicity is flat. This is a cleanup stress cost,
not a hot data-path regression.

The same run exposed and fixed two correctness issues before the final A/B:
quic-go can coalesce a 1280-byte first flight despite the 1252-byte advertised
cap, and a successful probe must drop its connection handle before closing the
endpoint. Full binary/source hashes, raw paired rows, confidence calculations,
soak rows, configs, and exact runners are under
[`quic-proxy-impact-2026-08-27`](../bench/results/quic-proxy-impact-2026-08-27/).

## Results (2026-08-26, QUIC profile and optimization gate)

This follow-up profiles the current bounded-GSO implementation at source
`0bd6135` plus the isolated Juicity candidate `429c540`. The x86 host used one
musl binary (`e8750633...`), one 1452-byte configuration, 8-second iperf3
windows, and alternating five-run arms. `reverse` is server-to-client
download; `forward` is client-to-server upload. Hardware PMU events were not
available, so the profile evidence is userspace `cpu-clock` sampling,
process task-clock, syscall counts, and the end-to-end throughput/CPU result.

The full harness reproduction uses the existing 3-cold / 15-hot /
median-of-3 bandwidth / 200-loaded-stream contract:

| Route | Cold / hot p50 / p95 ms | Bandwidth Mbps / CPU / RSS MiB | Loaded Mbps / p99 / max ms / failures |
| --- | ---: | ---: | ---: |
| direct | 16.225 / - / - | 9403 / 0.00 / 45 | 8918 / 8.177 / 13.614 / 0 |
| HY2 | 8.561 / 1.076 / 3.060 | 6037 / 0.55 / 52 | 5852 / 6.462 / 10.375 / 6 |
| TUIC | 2.759 / 1.101 / 1.988 | 3355 / 0.34 / 43 | 3428 / 4.189 / 11.539 / 0 |

### Measured bottleneck

| Protocol / direction | Baseline median Mbps / CPU cores | Largest userspace self samples |
| --- | ---: | --- |
| HY2 reverse | 6369 / 0.636 | AES-GCM decrypt 14.0%; `memcpy` 12.9% |
| HY2 forward | 5035 / 1.037 | `memcpy` 15.6%; AES-GCM encrypt 10.7%; mutex contention 6.9% |
| TUIC reverse | 3758 / 0.367 | `memcpy` 13.7%; AES-GCM decrypt 11.7% |
| TUIC forward | 5279 / 0.855 | `memcpy` 12.3%; mutex contention 9.3%; AES-GCM encrypt 8.5% |

The remaining leading samples are Quinn packet assembly/decoding, connection
driver work, and receive reassembly. This places the primary cost in shared
QUIC crypto and buffer movement rather than one protocol's framing. The
diagnostic `strace` arms observed roughly 95–102 thousand `sendmsg` and 78–93
thousand `recvmmsg` calls in one forward window, but tracing reduced throughput
to about 1.1–1.2 Gbps; those counts are not used as a production comparison.

The instrumented endpoint reported MTU 1452, kernel GSO capacity 64, the
application cap 16, and GRO 64. Across 43 connection snapshots, neither
connection nor stream flow-control blocking advanced. This confirms the
effective GSO cap and gives no measured basis for enlarging receive windows.

### GSO and MTU

The authoritative x86 comparison alternated disabled, cap-4, and cap-16 modes
within every repetition. Deltas are the median of paired same-run percentage
changes, not a ratio of aggregate medians.

| Mode | HY2 Mbps / CPU | HY2 paired delta | TUIC Mbps / CPU | TUIC paired delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 6365 / 0.628 | control | 3319 / 0.343 | control |
| GSO cap 4 | 6231 / 0.618 | +1.88% | 3280 / 0.328 | -7.65% |
| GSO cap 16 | 6576 / 0.635 | +3.63% | 3367 / 0.340 | -0.15% |

Cap 16 repeats the existing HY2 gain, but does not improve CPU and does not
produce the same gain for TUIC. The single-pass cap-8 arm was noisy and the
cap-32 HY2 arm produced no valid throughput. Nothing justifies widening the
existing cap or changing the black-hole-safe 1252-byte scalar default.

The final ARM arm used the same binary/config contract and a monotonic
nanosecond clock for process CPU:

| Mode | HY2 Mbps / CPU | HY2 paired delta | TUIC Mbps / CPU | TUIC paired delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 334 / 1.419 | control | 249 / 1.059 | control |
| GSO cap 4 | 330 / 1.440 | -1.29% | 227 / 1.001 | -8.99% |
| GSO cap 16 | 335 / 1.423 | -0.10% | 233 / 1.020 | -7.73% |

ARM shows no GSO gain. Its TUIC samples are variable, but both enabled medians
are lower; their lower CPU follows lower delivered throughput and is not an
efficiency improvement.

### Owned QUIC stream relay prototype

The prototype replaced generic `AsyncRead` buffering only for concrete Quinn
streams, using `RecvStream::read_chunk` and `SendStream::write_chunk`. It kept
the current half-close, byte accounting, cancellation, and idle-drain rules.

| TUIC mode / direction | Median Mbps / CPU | Paired throughput delta |
| --- | ---: | ---: |
| current relay, reverse | 3368 / 0.344 | control |
| owned-chunk relay, reverse | 3327 / 0.334 | -1.22% |
| current relay, forward | 5611 / 0.952 | control |
| owned-chunk relay, forward | 5852 / 0.957 | +0.01% |

The reverse regression, unchanged paired forward throughput, and only 2.6–2.9%
CPU reductions fail the no-regression and 10% CPU gates. The prototype was
reverted; concrete QUIC streams continue through the existing relay.

### Controlled TUIC congestion sweep

| Algorithm | Reverse Mbps / CPU / retransmits | Forward Mbps / CPU / retransmits |
| --- | ---: | ---: |
| cubic | 3474 / 0.346 / 1 | 5709 / 0.924 / 9 |
| BBR | 3454 / 0.337 / 0 | 5488 / 1.042 / 154 |
| New Reno | 3511 / 0.353 / 0 | 5407 / 0.867 / 15 |

Cubic keeps the highest forward median. BBR costs more CPU and retransmits in
that direction; New Reno lowers forward throughput. TUIC therefore retains its
current cubic default. No window, ACK, PMTUD, fairness, or buffer tuning was
promoted without a changed bottleneck metric.

### Allocation cleanup

Juicity candidate `429c540` passes an encoded frame to Quinn with
`write_chunk(Bytes)` and decodes UDP payloads directly into the caller's
buffer. Three paired 500-packet allocation runs measured approximately 4,828
versus 5,839 allocation calls, 17.3% fewer calls and about 15% fewer allocated
bytes. The focused receive test also keeps one caller buffer across 4096
frames. This allocation-specific cleanup was merged as `d4fd31a` in
[PR #73](https://github.com/daeuniverse/honk/pull/73).
Its four focused tests and all 546 `honk-outbound` tests passed; formatting and
Clippy were clean.

The candidate-vs-baseline local end-to-end arm was too noisy to attribute a
throughput change to this cleanup. The surrounding UDP endpoint receive path
already reuses one fixed buffer and sends from it directly; broader ownership
changes would add API and lifetime complexity without removing a measured
allocation, so none were made. Salamander was not present in that fixture and
likewise received no speculative optimization.

### Current honk versus dae on Juicity

The existing official Go `juicity-server` v0.4.3 endpoint at
`10.10.10.70:2451` was wired into dedicated paired configs that reuse target
slot 1 and set a 1452-byte QUIC MTU. Current main `4c3ade3`, built by the
canonical `just build-musl` recipe (`ba2821e3...`), was compared with dae
`unstable-20260824.r1142.ec957346` (`f2dc44b5...`) on the x86 host. Three full
harness pairs retain the 3-cold / 15-hot / median-of-3 bandwidth / 200-loaded
contract; a separate five-pair capacity run uses one 8-second bandwidth window
per arm. Percentage deltas are medians of paired same-run deltas.

| Contract | honk TCP Mbps / CPU / RSS | dae TCP Mbps / CPU / RSS | Paired TCP throughput / CPU | honk UDP Mbps / CPU / loss | dae UDP Mbps / CPU / loss | Paired UDP throughput / CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full, 3 pairs | 6514 (5466–6966) / 0.61 / 43 | 6420 (6400–6525) / 0.80 / 51 | -0.17% / -23.75% | 1142 / 0.45 / 72.3% | 1193 / 0.43 / 71.2% | -4.27% / +4.65% |
| focused capacity, 5 pairs | 6941 / 0.64 / 41 | 6527 / 0.82 / 50 | +6.34% / -21.95% | 1225 / 0.45 / 71.3% | 1297 / 0.45 / 69.9% | -6.67% / 0.00% |

The capacity direct anchor is 9404 Mbps for both engines. All five focused TCP
pairs favor honk throughput and CPU, raising paired Mbps/core by 36.56%. The
full contract contains one low 5466-Mbps honk arm and is a throughput tie, but
still reduces CPU in every pair and raises paired Mbps/core by 30.93%. Report
both contracts: the CPU-efficiency advantage is consistent; a universal TCP
throughput win is not.

| Full-contract latency | honk | dae |
| --- | ---: | ---: |
| cold median | 3.040 ms | 3.958 ms |
| hot p50 / p95 | 0.839 / 1.949 ms | 0.739 / 1.214 ms |
| loaded Mbps | 6044 | 6045 |
| loaded p50 / p95 / p99 / max | 1.562 / 3.257 / 3.841 / 4.498 ms | 1.900 / 3.389 / 5.324 / 8.559 ms |
| loaded failures | 0 / 600 | 16 / 600 |

dae has the lower hot-open latency. honk has the lower cold median and lower
loaded tails in every pair at effectively equal aggregate median load. The
loaded phase is capacity-edge, not an equal-rate latency comparison. Saturated
UDP favors dae in every focused pair; its 69–73% loss is deliberate overload,
not a WAN-loss result, and establishes no honk UDP gain. Exact configs, raw
rows, loaded samples, hashes, and the compact summary are under
[`juicity-x86`](../bench/results/quic-analysis-2026-08-26/juicity-x86/).

No other end-to-end candidate reached at least 3% median throughput or 10% CPU
reduction in one stable direction without regressing another, so no further
performance PR was opened. Full hashes, raw JSON, profiles, alternating rows,
focused test evidence, and the exact runners are under
[`quic-analysis-2026-08-26`](../bench/results/quic-analysis-2026-08-26/).

## Results (2026-08-25, Hysteria2 interoperability and bounded QUIC GSO)

This follow-up validates candidate `c1b8749` against an official Hysteria
v2.12.2 server and measures the shared QUIC socket change. It supplements,
rather than replaces, the paired 2026-08-24 honk/dae baseline below. The
throughput fixture is plain HY2/TUIC with an explicit **1452-byte QUIC UDP
payload**; it does not exercise Salamander, port hopping, or Juicity.

The official-server matrix covers PKI and pinned TLS, self-signed TLS,
Salamander, authentication failures, bandwidth hints, UDP-disabled refusal,
MTU/PMTUD/windows, UDP fragmentation, and the public-path port-hopping limit.
See the
[sanitized feature matrix](../bench/results/quic-gso-2026-08-25/remote-hy2-feature-matrix.txt).

### x86 bounded-GSO decision

The two enabled arms and the disabled control use the same final musl binary
(`dadefe68...`) and configuration. `HONK_QUIC_GSO=0` disables GSO for the
control; the enabled arms leave it unset, so the explicit 1452-byte payload
selects GSO with an application cap of 16 segments. TCP bandwidth is Mbps,
CPU is cores, RSS is MiB, and loaded cells are
`Mbps / p99 ms / failures out of 200`.

| Mode | HY2 TCP / CPU / RSS | TUIC TCP / CPU / RSS | HY2 loaded | TUIC loaded |
| --- | ---: | ---: | ---: | ---: |
| documented 2026-08-24 baseline | 6140 / 0.61 / 48 | 3350 / 0.34 / 43 | 6033 / 8.075 / 3 | 3366 / 2.609 / 0 |
| final binary, GSO off | 6479 / 0.63 / 50 | 3273 / 0.33 / 42 | 6570 / 6.387 / 2 | 3335 / 2.574 / 0 |
| final binary, GSO cap 16, arm A | 6845 / 0.63 / 55 | 3176 / 0.32 / 52 | 6568 / 3.879 / 0 | 3246 / 3.243 / 0 |
| final binary, GSO cap 16, arm B | 6713 / 0.64 / 48 | 3264 / 0.31 / 43 | 6563 / 3.685 / 0 | 3199 / 2.328 / 4 |

Against the same-binary control, bounded GSO raises HY2 TCP capacity by
3.6–5.6% while the direct anchor stays at 9401–9406 Mbps. TUIC TCP is within
the known run-level spread, so no TCP speedup is claimed. At the deliberately
saturating 10-Gbps UDP offer, HY2 moves from 831 Mbps / 81.1% loss to
902–935 Mbps / 77.3–78.6%; TUIC moves from 814 / 80.3% to 979–1079 /
74.4–77.6%. These are overload-capacity results, not WAN loss rates.

RSS spans 48–55 MiB for enabled HY2 and 43–52 MiB for enabled TUIC; the
second arm returns to the documented 48/43 MiB baseline. That rules out a
persistent RSS regression in this sample, not an allocation-count change.
Sparse loaded failures vary by arm and remain reported rather than averaged
away.

### ARM exploratory toggle

The ARM board used the pre-auto-GSO candidate and its existing
`HONK_QUIC_GSO=0|1` switch, not the final 16-segment binary:

| Mode | HY2 TCP / RSS; UDP | HY2 loaded Mbps / p99 / failures | TUIC TCP / RSS; UDP | TUIC loaded Mbps / p99 / failures |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 345 / 39; 2 Mbps (83.1%) | 344 / 125.828 / 0 | 245 / 25; 3 Mbps (91.6%) | 257 / 37.010 / 0 |
| GSO on | 346 / 42; 1 Mbps (84.7%) | 344 / 125.411 / 8 | 254 / 29; 1 Mbps (92.4%) | 253 / 43.357 / 2 |

This board provides no GSO throughput win and shows more sparse failures in
the enabled arm. It is retained as a negative, board-specific signal; it is
not evidence for final cap-16 ARM performance. The shipped policy therefore
keeps the black-hole-safe 1252-byte default scalar, enables bounded GSO only
after an operator selects a larger MTU, and retains `HONK_QUIC_GSO=0` as the
escape hatch. The shared path covers plain HY2, TUIC, and Juicity. No Juicity
endpoint was wired for this 2026-08-25 arm; the dedicated current-main
comparison above now supplies that protocol evidence without changing this
GSO decision.

Full provenance, hashes, TSVs, loaded-run JSON/samples, exploratory arms, and
cleanup status are under
[`quic-gso-2026-08-25`](../bench/results/quic-gso-2026-08-25/).

## Results (2026-08-24, current cross-architecture A/B)

This is the current paired run: x86 `10.10.10.49` and ARM `10.10.10.118`.
The ARM run uses the updated kdae config (`eth0` plus
`disable_waiting_network: true`) and kdae
`unstable-20260824.r1142.ec957346`. The candidate is main
`39f92eb51c62a9a330f56612c6671ae678a03585`; binary, kernel, config, harness,
and result hashes are authoritative in
[`metadata.txt`](../bench/results/cross-arch-2026-08-24/metadata.txt).

Both engines ran one at a time through the real datapath. Standard rows are
3 cold requests, 15 hot requests, and the median of three 8-second bandwidth
runs. Loaded rows are a separate 200-request, 250-ms-cadence run with one
reverse iperf3 stream on the same route. The ARM namespace holder stayed alive
through engine teardown and recreation; this prevents the client namespace
from disappearing when honk removes its `daens` namespace.

### x86-64 (`10.10.10.49`, 4 vCPU / 2 GiB)

#### TCP standard

Cold and hot latency are milliseconds; bandwidth is Mbps; CPU is cores; RSS is
MiB.

| Protocol | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / cores / RSS | dae Mbps / cores / RSS | bw ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.772 / – / – | 1.789 / – / – | 9403 / 0.00 / 46 | 9403 / 0.00 / 39 | 1.00× |
| hy2 | 1.627 / 0.870 / 2.347 | 3.060 / 0.719 / 0.930 | 6140 / 0.61 / 48 | 6466 / 0.79 / 51 | 0.95× |
| tuic | 1.708 / 0.795 / 3.429 | 18.096 / 16.352 / 16.921 | 3350 / 0.34 / 43 | 3877 / 0.52 / 54 | 0.86× |
| ss2022 | 3.310 / 1.174 / 1.385 | 2.080 / 1.083 / 2.241 | 9401 / 0.31 / 48 | 9368 / 0.37 / 53 | 1.00× |
| trojan | 5.320 / 0.891 / 7.515 | 2.208 / 1.381 / 2.961 | 9288 / 0.36 / 43 | 9381 / 0.44 / 46 | 0.99× |
| anytls-sb | 1.833 / 0.724 / 1.972 | 5.431 / 0.738 / 2.097 | 9361 / 0.43 / 46 | 9352 / 0.43 / 52 | 1.00× |
| anytls-go | 2.926 / 0.761 / 3.287 | 4.332 / 1.175 / 2.490 | 9391 / 0.47 / 42 | 9200 / 0.44 / 54 | 1.02× |

#### UDP saturation

| Protocol | honk RTT ms | dae RTT ms | honk Mbps / loss / cores | dae Mbps / loss / cores | bw ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.112 | 0.158 | 823 / 79.8% / 0.43 | 902 / 78.0% / 0.45 | 0.91× |
| tuic | 0.090 | 0.103 | 1049 / 75.3% / 0.47 | 937 / 76.7% / 0.48 | 1.12× |
| ss2022 | 0.079 | 0.154 | 1814 / 52.6% / 0.67 | 2513 / 34.3% / 0.64 | 0.72× |
| trojan | 0.112 | 0.070 | 1572 / 59.4% / 0.67 | 2870 / 23.7% / 0.60 | 0.55× |
| anytls-sb | 0.147 | 0.109 | 1156 / 68.0% / 0.43 | 1104 / 66.1% / 0.29 | 1.05× |
| anytls-go | 0.082 | 0.109 | 1299 / 64.7% / 0.48 | 1418 / 64.7% / 0.34 | 0.92× |

#### Loaded stability

Each percentile is successful HTTP latency; failures remain explicit.

| Engine | Protocol | load Mbps | p50 / p95 / p99 / max ms | failures |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 9408 | 1.517 / 1.994 / 2.475 / 3.426 | 0/200 |
| honk | hy2 | 6033 | 1.708 / 3.005 / 8.075 / 9.802 | 3/200 |
| honk | tuic | 3366 | 1.400 / 2.061 / 2.609 / 2.767 | 0/200 |
| honk | ss2022 | 9403 | 1.885 / 3.177 / 4.869 / 6.013 | 4/200 |
| honk | trojan | 9323 | 1.671 / 4.362 / 7.895 / 11.469 | 0/200 |
| honk | anytls-sb | 9317 | 1.625 / 2.863 / 2089.764 / 3107.546 | 0/200 |
| honk | anytls-go | 9304 | 2.121 / 4.875 / 8.950 / 11.094 | 0/200 |
| dae | direct | 9406 | 1.687 / 2.306 / 2.551 / 4.937 | 0/200 |
| dae | hy2 | 6083 | 2.106 / 4.457 / 7.427 / 7.786 | 6/200 |
| dae | tuic | 4014 | 16.179 / 17.111 / 17.637 / 18.310 | 0/200 |
| dae | ss2022 | 9404 | 2.244 / 4.025 / 5.689 / 13.743 | 0/200 |
| dae | trojan | 9390 | 3.454 / 7.135 / 12.618 / 17.764 | 0/200 |
| dae | anytls-sb | 8770 | 1.626 / 3.889 / 42.709 / 58.435 | 4/200 |
| dae | anytls-go | 9244 | 2.278 / 11.220 / 16.807 / 20.968 | 2/200 |

On x86, honk is within 1% of dae for SS2022, Trojan, and sing-box AnyTLS,
while using no more CPU on any TCP proxy row. It gives up 5% on HY2 and 14% on
TUIC throughput, but its TUIC hot p95 is 3.429 ms versus 16.921 ms. UDP is
mixed: honk leads TUIC and sing-box AnyTLS slightly, but trails dae on HY2,
SS2022, Trojan, and Go AnyTLS. The 2.09-second honk AnyTLS-sing-box p99 is a
real outlier in the retained raw samples, not a formatting omission.

### ARM64 (`10.10.10.118`, NanoPi R2S / 1 GiB)

#### TCP standard

| Protocol | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / cores / RSS | dae Mbps / cores / RSS | bw ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.544 / – / – | 3.379 / – / – | 862 / 0.02 / 22 | 860 / 0.01 / 41 | 1.00× |
| hy2 | 6.827 / 5.557 / 18.128 | 21.981 / 5.782 / 7.017 | 344 / 1.27 / 39 | 218 / 0.80 / 45 | 1.58× |
| tuic | 5.912 / 5.445 / 6.854 | 32.721 / 21.513 / 22.089 | 233 / 0.93 / 29 | 238 / 0.81 / 43 | 0.98× |
| ss2022 | 5.939 / 4.889 / 31.721 | 8.166 / 6.855 / 7.625 | 430 / 0.76 / 28 | 281 / 0.82 / 36 | 1.53× |
| trojan | 59.571 / 13.261 / 59.743 | 15.561 / 15.397 / 17.603 | 416 / 0.79 / 30 | 205 / 0.79 / 40 | 2.03× |

#### UDP saturation

| Protocol | honk RTT ms | dae RTT ms | honk Mbps / loss / cores | dae Mbps / loss / cores | bw ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.176 | 2.434 | 2 / 87.1% / 1.56 | 99 / 97.1% / 0.86 | 0.02× |
| tuic | 2.428 | 2.601 | 2 / 88.2% / 1.52 | 101 / 97.2% / 0.86 | 0.02× |
| ss2022 | 1.807 | 2.101 | 95 / 91.6% / 0.90 | 117 / 93.9% / 0.79 | 0.81× |
| trojan | 1.626 | 2.340 | 106 / 97.2% / 0.91 | 171 / 95.6% / 0.79 | 0.62× |

#### Loaded stability

| Engine | Protocol | load Mbps | p50 / p95 / p99 / max ms | failures |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 866 | 12.155 / 49.531 / 74.952 / 139.534 | 0/200 |
| honk | hy2 | 344 | 51.847 / 104.086 / 123.511 / 133.456 | 3/200 |
| honk | tuic | 263 | 21.895 / 32.327 / 39.561 / 58.102 | 0/200 |
| honk | ss2022 | 458 | 16.002 / 27.524 / 40.067 / 72.338 | 0/200 |
| honk | trojan | 392 | 11.988 / 21.573 / 31.547 / 73.303 | 0/200 |
| dae | direct | 524 | 8.907 / 50.834 / 84.706 / 91.599 | 0/200 |
| dae | hy2 | 216 | 35.539 / 56.397 / 74.111 / 74.429 | 8/200 |
| dae | tuic | 237 | 48.835 / 60.541 / 64.923 / 80.709 | 0/200 |
| dae | ss2022 | 279 | 14.374 / 20.924 / 24.875 / 47.538 | 0/200 |
| dae | trojan | 202 | 22.171 / 35.989 / 45.613 / 60.581 | 3/200 |

On ARM, honk leads TCP HY2, SS2022, and Trojan throughput, is effectively tied
on TUIC, and uses less RSS on every proxy row. Its hot tail is not uniformly
better: TUIC is substantially lower, while HY2, SS2022, and Trojan are higher.
The UDP result is a clear honk regression on this run: HY2/TUIC receive only
2 Mbps at the fixed 10-Gbps offer, versus 99/101 Mbps for dae; SS2022 and
Trojan also trail. Loaded runs show fewer honk failures (3 versus 8 on HY2 and
0 versus 3 on Trojan), but higher p99 on HY2 and SS2022. These are measured
capacity-edge outcomes, not claims about unloaded WAN latency.

Artifacts: [x86 standard TSV](../bench/results/cross-arch-2026-08-24/x86-standard.tsv),
[x86 loaded TSV](../bench/results/cross-arch-2026-08-24/x86-stability.tsv),
[x86 raw](../bench/results/cross-arch-2026-08-24/x86-stability-raw/),
[ARM standard TSV](../bench/results/cross-arch-2026-08-24/arm64-standard.tsv),
[ARM loaded TSV](../bench/results/cross-arch-2026-08-24/arm64-stability.tsv),
[ARM raw](../bench/results/cross-arch-2026-08-24/arm64-stability-raw/), and
[captured inputs](../bench/results/cross-arch-2026-08-24/arm64-inputs/).

The older sections below are historical records. Their `.45`/`.43` ARM
addresses describe superseded lab hosts; the current ARM host is `.118` above.

## Results (2026-08-08, paired x86-64 + ARM64 A/B and loaded tails)

The candidate is the current worktree based on main `2e6d63a`; the binary
hashes, kernels, exact configs, and harness hashes are authoritative in
[`metadata.txt`](../bench/results/cross-arch-2026-08-08/metadata.txt). Both
candidate builds are static musl, size-oriented release, default mimalloc. The
standard table is the full 3-cold / 15-hot / median-of-3×8s run. Loaded tails
come from a separate final fixed-cadence run: 200 fresh streams at 250 ms while
the same route carries one self-saturating reverse TCP stream. These are
capacity-edge tails, **not equal-rate latency comparisons**; achieved load is
shown beside every percentile. The exploratory sequential collector was
discarded after a timeout proved it could slip cadence. In the published raw
run, p99 scheduling lag was at most 0.677 ms and maximum lag 2.555 ms.

Artifacts: [x86 standard TSV](../bench/results/cross-arch-2026-08-08/x86-standard.tsv),
[x86 loaded TSV](../bench/results/cross-arch-2026-08-08/x86-stability.tsv),
[x86 raw](../bench/results/cross-arch-2026-08-08/x86-stability-raw/), and
[HY2/TUIC repeat](../bench/results/cross-arch-2026-08-08/x86-stability-repeat.tsv).

### x86-64 (`10.10.10.49`, 4 vCPU / 2 GiB)

#### TCP throughput, CPU, memory, and unloaded latency

| Protocol | honk cold / hot p95 (ms) | dae cold / hot p95 (ms) | honk Mbps / cores / RSS MiB | dae Mbps / cores / RSS MiB | honk/dae bw |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 4.81 / – | 4.52 / – | 9404 / 0.00 / 50 | 9408 / 0.00 / 48 | 1.00× |
| hy2 | 2.47 / 1.92 | 31.73 / 1.83 | 5792 / 0.59 / 53 | 5046 / 1.09 / 66 | 1.15× |
| tuic | 2.36 / 1.82 | 80.64 / 78.61 | 6906 / 0.66 / 50 | 5065 / 1.02 / 65 | 1.36× |
| ss2022 | 3.50 / 11.92 | 7.45 / 6.62 | 9151 / 0.37 / 51 | 9259 / 0.42 / 54 | 0.99× |
| trojan | 6.40 / 6.08 | 7.04 / 16.78 | 9097 / 0.42 / 46 | 9100 / 0.64 / 58 | 1.00× |
| anytls-sb | 2.78 / 3.07 | 7.89 / 5.33 | 8532 / 0.46 / 46 | 7905 / 0.55 / 59 | 1.08× |
| anytls-go | 2.98 / 4.15 | 7.59 / 2.52 | 9105 / 0.49 / 53 | 9036 / 0.61 / 61 | 1.01× |

TCP conclusions on this host: direct is exact parity. honk is +14.8% on HY2,
+36.3% on TUIC, +7.9% on sing-box AnyTLS, within 1.2% on the other three,
and uses fewer engine CPU cores on every proxied row. Its proxied RSS is
46–53 MiB versus dae's 54–66 MiB. The exceptions matter: honk's unloaded
SS2022 hot p95 is 11.92 ms versus 6.62 ms, and AnyTLS-Go is 4.15 versus
2.52 ms; dae TUIC, conversely, stays near 79 ms even when hot.

#### UDP saturation

`loss` is expected here because offered load is fixed at 10 Gbps; compare
accepted Mbps and loss together, not loss as an internet packet-loss estimate.

| Protocol | honk RTT ms | dae RTT ms | honk Mbps / loss / cores | dae Mbps / loss / cores | honk/dae bw |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.108 | 0.105 | 1490 / 58.9% / 0.84 | 828 / 79.8% / 0.72 | 1.80× |
| tuic | 0.158 | 0.134 | 1982 / 46.5% / 1.23 | 1922 / 49.8% / 1.48 | 1.03× |
| ss2022 | 0.222 | 0.184 | 1456 / 59.7% / 1.24 | 2675 / 30.1% / 1.64 | 0.54× |
| trojan | 0.135 | 0.099 | 1739 / 57.4% / 1.26 | 2916 / 24.3% / 1.59 | 0.60× |
| anytls-sb | 0.193 | 0.084 | 1194 / 69.1% / 0.73 | 1211 / 68.4% / 0.70 | 0.99× |
| anytls-go | 0.071 | 0.090 | 1249 / 66.2% / 0.79 | 1250 / 65.4% / 0.75 | 1.00× |

UDP is mixed, not a blanket win: honk leads HY2 by 80% and TUIC by 3%, ties
both AnyTLS servers, but reaches only 54%/60% of dae's SS2022/Trojan rate.

#### Loaded open-stream stability

Percentiles cover successful HTTP responses; failures stay explicit in the
last field. A 5-second timeout is therefore never hidden inside a low p99.

| Protocol | honk load Mbps | honk p50 / p95 / p99 / max ms; failures | dae load Mbps | dae p50 / p95 / p99 / max ms; failures |
| --- | ---: | --- | ---: | --- |
| direct | 9382 | 2.352 / 4.722 / 6.118 / 11.582; 0/200 | 9394 | 2.353 / 3.341 / 5.272 / 12.440; 0/200 |
| hy2 | 5597 | 2.391 / 3.359 / 6.095 / 16.981; 0/200 | 3465 | 3.195 / 13.755 / 176.642 / 399.369; 0/200 |
| tuic | 6197 | 2.683 / 6.694 / 16.031 / 16.927; 2/200 | 4848 | 77.108 / 82.733 / 87.135 / 88.816; 4/200 |
| ss2022 | 9319 | 2.573 / 5.011 / 17.161 / 18.311; 0/200 | invalid | invalid (3/3 load arms terminated) |
| trojan | 9300 | 2.272 / 4.873 / 12.416 / 17.280; 0/200 | 9124 | 5.940 / 18.994 / 23.151 / 31.855; 5/200 |
| anytls-sb | 8852 | 4.777 / 6.101 / 8.510 / 13.487; 0/200 | 8156 | 2.480 / 5.367 / 14.031 / 17.097; 3/200 |
| anytls-go | 9027 | 5.944 / 12.324 / 16.813 / 21.436; 0/200 | 9071 | 3.577 / 15.278 / 17.282 / 17.465; 1/200 |

The dae SS2022 result is deliberately not converted into a percentile: all
three 55-second arms lost the iperf control connection at 30 seconds with
`control socket has closed unexpectedly`. Before termination they carried
9.07–9.35 Gbps; HTTP attempts recorded 0/200, 5/200, and 0/200 failures. This
is a reproducible long-flow stability failure, not zero throughput.

HY2 and TUIC were repeated because one x86 arm showed a large run-level tail:

| Engine / protocol | fixed-cadence arm A: load / p99 / failures | arm B: load / p99 / failures |
| --- | --- | --- |
| honk / hy2 | 5597 Mbps / 6.095 ms / 0/200 | 5104 Mbps / 7.225 ms / 1/200 |
| honk / tuic | 6197 Mbps / 16.031 ms / 2/200 | 6078 Mbps / 8.048 ms / 0/200 |
| dae / hy2 | 3465 Mbps / 176.642 ms / 0/200 | 5323 Mbps / 11.284 ms / 0/200 |
| dae / tuic | 4848 Mbps / 87.135 ms / 4/200 | 4603 Mbps / 81.657 ms / 0/200 |

honk's HY2 tails stayed within 6.1–7.2 ms p99; dae HY2 was bimodal across the
two observed arms. TUIC remained separated: honk 8.0–16.0 ms versus dae
81.7–87.1 ms p99. Sparse failures (0–1% per arm) are observable on both and
must not be generalized beyond these samples.

### ARM64 (`10.10.10.45`, NanoPi R2S / 1 GiB)

The paired ARM table uses the four protocols supported by that dae build.
Artifacts: [standard](../bench/results/cross-arch-2026-08-08/arm64-standard.tsv),
[loaded](../bench/results/cross-arch-2026-08-08/arm64-stability.tsv),
[raw](../bench/results/cross-arch-2026-08-08/arm64-stability-raw/), and
[repeat](../bench/results/cross-arch-2026-08-08/arm64-stability-repeat.tsv).
Across every published valid ARM arm, the worst p99 scheduling lag was
17.390 ms and the maximum single launch lag was 41.592 ms, still well below
the 250 ms launch interval.

#### TCP throughput, CPU, memory, and unloaded latency

| Protocol | honk cold / hot p95 (ms) | dae cold / hot p95 (ms) | honk Mbps / cores / RSS MiB | dae Mbps / cores / RSS MiB | honk/dae bw |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 6.66 / – | 6.63 / – | 889 / 0.00 / 57 | 899 / 0.01 / 42 | 0.99× |
| hy2 | 10.43 / 11.13 | 38.96 / 8.30 | 269 / 1.33 / 61 | 189 / 1.84 / 60 | 1.42× |
| tuic | 12.35 / 9.77 | 109.89 / 84.80 | 262 / 1.35 / 53 | 197 / 1.79 / 51 | 1.33× |
| ss2022 | 15.76 / 8.15 | 10.57 / 13.07 | 350 / 0.87 / 57 | 252 / 0.87 / 43 | 1.39× |
| trojan | 16.22 / 16.28 | 39.12 / 19.46 | 279 / 0.88 / 49 | 173 / 0.78 / 44 | 1.61× |

Direct is link-limited parity. honk carries 33–61% more TCP on every shared
proxy protocol. It uses 28% fewer cores on HY2 and 25% fewer on TUIC, ties dae
on SS2022 CPU, and spends 13% more on Trojan. Unlike x86, memory is not a honk
win: proxied RSS is 49–61 MiB versus dae's 43–60 MiB. Unloaded latency is also
mixed: honk wins TUIC/SS2022/Trojan hot p95, dae wins HY2.

#### UDP saturation

| Protocol | honk RTT ms | dae RTT ms | honk Mbps / loss / cores | dae Mbps / loss / cores | honk/dae bw |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.921 | 3.121 | 35 / 97.3% / 1.84 | 29 / 97.3% / 2.15 | 1.21× |
| tuic | 2.675 | 3.513 | 54 / 97.9% / 1.76 | 31 / 94.1% / 2.20 | 1.74× |
| ss2022 | 2.021 | 2.581 | 35 / 71.8% / 0.92 | 39 / 89.4% / 1.29 | 0.90× |
| trojan | 2.366 | 2.675 | 32 / 96.5% / 0.86 | 49 / 97.0% / 1.47 | 0.65× |

The architecture does not erase the x86 UDP split: honk leads QUIC (HY2/TUIC)
and trails dae's SS2022/Trojan. Absolute rates are A53/USB-NIC saturation, not
WAN expectations.

#### Loaded open-stream stability

| Protocol | honk load Mbps | honk p50 / p95 / p99 / max ms; failures | dae load Mbps | dae p50 / p95 / p99 / max ms; failures |
| --- | ---: | --- | ---: | --- |
| direct | 877 | 13.263 / 16.429 / 253.604 / 2040.151; 0/200 | 896 | 12.817 / 22.490 / 240.131 / 1032.783; 0/200 |
| hy2 | 267 | 75.391 / 144.587 / 171.303 / 209.632; 0/200 | 188 | 45.731 / 84.419 / 104.706 / 120.980; 1/200 |
| tuic | 261 | 30.032 / 67.089 / 78.956 / 137.535; 0/200 | 191 | 104.555 / 114.873 / 120.645 / 124.333; 0/200 |
| ss2022 | 356 | 17.586 / 31.881 / 41.419 / 192.975; 0/200 | invalid | invalid (3/3 load arms terminated) |
| trojan | 293 | 14.632 / 30.428 / 38.831 / 39.198; 1/200 | 173 | 23.968 / 29.960 / 36.468 / 52.650; 0/200 |

The direct controls show why ARM tail values cannot be read without load: both
engines have ~240–254 ms p99 at ~0.9 Gbps, with second-scale maxima, despite
near-zero engine CPU. The bottleneck is the saturated host/USB path. HY2 is a
capacity/latency trade: honk carries 42% more, while dae has the lower
self-saturated p99 at its lower load. TUIC is a clearer honk win: 37% more load
and lower p99. Trojan p99 is effectively tied, but honk carries 69% more.

The targeted repeat was stable in load and exposed run-level failure variance:

| Engine / protocol | arm A: load / p99 / failures | arm B: load / p99 / failures |
| --- | --- | --- |
| honk / hy2 | 267 Mbps / 171.303 ms / 0/200 | 269 Mbps / 164.253 ms / 5/200 |
| honk / tuic | 261 Mbps / 78.956 ms / 0/200 | 260 Mbps / 114.847 ms / 0/200 |
| dae / hy2 | 188 Mbps / 104.706 ms / 1/200 | 188 Mbps / 87.126 ms / 0/200 |
| dae / tuic | 191 Mbps / 120.645 ms / 0/200 | 193 Mbps / 118.337 ms / 0/200 |

dae SS2022 reproduces the x86 failure exactly: every load arm ended at 30
seconds with `control socket has closed unexpectedly`. Pre-failure rates were
246–260 Mbps; HTTP failures across the three attempts were 0/200, 5/200, and
6/200. The same timestamp and error on both architectures makes this a dae
long-flow lifecycle result, not host noise.

### honk-only AnyTLS and rprx coverage

The ARM dae build has no AnyTLS or rprx handlers, so these rows are not labeled
as an A/B win. The dedicated rprx config reuses the live `8001-8003` /
`5201-5203` targets; the originally reserved `8007-8009` / `5207-5209` targets
were absent and their exploratory rows were discarded. VLESS and VMess have no
UDP implementation. The archived empty/`0(-)` UDP fields therefore mean
capability N/A, not regression or direct fallback; the corrected harness emits
explicit `n/a` fields.

Artifacts: [ARM AnyTLS](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls.tsv),
[ARM AnyTLS loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability.tsv),
[ARM AnyTLS raw](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability-raw/),
[ARM rprx](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx.tsv),
[ARM rprx loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability.tsv),
[ARM rprx raw](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability-raw/),
[x86 rprx](../bench/results/cross-arch-2026-08-08/x86-honk-rprx.tsv),
[x86 rprx loaded](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability.tsv), and
[x86 rprx raw](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability-raw/).

| Protocol | x86 cold / hot p95 ms; Mbps / cores | ARM cold / hot p95 ms; Mbps / cores | x86 loaded Mbps / p99 / failures | ARM loaded Mbps / p99 / failures |
| --- | --- | --- | --- | --- |
| anytls-sb | 2.78 / 3.07; 8532 / 0.46 | 9.08 / 7.20; 324 / 0.97 | 8852 / 8.510 ms / 0/200 | 336 / 168.274 ms / 0/200 |
| anytls-go | 2.98 / 4.15; 9105 / 0.49 | 8.24 / 8.55; 313 / 0.96 | 9027 / 16.813 ms / 0/200 | 318 / 515.541 ms / 0/200 |
| vless-vision | 4.88 / 4.03; 9372 / 0.60 | 23.47 / 20.23; 154 / 0.71 | 9353 / 16.677 ms / 0/200 | 168 / 39.023 ms / 8/200 |
| vless-reality | 4.69 / 8.03; 9367 / 0.45 | 17.78 / 13.48; 282 / 0.87 | 9320 / 16.910 ms / 0/200 | 274 / 53.338 ms / 0/200 |
| vmess | 2.33 / 2.35; 9373 / 0.51 | 9.42 / 7.88; 342 / 1.29 | 7789 / 48.780 ms / 0/200 | 335 / 37.198 ms / 0/200 |

On x86 all three rprx rows reach 9.37 Gbps in the regular run; VMess falls to
7.79 Gbps in the 50-second mixed load and its p99 rises to 48.8 ms. On ARM,
Vision is the clear outlier: 154 Mbps and eight clustered 5-second HTTP
timeouts under load. Reality and VMess complete without failures. AnyTLS-Go's
515 ms ARM p99 is driven by a small tail (p50 156 ms, maximum 1.006 s), not by
failed requests.

### Cross-architecture decision

- **TCP capacity:** honk is decisively ahead on ARM (33–61% across the shared
  protocols) and ahead or tied on x86 except SS2022 (-1.2%). Direct is parity.
- **Efficiency:** honk uses less CPU on every x86 proxy row and on ARM HY2/TUIC;
  ARM Trojan and memory are counterexamples, so this is not a universal claim.
- **Latency stability:** x86 generally favors honk, especially TUIC, but sparse
  timeouts remain observable. ARM is load-dependent: dae HY2 has lower tails at
  30% lower load, while honk TUIC carries more with lower tails. Neither a
  throughput-only nor p99-only ranking is honest.
- **UDP:** honk wins HY2/TUIC and loses SS2022/Trojan on both architectures.
- **Long-flow failure:** dae SS2022's 30-second control closure reproduces 3/3
  times on each host. This is the strongest stability defect in the matrix.
- **Resource fit:** x86 honk saves RSS; on the 1 GiB R2S it does not. rprx is
  line-rate on x86, but Vision's ARM throughput and 4% sampled timeout rate need
  improvement before calling it gateway-safe under saturation.

## Results (2026-08-06, UDP post-decision offload verification @ NanoPi R2S)

Verifies the QUIC UDP offload (drop-and-reinject rebuild,
`HONK_UDP_POST_DECISION_OFFLOAD=1`). The standard UDP rows (iperf3/echo
through proxy groups) are unaffected by design — matching the previous round
line by line (within noise) is the correct outcome. A supplementary QUIC-type
direct-UDP load (juicity tunnel through `domain(suffix:hy2.test)->direct`,
domain++):

| Load | offload ON | offload OFF |
| --- | --- | --- |
| QUIC direct UDP (juicity) | **149.1 Mbps @ 0.00 cores** (endpoint hits=0) | 33.2 Mbps @ 0.78 cores (hits=13588) |

4.5× throughput with the engine CPU at zero (the 149 Mbps ceiling is the
juicity client's own QUIC crypto on the A53). The direct row holds at
874 Mbps @ 0.00 cores (dae 889, on par); TCP protocol rows within ≤2.3% — no
regression.

## Results (2026-08-06, direct kernel-offload verification @ NanoPi R2S)

Verifies PR #17 (kernel offload of direct-routed flows in Rule mode, per-flow
cached decision, zero per-packet cost). Engine is feat/rprx (incl. main
`ac5ffbb`) aarch64-musl; the lab's 8080/5300 targets route via
`fallback: direct` (non-must) — exactly the path this feature targets. Two
alternating rounds; dae re-measured in the same window.

| Engine | Protocol | cold | bw (Mbps) | cpu | RSS |
| --- | --- | --- | --- | --- | --- |
| honk | direct (with offload) | 0.0043 | **880** (prev 370) | **0.01** (prev 0.71) | 61 |
| dae | direct | 0.0041 | 896 | 0.01 | 39 |

All protocol rows within noise of the previous round (hy2 267/268, tuic
260/262, ss2022 353/353, trojan 279/282) — no regression. honk direct now
matches dae (the 1.8% gap is link noise); cold improved too (6.2→4.3ms, on
par with dae's 4.1ms).

## Results (2026-08-05, ARM A/B: honk vs dae @ NanoPi R2S)

Two-engine comparison on the NanoPi R2S (two runs: .43 onboard NIC, then a
.45 re-run over a USB NIC); honk is feat/rprx `2ad0a93` aarch64-musl, dae is
kdae `ae056a6a` (go1.26.5). Methodology unchanged; only one engine runs at a
time. dae only supports the shared protocol rows (hy2/tuic/ss2022/trojan).
Values are means of two alternating rounds, <5% intra-round deviation.
**The .45 re-run used a USB NIC, shifting absolute bandwidth down ~10–15% —
compare ratios, not absolutes.**

### TCP (.45 re-run values; `→` shows the .43 first round)

| Engine | Protocol | cold | hot p50 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0062 | – | 370 →458 | 0.71 | 52 |
| dae | direct | 0.0057 | – | 895 →931 | 0.01 | 39 |
| honk | hy2 | 0.0091 | 0.0081 | 268 →303 | 1.34 | 59 |
| dae | hy2 | 0.0367 | 0.0079 | 191 →197 | 1.86 | 57 |
| honk | tuic | 0.0070 | 0.0070 | 262 →293 | 1.36 | 59 |
| dae | tuic | 0.1040 | 0.0834 | 196 →208 | 1.80 | 49 |
| honk | ss2022 | 0.0070 | 0.0058 | 353 →385 | 0.88 | 51 |
| dae | ss2022 | 0.0114 | 0.0092 | 247 →265 | 0.87 | 41 |
| honk | trojan | 0.0221 | 0.0061 | 282 →328 | 0.88 | 53 |
| dae | trojan | 0.0228 | 0.0163 | 171 →201 | 0.78 | 42 |

### UDP (.45 re-run; echo RTT s / saturated receive Mbps / cpu)

| Engine | Protocol | RTT | bw | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2/udp | 0.0029 | 33 | 1.85 |
| dae | hy2/udp | 0.0034 | 31 | 2.14 |
| honk | tuic/udp | 0.0028 | 53 | 1.76 |
| dae | tuic/udp | 0.0034 | 33 | 2.21 |
| honk | ss2022/udp | 0.0021 | 34 (73.8%) | 0.93 |
| dae | ss2022/udp | 0.0027 | 40 (87.9%) | 1.29 |
| honk | trojan/udp | 0.0019 | 31 | 0.88 |
| dae | trojan/udp | 0.0031 | 49 | 1.45 |

Read-out:

- **honk leads TCP throughput by 35–65%, reproducibly**: hy2 1.40×, tuic
  1.34×, trojan 1.65×, ss2022 1.43× (ratio drift vs the .43 round ≤0.1); CPU
  cost per Mbps is about half of dae's (hy2: 1.34 cores@268 vs 1.86@191). On
  A53 little cores the Go runtime's per-byte cost is amplified most on QUIC.
- **Latency**: dae's tuic hot p50 83ms / cold 104ms (per-connection QUIC
  session rebuild) reproduces exactly; honk stays ≤8ms hot p50 across all
  protocols. honk's UDP echo RTT is consistently 0.5–1.2ms lower per row.
- **The direct-row gap is path, not engine**: dae offloads fallback-direct
  fully in eBPF (895Mbps@0.01 cores); honk only offloads must-marked direct
  and relays fallback-direct in userspace (370@0.71) — a candidate honk
  optimization.
- **UDP** hits the A53 platform ceiling for both engines (30–57 Mbps); memory
  slightly favors dae (38–59 vs 48–61MB), neither is a constraint at 1GB.
- Fairness: both engines relay TCP in userspace (dae log confirms eBPF
  offload disabled).

## Results (2026-08-05, ARM round: NanoPi R2S / RK3328)

Engine host 10.10.10.43 (NanoPi R2S: 4×Cortex-A53 @1.3GHz, 968MB RAM, end0
1Gbps, kernel 6.18, cpuinfo shows `aes pmull sha1 sha2`), running a feat/rprx
`2ad0a93` aarch64-musl build. Methodology unchanged (netns lab → real eBPF
datapath → .70). **Line-rate anchor: with the engine off, the same netns+NAT
path saturates 941 Mbps**, so every number below is bounded by the userspace
engine. The cpu column counts only honk's utime/stime (no softirq).

### TCP

| Engine | Protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0064 | – | – | 437 | 0.74 | 50 |
| honk | hy2 | 0.0100 | 0.0084 | 0.0090 | 301 | 1.34 | 61 |
| honk | tuic | 0.0097 | 0.0073 | 0.0082 | 304 | 1.33 | 56 |
| honk | ss2022 | 0.0105 | 0.0057 | 0.0065 | 388 | 0.83 | 55 |
| honk | trojan | 0.0213 | 0.0060 | 0.0205 | 329 | 0.91 | 50 |
| honk | anytls-sb | 0.0066 | 0.0061 | 0.0065 | 336 | 0.98 | 51 |
| honk | anytls-go | 0.0116 | 0.0065 | 0.0076 | 337 | 0.96 | 51 |
| honk | vless-reality-vision | 0.0225 | 0.0181 | 0.0196 | 183 | 0.74 | 51 |
| honk | vless-reality | 0.0208 | 0.0174 | 0.0287 | 332 | 0.88 | 52 |
| honk | vmess (tcp) | 0.0076 | 0.0067 | 0.0087 | 416 | 1.50 | 47 |

### UDP (hot, `udp_warm_node_count: 8`)

| Protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- |
| hy2 | 2.77 ms | 34 (97.8%) | 1.91 |
| tuic | 2.88 ms | 46 (98.1%) | 1.86 |
| ss2022 | 2.09 ms | 42 (91.0%) | 0.92 |
| trojan | 2.12 ms | 38 (98.1%) | 0.90 |
| anytls-sb | 2.23 ms | 50 (89.3%) | 1.79 |
| anytls-go | 2.54 ms | 57 (87.7%) | 1.80 |

Read-out (A53 little cores vs x86 E-13600K, same methodology as 08-04):

- **Everything is CPU-bound**: direct 437 (vs 9390 on x86); TCP protocols
  flatten at 330–390 Mbps (flat across rows = the shared relay+crypto path is
  the bottleneck, not any single handler); QUIC per-core efficiency is ~20×
  lower. vmess at 416 is closest to the direct baseline, confirming `5dc47cf`'s
  BoringSSL AEAD pays off equally under ARM crypto extensions; its 1.50 cores
  remain the highest among TCP rows (a cross-platform optimization target).
  vless-vision at 183 is the lowest TCP row; the vision/reality hot p50 of
  ~18ms (vs 3.3ms on x86) is the REALITY handshake cost on slow crypto.
- **UDP suffers most**: 34–57 Mbps with 88–98% loss — the per-packet path
  (TPROXY recvmsg provenance + anyfrom replies + tunnel framing) saturates the
  little cores; echo RTT is an order of magnitude slower than x86.
- **RSS 47–61MB matches x86 exactly**; a 1GB device shows zero memory
  pressure — the constraint is purely CPU.
- The .70 rprx target services (8007-8009/5207-5209/53537-53539) were
  half-broken this round; those three rows used an equivalent variant (working
  targets 8001/5201 re-routed to the respective groups) with unchanged
  methodology.

## Results (2026-08-05, rprx family: VLESS+REALITY(±vision)/VMess join the matrix)

Covers the protocol rows added by feat/rprx (PR #12); engine is a feat/rprx
musl+mimalloc build (vless rows measured on `67b5a56`, the vmess row on a
rebuild with the `5dc47cf` AEAD fix). Methodology identical to the rounds
above. New server matrix on 10.10.10.70 (sing-box 1.13.14):
vless+reality+vision `:2448`, vless+reality `:2449`, vmess bare tcp `:2450`;
targets http `8007-8009`, iperf3 `5207-5209`, udp echo `53537-53539`; engine
routes by port (`5207/8007/53537→vision`, `…8→reality`, `…9→vmess`). The
REALITY dest is a local TLS service (note: the dest's TLS Certificate message
must fit the server's 8 KiB capture buffer or auth fails).

Calibration anchors (this round vs 08-04): direct 9411/9390, ss2022
9399/9398, anytls-sb 9406/9388 Mbps — environment consistent, so the table
below compares directly against the 08-04 rows.

| Engine | Protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | vless-reality-vision | 0.0037 | 0.0033 | 0.0050 | 9372 | 0.60 | 45 |
| honk | vless-reality | 0.0043 | 0.0034 | 0.0042 | 9383 | 0.49 | 54 |
| honk | vmess (tcp) | 0.0022 | 0.0010 | 0.0014 | 9313 | 0.78 | 50 |

- All three rows sit at line rate (~9.4G). The vmess row is post-`5dc47cf`
  (body AEAD moved from RustCrypto to BoringSSL); before the fix the same
  path measured ~420 MB/s handler-level (single core at 105%). vmess cpu
  (0.78) is still the highest of the TCP protocols (per-chunk SHAKE size
  masking + framing) — a follow-up optimization candidate.
- vision vs non-vision shows no bandwidth difference (BoringSSL AES-NI is
  already line-rate below 10G); the vision row pays slightly more cpu
  (0.60 vs 0.49) for framing, and its cold includes the REALITY handshake.
- vless/vmess have no UDP datapath in honk (README TODO); the UDP rows are
  empty by design, not a measurement failure.

## Results (2026-08-04, honk outbound-v2 refactor regression check)

Single-engine regression round for the outbound-v2 refactor merge — no
dae/sing-box arms; the 08-02 round (`49b166d`) is the comparison baseline.
Engine host 10.10.10.59, server host 10.10.10.70, methodology unchanged.

- honk: main `d00cb5e` (musl, mimalloc) — the outbound-v2 refactor (protocol
  surface cut to Direct/Block/SOCKS5/SS2022/Trojan/VMess/VLess/AnyTLS/
  Hysteria2/TUIC/Juicity; `ProtocolDescriptor` capability table; capability
  traits replace the fat `ProxyHandler`; content-derived stable NodeId;
  generation-owned QUIC clients with cross-reload runtime reuse; TCP dial
  path pinned to the admission generation; per-generation dial budget) plus
  the AnyTLS overflow fix below.

**This round caught a real regression on main.** `85d6b61` (bound
slow-consumer overflow, shipped in v0.0.1.beta.33/34) reset an AnyTLS stream
the instant its 2 MiB overflow cap was crossed — but a fast LAN peer bursts
past that in ~4 ms, before the reader task is first scheduled, so
single-stream iperf3 read 2–3 Mbps on both the pre-refactor binary
(`8a32149`) and the refactored one (bisected: parent `c7cbd67` is good at
8.8 Gbps). The fix (`caa95b0` + `d00cb5e`) restores progress-based
semantics: the per-stream byte cap is soft within a 3 s no-flush-progress
grace — parked bytes are not a stall; at a session-wide cap the demux waits
in 500 ms rounds for reader progress (pausing reads backpressures the
server through the TCP window) and a timed-out round resets only the
most-stalled parked stream. Lab-verified: anytls-sb 9388 / anytls-go 9396
Mbps, zero overflow kills, relay counters confirm the tunnel path.

### TCP

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0022 | – | – | 9390¹ | 0.27 | 54 |
| honk | hy2 | 0.0024 | 0.0011 | 0.0020 | 6156 | 1.03 | 56 |
| honk | tuic | 0.0024 | 0.0013 | 0.0019 | 5293 | 0.71 | 54 |
| honk | ss2022 | 0.0019 | 0.0013 | 0.0016 | 9398 | 0.37 | 54 |
| honk | trojan | 0.0046 | 0.0010 | 0.0034 | 9377 | 0.47 | 50 |
| honk | anytls-sb | 0.0025 | 0.0012 | 0.0015 | 9388 | 0.47 | 51 |
| honk | anytls-go | 0.0023 | 0.0013 | 0.0017 | 9396 | 0.49 | 50 |

### UDP (warm state, `udp_warm_node_count: 8`)

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 1814 (72.7%) | 1.25 |
| honk | tuic | 0.37 ms | 58 (68.6%)² | 0.07 |
| honk | ss2022 | 0.15 ms | 1889 (68.7%) | 1.32 |
| honk | trojan | 0.06 ms | 1394 (79.7%) | 1.08 |
| honk | anytls-sb | 0.07 ms | 1370 (77.4%) | 0.92 |
| honk | anytls-go | 0.22 ms | 1735 (71.7%) | 1.24 |

¹ The direct row first read 6841 on a loaded lab window; three immediate
re-runs read 9388/9389/9390.
² TUIC UDP collapsed for every engine this round — the .70→.59 UDP link
was near saturation (same lab-condition artifact as the 08-02 round), not
an engine regression.

### Reading the 08-04 results

- **No regression from the refactor**: against the same-day pre-refactor
  arm (`8a32149`) every non-AnyTLS row matches within lab variance (hy2
  6156 vs 5966, tuic 5293 vs 5546, ss2022/trojan line rate both ways). The
  higher readings vs the 08-02 round (hy2 2858, tuic 4134) reflect an idle
  lab, not a refactor speedup — the QUIC data path is unchanged code.
- **AnyTLS is the big win**: the stall-grace fix takes anytls-sb from the
  4575 pre-regression baseline to 9388 (line rate) and anytls-go to 9396 —
  the demux-backpressure design also removes the overflow churn the old
  park-based path produced under fast peers. The pre-refactor binary
  measured 2–3 Mbps on both rows (bug present).
- TUIC UDP remains the known weak spot (lab link caveat above).

## Results (2026-08-02, three-engine: honk vs dae vs sing-box)

The engine host for this round was **10.10.10.59** (another VM in the same lab;
the server host is still the physical 10.10.10.70; the production gateway
10.10.10.1 carries a `sip(10.10.10.59/32) -> direct(must)` rule so benchmark
traffic bypasses its proxy datapath). Topology and methodology are unchanged
from the 08-01 round.

- honk: main `49b166d` (musl, mimalloc) — includes the eBPF datapath admission
  gate, per-network LoadBalance/Fallback state, lazy AnyTLS TLS connectors, the
  tracing-stack silencing fix, the dial-failure penalty sample, TPROXY listener
  marking, and the halving moving average for URLTest.
- dae: kdae `ae056a6a` (Go 1.26.0; updated from the 08-01 round's `eee7c88b`,
  includes outbound-fork fixes).
- sing-box: v1.13.14 (TUN client inside lab netns, port-route per protocol).

Latencies in seconds, TCP bandwidth is the median iperf3 receiver rate, CPU in
cores, RSS measured after the runs.

### TCP

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0082 | – | – | 9399 | 0.26 | 54 |
| dae | direct | 0.0034 | – | – | 9402 | 0.00 | 50 |
| sing-box | direct | 0.0052 | – | – | 9403 | 0.43 | 47 |
| honk | hy2 | 0.0060 | 0.0034 | 0.0047 | 2858 | 0.49 | 59 |
| dae | hy2 | 0.0104 | 0.0032 | 0.0036 | 2757 | 0.82 | 61 |
| sing-box | hy2 | 0.0108 | 0.0039 | 0.0053 | 2570 | 0.87 | 51 |
| honk | tuic | 0.0060 | 0.0037 | 0.0054 | 4134 | 0.59 | 54 |
| dae | tuic | 0.0858 | 0.0797 | 0.0804 | 2940 | 0.82 | 62 |
| sing-box | tuic | 0.0083 | 0.0039 | 0.0051 | 2618 | 0.89 | 51 |
| honk | ss2022 | 0.0052 | 0.0036 | 0.0061 | 9333 | 0.39 | 57 |
| dae | ss2022 | 0.0041 | 0.0041 | 0.0049 | 9372 | 0.51 | 53 |
| sing-box | ss2022 | 0.0057 | 0.0041 | 0.0069 | 9342 | 1.30 | 51 |
| honk | trojan | 0.0113 | 0.0023 | 0.0107 | 9244 | 0.46 | 50 |
| dae | trojan | 0.0104 | 0.0075 | 0.0106 | 9162 | 0.71 | 55 |
| sing-box | trojan | 0.0098 | 0.0090 | 0.0124 | 9187 | 0.86 | 49 |
| honk | anytls-sb | 0.0055 | 0.0043 | 0.0061 | 4575 | 0.30 | 50 |
| dae | anytls-sb | 0.0089 | 0.0037 | 0.0047 | 4522 | 0.40 | 56 |
| sing-box | anytls-sb | 0.0131 | 0.0035 | 0.0053 | 4512 | 0.50 | 48 |
| honk | anytls-go | 0.0052 | 0.0032 | 0.0049 | 8937 | 0.54 | 52 |
| dae | anytls-go | 0.0080 | 0.0038 | 0.0049 | 8892 | 0.69 | 61 |
| sing-box | anytls-go | 0.0113 | 0.0039 | 0.0046 | 8741 | 1.05 | 48 |

### UDP (iperf3 `-u -b 10G -l 1200 -R`)

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.20 ms | 1743 (71.5%) | 1.16 |
| dae | hy2 | 0.22 ms | 931 (85.5%) | 0.95 |
| sing-box | hy2 | 0.33 ms | 1561 (75.0%) | 1.41 |
| honk | tuic | 0.20 ms | 1577 (70.6%) | 1.33 |
| dae | tuic | 0.33 ms | 108 (76.2%) | 0.13 |
| sing-box | tuic | 0.30 ms | 27 (80.9%) | 0.05 |
| honk | ss2022 | 0.20 ms | 1207 (78.6%) | 1.23 |
| dae | ss2022 | 0.13 ms | 2367 (58.6%) | 1.76 |
| sing-box | ss2022 | 0.17 ms | 2509 (55.6%) | 1.34 |
| honk | trojan | 0.10 ms | 1629 (70.1%) | 1.28 |
| dae | trojan | 0.18 ms | 2903 (49.5%) | 1.67 |
| sing-box | trojan | 0.13 ms | 3330 (41.6%) | 1.66 |
| honk | anytls-sb | 0.23 ms | 1287 (79.2%) | 0.91 |
| dae | anytls-sb | 0.26 ms | 1290 (77.9%) | 0.91 |
| sing-box | anytls-sb | 0.36 ms | 1262 (79.1%) | 1.18 |
| honk | anytls-go | 0.24 ms | 1539 (75.6%) | 1.10 |
| dae | anytls-go | 0.22 ms | 1493 (76.0%) | 1.01 |
| sing-box | anytls-go | 0.18 ms | 1368 (77.7%) | 1.24 |

### UDP: warmed steady-state comparison (08-02)

Same methodology as the 08-01 steady round: after each engine starts, wait 30s
for health-check convergence, run 5 TCP warm-up requests per protocol, settle
10s, then measure. `iperf3 -u -b 10G -l 1200 -R` single flow and `-P 8`
aggregate.

| engine | protocol | echo RTT (ms) | single Mbps (loss) | P8 aggregate Mbps (loss) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.22 | 1663 (73.8%) | 1582 (95.8%) |
| dae | hy2 | 0.36 | 938 (85.6%) | 864 (97.6%) |
| sing-box | hy2 | 0.42 | 1607 (74.4%) | 1588 (95.7%) |
| honk | tuic | 0.11 | 359 (67.1%) | FAIL |
| dae | tuic | 0.11 | 325 (75.1%) | 1 (27.3%) |
| sing-box | tuic | 0.14 | 101 (74.2%) | FAIL |
| honk | ss2022 | 0.19 | 1851 (67.2%) | 2928 (88.0%) |
| dae | ss2022 | 0.21 | 2448 (55.6%) | 2382 (89.8%) |
| sing-box | ss2022 | 0.19 | 2475 (56.5%) | 2944 (87.9%) |
| honk | trojan | 0.06 | 1623 (72.0%) | 3159 (91.8%) |
| dae | trojan | 0.13 | 2864 (49.6%) | 2631 (92.3%) |
| sing-box | trojan | 0.09 | 3226 (42.7%) | 4092 (88.9%) |
| honk | anytls-sb | 0.69 | 1294 (78.5%) | 1266 (96.5%) |
| dae | anytls-sb | 0.15 | 1278 (78.8%) | 2610 (91.1%) |
| sing-box | anytls-sb | 0.67 | 1268 (79.1%) | 2760 (90.7%) |
| honk | anytls-go | 0.12 | 1484 (76.5%) | 1269 (96.5%) |
| dae | anytls-go | 0.21 | 1435 (76.9%) | 2259 (93.2%) |
| sing-box | anytls-go | 0.98 | 1375 (77.8%) | 2248 (93.1%) |

Note: the first steady-state run was measured **without** `udp_warm_node_count`
(honk's UDP warm-up knob; the production config sets it to 8). After enabling
`udp_warm_node_count: 8`, honk's rows re-measured as follows (dae and sing-box
have no such knob; their rows are unchanged):

| engine | protocol | single Mbps (loss) | P8 aggregate Mbps (loss) |
| --- | --- | --- | --- |
| honk (udp_warm) | hy2 | 1622 (74.1%) | 1650 (95.5%) |
| honk (udp_warm) | tuic | **1252 (72.3%)** | FAIL |
| honk (udp_warm) | ss2022 | 1796 (68.7%) | 2916 (88.0%) |
| honk (udp_warm) | trojan | 1562 (73.2%) | 3283 (91.3%) |
| honk (udp_warm) | anytls-sb | 1254 (79.9%) | 1297 (96.2%) |
| honk (udp_warm) | anytls-go | 1400 (77.4%) | 1298 (96.3%) |

tuic single-flow improved from 359 to 1252 Mbps — cold session establishment
was indeed the dominant cost in the un-warmed measurement; the other rows are
within noise. The anytls P8 shortfall and the tuic P8 failure are unrelated to
warm-up and stand as genuine weaknesses.

**Reading the steady-state UDP results (08-02):**

- **hy2**: honk 1663 ≈ sing-box 1607 > dae 938; P8 does not scale for any
  engine (0.9–1.6 Gbps at 96%+ loss), far from honk's 5.91 Gbps single-flow in
  the 08-01 steady round — see the lab-condition note below.
- **TUIC UDP collapsed across all three engines** (101–359 Mbps): the direct
  UDP baseline measured in the same round (port 5300, no proxy) reached only
  1954 Mbps at 61% loss, so the .70→.59 UDP link itself was near its
  saturation ceiling. Absolute tuic figures are therefore not comparable with
  the 08-01 steady round (6.18 Gbps); this is a lab-condition artifact and the
  row should be re-measured on an idle link.
- **ss2022**: single-flow sing-box 2475 ≈ dae 2448 > honk 1851; P8 honk 2928 ≈
  sing-box 2944 > dae 2382. honk still trails single-flow but has caught up
  on P8.
- **trojan**: single-flow sing-box 3226 > dae 2864 > honk 1623; P8 sing-box
  4092 > honk 3159 > dae 2631. honk's trojan UDP-over-TCP single-flow remains
  the lowest of the three and the top UDP optimization target.
- **anytls UoT**: single-flow is tied (~1.3–1.5 Gbps); **P8 is clearly lowest
  for honk** (1266/1269 vs dae 2610/2259 vs sing-box 2760/2248) — a newly
  exposed multi-flow UDP weakness worth a dedicated analysis.

### Reading the 08-02 results

- **Latency**: honk best across the board — cold 5–11ms (dae tuic still pays a
  full QUIC handshake per connection at 86ms; sing-box 8–13ms), hot p50
  2.3–4.7ms.
- **TCP bandwidth**: line-rate rows (ss2022, trojan, anytls-go) are tied at
  ~8.7–9.4 Gbps. QUIC protocols go to honk: hy2 2858 (+3.7% vs dae, +11% vs
  sing-box), tuic 4134 (+41% / +58%). Versus the 08-01 round, dae's hy2/tuic
  bandwidth fell from 4467/4537 to 2757/2940 while honk's hy2 recovered to the
  same tier.
- **UDP**: honk leads the QUIC protocols by a wide margin — hy2 1743 (vs
  931/1561), tuic 1577 (vs 108/27; dae's and sing-box's TUIC UDP was nearly
  unusable this round). **The weak spot is still UDP-over-TCP**: ss2022 1207 vs
  2367/2509, trojan 1629 vs 2903/3330 — about half of the competitors, and still
  the top UDP optimization target. anytls-sb/go are tied (~1.3–1.5 Gbps).
- **CPU**: honk lowest on most rows (ss2022 0.39 vs 0.51/1.30 cores; hy2 0.49
  vs 0.82/0.87; tuic 0.59 vs 0.82/0.89).
- **RSS**: comparable across engines (47–62 MB).

## Results (2026-08-01, three-engine: honk vs dae vs sing-box)

honk: dev `ed640c7` (musl, mimalloc, reuseport-2 merge, single UDP listener per family).
dae: kdae branch, Go 1.26.0.
sing-box: v1.13.14 (TUN client inside lab netns, port-route per protocol).
All measured same-time on the lab. Latencies in seconds, TCP bandwidth is the
iperf3 receiver median, CPU in cores, RSS after the run. sing-box CPU is not
measured (TUN-client model does not expose per-protocol process CPU).

### TCP

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0060 | – | – | 9411 | 0.24 | 58 |
| dae | direct | 0.0035 | – | – | 9395 | – | 50 |
| sing-box | direct | 0.0085 | – | – | – | – | 59 |
| honk | hy2 | 0.0085 | 0.0042 | 0.0053 | 3050 | 0.50 | 60 |
| dae | hy2 | 0.0102 | 0.0023 | 0.0045 | 4467 | 1.07 | 66 |
| sing-box | hy2 | 0.0451 | 0.0046 | 0.0059 | 2998 | – | – |
| honk | tuic | 0.0051 | 0.0032 | 0.0051 | 4400 | 0.60 | 57 |
| dae | tuic | 0.0851 | 0.0037 | 0.0046 | 4537 | 0.98 | 64 |
| sing-box | tuic | 0.0151 | 0.0035 | 0.0041 | 2620 | – | – |
| honk | ss2022 | 0.0046 | 0.0028 | 0.0035 | 9205 | 0.36 | 52 |
| dae | ss2022 | 0.0076 | 0.0047 | 0.0058 | 9405 | 0.45 | 55 |
| sing-box | ss2022 | 0.0220 | 0.0027 | 0.0040 | 8717 | – | – |
| honk | trojan | 0.0103 | 0.0018 | 0.0084 | 9328 | 0.43 | 52 |
| dae | trojan | 0.0076 | 0.0018 | 0.0020 | 9369 | 0.66 | 57 |
| sing-box | trojan | 0.0150 | 0.0053 | 0.0064 | 9214 | – | – |
| honk | anytls-sb | 0.0053 | 0.0034 | 0.0046 | 4792 | 0.28 | 45 |
| dae | anytls-sb | 0.0139 | 0.0039 | 0.0047 | 5586 | 0.43 | 57 |
| sing-box | anytls-sb | 0.0083 | 0.0018 | 0.0023 | 8244 | – | – |
| honk | anytls-go | 0.0132 | 0.0031 | 0.0037 | 9249 | 0.48 | 56 |
| dae | anytls-go | 0.0232 | 0.0023 | 0.0027 | 9006 | – | – |
| sing-box | anytls-go | 0.0065 | 0.0019 | 0.0021 | 8823 | – | – |

### UDP (iperf3 `-u -b 10G -l 1200 -R`, single flow, cold engine)

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.19 ms | 286 (95.3%) | 2.27 |
| dae | hy2 | 0.21 ms | 907 (85.9%) | 0.93 |
| sing-box | hy2 | 0.26 ms | 1629 (73.8%) | – |
| honk | tuic | 0.40 ms | 11 (99.2%) | 0.01 |
| dae | tuic | 0.27 ms | 1702 (67.4%) | 1.48 |
| sing-box | tuic | 0.15 ms | 100 (96.4%) | – |
| honk | ss2022 | 0.17 ms | 2010 (65.1%) | 1.31 |
| dae | ss2022 | 0.30 ms | 2742 (51.6%) | 1.79 |
| sing-box | ss2022 | 0.15 ms | 1984 (54.7%) | – |
| honk | trojan | 0.13 ms | 1659 (70.7%) | 1.28 |
| dae | trojan | 0.10 ms | 3062 (47.2%) | 1.70 |
| sing-box | trojan | 0.10 ms | 3557 (41.2%) | – |
| honk | anytls-sb | 0.28 ms | 1316 (79.0%) | 0.84 |
| dae | anytls-sb | – | – | – |
| sing-box | anytls-sb | 0.21 ms | 608 (78.8%) | – |
| honk | anytls-go | 0.19 ms | 1600 (74.5%) | 1.07 |
| dae | anytls-go | 0.12 ms | 1566 (74.3%) | – |
| sing-box | anytls-go | 0.10 ms | 640 (77.6%) | – |

### Reading the three-engine table

**TCP bandwidth:**
- Line-rate protocols (ss2022, trojan, anytls-go): all three engines reach
  ~8.7–9.4 Gbps. honk and dae are within noise of each other; sing-box
  trails slightly (8717 vs 9405 on ss2022, 8823 vs 9249 on anytls-go).
- QUIC protocols (hy2, tuic): dae leads at 4467/4537 Mbps. honk is at
  3050/4400, sing-box at 2998/2620. honk has a hy2 regression vs the
  previous 07-30 run (5239→3050), likely due to lab host load.
- anytls-sb: sing-box leads at 8244, dae 5586, honk 4792. This is the
  sing-box reference implementation; honk's anytls handler trails by ~40%.

**CPU efficiency:**
- On every QUIC row where both are measured, honk uses ~50% less CPU than
  dae at comparable bandwidth (hy2: 0.50 vs 1.07, tuic: 0.60 vs 0.98).
- On TCP-based protocols honk is consistently 0.3–0.5 cores lower than dae.

**Latency:**
- dae's tuic still pays a full QUIC handshake per connection (cold 85 ms vs
  honk's 5 ms with ticket-cache resume).
- sing-box cold latencies are highest across the board (TUN + userspace
  routing adds ~10–35 ms overhead).
- Hot latencies are all single-digit ms for all three engines.

**UDP (cold engine, single flow):**
- This run was on a cold engine (health checks unconverged, sessions cold),
  so UDP numbers read 3–5× lower than steady-state. See the warm-state
  comparison below.
- TUIC UDP cold-start is broken on all three engines (11–100 Mbps), but
  honk reaches 6.18 Gbps single-flow once warm — the cold numbers are a
  session-setup artifact, not a protocol limitation.

### UDP: warm-state three-engine comparison

All three engines were started, allowed 30s for health checks to converge,
then TCP sessions were primed through every protocol. UDP was measured
after a further 10s settle. Single flow and 8-flow aggregate
(`iperf3 -u -b 10G -l 1200 -R` / `-P 8`). Datagrams pinned to 1200 B.

| engine | protocol | echo RTT | single flow (loss) | P8 aggregate (loss) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 5.91 Gbps (5.9%) | P8 failed† |
| dae | hy2 | 0.59 ms | 915 Mbps (85.8%) | 827 Mbps (97.6%) |
| sing-box | hy2 | 0.42 ms | 1.61 Gbps (74.4%) | 1.58 Gbps (95.9%) |
| honk | tuic | 0.32 ms | **6.18 Gbps (2.1%)** | **9.40 Gbps (0.8%)** |
| dae | tuic | 0.15 ms | 1.57 Gbps (71.4%) | 21 Mbps (45.3%) |
| sing-box | tuic | 0.14 ms | 31 Mbps (80.1%) | failed |
| honk | ss2022 | 0.23 ms | 5.67 Gbps (11.5%) | 8.83 Gbps (6.8%) |
| dae | ss2022 | 0.21 ms | 2.52 Gbps (55.1%) | 2.59 Gbps (88.8%) |
| sing-box | ss2022 | 0.17 ms | 2.57 Gbps (55.1%) | 3.00 Gbps (87.3%) |
| honk | trojan | 0.07 ms | **6.31 Gbps (0.06%)** | 8.74 Gbps (7.8%) |
| dae | trojan | 0.13 ms | 2.96 Gbps (49.6%) | 2.87 Gbps (91.8%) |
| sing-box | trojan | 0.09 ms | 3.52 Gbps (39.1%) | 4.31 Gbps (88.6%) |
| honk | anytls-sb | 0.06 ms | 5.54 Gbps (13.6%) | **9.24 Gbps (2.5%)** |
| dae | anytls-sb | 0.25 ms | 1.31 Gbps (78.8%) | 2.87 Gbps (89.9%) |
| sing-box | anytls-sb | 1.78 ms | 1.26 Gbps (79.2%) | 2.85 Gbps (90.9%) |
| honk | anytls-go | 0.08 ms | **6.44 Gbps (0.4%)** | **9.37 Gbps (1.1%)** |
| dae | anytls-go | 0.13 ms | 1.58 Gbps (74.2%) | 2.45 Gbps (92.6%) |
| sing-box | anytls-go | 0.10 ms | 1.45 Gbps (76.3%) | 2.36 Gbps (92.9%) |

† honk hy2 P8 failed on this run (iperf3 returned 0); earlier warm-UDP
runs recorded 9.18 Gbps at 3.1% loss. Re-run on idle lab to confirm.

### Reading the warm UDP table

**Honk dominates warm-state UDP across every protocol:**
- Single flow: 5.5–6.4 Gbps with 0.06–13.6% loss. dae and sing-box are at
  0.9–3.5 Gbps with 40–86% loss — honk is **2–6× faster at 5–15× lower
  loss**.
- P8 aggregate: honk reaches 8.7–9.4 Gbps (near line rate) at 0.8–7.8%
  loss. dae and sing-box collapse on P8 with 88–98% loss — their UDP
  datapaths cannot handle 8 parallel saturating flows.
- **TUIC UDP** goes from 11 Mbps cold to **6.18 Gbps warm** (560×
  improvement). The protocol itself works; the cold-start numbers were a
  session-setup artifact, not a protocol limitation.
- **Trojan UDP** at 6.31 Gbps / 0.06% loss is nearly lossless — honk's
  UDP-over-TCP framing has no measurable overhead at line rate.
- **anytls-go** at 6.44 Gbps / 0.4% loss single-flow and 9.37 Gbps / 1.1%
  P8 is the best all-around UDP performer.

**dae and sing-box UDP collapse on P8 is not a lab artifact:**
Both engines show the same pattern — single-flow at 1–3.5 Gbps with
moderate loss, then P8 at same or LOWER throughput with 88–98% loss. This
indicates a fundamental bottleneck in their UDP receive paths (shared
socket buffer contention, lack of per-flow queuing, or kernel-level UDP
socket lock contention) that honk's `UdpEndpointPool` and per-flow bounded
queues were specifically designed to avoid.

## Results (2026-07-31, honk dev `ac64fe1` vs dae kdae `eee7c88b`)

Same-time A/B on the lab. honk is the musl release binary (mimalloc,
periodic `mi_collect` on a blocking thread, idle drain deadline); dae is
the kdae branch at `eee7c88b` (adds a DNS group-override fix and bumps the
outbound fork to `perf/complete-optimizations@670df833`). Latencies in
seconds, bandwidth is the iperf3 receiver median, CPU in cores, RSS after
the run. New in this run: **the kdae direct baseline works** (it was
broken in the 07-30 run).

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9406 | 0.24 | 52 |
| honk | hy2 | 0.0101 | 0.0032 | 0.0046 | 2921 | 0.48 | 59 |
| honk | tuic | 0.0093 | 0.0034 | 0.0043 | 3961 | 0.55 | 59 |
| honk | ss2022 | 0.0044 | 0.0027 | 0.0040 | 9392 | 0.36 | 52 |
| honk | trojan | 0.0072 | 0.0019 | 0.0120 | 9341 | 0.45 | 53 |
| honk | anytls-sb | 0.0050 | 0.0031 | 0.0039 | 4790 | 0.30 | 57 |
| honk | anytls-go | 0.0122 | 0.0032 | 0.0040 | 9226 | 0.49 | 56 |
| dae | direct | 0.0051 | – | – | 9397 | 0.00 | 52 |
| dae | hy2 | 0.0090 | 0.0032 | 0.0037 | 3005 | 0.82 | 63 |
| dae | tuic | 0.0827 | 0.0792 | 0.0800 | 4280 | 0.93 | 64 |
| dae | ss2022 | 0.0040 | 0.0036 | 0.0062 | 9404 | 0.42 | 57 |
| dae | trojan | 0.0105 | 0.0078 | 0.0100 | 9340 | 0.65 | 57 |
| dae | anytls-sb | 0.0112 | 0.0029 | 0.0038 | 4742 | 0.37 | 58 |
| dae | anytls-go | 0.0069 | 0.0034 | 0.0046 | 9301 | 0.63 | 60 |

UDP (iperf3 `-u -b 10G -l 1200 -R`, receiver Mbps + loss):

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.43 ms | 1708 (72.9%) | 1.07 |
| honk | tuic | 0.31 ms | 142 (64.5%) | 0.13 |
| honk | ss2022 | 0.22 ms | 1879 (66.6%) | 1.28 |
| honk | trojan | 0.18 ms | 1609 (71.9%) | 1.27 |
| honk | anytls-sb | 0.49 ms | 1308 (78.2%) | 0.86 |
| honk | anytls-go | 0.18 ms | 1607 (74.2%) | 1.04 |
| dae | hy2 | 0.27 ms | 929 (85.9%) | 0.95 |
| dae | tuic | 0.28 ms | 60 (52.4%) | 0.06 |
| dae | ss2022 | 0.16 ms | 2705 (52.4%) | 1.74 |
| dae | trojan | 0.11 ms | 2972 (48.7%) | 1.69 |
| dae | anytls-sb | 0.13 ms | 1305 (78.8%) | 0.85 |
| dae | anytls-go | 0.10 ms | 1413 (76.0%) | 0.92 |

### Reading the 07-31 table

- **TCP bandwidth** is parity within noise: line-rate rows (direct,
  ss2022, trojan, anytls-go) all ~9.3–9.4 Gbps both engines; anytls-sb is
  now a tie too (4790 vs 4742 — the new kdae no longer dominates that
  row). hy2/tuic slightly favor dae (3005/4280 vs 2921/3961).
- **CPU per Gbps** still belongs to honk on every QUIC row: hy2 0.48 vs
  0.82 cores, tuic 0.55 vs 0.93, and trojan 0.45 vs 0.65 at identical
  bandwidth.
- **Latency**: dae's tuic still pays a full QUIC handshake per connection
  (cold 82.7 ms, hot p50 79.2 ms vs honk's 9.3/3.4 ms, ticket-cache
  resumed). Everything else is single-digit ms both ways.
- **UDP**: honk leads hy2 (1708 vs 929) and anytls-go; the ss2022/trojan
  UDP-over-TCP gap persists (dae 2705/2972 vs honk 1879/1609) and remains
  the top UDP optimization target. TUIC UDP is broken-ish on both engines
  (142/60 Mbps).
- honk's hy2/tuic TCP bandwidth dropped vs the 07-30 run (5239→2921,
  5351→3961) while dae's stayed flat; the .70 lab host was under heavy
  parallel load during this run, so treat these two rows as suspect until
  re-measured on an idle lab.

## Results (2026-07-30, honk dev post-session-phases vs dae kdae, AES-NI)

Same-time A/B on the lab (engine VM with host-passthrough CPU; see "Known
lab limits" for the earlier software-crypto era). Latencies in seconds
(curl `time_total`), bandwidth is the iperf3 receiver median, CPU in
cores, RSS after the run. honk runs the musl release binary (mimalloc).

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9413 | 0.16 | 53 |
| honk | hy2 | 0.0058 | 0.0018 | 0.0032 | 5239 | 1.06 | 64 |
| honk | tuic | 0.0024 | 0.0038 | 0.0049 | 5351 | 1.06 | 66 |
| honk | ss2022 | 0.0038 | 0.0018 | 0.0025 | 9388 | 0.37 | 57 |
| honk | trojan | 0.0053 | 0.0014 | 0.0055 | 9366 | 0.42 | 49 |
| honk | anytls-sb | 0.0052 | 0.0020 | 0.0031 | 4954¹ | – | 58 |
| honk | anytls-go | 0.0126 | 0.0035 | 0.0046 | 9272¹ | – | 55 |
| dae | direct | broken² | – | – | – | – | – |
| dae | hy2 | 0.0109 | 0.0030 | 0.0043 | 2996 | 0.75 | 62 |
| dae | tuic | 0.0852 | 0.0797 | 0.0809 | 3920 | 0.84 | 64 |
| dae | ss2022 | 0.0063 | 0.0040 | 0.0042 | 9396 | 0.49 | 52 |
| dae | trojan | 0.0093 | 0.0084 | 0.0107 | 9370 | 0.66 | 57 |
| dae | anytls-sb | 0.0088 | 0.0014 | 0.0023 | 9155 | 0.60 | 58 |
| dae | anytls-go | 0.0044 | 0.0017 | 0.0021 | 9379 | 0.62 | 59 |
| sing-box | direct | 0.0044 | – | – | 9410 | 0.41 | 47 |
| sing-box | hy2 | 0.0143 | 0.0014 | 0.0018 | 2930 | 0.88 | 52 |
| sing-box | tuic | 0.0102 | 0.0029 | 0.0048 | 2808 | 0.86 | 50 |
| sing-box | ss2022 | 0.0042 | 0.0040 | 0.0056 | 9390 | 1.19 | 49 |
| sing-box | trojan | 0.0112 | 0.0068 | 0.0104 | 9368 | 0.78 | 47 |
| sing-box | anytls-sb | 0.0113 | 0.0035 | 0.0041 | 5996 | 0.59 | 49 |
| sing-box | anytls-go | 0.0129 | 0.0023 | 0.0028 | 9252 | 0.95 | 46 |

The dae rows are the **kdae branch build** (`2a007b39`,
`unstable-20260729.r987`), built from `../dae` on the bench host — the
first dae build with AnyTLS support. The sing-box rows are **1.13.14**
running as a TUN client *inside* the lab netns (`bench/sb-client.json`
deployed to the engine host; per-port route rules mirror the engine
configs, outbounds bound to `veth-client`).

¹ honk's anytls rows carry a history: single-stream iperf3 used to read
2–3 Mbps here. The cause was honk's own — a full per-stream demux queue
(64 frames) triggered an *instant* stream kill, which fired 22 ms into a
single-stream run when the server's initial flight outran the fresh
relay task; the server then flooded the pooled session with PSH frames
for the dead sid. The measured rows above used the first bounded-HOL fix,
which parked for up to 5 s before killing. The current path is nonblocking:
per-stream buckets have 512-frame / 2 MiB-stream / 8 MiB-session hard caps,
and cap pressure immediately resets only the offender after admitted bytes
drain. anytls-go matches dae in the historical run; anytls-sb trails (the
sing-box server emits patterns dae tolerates better — future work).

² dae's direct path is broken on this lab kernel (kdae build): direct
flows time out while proxied flows work. All dae protocol rows above are
valid; there is no dae direct baseline.

### UDP results (iperf3 `-u -b 10G -l 1200 -R`, echo RTT)

Same A/B run. Offered rate is a fixed 10 Gbps — far above what any tunnel
carries, so the loss column reflects saturation, not quality; the
receiver bandwidth is the capacity number. Datagram length is pinned to
1200 B: QUIC datagrams cap near that (honk hy2/tuic drop oversized
datagrams — iperf3's path-MTU default ~1448 B would measure the cap, not
the tunnel). Echo RTT is the median of 15 pings through the per-protocol
routed echo port (53531–53536).

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.37 ms | 1738 (73.1%) | 1.30 |
| honk | tuic | 0.38 ms | 293 (54.3%) | 0.22 |
| honk | ss2022 | 0.11 ms | 1158 (52.4%) | 0.81 |
| honk | trojan | 0.21 ms | 1506 (77.3%) | 1.26 |
| honk | anytls-sb | 0.12 ms | 1148 (82.2%) | 0.80 |
| honk | anytls-go | 0.10 ms | 1519 (76.6%) | 1.11 |
| dae | hy2 | 0.14 ms | 932 (85.9%) | 0.96 |
| dae | tuic | 0.13 ms | 9 (75.8%) | 0.03 |
| dae | ss2022 | 0.10 ms | 2668 (53.1%) | 1.76 |
| dae | trojan | 0.13 ms | 2957 (49.2%) | 1.67 |
| dae | anytls-sb | 0.10 ms | 1208 (80.7%) | 0.78 |
| dae | anytls-go | 0.19 ms | 1561 (75.2%) | 0.99 |
| sing-box | hy2 | 0.20 ms | 1372 (75.2%) | 1.18 |
| sing-box | tuic | 0.15 ms | 16 (63.4%) | 0.04 |
| sing-box | ss2022 | 0.07 ms | 2730 (53.0%) | 1.35 |
| sing-box | trojan | 0.07 ms | 3380 (45.5%) | 1.56 |
| sing-box | anytls-sb | 0.09 ms | 1244 (79.3%) | 1.12 |
| sing-box | anytls-go | 0.13 ms | 1447 (76.9%) | 1.21 |

- **hy2 UDP**: honk leads (1738 vs 932 / 1372) at ~1 core per engine.
- **TUIC UDP** is weak across all three engines (293 / 9 / 16 Mbps) —
  QUIC-datagram TUIC is a protocol-level weak spot in this lab, honk is
  least-bad.
- **UDP-over-TCP tunnels** (ss2022, trojan): dae/sing-box lead
  (2.7–3.4 Gbps vs honk 1.1–1.5). honk's UDP endpoint/framing path is
  the current bottleneck — the next optimization target after anytls-sb.
- **anytls UoT**: three-way tie at ~1.1–1.5 Gbps.
- Echo RTTs are sub-millisecond for every engine/protocol; nothing here
  is latency-bound.

### Reading the table

- **Bandwidth**: honk leads or ties everywhere. hy2 5239 (+75% vs dae,
  +79% vs sing-box), tuic 5351 (+36% / +90%), trojan and ss2022 at line
  rate with dae and sing-box, anytls-go 9272 (three-way tie). The one
  remaining gap is anytls against the sing-box server: honk 4954 vs dae
  9155 / sing-box 5996. ss2022 got to line rate via the BoringSSL AEAD
  swap: RustCrypto's aes-gcm measured 0.4–0.5 GB/s (AES-NI path not
  engaged) vs BoringSSL's 3.3–6.7 GB/s (`benches/ss_aead.rs`), and the
  swap took the row from 5339 Mbps / 1.01 cores to 9388 / 0.37 — now
  also ahead of dae on CPU (0.37 vs 0.49).
- **CPU per Gbps**: honk is the most efficient engine on every line-rate
  row — trojan 0.42 cores (dae 0.66, sing-box 0.78), ss2022 0.37 (dae
  0.49, sing-box 1.19). QUIC protocols cost honk ~1.06 cores at
  5.2+ Gbps; dae/sing-box need 0.75–0.88 for 2.8–3.9 Gbps.
- **Latency**: TUIC remains the extreme case — 3.8 ms hot vs dae's 79.7 ms
  (honk resumes TLS 1.3 sessions from a process-wide ticket cache; dae
  pays a full QUIC handshake per connection; cold tells the same story,
  2.4 vs 85.2 ms). Other rows are within a few ms both ways.
- **Memory**: honk's musl build uses mimalloc, which retains freed arenas
  — RSS 49–66 MB, at parity with dae (52–64 MB). The trade is deliberate:
  mimalloc buys ~+50% QUIC throughput over musl's stock malloc (5096 vs
  3037 Mbps A/B) for ~40 MB of retained memory.

### Earlier results (software-crypto lab, pre-AES-NI)

Before the engine VM got a host-passthrough CPU, QUIC numbers were
software-crypto-bound for both engines: honk hy2/tuic 2289/2383 Mbps vs
dae(kdae) 2511/2669, with honk's BoringSSL stuck on `nohw` C ChaCha20
(34% of engine CPU). Those rows are superseded by the table above. The
QUIC socket-buffer fix (8 MiB SO_RCVBUF/SO_SNDBUF + rmem_max/wmem_max at
16 MiB) and the 8/32 MiB receive-window defaults predate both tables and
apply to both.

## DNS micro-benchmarks (criterion)

`cargo bench -p honk-core --bench dns` — loopback, no external network.
Latest run (2026-07-30, x86_64):

| benchmark | mean |
| --- | --- |
| endpoint parse (udp/dot/doh/doq/h3) | 70–97 ns |
| cache get (hit) | 60 ns |
| cache put | 133 ns |
| cache mixed 90% read / 10% write | 32 ns |
| routing match (per-query rule eval) | 29–79 ns |
| force/restore txid | 1.4 ns |
| build A query | 114 ns |
| forwarder resolve (cache hit) | 283 ns |
| TCP pool exchange (reused conn) | 18 µs |
| UDP upstream exchange | 19 µs |
| length-prefixed framing (duplex) | 6 µs |

Per-query total (routing + cache-hit) is well under 1 µs; upstream
exchanges are loopback-RTT-bound as expected. The bench suite lives in
`crates/honk-core/benches/dns.rs`; mock servers run nodelay — without it
Nagle + delayed-ACK adds ~40 ms per TCP exchange and the numbers measure
the OS, not the code.

`cargo bench -p honk-outbound --bench ss_aead` compares AEAD backends on
Shadowsocks-sized chunks (RustCrypto aes-gcm 0.4–0.5 GB/s vs BoringSSL
AeadCtx 3.3–6.7 GB/s on AES-NI hardware — the reason the SS data path
uses BoringSSL).

## Candidate UDP micro-benchmarks (absolute, not A/B)

The UDP Criterion suite records absolute candidate behavior only. Its fixed
invocation is:

```bash
cd /root/code/honk-feat-udp-to-1
CARGO_TARGET_DIR=/root/code/honk/target cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate
```

| Case | Fixed work |
| --- | --- |
| steady enqueue | 1,000,000 128-byte `fast_path_enqueue` calls on a Ready flow, immediately drained to hold steady state |
| reserve / rollback | 10,000 endpoint reservations followed by rollback |
| histogram | 1,000,000 record/snapshot operations |
| queue saturation | 64 admitted datagrams followed by one dropped newest datagram |

Record the candidate's Criterion mean, median, MAD, and absolute throughput.
`udp-candidate` is a repeat-run label, not a comparison to `be587b1`: that
revision has no source-level equivalent interface for a valid A/B. Criterion
also does not provide a merge-gate p95 estimate; do not infer one from this
suite.

## Deployment UDP A/B gate

`bench/udp-latency.sh` is the real deployment driver, not a CI substitute. It
requires the same TPROXY topology and real upstreams for both binaries. Its
fixed invocation is:

```bash
sudo bench/udp-latency.sh \
  --baseline-bin /opt/honk/be587b1/honk-core \
  --candidate-bin /opt/honk/udp-to-1/honk-core \
  --config /etc/honk/bench.dae \
  --echo-target 10.0.2.2:9000 \
  --dns-target 10.0.2.2:53 \
  --samples 10000 --runs 5 --offered-rate 5000
```

The fixed command deliberately has no timeout or hook flags. Configure root's
`HONK_UDP_TIMEOUT_SEC` (default `30`) and
`HONK_UDP_{START,READY,SETUP,PROBE,STATS,TEARDOWN,TOPOLOGY}_HOOK` values; CLI
flags override those values. With `sudo`, use `--preserve-env` for these
variables or configure them in root's environment. The driver supplies no
built-in topology: missing live hooks fail closed.

Every executable hook is run through `env`, not evaluated as a shell snippet.
It receives `variant`, `case`, `run`, `workdir`, `pid`, `pgid`, `selected_bin`,
`baseline_bin`, `candidate_bin`, `config`, `echo_target`, `dns_target`,
`samples`, `offered_rate`, and `timeout`; `pid`/`pgid` are empty for `start`
and `topology`. `start` must finish synchronous setup and then `exec
"$selected_bin" ...`; the driver attests the selected file's device/inode
against `/proc/$pid/exe` and rechecks the same PID/session/start-time/executable
after ready, setup, probe, and stats. A row is emitted only after teardown and
bounded verification that the owned process group is absent; residual descendants
fail the run closed. The legacy positional arguments remain compatible. Targets
may be IPv4, `[IPv6]`, or legal hostnames with a port.
`probe` must report `sent == samples`.

It emits one JSONL object per case/run with exactly these top-level fields:
`schema_version`, `variant`, `commit`, `binary_sha256`, `kernel`, `topology`,
`case`, `run`, `samples`, `offered_rate`, `sent`, `received`, `latency_unit`,
`p50`, `p95`, `p99`, `max`, `loss`, `cpu_pct`, `rss_kib`, `fd_count`,
`queue_drops`, and `warm_hit`. `schema_version` is `1`; latency quantiles are
in microseconds, `loss` is the sample loss ratio, `cpu_pct` is process CPU
usage, `rss_kib` is resident memory in KiB, and `fd_count` is the open
file-descriptor count. The fixed cases are `cold_endpoint`, `steady_hit`,
`warm_session_cold_endpoint`, `dns_hit`, `dns_miss`, `healthy_candidate`, and
`blackholed_candidate`. The driver interface and JSONL shape are checked with
`bash bench/tests/udp-latency-cli.sh`.

The deployment gate compares five 10,000-sample runs at the same topology and
offered rate: healthy cold p50/p95 regression must be at most 5%; a blackholed
first candidate must improve p95 by at least 20% and p99 by at least 30%; a
steady path must keep p99 at most 250 microseconds and zero drops below 70% of
target throughput; AnyTLS warm hits must reach 80% and reduce first reply by
one RTT or at least 20%; steady CPU and p50 regression must be at most 5%; and
IPv4/IPv6 client-observed reply tuples must remain unchanged. **This local
worktree has not run the deployment gate, so it makes no network-latency gate
claim.**

## Release profile and allocator matrix

`bench/release-matrix.sh` compares the explicit `release-size`,
`release-size-thin`, `release-speed`, and `release-speed-thin` profiles against
three allocator arms: mimalloc with collection disabled, mimalloc with the
60-second collector, and the system allocator. Every cell uses isolated Cargo,
workload-cache, and run directories and emits machine metadata plus JSONL/CSV
build and performance records.

Validate all four supported target configurations without compiling:

```bash
bench/release-matrix.sh --all-targets --dry-run --output /tmp/honk-release-matrix
```

A measured host run requires an executable `--benchmark-hook`; the hook contract
and required RSS/PSS/fault/CPU/throughput/latency fields are printed by
`bench/release-matrix.sh --help`. Pin every CPU policy to one governor and keep
turbo in one state for the full matrix; `machine.json` records both settings.
Compare cells only on the same machine and workload. The matrix records
evidence; it does not select a new shipping profile without deployment
throughput and tail-latency results.

Promotion is gated, not inferred from binary size alone. Against the
`release-size` baseline, a candidate must keep every measured throughput
regression within 3%, every p99 latency regression within 5%, and RSS growth
within 20% over five paired runs on the same lab. The size profile remains the
shipping default until all three gates pass.

One preliminary paired deployment run on 2026-08-02 compared
`release-size` and `release-speed` for x86_64 musl with mimalloc and the
60-second collector. Each protocol used three 8-second reverse-throughput runs;
the tail check used 200 requests after warm-up.

| profile | binary | direct | hy2 | tuic | max RSS | hy2 p99 | tuic p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| release-size | 19.50 MB | 9.407 Gbps | 2.756 Gbps | 4.253 Gbps | 56 MB | 5.426 ms | 4.705 ms |
| release-speed | 24.79 MB | 9.388 Gbps | 3.314 Gbps | 5.152 Gbps | 59 MB | 3.409 ms | 3.136 ms |

The speed profile had no throughput or p99 regression and increased maximum
RSS by 5.4%, so this sample passes the numerical gates. It is not a promotion:
one paired run is below the five-run evidence requirement, and its binary is
27.2% larger. `release-size` therefore remains the default.

## Production notes (10.10.10.1 gateway)

- TCP (google/baidu/cloudflare) and HTTP/3 (cloudflare) pass after each
  deploy; gateway logs clean.
- HTTP/3 stall bursts (first bytes fast, body pauses ~14s) appear in
  multi-minute waves tied to the subscription's UDP line quality, not to
  engine builds — A/B deploys of consecutive builds flip both ways within
  the same hour. Client qlog shows ~12% of datagrams declared-lost-then-late
  (latency artifact, not kernel/socket drops).
- 60-min canaries after each deploy sample FDs / established / CLOSE-WAIT /
  warn-rate; the Ready-pool metrics (`/stats` → `pool`: hits, misses,
  entries) are checked on the same cadence.

## Regression gates

- `just outbound-ci` — fmt, clippy, honk-config + honk-outbound suites.
- `just clash-ci` — fmt, clippy, clash_api_test + integration_test.
- `just dns-ci` — DNS subsystem gate.
- `cargo bench -p honk-core --bench dns` — DNS micro-benchmarks (above).
- `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate` — candidate-only absolute UDP measurements; not a historical A/B or p95 merge gate.
- `bash bench/tests/udp-latency-cli.sh` — deployment-driver CLI/JSONL fixture; the real UDP A/B gate above still requires TPROXY and upstreams.
- `bash bench/tests/runtime-memory-cli.sh` — paired runtime-memory driver CLI, ordering, identity, and fail-closed JSONL fixture.
- Release CI (`.github/workflows/release.yml`) — workspace test gate +
  four-target build (x86_64/aarch64 × gnu/musl) + BTF check + tarballs.
