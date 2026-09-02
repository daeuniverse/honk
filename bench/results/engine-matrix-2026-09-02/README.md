# Engine matrix: dae / kdae / cdae / sing-box (2026-09-02)

Same-host A/B on the x86 lab (`10.10.10.49`, 4× host-passthrough i5-13600K,
2 GiB, kernel 7.1.8) using `bench/lab-bench.sh` with the full six-protocol
set (hy2, tuic, ss2022, trojan, anytls-sb, anytls-go) plus the direct
baseline. No honk arm in this run — this matrix compares the dae-family
builds against sing-box only.

## Engines under test

| Label | Binary | Version |
| --- | --- | --- |
| dae | upstream dae | `unstable-20260729.r987.2a007b39` |
| kdae | kdae fork | `unstable-20260824.r1142.ec957346` (go1.26.0 newinliner/simd) |
| cdae | LostAttractor/dae `dev` | `unstable-20260828.r1.2630677` (built from source, go1.25.7) |
| sing-box | sing-box | 1.13.18 (TUN client inside the lab netns) |

Servers (10.10.10.70): one sing-box 1.12.4 instance serves hy2 `:8443`,
tuic `:2444`, ss2022 `:2447`, trojan `:2446`, and anytls `:2445`;
anytls-go `:2443` is the Go reference `anytls-server`.

## cdae protocol surface (build-time)

`component/outbound/outbound.go` on `dev` imports only anytls / http /
hysteria2 / shadowsocks / socks / trojan — **tuic, juicity, vless, vmess,
ssr are commented out** (nodes fail to parse: "failed to parse node").
Additionally the anytls dialer fails to register at runtime in this build
("no conn creator registered for anytls"), so the effective surface here is
**hy2 + ss2022 + trojan**. The tuic/anytls rows are recorded as 0/invalid,
not as performance numbers.

Note: cdae's config parser rejects `dial_mode`, `tcp_check_url`,
`tcp_check_http_method`, `udp_check_dns`, `check_interval`, and
`check_tolerance`; `cdae-lab.dae` is `dae-lab.dae` with those keys removed.
The harness's health-check suppression (3600s interval) therefore does not
apply to the cdae arm.

## Bandwidth (iperf3 -R, median of 3, Mbps)

| protocol | dae | kdae | cdae | sing-box |
| --- | --- | --- | --- | --- |
| direct | 9404 | 9407 | 9405 | 9404 |
| hy2 | 3066 | 3105 | 3222 | 3206 |
| tuic | 3339 | 3371 | n/a | 2910 |
| ss2022 | 9394 | 9399 | 9405 | 9395 |
| trojan | 9388 | 9388 | 9397 | 9384 |
| anytls-sb | 5614 | 5600 | n/a | 5659 |
| anytls-go | 9378 | 9380 | n/a | 9378 |

UDP offered 10G, receiver bps (and share of offered): hy2 ≈ 0.97–1.12 Gbps
(84–86%), ss2022 ≈ 2.7–2.9 Gbps (~51%), trojan ≈ 2.9–3.7 Gbps (42–56%),
anytls ≈ 1.3–1.8 Gbps (73–79%). Engines are within noise of each other on
the shared rows.

## Latency

Cold (first request after engine restart, median of 3): all engines ~2–9 ms
except **dae tuic cold = 82.8 ms** (kdae 23.0 ms, sing-box 7.6 ms). Hot
p50/p95 are 1.7–3.7 ms across the board except **dae tuic hot p50 =
78.8 ms** (kdae 17.9 ms, sing-box 2.2 ms) — upstream dae's tuic path carries
a persistent per-stream penalty even warm.

## Loaded-latency stability (200 streams at 250 ms cadence over one reverse
iperf3 stream on the same outbound; p99 ms)

| protocol | dae | kdae | cdae | sing-box |
| --- | --- | --- | --- | --- |
| direct | 4.86 | 4.72 | 5.02 | 4.88 |
| hy2 | 3.25 | 3.10 | 3.28 | 3.40 |
| tuic | **77.50** | 17.28 | n/a | 2.93 |
| ss2022 | arm-failed* | 16.03 | 15.87 | 15.32 |
| trojan | 25.58 | 22.42 | 19.62 | 22.42 |
| anytls-sb | 2.70 | 2.86 | n/a | 2.69 |
| anytls-go | 16.43 | 19.87 | n/a | 16.12 |

\* the upstream-dae ss2022 loaded-latency arm failed to collect after three
retries (`arm-failed` in dae.md); the row is absent rather than
interpolated. All other cells: 0/200 failures except kdae anytls-go 4/200.

## Files

- `<engine>.md` — harness stdout (latency/bw/cpu/rss + loaded-latency
  tables, engine binary sha256 in the header)
- `<engine>.raw.tsv` — raw bench rows appended by the harness
- `<engine>.stability.tsv` — loaded-latency summary rows
- `dae-lab.dae` / `cdae-lab.dae` / `sb-client.json` — exact engine configs
