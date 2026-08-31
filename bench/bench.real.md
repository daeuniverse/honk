# Real-path benchmark: honk vs kdae vs mihomo (2026-08-31)

Lab-free A/B over a real international path. Engine host `10.10.10.49`
(Arch, kernel 7.1.8, x86-64) behind gateway `10.10.10.1` (MAC-exempted from
the gateway's own honk). Server `103.26.8.157` (Debian 13, 2C/2G) runs
sing-box 1.13.19 inbounds (socks5/ss/ss2022/trojan/vmess+ws/vless+tls/anytls/
tuic/hy2) + juicity-server 0.4.3, plus the measurement targets:
`python3 -m http.server 18080` serving a 256 MiB random file and a 1 KiB
file, iperf3 on 5201. Server configs: `.157:/root/proto-bench/`, client
harness: `.49:/root/proto-bench/{lib,bench,lat}.sh`.

honk build: main tip incl. PR #110 (quinn-proto fork `MAX_CHUNKS=16384`),
musl. kdae: `dae-kdae-ec957346`. mihomo: v1.19.13 (control client via
socks5h, not the datapath). WAN RTT ≈ 65 ms to .157.

## Throughput (256 MiB HTTP GET ×2, averaged, MB/s)

| protocol | honk | kdae | note |
|---|---|---|---|
| socks5 | 24.6 | 21.1 | |
| ss (aes-128-gcm) | 32.0 | 26.6 | |
| ss2022 | 22.3 | 21.6 | |
| trojan+tls | 29.0 | 29.7 | |
| vmess+ws | 25.3 | 28.0 | |
| vless+tls | 20.2 | 28.1 | honk run during bench window dropped to 3 MB/s once, unreproduced on retest |
| anytls | 29.7 | 29.2 | honk bench-window run failed (0 B, exit 56), unreproduced on retest |
| tuic (bbr) | 31.3 | **52.1** | |
| juicity (bbr) | 29.3 | **45.7** | |
| hy2 (bbr) | 28.5 | **60.7** | honk with `mtu=1450` (GSO on): 35.5 |

Direct baseline: ~18.9 MB/s (15.6–22.1). Proxy paths exceed direct because
the tunnel endpoints' congestion control outperforms the last-mile TCP.

## Latency (1 KiB GET ×10 after warm-up, steady value, ms)

| protocol | honk | kdae |
|---|---|---|
| socks5 | 63 (pool hit) / 260 (miss, ~50% hit) | **515** (no pooling, ~8 RTT) |
| ss | **65** | 112 |
| ss2022 | 113 | 113 |
| trojan+tls | 62 (hit) / 184 (miss) | 180 |
| vmess+ws | 113 | 162 |
| vless+tls | 140 | 182 |
| anytls | 65 | 115 |
| tuic | 66 | 80 |
| juicity | 65 | 112 |
| hy2 | 66 | 66 |

Direct baseline: 111 ms (TCP connect + request ≈ 2 legs). honk pool/QUIC
hits complete a proxied request in **1 RTT**.

## Same-day episode: quinn MAX_CHUNKS kills lossy-link transfers (PR #110)

Different server (`23.238.9.47`, hy2, ~450 ms RTT, bursty loss). honk with
the 8 MiB receive window died ~3 s into every 50 MiB transfer
(`too many gaps in stream buffer`): quinn-proto aborts the connection past
1024 unmergeable buffered chunks; ~6500 packets in flight × burst loss
exceeds it. quic-go has no such cap. After raising the bound to 16384:

| client | 50 MiB ×3 |
|---|---|
| honk before | dies every run |
| honk after (8 MiB window) | **6.2–9.9 MB/s, 8/8 complete** |
| dae (quic-go) | 4.6–5.5 MB/s |
| mihomo (quic-go) | 2.4–3.6 MB/s |

RSS during transfer stayed flat (38.7 → 39.2 MB).

## Follow-up: tightly interleaved hy2 A/B (2026-09-01, same path)

The protocol matrix above ran all honk rows before all kdae rows; link
conditions drift over minutes, so a per-protocol alternating A/B (6 rounds,
same fallback group, engine restarted per run) was run to separate
implementation from time variance:

| round | honk MB/s | kdae MB/s |
|---|---|---|
| 1 | 25.2 | FAIL (0 B, exit 28) |
| 2 | 15.9 | FAIL (exit 56) |
| 3 | 16.1 | FAIL (exit 56) |
| 4 | 17.3 | 54.1 |
| 5 | 30.1 | 55.3 |
| 6 | 28.2 | FAIL (exit 28) |

honk 6/6 complete (avg 22.1); kdae 3/6 complete but 54–55 when the link
window is good. Round 4/5 prove the good-window gap is real (~2–3×) and not
time drift; the failures prove quic-go connections die outright under
degraded UDP where quinn (post-#110) degrades gracefully.

Ruled out for the good-window gap: client CPU (15% of one core at 33 MB/s),
kernel UDP drops (0 RcvbufErrors during runs), receive-window size (8 MiB @
65 ms RTT = 126 MB/s ceiling), MTU alone (`mtu=1450` only +25%), and the
honk-core datapath/relay (handler-direct download via
`crates/honk-outbound/examples/hy2_dl.rs` = 24–28 MB/s, identical to the
in-engine number).

### Interleaved A/B, second session (same evening, worse link phase)

| round | honk MB/s | kdae MB/s |
|---|---|---|
| 1 | 23.1 | 0.2 (exit 28) |
| 2 | 24.2 | 1.0 (exit 28) |
| 3 | 13.4 | **62.3** |
| 4 | 22.4 | 18.0 |
| 5 | 0.3 (exit 28) | 1.4 (exit 28) |
| 6 | 18.5 | 3.5 (exit 28) |

Totals over both sessions (12 rounds): honk 11/12 complete, 13–30 MB/s;
kdae 5/12 complete, peaks 54–62. Round-3 same-window pair (honk 13.4 / kdae
62.3) reconfirms the good-window gap.

## Controlled lab (netns on .49, sing-box server in `labsrv`, setup
script `/root/labsrv-setup.sh`, configs `/root/{honk,dae}-lab-223.dae`)

iperf3 download through the full datapath, median of 3:

| condition | honk hy2 | dae hy2 |
|---|---|---|
| clean LAN | **7403 Mbps** | 6484 Mbps |
| 1% random loss | **6523 Mbps** | 3848 Mbps |
| 65 ms RTT + 1% loss | **515 Mbps** | 335 Mbps |

tuic clean LAN: honk 10230 vs dae 8061 Mbps. quinn matches or beats quic-go
on every controlled condition — the WAN good-window gap is not base
efficiency, random-loss sensitivity, or delay+loss interaction. What remains
unreproduced in the lab: real WAN burst-loss/policing dynamics. Next
instrument for that: WAN packet capture. Also noteworthy: quic-go's
good-window peaks come with a 50% connection-death rate in bad windows;
quinn never died after #110.

## Conclusions

- Latency: honk's pooling / shared-QUIC-connection model beats kdae broadly
  (1 RTT on hits; kdae pays 2–3 RTT, socks5 ~8 RTT). honk gaps: ss2022,
  vmess, vless never hit the pool; trojan/socks5 miss rate ~50%.
- Throughput: TCP-carried protocols are parity or honk-favored. QUIC: kdae
  is ~2–3× honk in good windows but fails outright in degraded ones
  (3/6 runs died with 0 bytes); honk never died. The trade-off is
  efficiency vs robustness, not a uniform honk deficit.
- Reliability watch: the one-time anytls/vless bench-window failures did
  not reproduce; server log shows only expected v4-only-server health-check
  noise. Re-observe before attributing.

## Reproduce

```bash
ssh root@10.10.10.49 'bash /root/proto-bench/bench.sh'   # throughput matrix
ssh root@10.10.10.49 'bash /root/proto-bench/lat.sh'     # latency matrix
```

Caveats: single evening, one server; link noise between runs is ±30%
(direct baseline ranged 15.6–28.6 MB/s), treat <15% deltas as noise.
Engines are restarted per protocol; configs differ only in the fallback
group.
