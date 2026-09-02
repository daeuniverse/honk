# host=archlinux arch=x86_64 kernel=7.1.8-arch1-3
# honk_bin=/root/honk sha256=
# dae_bin=/root/dae sha256=f2dc44b5fa96cd1041ed54082d753a75f81e400b2fe40b7817df0acfae36c2d7
# lab-bench 2026-09-02T17:52:52Z engines=(sing-box) protos=(hy2 tuic ss2022 trojan anytls-sb anytls-go)
| engine | protocol | cold(s) | hot p50(s) | hot p95(s) | bw(Mbps) | cpu(cores) | rss(MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
# engine=sing-box
| sing-box | direct | 0.002222 | - | - | 9404 | 0.36 | 48 |
| sing-box | hy2 | 0.007852 | 0.003036 | 0.003969 | 3206 | 0.71 | 55 |
| sing-box | hy2/udp | 0.000174 | - | - | 968(86.1%) | 1.14 | - |
| sing-box | tuic | 0.007596 | 0.002214 | 0.003464 | 2910 | 0.64 | 52 |
| sing-box | tuic/udp | 0.000323 | - | - | 983(85.8%) | 1.16 | - |
| sing-box | ss2022 | 0.005352 | 0.002812 | 0.003152 | 9395 | 1.09 | 53 |
| sing-box | ss2022/udp | 0.000355 | - | - | 2818(51.3%) | 1.23 | - |
| sing-box | trojan | 0.006972 | 0.003645 | 0.004738 | 9384 | 0.70 | 54 |
| sing-box | trojan/udp | 0.000330 | - | - | 3673(41.9%) | 1.58 | - |
| sing-box | anytls-sb | 0.006892 | 0.001994 | 0.002689 | 5659 | 0.43 | 51 |
| sing-box | anytls-sb/udp | 0.000327 | - | - | 1363(79.2%) | 1.11 | - |
| sing-box | anytls-go | 0.008806 | 0.002150 | 0.002935 | 9378 | 0.90 | 51 |
| sing-box | anytls-go/udp | 0.000229 | - | - | 1329(79.2%) | 1.18 | - |

## loaded latency stability (200 samples, 250ms cadence)
| engine | protocol | load(Mbps) | p50(ms) | p95(ms) | p99(ms) | max(ms) | failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| sing-box | direct | 9412 | 4.066 | 4.740 | 4.880 | 5.092 | 0/200 |
| sing-box | hy2 | 3005 | 2.276 | 2.883 | 3.395 | 11.051 | 0/200 |
| sing-box | tuic | 2882 | 2.224 | 2.731 | 2.933 | 3.115 | 0/200 |
| sing-box | ss2022 | 9398 | 3.935 | 12.607 | 15.317 | 16.214 | 0/200 |
| sing-box | trojan | 9387 | 4.827 | 16.290 | 22.424 | 23.708 | 0/200 |
| sing-box | anytls-sb | 5542 | 2.083 | 2.476 | 2.688 | 3.889 | 0/200 |
| sing-box | anytls-go | 9378 | 2.938 | 9.688 | 16.116 | 18.167 | 0/200 |
