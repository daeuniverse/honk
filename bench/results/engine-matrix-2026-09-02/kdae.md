# host=archlinux arch=x86_64 kernel=7.1.8-arch1-3
# honk_bin=/root/honk sha256=
# dae_bin=/root/dae sha256=f2dc44b5fa96cd1041ed54082d753a75f81e400b2fe40b7817df0acfae36c2d7
# lab-bench 2026-09-02T17:27:40Z engines=(dae) protos=(hy2 tuic ss2022 trojan anytls-sb anytls-go)
| engine | protocol | cold(s) | hot p50(s) | hot p95(s) | bw(Mbps) | cpu(cores) | rss(MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
# engine=dae
| dae | direct | 0.001394 | - | - | 9407 | 0.00 | 38 |
| dae | hy2 | 0.007579 | 0.002031 | 0.002557 | 3105 | 0.45 | 44 |
| dae | hy2/udp | 0.000189 | - | - | 1021(85.3%) | 0.48 | - |
| dae | tuic | 0.023038 | 0.017943 | 0.018809 | 3371 | 0.49 | 43 |
| dae | tuic/udp | 0.000419 | - | - | 1123(83.7%) | 0.54 | - |
| dae | ss2022 | 0.005237 | 0.002005 | 0.003517 | 9399 | 0.37 | 46 |
| dae | ss2022/udp | 0.000135 | - | - | 2725(52.8%) | 0.68 | - |
| dae | trojan | 0.005812 | 0.003724 | 0.004368 | 9388 | 0.43 | 46 |
| dae | trojan/udp | 0.000115 | - | - | 2907(55.8%) | 0.62 | - |
| dae | anytls-sb | 0.005062 | 0.002069 | 0.002565 | 5600 | 0.29 | 50 |
| dae | anytls-sb/udp | 0.000344 | - | - | 1460(77.6%) | 0.38 | - |
| dae | anytls-go | 0.008571 | 0.002270 | 0.002710 | 9380 | 0.45 | 49 |
| dae | anytls-go/udp | 0.000089 | - | - | 1771(73.3%) | 0.42 | - |

## loaded latency stability (200 samples, 250ms cadence)
| engine | protocol | load(Mbps) | p50(ms) | p95(ms) | p99(ms) | max(ms) | failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dae | direct | 9409 | 3.485 | 4.506 | 4.721 | 5.192 | 0/200 |
| dae | hy2 | 3000 | 2.262 | 2.695 | 3.101 | 3.201 | 0/200 |
| dae | tuic | 3395 | 16.512 | 16.822 | 17.282 | 17.440 | 0/200 |
| dae | ss2022 | 9401 | 4.287 | 12.530 | 16.025 | 19.589 | 0/200 |
| dae | trojan | 9393 | 4.658 | 16.470 | 22.422 | 43.774 | 0/200 |
| dae | anytls-sb | 5776 | 2.007 | 2.488 | 2.857 | 4.116 | 0/200 |
| dae | anytls-go | 9383 | 2.768 | 9.749 | 19.872 | 21.444 | 4/200 |
