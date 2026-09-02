# host=archlinux arch=x86_64 kernel=7.1.8-arch1-3
# honk_bin=/root/honk sha256=
# dae_bin=/root/cdae sha256=2362935a177f6850eee48b3032c48674c7399fa6117f1a31a77b1b49594cc22d
# lab-bench 2026-09-02T18:10:56Z engines=(dae) protos=(hy2 tuic ss2022 trojan anytls-sb anytls-go)
| engine | protocol | cold(s) | hot p50(s) | hot p95(s) | bw(Mbps) | cpu(cores) | rss(MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
# engine=dae
| dae | direct | 0.003296 | - | - | 9405 | 0.74 | 40 |
| dae | hy2 | 0.003521 | 0.002146 | 0.002599 | 3222 | 0.69 | 46 |
| dae | hy2/udp | 0.000472 | - | - | 1005(85.5%) | 0.85 | - |
| dae | tuic | 0.003593 | 0.001952 | 0.002532 | 0 | 0.00 | 42 |
loaded-latency arm failed: engine=dae protocol=tuic collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=tuic attempt=1/3
loaded-latency arm failed: engine=dae protocol=tuic collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=tuic attempt=2/3
loaded-latency arm failed: engine=dae protocol=tuic collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=tuic attempt=3/3
| dae | tuic/udp |  | - | - | 0(-) | 0.00 | - |
| dae | ss2022 | 0.003209 | 0.001818 | 0.002274 | 9405 | 0.70 | 46 |
| dae | ss2022/udp | 0.000261 | - | - | 1389(76.0%) | 1.14 | - |
| dae | trojan | 0.003115 | 0.002127 | 0.002724 | 9397 | 0.44 | 44 |
| dae | trojan/udp | 0.000102 | - | - | 1885(72.4%) | 0.85 | - |
| dae | anytls-sb | 0.003392 | 0.001720 | 0.002941 | 0 | 0.00 | 45 |
loaded-latency arm failed: engine=dae protocol=anytls-sb collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-sb attempt=1/3
loaded-latency arm failed: engine=dae protocol=anytls-sb collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-sb attempt=2/3
loaded-latency arm failed: engine=dae protocol=anytls-sb collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-sb attempt=3/3
| dae | anytls-sb/udp |  | - | - | 0(-) | 0.00 | - |
| dae | anytls-go | 0.003376 | 0.001920 | 0.002762 | 0 | 0.00 | 43 |
loaded-latency arm failed: engine=dae protocol=anytls-go collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-go attempt=1/3
loaded-latency arm failed: engine=dae protocol=anytls-go collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-go attempt=2/3
loaded-latency arm failed: engine=dae protocol=anytls-go collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=anytls-go attempt=3/3
| dae | anytls-go/udp |  | - | - | 0(-) | 0.00 | - |

## loaded latency stability (200 samples, 250ms cadence)
| engine | protocol | load(Mbps) | p50(ms) | p95(ms) | p99(ms) | max(ms) | failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dae | direct | 9411 | 3.962 | 4.713 | 5.023 | 5.747 | 0/200 |
| dae | hy2 | 3044 | 2.308 | 2.749 | 3.284 | 3.382 | 0/200 |
| dae | tuic | invalid | - | - | - | - | arm-failed |
| dae | ss2022 | 9395 | 3.567 | 11.127 | 15.867 | 21.234 | 0/200 |
| dae | trojan | 9396 | 4.483 | 15.454 | 19.622 | 23.316 | 0/200 |
| dae | anytls-sb | invalid | - | - | - | - | arm-failed |
| dae | anytls-go | invalid | - | - | - | - | arm-failed |
