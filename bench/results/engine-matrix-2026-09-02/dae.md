# host=archlinux arch=x86_64 kernel=7.1.8-arch1-3
# honk_bin=/root/honk sha256=
# dae_bin=/root/dae.test sha256=bc2f70bfa79ed6adc14fb899b76555defc5ac2f12758944ae58b8e1a6b702de1
# lab-bench 2026-09-02T17:12:27Z engines=(dae) protos=(hy2 tuic ss2022 trojan anytls-sb anytls-go)
| engine | protocol | cold(s) | hot p50(s) | hot p95(s) | bw(Mbps) | cpu(cores) | rss(MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
# engine=dae
| dae | direct | 0.003169 | - | - | 9404 | 0.00 | 41 |
| dae | hy2 | 0.008543 | 0.002585 | 0.002835 | 3066 | 0.62 | 56 |
| dae | hy2/udp | 0.000312 | - | - | 1011(85.4%) | 0.77 | - |
| dae | tuic | 0.082765 | 0.078843 | 0.079904 | 3339 | 0.66 | 55 |
| dae | tuic/udp | 0.000437 | - | - | 1087(84.3%) | 0.89 | - |
| dae | ss2022 | 0.005517 | 0.002302 | 0.002985 | 9394 | 0.38 | 52 |
loaded-latency arm failed: engine=dae protocol=ss2022 collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=ss2022 attempt=1/3
loaded-latency arm failed: engine=dae protocol=ss2022 collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=ss2022 attempt=2/3
loaded-latency arm failed: engine=dae protocol=ss2022 collector=0 load=1
retrying loaded-latency arm: engine=dae protocol=ss2022 attempt=3/3
| dae | ss2022/udp | 0.000376 | - | - | 2865(50.3%) | 1.20 | - |
| dae | trojan | 0.007759 | 0.003332 | 0.004291 | 9388 | 0.42 | 52 |
| dae | trojan/udp | 0.000236 | - | - | 3010(53.6%) | 1.10 | - |
| dae | anytls-sb | 0.006615 | 0.002150 | 0.003250 | 5614 | 0.34 | 53 |
| dae | anytls-sb/udp | 0.000192 | - | - | 1435(78.0%) | 0.61 | - |
| dae | anytls-go | 0.008926 | 0.001681 | 0.003201 | 9378 | 0.54 | 55 |
| dae | anytls-go/udp | 0.000176 | - | - | 1761(73.4%) | 0.69 | - |

## loaded latency stability (200 samples, 250ms cadence)
| engine | protocol | load(Mbps) | p50(ms) | p95(ms) | p99(ms) | max(ms) | failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dae | direct | 9407 | 3.594 | 4.359 | 4.857 | 1007.212 | 0/200 |
| dae | hy2 | 2898 | 2.227 | 2.834 | 3.250 | 4.332 | 0/200 |
| dae | tuic | 3366 | 76.594 | 76.937 | 77.504 | 78.227 | 0/200 |
| dae | ss2022 | invalid | - | - | - | - | arm-failed |
| dae | trojan | 9390 | 5.339 | 17.980 | 25.575 | 45.703 | 0/200 |
| dae | anytls-sb | 5709 | 1.977 | 2.496 | 2.702 | 3.987 | 0/200 |
| dae | anytls-go | 9380 | 2.429 | 12.387 | 16.434 | 19.094 | 0/200 |
