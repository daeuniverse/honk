1:#!/bin/bash
2:set -euo pipefail
3:/etc/init.d/honk stop
4:sleep 10
5:/root/setup-arm-lab.sh >/dev/null 2>&1 || true
6:nft insert rule inet fw4 forward iifname "veth-lab" accept comment "honk-bench-lab"
7:forward_handle=$(nft -a list chain inet fw4 forward | awk '/honk-bench-lab/ { for (i = 1; i <= NF; i++) if ($i == "handle") print $(i + 1) }')
8:ip netns exec lab sleep 86400 >/dev/null 2>&1 &
9:holder=$!
10:restore_host() {
11:    nft delete rule inet fw4 forward handle "$forward_handle" 2>/dev/null || true
12:    kill "$holder" 2>/dev/null || true
13:    wait "$holder" 2>/dev/null || true
14:    /etc/init.d/honk start
15:}
16:trap restore_host EXIT
17:rm -rf /root/quic-gso-ab-20260826-arm
18:LAB_HOLDER_PID=$holder RUNS=5 DURATION=8 bash /root/quic-gso-ab.sh \
19:    /root/honk-quic-profile2-429c540-musl \
20:    /root/honk-lab.dae \
21:    /root/quic-gso-ab-20260826-arm