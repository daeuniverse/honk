1:#!/bin/bash
2:set -euo pipefail
3:
4:BIN=${1:?binary path required}
5:CONFIG=${2:?config path required}
6:OUT=${3:?output directory required}
7:TARGET=${TARGET:-10.10.10.70}
8:NETNS=${NETNS:-lab}
9:DURATION=${DURATION:-8}
10:RUNS=${RUNS:-5}
11:mkdir -p "$OUT"
12:printf 'run\tmode\tprotocol\tmbps\tengine_cores\tretransmits\tstatus\n' >"$OUT/results.tsv"
13:
14:stop_honk() {
15:    local pids="" link exe pid
16:    for link in /proc/[0-9]*/exe; do
17:        exe=$(readlink "$link" 2>/dev/null) || continue
18:        case "$exe" in
19:            /root/honk*)
20:                pid=${link#/proc/}
21:                pids="$pids ${pid%/exe}"
22:                ;;
23:        esac
24:    done
25:    if [ -n "${pids// /}" ]; then
26:        kill $pids 2>/dev/null || true
27:        for _ in $(seq 1 30); do
28:            local alive=0
29:            for pid in $pids; do
30:                [ -e "/proc/$pid" ] && alive=1
31:            done
32:            [ "$alive" -eq 0 ] && break
33:            sleep 1
34:        done
35:        for pid in $pids; do
36:            [ -e "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null || true
37:        done
38:    fi
39:    ip link del dae0 2>/dev/null || true
40:    ip netns del daens 2>/dev/null || true
41:}
42:
43:start_honk() {
44:    local mode=$1 launcher
45:    stop_honk
46:    case "$mode" in
47:        off) env HONK_QUIC_GSO=0 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
48:        cap4) env HONK_QUIC_GSO=1 HONK_QUIC_GSO_SEGMENTS=4 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
49:        cap16) env HONK_QUIC_GSO=1 HONK_QUIC_GSO_SEGMENTS=16 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
50:        *) return 2 ;;
51:    esac
52:    launcher=$!
53:    for _ in $(seq 1 30); do
54:        curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
55:        [ -e "/proc/$launcher" ] || break
56:        sleep 1
57:    done
58:    pid=$(ss -tlnp | awk '/:9090 / { if (match($0, /pid=([0-9]+)/, a)) { print a[1]; exit } }')
59:    [ -n "$pid" ]
60:}
61:
62:measure() {
63:    local run=$1 mode=$2 protocol=$3 port=$4 json=$5 status=0 ticks0 ticks1 ns0 ns1
64:    ticks0=$(awk '{print $14+$15}' "/proc/$pid/stat")
65:    ns0=$(date +%s%N)
66:    ip netns exec "$NETNS" iperf3 -c "$TARGET" -p "$port" -t "$DURATION" -R -J >"$json" 2>"$json.err" || status=$?
67:    ns1=$(date +%s%N)
68:    ticks1=$(awk '{print $14+$15}' "/proc/$pid/stat")
69:    python3 - "$run" "$mode" "$protocol" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status" >>"$OUT/results.tsv" <<'PY'
70:import json, pathlib, sys
71:run, mode, protocol, path, ticks0, ticks1, ns0, ns1, status = sys.argv[1:]
72:try:
73:    data = json.loads(pathlib.Path(path).read_text())
74:    mbps = data["end"]["sum_received"]["bits_per_second"] / 1_000_000
75:    retransmits = data["end"].get("sum_sent", {}).get("retransmits", -1)
76:except Exception:
77:    mbps, retransmits = 0.0, -1
78:elapsed = (int(ns1) - int(ns0)) / 1e9
79:cores = (int(ticks1) - int(ticks0)) / 100 / elapsed if elapsed > 0 else 0
80:print(f"{run}\t{mode}\t{protocol}\t{mbps:.3f}\t{cores:.4f}\t{retransmits}\t{status}")
81:PY
82:}
83:
84:cleanup() {
85:    stop_honk
86:}
87:trap cleanup EXIT
88:
89:{
90:    date -u +%Y-%m-%dT%H:%M:%SZ
91:    uname -a
92:    sha256sum "$BIN" "$CONFIG"
93:    printf 'target=%s netns=%s duration=%s runs=%s\n' "$TARGET" "$NETNS" "$DURATION" "$RUNS"
94:} >"$OUT/metadata.txt"
95:
96:for run in $(seq 1 "$RUNS"); do
97:    case $((run % 3)) in
98:        1) modes="off cap4 cap16" ;;
99:        2) modes="cap4 cap16 off" ;;
100:        0) modes="cap16 off cap4" ;;
101:    esac
102:    for mode in $modes; do
103:        start_honk "$mode"
104:        ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5201 -t 1 -R >/dev/null
105:        ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5202 -t 1 -R >/dev/null
106:        measure "$run" "$mode" hy2 5201 "$OUT/run-$run-$mode-hy2.json"
107:        sleep 1
108:        measure "$run" "$mode" tuic 5202 "$OUT/run-$run-$mode-tuic.json"
109:        sleep 1
110:    done
111:done
112:
113:cat "$OUT/results.tsv"