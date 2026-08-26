#!/bin/bash
set -euo pipefail

BIN=${1:?binary path required}
OUT=${2:?output directory required}
TARGET=${TARGET:-10.10.10.70}
NETNS=${NETNS:-lab}
DURATION=${DURATION:-8}
RUNS=${RUNS:-5}
mkdir -p "$OUT"
printf 'run\talgorithm\tdirection\tmbps\tengine_cores\tretransmits\tstatus\n' >"$OUT/results.tsv"

stop_honk() {
    local pids="" link exe pid
    for link in /proc/[0-9]*/exe; do
        exe=$(readlink "$link" 2>/dev/null) || continue
        case "$exe" in
            /root/honk*)
                pid=${link#/proc/}
                pids="$pids ${pid%/exe}"
                ;;
        esac
    done
    [ -z "${pids// /}" ] || kill $pids 2>/dev/null || true
    for _ in $(seq 1 30); do
        local alive=0
        for pid in $pids; do [ -e "/proc/$pid" ] && alive=1; done
        [ "$alive" -eq 0 ] && break
        sleep 1
    done
    for pid in $pids; do [ -e "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null || true; done
    ip link del dae0 2>/dev/null || true
    ip netns del daens 2>/dev/null || true
}

start_honk() {
    local algorithm=$1 config launcher
    config="/root/honk-lab-tuic-$algorithm.dae"
    stop_honk
    setsid "$BIN" --config "$config" >"$OUT/run-$run-$algorithm.honk.log" 2>&1 </dev/null &
    launcher=$!
    for _ in $(seq 1 30); do
        curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
        [ -e "/proc/$launcher" ] || break
        sleep 1
    done
    pid=$(ss -tlnp | awk '/:9090 / { if (match($0, /pid=([0-9]+)/, a)) { print a[1]; exit } }')
    [ -n "$pid" ]
}

measure() {
    local algorithm=$1 direction=$2 json=$3 args=() status=0 ticks0 ticks1 ns0 ns1
    [ "$direction" = reverse ] && args=(-R)
    ticks0=$(awk '{print $14+$15}' "/proc/$pid/stat")
    ns0=$(date +%s%N)
    ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5202 -t "$DURATION" "${args[@]}" -J >"$json" 2>"$json.err" || status=$?
    ns1=$(date +%s%N)
    ticks1=$(awk '{print $14+$15}' "/proc/$pid/stat")
    python3 - "$run" "$algorithm" "$direction" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status" >>"$OUT/results.tsv" <<'PY'
import json, pathlib, sys
run, algorithm, direction, path, ticks0, ticks1, ns0, ns1, status = sys.argv[1:]
try:
    data = json.loads(pathlib.Path(path).read_text())
    mbps = data["end"]["sum_received"]["bits_per_second"] / 1_000_000
    retransmits = data["end"].get("sum_sent", {}).get("retransmits", -1)
except Exception:
    mbps, retransmits = 0.0, -1
elapsed = (int(ns1) - int(ns0)) / 1e9
cores = (int(ticks1) - int(ticks0)) / 100 / elapsed if elapsed > 0 else 0
print(f"{run}\t{algorithm}\t{direction}\t{mbps:.3f}\t{cores:.4f}\t{retransmits}\t{status}")
PY
}

trap stop_honk EXIT
{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    sha256sum "$BIN" /root/honk-lab-tuic-*.dae
    printf 'target=%s netns=%s duration=%s runs=%s\n' "$TARGET" "$NETNS" "$DURATION" "$RUNS"
} >"$OUT/metadata.txt"

for run in $(seq 1 "$RUNS"); do
    case $((run % 3)) in
        1) algorithms="cubic bbr new-reno" ;;
        2) algorithms="bbr new-reno cubic" ;;
        0) algorithms="new-reno cubic bbr" ;;
    esac
    if [ $((run % 2)) -eq 1 ]; then directions="reverse forward"; else directions="forward reverse"; fi
    for algorithm in $algorithms; do
        start_honk "$algorithm"
        ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5202 -t 1 -R >/dev/null
        for direction in $directions; do
            measure "$algorithm" "$direction" "$OUT/run-$run-$algorithm-$direction.json"
            sleep 1
        done
    done
done

cat "$OUT/results.tsv"
