#!/bin/bash
set -euo pipefail

BIN=${1:?binary path required}
CONFIG=${2:?config path required}
OUT=${3:?output directory required}
TARGET=${TARGET:-10.10.10.70}
NETNS=${NETNS:-lab}
DURATION=${DURATION:-8}
RUNS=${RUNS:-5}
mkdir -p "$OUT"
printf 'run\tmode\tprotocol\tmbps\tengine_cores\tretransmits\tstatus\n' >"$OUT/results.tsv"

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
    if [ -n "${pids// /}" ]; then
        kill $pids 2>/dev/null || true
        for _ in $(seq 1 30); do
            local alive=0
            for pid in $pids; do
                [ -e "/proc/$pid" ] && alive=1
            done
            [ "$alive" -eq 0 ] && break
            sleep 1
        done
        for pid in $pids; do
            [ -e "/proc/$pid" ] && kill -KILL "$pid" 2>/dev/null || true
        done
    fi
    ip link del dae0 2>/dev/null || true
    ip netns del daens 2>/dev/null || true
}

start_honk() {
    local mode=$1 launcher
    stop_honk
    case "$mode" in
        off) env HONK_QUIC_GSO=0 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
        cap4) env HONK_QUIC_GSO=1 HONK_QUIC_GSO_SEGMENTS=4 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
        cap16) env HONK_QUIC_GSO=1 HONK_QUIC_GSO_SEGMENTS=16 setsid "$BIN" --config "$CONFIG" >/root/honk.log 2>&1 </dev/null & ;;
        *) return 2 ;;
    esac
    launcher=$!
    for _ in $(seq 1 30); do
        curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
        [ -e "/proc/$launcher" ] || break
        sleep 1
    done
    pid=$launcher
    [ -r "/proc/$pid/stat" ]
}
repair_lab_namespace() {
    [ -n "${LAB_HOLDER_PID:-}" ] || return 0
    [ -e "/var/run/netns/$NETNS" ] || ip netns attach "$NETNS" "$LAB_HOLDER_PID"
}


measure() {
    local run=$1 mode=$2 protocol=$3 port=$4 json=$5 status=0 ticks0 ticks1 ns0 ns1
    ticks0=$(awk '{print $14+$15}' "/proc/$pid/stat")
    ns0=$(python3 -c 'import time; print(time.monotonic_ns())')
    ip netns exec "$NETNS" iperf3 -c "$TARGET" -p "$port" -t "$DURATION" -R -J >"$json" 2>"$json.err" || status=$?
    ns1=$(python3 -c 'import time; print(time.monotonic_ns())')
    ticks1=$(awk '{print $14+$15}' "/proc/$pid/stat")
    python3 - "$run" "$mode" "$protocol" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status" >>"$OUT/results.tsv" <<'PY'
import json, pathlib, sys
run, mode, protocol, path, ticks0, ticks1, ns0, ns1, status = sys.argv[1:]
try:
    data = json.loads(pathlib.Path(path).read_text())
    mbps = data["end"]["sum_received"]["bits_per_second"] / 1_000_000
    retransmits = data["end"].get("sum_sent", {}).get("retransmits", -1)
except Exception:
    mbps, retransmits = 0.0, -1
elapsed = (int(ns1) - int(ns0)) / 1e9
cores = (int(ticks1) - int(ticks0)) / 100 / elapsed if elapsed > 0 else 0
print(f"{run}\t{mode}\t{protocol}\t{mbps:.3f}\t{cores:.4f}\t{retransmits}\t{status}")
PY
}

cleanup() {
    stop_honk
}
trap cleanup EXIT

{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    sha256sum "$BIN" "$CONFIG"
    printf 'target=%s netns=%s duration=%s runs=%s\n' "$TARGET" "$NETNS" "$DURATION" "$RUNS"
} >"$OUT/metadata.txt"

for run in $(seq 1 "$RUNS"); do
    case $((run % 3)) in
        1) modes="off cap4 cap16" ;;
        2) modes="cap4 cap16 off" ;;
        0) modes="cap16 off cap4" ;;
    esac
    for mode in $modes; do
        start_honk "$mode"
        repair_lab_namespace
        ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5201 -t 1 -R >/dev/null
        ip netns exec "$NETNS" iperf3 -c "$TARGET" -p 5202 -t 1 -R >/dev/null
        measure "$run" "$mode" hy2 5201 "$OUT/run-$run-$mode-hy2.json"
        sleep 1
        measure "$run" "$mode" tuic 5202 "$OUT/run-$run-$mode-tuic.json"
        sleep 1
    done
done

cat "$OUT/results.tsv"
