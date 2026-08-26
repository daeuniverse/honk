#!/bin/bash
set -euo pipefail

BIN=${1:?binary path required}
CONFIG=${2:-/root/honk-lab.dae}
OUT=${3:-/root/quic-bottleneck-$(date -u +%Y%m%dT%H%M%SZ)}
TARGET=${TARGET:-10.10.10.70}
NETNS=${NETNS:-lab}
DURATION=${DURATION:-8}
OBSERVE_SECONDS=$((DURATION + 3))
mkdir -p "$OUT"

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
    stop_honk
    env HONK_QUIC_TELEMETRY=1 setsid "$BIN" --config "$CONFIG" >"$OUT/honk.log" 2>&1 </dev/null &
    launcher=$!
    for _ in $(seq 1 30); do
        curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
        [ -e "/proc/$launcher" ] || break
        sleep 1
    done
    pid=$(ss -tlnp | awk '/:9090 / { if (match($0, /pid=([0-9]+)/, a)) { print a[1]; exit } }')
    [ -n "$pid" ] || {
        echo "honk failed to expose Clash API" >&2
        return 1
    }
    readlink "/proc/$pid/exe" >"$OUT/engine-exe.txt"
    sha256sum "/proc/$pid/exe" >"$OUT/engine-running.sha256"
    printf '%s\n' "$pid" >"$OUT/engine.pid"
}

proc_ticks() {
    awk '{print $14+$15}' "/proc/$pid/stat"
}

thread_snapshot() {
    local label=$1 stat tid comm
    : >"$OUT/$label.threads.tsv"
    for stat in /proc/"$pid"/task/*/stat; do
        tid=${stat%/stat}
        tid=${tid##*/}
        comm=$(cat "/proc/$pid/task/$tid/comm")
        awk -v tid="$tid" -v comm="$comm" '{print tid "\t" comm "\t" $14 "\t" $15 "\t" $39}' "$stat" >>"$OUT/$label.threads.tsv"
    done
}

capture_state() {
    local label=$1
    cat "/proc/$pid/status" >"$OUT/$label.status"
    cat "/proc/$pid/smaps_rollup" >"$OUT/$label.smaps_rollup"
    cat /proc/net/snmp >"$OUT/$label.snmp"
    cat /proc/net/softnet_stat >"$OUT/$label.softnet_stat"
    cat /proc/softirqs >"$OUT/$label.softirqs"
    cat /proc/interrupts >"$OUT/$label.interrupts"
    cat /proc/net/dev >"$OUT/$label.netdev"
    ip -s link show ens3 >"$OUT/$label.ens3"
    ip -s link show veth-lab >"$OUT/$label.veth-lab"
    ss -u -a -n -m -p >"$OUT/$label.udp-sockets"
    curl -fsS --max-time 2 http://127.0.0.1:9090/stats >"$OUT/$label.honk-stats.json" || true
    thread_snapshot "$label"
}

iperf_run() {
    local port=$1 direction=$2 output=$3
    local args=()
    [ "$direction" = reverse ] && args=(-R)
    ip netns exec "$NETNS" iperf3 -c "$TARGET" -p "$port" -t "$DURATION" "${args[@]}" -J >"$output" 2>"$output.err"
}

record_result() {
    local proto=$1 direction=$2 arm=$3 json=$4 ticks0=$5 ticks1=$6 ns0=$7 ns1=$8 status=$9
    python3 - "$proto" "$direction" "$arm" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status" >>"$OUT/results.tsv" <<'PY'
import json, pathlib, sys
proto, direction, arm, path, ticks0, ticks1, ns0, ns1, status = sys.argv[1:]
try:
    data = json.loads(pathlib.Path(path).read_text())
    end = data["end"]
    mbps = end["sum_received"]["bits_per_second"] / 1_000_000
    retransmits = end.get("sum_sent", {}).get("retransmits", -1)
except Exception:
    mbps, retransmits = 0.0, -1
elapsed = (int(ns1) - int(ns0)) / 1e9
cores = (int(ticks1) - int(ticks0)) / 100 / elapsed if elapsed > 0 else 0
print(f"{proto}\t{direction}\t{arm}\t{mbps:.3f}\t{cores:.4f}\t{retransmits}\t{status}")
PY
}

baseline_arm() {
    local proto=$1 port=$2 direction=$3 run json ticks0 ticks1 ns0 ns1 status
    for run in 1 2 3; do
        json="$OUT/$proto-$direction-baseline-$run.json"
        ticks0=$(proc_ticks)
        ns0=$(date +%s%N)
        status=0
        iperf_run "$port" "$direction" "$json" || status=$?
        ns1=$(date +%s%N)
        ticks1=$(proc_ticks)
        record_result "$proto" "$direction" "baseline-$run" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status"
        sleep 1
    done
}

observed_arm() {
    local proto=$1 port=$2 direction=$3 observer=$4 slug json ticks0 ticks1 ns0 ns1 status observer_status=0 observer_pid socket_pid
    slug="$proto-$direction-$observer"
    json="$OUT/$slug.json"
    case "$observer" in
        stat)
            perf stat -x, -o "$OUT/$slug.perf-stat" -e task-clock,context-switches,cpu-migrations,page-faults -p "$pid" -- sleep "$OBSERVE_SECONDS" &
            ;;
        user)
            perf record -q -e cpu-clock:u -F 499 -g --call-graph dwarf,8192 -p "$pid" -o "$OUT/$slug.perf.data" -- sleep "$OBSERVE_SECONDS" &
            ;;
        kernel)
            perf record -q -e cpu-clock:k -F 499 -g --call-graph fp -p "$pid" -o "$OUT/$slug.perf.data" -- sleep "$OBSERVE_SECONDS" &
            ;;
        strace)
            timeout -s INT "$OBSERVE_SECONDS" strace -f -qq -c -e trace=sendmsg,sendmmsg,recvmsg,recvmmsg,epoll_wait,epoll_pwait,epoll_pwait2,epoll_ctl -p "$pid" -o "$OUT/$slug.strace" &
            ;;
        *) return 2 ;;
    esac
    observer_pid=$!
    sleep 1
    (sleep 2; ss -u -a -n -m -p >"$OUT/$slug.udp-sockets") &
    socket_pid=$!
    ticks0=$(proc_ticks)
    ns0=$(date +%s%N)
    status=0
    iperf_run "$port" "$direction" "$json" || status=$?
    ns1=$(date +%s%N)
    ticks1=$(proc_ticks)
    wait "$socket_pid" || true
    wait "$observer_pid" || observer_status=$?
    printf '%s\n' "$observer_status" >"$OUT/$slug.observer-status"
    record_result "$proto" "$direction" "$observer" "$json" "$ticks0" "$ticks1" "$ns0" "$ns1" "$status"
    cp /root/honk.log "$OUT/$slug.honk.log"
    if [ "$observer" = user ]; then
        perf report --stdio --no-children --percent-limit 0.2 --sort comm,dso,symbol -i "$OUT/$slug.perf.data" >"$OUT/$slug.perf-self.txt"
        perf report --stdio --children --percent-limit 0.5 --sort comm,dso,symbol -i "$OUT/$slug.perf.data" >"$OUT/$slug.perf-children.txt"
        perf buildid-list -i "$OUT/$slug.perf.data" >"$OUT/$slug.buildids"
    elif [ "$observer" = kernel ]; then
        perf report --stdio --no-children --percent-limit 0.2 --sort comm,dso,symbol -i "$OUT/$slug.perf.data" >"$OUT/$slug.perf-self.txt"
        perf report --stdio --children --percent-limit 0.5 --sort comm,dso,symbol -i "$OUT/$slug.perf.data" >"$OUT/$slug.perf-children.txt"
    fi
    sleep 1
}

cleanup() {
    stop_honk
}
trap cleanup EXIT

{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    perf --version
    strace -V | sed -n '1p'
    sha256sum "$BIN" "$CONFIG" /root/lab-bench.sh /root/latency_stability.py
    printf 'target=%s netns=%s duration=%s\n' "$TARGET" "$NETNS" "$DURATION"
    printf 'hardware_pmu='; perf stat -e cycles -- true >/dev/null 2>&1 && echo available || echo unavailable
} >"$OUT/metadata.txt"
printf 'protocol\tdirection\tarm\tmbps\tengine_cores\tretransmits\tstatus\n' >"$OUT/results.tsv"

start_honk
capture_state start

iperf_run 5300 reverse "$OUT/direct-reverse.json"
iperf_run 5300 forward "$OUT/direct-forward.json"

for spec in hy2:5201 tuic:5202; do
    proto=${spec%%:*}
    port=${spec##*:}
    for direction in reverse forward; do
        iperf_run "$port" "$direction" "$OUT/$proto-$direction-warm.json"
        baseline_arm "$proto" "$port" "$direction"
        observed_arm "$proto" "$port" "$direction" stat
        observed_arm "$proto" "$port" "$direction" user
        observed_arm "$proto" "$port" "$direction" strace
    done
    observed_arm "$proto" "$port" reverse kernel
done

capture_state end
printf '%s\n' "$OUT"
