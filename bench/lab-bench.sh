#!/bin/bash
# lab-bench.sh — honk vs dae vs sing-box A/B protocol benchmark on the lab.
#
# Runs ON an engine host (10.10.10.49 x86-64 or 10.10.10.118 ARM64).
# Client traffic originates in netns "lab", so every measurement crosses the real datapath (eBPF/TPROXY for honk/dae;
# a TUN client inside the netns for sing-box). One script replaces the old
# bench.sh / bench-cold.sh / bench-cpu.sh / bench-honest.sh set.
#
# Per engine × protocol:
#   cold   — first-request latency on a freshly restarted engine, 3 runs
#   hot    — open-stream latency over 15 requests, p50/p95
#   bw     — iperf3 -R (download) 3 runs, median receiver bitrate
#   cpu    — engine CPU cores during the median bandwidth run
#   rss    — engine RSS after the bandwidth runs
#   stability — 200 paced opens while one same-route reverse stream is loaded
# Plus a direct-path baseline per engine (no proxy involved).
#
# dae has no AnyTLS support on mainline; the lab's kdae build does (the
# harness no longer skips anytls-* for dae).
#
# Usage: lab-bench.sh [engines] [protocols]
#   engines:   space list within one arg, default "honk dae"
#   protocols: space list within one arg; default six comparison routes,
#              also accepts vless-vision/vless-reality/vmess (ports 7-9)
# Output: markdown table on stdout; raw TSV appended to /root/bench-results.tsv
set -u

T=${T:-10.10.10.70}
N=${N:-lab}
HOT_N=${HOT_N:-15}
BW_RUNS=${BW_RUNS:-3}
BW_TIME=${BW_TIME:-8}
COLD_RUNS=${COLD_RUNS:-3}
TSV=${TSV:-/root/bench-results.tsv}

ENGINES=${1:-"honk dae"}
PROTOS=${2:-"hy2 tuic ss2022 trojan anytls-sb anytls-go"}

HONK_BIN=${HONK_BIN:-/root/honk}
HONK_CONFIG=${HONK_CONFIG:-/root/honk-lab.dae}
DAE_BIN=${DAE_BIN:-/root/dae}
DAE_CONFIG=${DAE_CONFIG:-/root/dae-lab.dae}

LATENCY_STABILITY=${LATENCY_STABILITY:-1}
STABILITY_SAMPLES=${STABILITY_SAMPLES:-200}
STABILITY_INTERVAL_MS=${STABILITY_INTERVAL_MS:-250}
STABILITY_TIMEOUT=${STABILITY_TIMEOUT:-5}
STABILITY_RETRIES=${STABILITY_RETRIES:-2}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STABILITY_COLLECTOR=${STABILITY_COLLECTOR:-$SCRIPT_DIR/latency_stability.py}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
STABILITY_DIR=${STABILITY_DIR:-/root/bench-stability-$RUN_ID}
STABILITY_TSV=${STABILITY_TSV:-/root/bench-stability-results.tsv}
LAB_HOLDER_PID=${LAB_HOLDER_PID:-}
LAB_HOLDER_OWNED=0

start_lab_holder() {
    [ -n "$LAB_HOLDER_PID" ] && return 0
    [ -e "/var/run/netns/$N" ] || {
        echo "client namespace is missing: $N" >&2
        return 1
    }
    ip netns exec "$N" sleep 86400 >/dev/null 2>&1 &
    LAB_HOLDER_PID=$!
    LAB_HOLDER_OWNED=1
}

stop_lab_holder() {
    [ "$LAB_HOLDER_OWNED" -eq 1 ] || return 0
    kill "$LAB_HOLDER_PID" 2>/dev/null || true
    wait "$LAB_HOLDER_PID" 2>/dev/null || true
    LAB_HOLDER_PID=
}

trap stop_lab_holder EXIT
STABILITY_ROWS=$(mktemp "${TMPDIR:-/tmp}/honk-stability-rows.XXXXXX")
mkdir -p "$STABILITY_DIR"

# protocol → index (ports: 800<idx> http, 520<idx> iperf3)
proto_idx() {
    case $1 in
    hy2) echo 1 ;;
    tuic) echo 2 ;;
    ss2022) echo 3 ;;
    trojan) echo 4 ;;
    anytls-sb) echo 5 ;;
    anytls-go) echo 6 ;;
    vless-vision) echo "${VLESS_VISION_INDEX:-7}" ;;
    vless-reality) echo "${VLESS_REALITY_INDEX:-8}" ;;
    vmess) echo "${VMESS_INDEX:-9}" ;;
    *) echo 0 ;;
    esac
}

supports_udp() { # engine protocol
    case "$1:$2" in
    honk:vless-vision|honk:vless-reality|honk:vmess) return 1 ;;
    *) return 0 ;;
    esac
}

cpu_ticks() {
    [ -n "$1" ] || {
        echo 0
        return
    }
    awk '{print $14+$15}' /proc/"$1"/stat 2>/dev/null || echo 0
}

now_ns() {
    python3 -c 'import time; print(time.monotonic_ns())'
}

rss_mb() {
    [ -n "$1" ] || {
        echo 0
        return
    }
    awk '/VmRSS/{print int($2/1024)}' /proc/"$1"/status 2>/dev/null || echo 0
}

process_pids() { # honk|dae|sing-box → executable-matched PIDs
    local kind=$1 target link exe pid
    case "$kind" in
    honk) target=$(readlink -f -- "$HONK_BIN" 2>/dev/null || printf '%s' "$HONK_BIN") ;;
    dae) target=$(readlink -f -- "$DAE_BIN" 2>/dev/null || printf '%s' "$DAE_BIN") ;;
    sing-box) target=$(readlink -f -- /root/sing-box 2>/dev/null || printf '%s' /root/sing-box) ;;
    *) return 1 ;;
    esac
    for link in /proc/[0-9]*/exe; do
        exe=$(readlink "$link" 2>/dev/null) || continue
        exe=${exe% (deleted)}
        case "$kind" in
        honk) [[ "$exe" == "$target" || "$exe" == /root/honk* ]] || continue ;;
        dae) [[ "$exe" == "$target" || "$exe" == /root/dae || "$exe" == /root/dae-* ]] || continue ;;
        sing-box) [ "$exe" = "$target" ] || continue ;;
        esac
        pid=${link#/proc/}
        printf '%s\n' "${pid%/exe}"
    done
}

stop_engines() {
    local kind pids remaining sb_running
    sb_running=$(process_pids sing-box)
    for kind in honk dae sing-box; do
        pids=$(process_pids "$kind")
        [ -z "$pids" ] || kill $pids 2>/dev/null
    done
    # honk may drain before releasing its singleton lock. Match executable
    # paths rather than command lines: the benchmark shell itself carries
    # HONK_BIN=/root/honk-* in its environment and must never be killed.
    for _ in $(seq 1 30); do
        remaining="$(process_pids honk) $(process_pids dae) $(process_pids sing-box)"
        [ -z "${remaining// /}" ] && break
        sleep 1
    done
    remaining="$(process_pids honk) $(process_pids dae) $(process_pids sing-box)"
    [ -z "${remaining// /}" ] || kill -KILL $remaining 2>/dev/null
    if [ -z "$(process_pids honk)" ] && [ -z "$(process_pids dae)" ]; then
        ip link del dae0 2>/dev/null
        ip netns del daens 2>/dev/null
    fi
    # sing-box's TUN auto_route rewrites the lab netns routing table.
    [ -n "$sb_running" ] && bash /root/setup-netns.sh >/dev/null 2>&1
}

repair_lab_namespace() {
    [ -n "$LAB_HOLDER_PID" ] || return 0
    [ -e "/var/run/netns/$N" ] || ip netns attach "$N" "$LAB_HOLDER_PID" 2>/dev/null || true
}

start_engine() { # engine → prints pid
    stop_engines
    case $1 in
    honk)
        setsid "$HONK_BIN" --config "$HONK_CONFIG" >/root/honk.log 2>&1 </dev/null &
        for _ in $(seq 1 20); do
            curl -s -m 2 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
            sleep 1
        done
        # pgrep can match a second instance parked on the singleton flock
        repair_lab_namespace

        # Anchor on the Clash API listener; a parked second instance has no listener.
        local api_pid
        if command -v ss >/dev/null 2>&1; then
            api_pid=$(ss -tlnp | grep ':9090 ' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
        else
            api_pid=$(process_pids honk | head -1)
        fi
        [ -n "$api_pid" ] || {
            echo "honk failed to expose Clash API" >&2
            return 1
        }
        printf '%s\n' "$api_pid"
        ;;
    dae)
        chmod 600 "$DAE_CONFIG"
        setsid "$DAE_BIN" run -c "$DAE_CONFIG" >/root/dae.log 2>&1 </dev/null &
        for _ in $(seq 1 30); do
            ip link show dae0 >/dev/null 2>&1 && ip netns list | grep -q '^daens' && break
            [ -n "$(process_pids dae)" ] || break
            sleep 1
        done
        sleep 2
        repair_lab_namespace
        local dae_pid
        dae_pid=$(process_pids dae | head -1)
        [ -n "$dae_pid" ] || {
            echo "dae failed to start; see /root/dae.log" >&2
            return 1
        }
        printf '%s\n' "$dae_pid"
        ;;
    sing-box)
        # sing-box runs INSIDE the lab netns as a TUN client (not a
        # gateway): client traffic hits the TUN, per-port route rules pick
        # the outbound, outbounds dial out via veth-client.
        ip netns exec $N setsid /root/sing-box run -c /root/sb-client.json \
            >/root/sb.log 2>&1 </dev/null &
        sleep 4
        process_pids sing-box | head -1
        ;;
    esac
}

ncurl() { # port → time_total (seconds, empty on failure)
    local elapsed
    if elapsed=$(ip netns exec "$N" curl --fail --silent --output /dev/null \
        --write-out "%{time_total}" --max-time 20 "http://$T:$1/" 2>/dev/null); then
        printf '%s\n' "$elapsed"
    else
        return 1
    fi
}

median() { # numbers on stdin → median
    sort -n | awk '{a[NR]=$1} END{print (NR%2)? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'
}

pct() { # numbers on stdin, $1 = percentile 0..100 → value
    sort -n | awk -v p="$1" '{a[NR]=$1} END{i=int((p/100)*NR+0.999); if(i<1)i=1; if(i>NR)i=NR; print a[i]}'
}

cold_latency() { # engine port → median of COLD_RUNS fresh-engine first requests
    local runs="" sample
    for _ in $(seq 1 "$COLD_RUNS"); do
        start_engine "$1" >/dev/null
        sleep 2
        if ! sample=$(ncurl "$2"); then
            echo "invalid"
            return 1
        fi
        runs="$runs $sample"
    done
    echo "$runs" | tr ' ' '\n' | grep -E '^[0-9.]+$' | median
}

hot_latency() { # port → "p50 p95" over HOT_N requests (first is warmup)
    local vals="" sample p50 p95
    if ! ncurl "$1" >/dev/null; then
        echo "invalid invalid"
        return 1
    fi
    for _ in $(seq 1 "$HOT_N"); do
        if ! sample=$(ncurl "$1"); then
            echo "invalid invalid"
            return 1
        fi
        vals="$vals $sample"
    done
    p50=$(echo "$vals" | tr ' ' '\n' | grep -E '^[0-9.]+$' | pct 50)
    p95=$(echo "$vals" | tr ' ' '\n' | grep -E '^[0-9.]+$' | pct 95)
    echo "$p50 $p95"
}

bandwidth() { # pid iperf_port → "median_mbps cpu_cores"
    local pid=$1 port=$2
    local results="" i bw ticks0 ticks1 ns0 ns1 cores
    for i in $(seq 1 $BW_RUNS); do
        ticks0=$(cpu_ticks "$pid")
        ns0=$(now_ns)
        bw=$(ip netns exec $N iperf3 -c $T -p "$port" -t $BW_TIME -R -J 2>/dev/null |
            python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(int(d["end"]["sum_received"]["bits_per_second"]/1e6))
except Exception: print(0)')
        ns1=$(now_ns)
        ticks1=$(cpu_ticks "$pid")
        cores=$(python3 -c "print(f'{($ticks1-$ticks0)/100/(($ns1-$ns0)/1e9):.2f}')")
        results="$results$bw:$cores\n"
    done
    # median by bandwidth; report that run's cpu alongside
    echo -e "$results" | grep -E '^[0-9]+:' | sort -t: -k1 -n |
        awk -F: '{a[NR]=$1; c[NR]=$2} END{m=int((NR+1)/2); printf "%s %s", a[m], c[m]}'
}

# Tail stability under contention: pace fresh HTTP opens while a reverse
# iperf3 stream saturates the same outbound. Raw samples and the load JSON
# remain separate so a low-pressure or failed load cannot masquerade as a
# stable result.
latency_stability() { # engine proto http_port iperf_port → load p50 p95 p99 max failures/attempts
    local engine=$1 proto=$2 http_port=$3 iperf_port=$4
    local slug=${engine}-${proto}
    local raw=$STABILITY_DIR/${slug}.samples.jsonl
    local summary=$STABILITY_DIR/${slug}.summary.json
    local load=$STABILITY_DIR/${slug}.iperf.json
    local load_err=$STABILITY_DIR/${slug}.iperf.err
    local load_warmup_seconds=1 load_seconds load_pid collector_status=0 load_status=0
    # Keep pressure alive past the final deadline and its full request timeout.
    load_seconds=$(awk -v samples="$STABILITY_SAMPLES" \
        -v interval="$STABILITY_INTERVAL_MS" -v timeout="$STABILITY_TIMEOUT" \
        -v warmup="$load_warmup_seconds" \
        'BEGIN { seconds = warmup + samples * interval / 1000 + timeout + 1; print int(seconds + 0.999999) }')

    ip netns exec "$N" iperf3 -c "$T" -p "$iperf_port" -R -t "$load_seconds" -J \
        >"$load" 2>"$load_err" &
    load_pid=$!
    sleep "$load_warmup_seconds"
    ip netns exec "$N" python3 "$STABILITY_COLLECTOR" \
        --target "$T" --port "$http_port" \
        --samples "$STABILITY_SAMPLES" --interval-ms "$STABILITY_INTERVAL_MS" \
        --timeout "$STABILITY_TIMEOUT" --engine "$engine" --protocol "$proto" \
        --output "$raw" >"$summary" || collector_status=$?
    wait "$load_pid" || load_status=$?

    if [ "$collector_status" -ne 0 ] || [ "$load_status" -ne 0 ] || \
        [ ! -s "$summary" ] || [ ! -s "$load" ]; then
        echo "loaded-latency arm failed: engine=$engine protocol=$proto collector=$collector_status load=$load_status" >&2
        return 1
    fi
    python3 - "$load" "$summary" <<'PY'
import math
import json, sys

with open(sys.argv[1], encoding="utf-8") as source:
    load = json.load(source)["end"]["sum_received"]["bits_per_second"] / 1_000_000
if not math.isfinite(load) or load <= 0:
    raise ValueError(f"invalid loaded-latency pressure: {load} Mbps")
with open(sys.argv[2], encoding="utf-8") as source:
    summary = json.load(source)

def metric(name):
    value = summary.get(name)
    return "-" if value is None else f"{value:.3f}"

print(
    f"{load:.0f}",
    metric("p50_ms"), metric("p95_ms"), metric("p99_ms"), metric("max_ms"),
    f'{summary["failures"]}/{summary["attempts"]}',
)
PY
}

record_stability() { # engine proto http_port iperf_port
    [ "$LATENCY_STABILITY" = 1 ] || return
    local metrics load p50 p95 p99 maximum failures line artifact attempt
    local base="$STABILITY_DIR/${1}-${2}"
    local attempts=$((STABILITY_RETRIES + 1))
    for attempt in $(seq 1 "$attempts"); do
        if metrics=$(latency_stability "$@"); then
            read -r load p50 p95 p99 maximum failures <<<"$metrics"
            line="$1|$2|$load|$p50|$p95|$p99|$maximum|$failures"
            printf '%s\n' "$line" >>"$STABILITY_ROWS"
            printf '%s\n' "$line" >>"$STABILITY_TSV"
            if [ -r "/root/$1.log" ]; then
                cp "/root/$1.log" "${base}.engine.log"
            fi
            return
        fi
        for artifact in samples.jsonl summary.json iperf.json iperf.err; do
            if [ -e "${base}.${artifact}" ]; then
                mv "${base}.${artifact}" "${base}.attempt-${attempt}.${artifact}"
            fi
        done
        echo "retrying loaded-latency arm: engine=$1 protocol=$2 attempt=$attempt/$attempts" >&2
        [ "$attempt" -eq "$attempts" ] || sleep 2
    done
    line="$1|$2|invalid|-|-|-|-|arm-failed"
    printf '%s\n' "$line" >>"$STABILITY_ROWS"
    printf '%s\n' "$line" >>"$STABILITY_TSV"
    if [ -r "/root/$1.log" ]; then
        cp "/root/$1.log" "${base}.engine.log"
    fi
    return 1
}

row() { # engine proto cold p50 p95 mbps cores rss
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$@"
}

stability_row() {
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$@"
}

# Median UDP echo RTT (seconds) through the protocol at 53530+idx. Dedicated
# rprx runs reuse slots 1-3; VLESS/VMess correctly return no sample (no UDP).
udp_echo_rtt() { # idx → p50 seconds
    ip netns exec $N python3 - "$1" <<'PY' 2>/dev/null
import socket, sys, time
port = 53530 + int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
rtts = []
for _ in range(15):
    t = time.time()
    try:
        s.sendto(b"lab-udp-ping", ("10.10.10.70", port))
        s.recvfrom(64)
        rtts.append(time.time() - t)
    except Exception:
        pass
rtts.sort()
print(f"{rtts[len(rtts)//2]:.6f}" if rtts else "")
PY
}

# UDP bandwidth: iperf3 -u at a fixed offered rate, receiver bps + loss%.
# Datagram length is pinned to 1200: QUIC tunnels cap datagrams near that
# (honk hy2/tuic drop oversized ones), and iperf3's path-MTU default
# (~1448) would measure the cap, not the tunnel.
udp_bandwidth() { # pid iperf_port → "mbps(loss%) cores"
    local pid=$1 port=$2
    local ticks0 ticks1 ns0 ns1 res
    ticks0=$(cpu_ticks "$pid")
    ns0=$(now_ns)
    res=$(ip netns exec $N iperf3 -c $T -p "$port" -u -b 10G -l 1200 -t $BW_TIME -R -J 2>/dev/null |
        python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); e=d["end"]
    mbps = int(e["sum_received"]["bits_per_second"]/1e6)
    loss = e["sum"]["lost_percent"]
    print("%d(%.1f%%)" % (mbps, loss))
except Exception: print("0(-)")')
    ns1=$(now_ns)
    ticks1=$(cpu_ticks "$pid")
    echo "$res $(python3 -c "print(f'{($ticks1-$ticks0)/100/(($ns1-$ns0)/1e9):.2f}')")"
}

if [ "$LATENCY_STABILITY" = 1 ] && [ ! -r "$STABILITY_COLLECTOR" ]; then
    echo "latency stability collector not found: $STABILITY_COLLECTOR" >&2
    exit 2
fi
start_lab_holder
echo "# host=$(uname -n) arch=$(uname -m) kernel=$(uname -r)" >&2
echo "# honk_bin=$HONK_BIN sha256=$(sha256sum "$HONK_BIN" 2>/dev/null | awk '{print $1}')" >&2
echo "# dae_bin=$DAE_BIN sha256=$(sha256sum "$DAE_BIN" 2>/dev/null | awk '{print $1}')" >&2
echo "# lab-bench $(date -u +%Y-%m-%dT%H:%M:%SZ) engines=($ENGINES) protos=($PROTOS)" >&2
row engine protocol 'cold(s)' 'hot p50(s)' 'hot p95(s)' 'bw(Mbps)' 'cpu(cores)' 'rss(MB)'
row '---' '---' '---' '---' '---' '---' '---' '---'

for engine in $ENGINES; do
    echo "# engine=$engine" >&2
    # direct baseline (unproxied path through the engine datapath)
    pid=$(start_engine "$engine")
    if ! direct_cold=$(ncurl 8080); then
        direct_cold=invalid
    fi
    read -r direct_bw direct_cpu <<<"$(bandwidth "$pid" 5300)"
    row "$engine" direct "$direct_cold" '-' '-' "$direct_bw" "$direct_cpu" "$(rss_mb "$pid")"
    echo "$engine|direct|$direct_cold|-|-|$direct_bw|$direct_cpu|$(rss_mb "$pid")" >>$TSV
    record_stability "$engine" direct 8080 5300

    for proto in $PROTOS; do
        idx=$(proto_idx "$proto")
        [ "$idx" = 0 ] && continue
        cold=$(cold_latency "$engine" 800"$idx")
        pid=$(start_engine "$engine")
        read -r p50 p95 <<<"$(hot_latency 800"$idx")"
        read -r bw cores <<<"$(bandwidth "$pid" 520"$idx")"
        rss=$(rss_mb "$pid")
        row "$engine" "$proto" "$cold" "$p50" "$p95" "$bw" "$cores" "$rss"
        echo "$engine|$proto|$cold|$p50|$p95|$bw|$cores|$rss" >>$TSV
        record_stability "$engine" "$proto" 800"$idx" 520"$idx"
        # UDP: echo RTT (routed 5353x) + iperf3 -u at 10G offered.
        if supports_udp "$engine" "$proto"; then
            urtt=$(udp_echo_rtt "$idx")
            read -r ubw ucores <<<"$(udp_bandwidth "$pid" 520"$idx")"
            row "$engine" "$proto/udp" "$urtt" '-' '-' "$ubw" "$ucores" '-'
            echo "$engine|$proto/udp|$urtt|-|-|$ubw|$ucores|-" >>$TSV
        else
            row "$engine" "$proto/udp" 'n/a' '-' '-' 'n/a' '-' '-'
            echo "$engine|$proto/udp|n/a|-|-|n/a|-|-" >>$TSV
        fi
    done
done
stop_engines
if [ "$LATENCY_STABILITY" = 1 ]; then
    echo
    echo "## loaded latency stability ($STABILITY_SAMPLES samples, ${STABILITY_INTERVAL_MS}ms cadence)"
    stability_row engine protocol 'load(Mbps)' 'p50(ms)' 'p95(ms)' 'p99(ms)' 'max(ms)' failures
    stability_row '---' '---' '---' '---' '---' '---' '---' '---'
    while IFS='|' read -r engine protocol load p50 p95 p99 maximum failures; do
        stability_row "$engine" "$protocol" "$load" "$p50" "$p95" "$p99" "$maximum" "$failures"
    done <"$STABILITY_ROWS"
fi
rm -f "$STABILITY_ROWS"
