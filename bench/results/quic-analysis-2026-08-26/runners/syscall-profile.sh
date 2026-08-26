#!/bin/bash
set -euo pipefail

BIN=${1:?binary path required}
CONFIG=${2:?config path required}
OUT=${3:?output directory required}
TARGET=${TARGET:-10.10.10.70}
NETNS=${NETNS:-lab}
DURATION=${DURATION:-12}
mkdir -p "$OUT"

stop_honk() {
  local pids
  pids=$(pgrep -f "^$BIN --config " 2>/dev/null || true)
  [ -z "$pids" ] || kill $pids 2>/dev/null || true
  for _ in $(seq 1 30); do
    [ -z "$(pgrep -f "^$BIN --config " 2>/dev/null || true)" ] && break
    sleep 1
  done
  pids=$(pgrep -f "^$BIN --config " 2>/dev/null || true)
  [ -z "$pids" ] || kill -KILL $pids 2>/dev/null || true
  ip link del dae0 2>/dev/null || true
  ip netns del daens 2>/dev/null || true
  rm -f /run/honk-core.lock
}
trap stop_honk EXIT

start_honk() {
  local log=$1
  stop_honk
  env HONK_QUIC_MAX_GSO_SEGMENTS=16 setsid "$BIN" --config "$CONFIG" >"$log" 2>&1 </dev/null &
  for _ in $(seq 1 30); do
    curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null
  pgrep -f "^$BIN --config " | tail -1
}

profile() {
  local proto=$1 port=$2 pid tracer
  pid=$(start_honk "$OUT/$proto.engine.log")
  ip netns exec "$NETNS" iperf3 -c "$TARGET" -p "$port" -t 2 -R -J >/dev/null
  cp "/proc/$pid/status" "$OUT/$proto.status.before"
  cp "/proc/$pid/io" "$OUT/$proto.io.before"
  strace -qq -f -c -e trace=read,write,sendmsg,recvmsg,sendmmsg,recvmmsg,epoll_wait,futex -p "$pid" -o "$OUT/$proto.strace" &
  tracer=$!
  sleep 1
  ip netns exec "$NETNS" iperf3 -c "$TARGET" -p "$port" -t "$DURATION" -R -J >"$OUT/$proto.iperf.json"
  kill -INT "$tracer" 2>/dev/null || true
  wait "$tracer" 2>/dev/null || true
  cp "/proc/$pid/status" "$OUT/$proto.status.after"
  cp "/proc/$pid/io" "$OUT/$proto.io.after"
}

profile hy2 5201
profile tuic 5202
