#!/bin/bash
set -u

BIN=${1:?binary path required}
CONFIG_1452=${2:?1452 config required}
CONFIG_1252=${3:?1252 config required}
OUT=${4:?output directory required}
mkdir -p "$OUT"

{
    date -u +%Y-%m-%dT%H:%M:%SZ
    uname -a
    sha256sum "$BIN" "$CONFIG_1452" "$CONFIG_1252" /root/lab-bench.sh /root/latency_stability.py
} >"$OUT/metadata.txt"
printf 'arm\tstatus\n' >"$OUT/status.tsv"

run_arm() {
    local arm=$1 config=$2 gso=$3 segments=$4 dir status=0
    dir="$OUT/$arm"
    mkdir -p "$dir"
    (
        unset HONK_QUIC_GSO HONK_QUIC_GSO_SEGMENTS HONK_QUIC_TELEMETRY
        if [ -n "$gso" ]; then
            export HONK_QUIC_GSO=$gso
        fi
        if [ -n "$segments" ]; then
            export HONK_QUIC_GSO_SEGMENTS=$segments
        fi
        export RUN_ID="quic-gso-$arm"
        export TSV="$dir/standard.tsv"
        export STABILITY_TSV="$dir/stability.tsv"
        export STABILITY_DIR="$dir/stability"
        export LATENCY_STABILITY=0
        export HONK_BIN="$BIN"
        export HONK_CONFIG="$config"
        bash /root/lab-bench.sh "honk" "hy2 tuic"
    ) >"$dir/stdout.txt" 2>"$dir/stderr.txt" || status=$?
    cp /root/honk.log "$dir/honk.log" 2>/dev/null || true
    printf '%s\t%s\n' "$arm" "$status" >>"$OUT/status.tsv"
}

run_arm mtu1252 "$CONFIG_1252" "" ""
run_arm gso-off "$CONFIG_1452" 0 ""
run_arm gso-cap4 "$CONFIG_1452" 1 4
run_arm gso-cap8 "$CONFIG_1452" 1 8
run_arm gso-cap16 "$CONFIG_1452" 1 16
run_arm gso-cap32 "$CONFIG_1452" 1 32

printf '%s\n' "$OUT"
