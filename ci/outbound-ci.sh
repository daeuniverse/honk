#!/bin/sh
# outbound-ci — full test gate for honk-outbound after any change.
#
# Runs, in order and with early exit on failure:
#   1. fmt check (honk-outbound and honk-netstack, the WireGuard driver's stack)
#   2. clippy (all targets, warnings denied; honk-netstack once, honk-outbound rprx off and on separately)
#   3. honk-config tests (node/share-link fields change together)
#   4. honk-netstack tests (the WireGuard driver depends on its behaviour)
#   5. honk-outbound test suites (rprx off and on separately)
#
# Optional live-server e2e (skipped by default):
#   HONK_HY2_SERVER=host:port HONK_HY2_PASSWORD=... [HONK_HY2_MPORT=.. HONK_HY2_MHOP=..]
#   HONK_HY2_SOAK_TARGET=host:port HONK_HY2_SOAK_UDP_TARGET=host:port
#     → runs the hysteria2 real-server e2e + hop soak tests.
#
# Usage: ci/outbound-ci.sh [--with-e2e-env]
set -eu

cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

step "cargo fmt --check"
cargo fmt -p honk-outbound -p honk-netstack -- --check

step "cargo clippy -p honk-netstack --all-targets -D warnings"
cargo clippy -p honk-netstack --all-targets -- -D warnings

step "cargo clippy --all-targets --no-default-features -D warnings"
cargo clippy -p honk-outbound --all-targets --no-default-features -- -D warnings

step "cargo clippy --all-targets --no-default-features --features rprx -D warnings"
cargo clippy -p honk-outbound --all-targets --no-default-features --features rprx -- -D warnings

step "cargo test -p honk-config"
cargo test -p honk-config

step "cargo test -p honk-netstack"
cargo test -p honk-netstack

step "cargo test -p honk-outbound --no-default-features"
cargo test -p honk-outbound --no-default-features

step "cargo test -p honk-outbound --no-default-features --features rprx"
cargo test -p honk-outbound --no-default-features --features rprx

if [ "${1:-}" = "--with-e2e-env" ]; then
    if [ -n "${HONK_HY2_SERVER:-}" ]; then
        step "hysteria2 real-server e2e ($HONK_HY2_SERVER)"
        cargo test -p honk-outbound --lib e2e_real_server_ -- --nocapture
    else
        echo "HONK_HY2_SERVER unset; skipping live e2e"
    fi
fi

printf '\noutbound-ci: ALL GREEN\n'
