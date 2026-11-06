#!/bin/sh
# clash-ci — gate for the Clash-compatible API surface (honk-core).
#
# Runs, in order and with early exit on failure:
#   1. fmt check
#   2. clippy (all targets, warnings denied)
#   3. clash_api integration tests (auth, proxies, delay, connections,
#      traffic/logs chunked+WS, /dns/query, cache flush, providers, UI)
#   4. honk-core integration tests (engine workflows incl. mock-eBPF)
#
# Usage: ci/clash-ci.sh
set -eu

cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

step "cargo fmt --check"
cargo fmt -p honk-core -- --check

step "cargo clippy -p honk-core --all-targets --features udp-bench,dns-bench -D warnings"
cargo clippy -p honk-core --all-targets --features udp-bench,dns-bench -- -D warnings

step "cargo test -p honk-core --test clash_api_test"
cargo test -p honk-core --test clash_api_test

step "cargo test -p honk-core --test integration_test"
cargo test -p honk-core --test integration_test

printf '\nclash-ci: ALL GREEN\n'
