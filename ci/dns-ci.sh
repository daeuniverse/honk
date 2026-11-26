#!/bin/sh
# dns-ci — DNS subsystem test gate after DNS-path changes.
#
#   1. fmt check (dns-touched crates)
#   2. clippy -D warnings
#   3. honk-config tests
#   4. all honk-core DNS unit tests
#   5. dns_runtime integration test (mock eBPF, no Clash API)
#   6. honk-core control tests (listeners / probers / resolver wiring)
#   7. DNS audit sender and feature-disabled hooks
#   8. honk-outbound full suite (alive/urltest/bootstrap/quic transports)
#
# Usage: ci/dns-ci.sh
set -eu

cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

step "cargo fmt --check"
cargo fmt -p honk-config -p honk-core -p honk-outbound -- --check

step "cargo clippy -D warnings"
cargo clippy -p honk-config -p honk-core -p honk-outbound --all-targets --features honk-core/udp-bench,honk-core/dns-bench,honk-core/dns-syslog -- -D warnings

step "cargo test -p honk-config"
cargo test -p honk-config

step "cargo test -p honk-core (all DNS unit tests)"
cargo test -p honk-core --features dns-syslog --lib dns::

step "cargo test -p honk-core --features dns-syslog --test dns_runtime_test"
cargo test -p honk-core --features dns-syslog --test dns_runtime_test

step "cargo test -p honk-core (control resolver wiring)"
cargo test -p honk-core --features dns-syslog --lib control

step "cargo test -p honk-core (DNS audit sender)"
cargo test -p honk-core --features dns-syslog --lib audit::

step "cargo test -p honk-core (DNS audit feature disabled)"
cargo test -p honk-core --no-default-features --lib audit_feature_tests::

step "cargo test -p honk-outbound"
cargo test -p honk-outbound --lib

printf '\ndns-ci: ALL GREEN\n'
