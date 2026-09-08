#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "${CARGO_TARGET_DIR:?}/kernel-test-bins.env"
test -x "$HONK_CORE_TEST_BIN"
test -x "$HONK_DATAPATH_TEST_BIN"
test -x "$HONK_NFQUEUE_TEST_BIN"

cd "$repo"
test "$(id -u)" -eq 0
test "$(uname -r)" = 6.12.0-061200-generic
test -d "/lib/modules/$(uname -r)"
modprobe -a tun sch_ingress cls_bpf nf_tables nfnetlink_queue nft_queue
test -e /sys/fs/cgroup/cgroup.controllers
test -r "${HONK_ROUTING_TEST_OBJECT:?}"
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
test "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs

"$HONK_CORE_TEST_BIN" ebpf::real::tests --ignored --test-threads=1
"$HONK_CORE_TEST_BIN" \
  ebpf::real::routing::tests \
  --ignored --test-threads=1
"$HONK_DATAPATH_TEST_BIN" --ignored --test-threads=1
"$HONK_NFQUEUE_TEST_BIN" nfqueue_service_isolated_netns_kernel_contract \
  --ignored --test-threads=1
"$HONK_CORE_TEST_BIN" netns --ignored --test-threads=1
