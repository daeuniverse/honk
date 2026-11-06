#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "${CARGO_TARGET_DIR:?}/kernel-test-bins.env"
test -x "$HONK_CORE_TEST_BIN"
test -x "$HONK_DATAPATH_TEST_BIN"
test -x "$HONK_NFQUEUE_TEST_BIN"
test -x "$HONK_OUTBOUND_TEST_BIN"
test -x "$HONK_XSK_TEST_BIN"
test -x "$HONK_XDP_DAEMON"

cd "$repo"
test "$(id -u)" -eq 0
read -r cmdline </proc/cmdline
[[ " $cmdline " == *' virtme.'* ]]
kernel=$(uname -r)
printf 'Guest uname -r: %s\n' "$kernel" >> "${GITHUB_STEP_SUMMARY:?}"
test "$kernel" = "${HONK_CI_EXPECTED_KERNEL:?}"
test -d "/lib/modules/$kernel"
modprobe -a tun sch_ingress cls_bpf nf_tables nfnetlink_queue nft_queue veth 8021q
test -e /sys/fs/cgroup/cgroup.controllers
test -r "${HONK_ROUTING_TEST_OBJECT:?}"
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
test "$(stat -f -c %T /sys/fs/bpf)" = bpf_fs

log_dir="${GITHUB_WORKSPACE:?}/target/vm-tests/${HONK_CI_VM_LANE:?}"
mkdir -p "$log_dir"

"$HONK_CORE_TEST_BIN" ebpf::real::tests --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-real.log"
for real_test in \
  ebpf::real::tests::bare_load_holds_no_tracing_links \
  ebpf::real::tests::mandatory_helpers::mandatory_programs_call_no_probe_read_helper \
  ebpf::real::tests::socket_identity::occupied_sock_ops_slot_refuses_startup_without_leaving_links \
  ebpf::real::receive_trace::tests::receive_trace_family_failure_is_isolated \
  ebpf::real::receive_trace::tests::receive_trace_registration_loss_and_successful_zero_byte \
  ebpf::real::receive_trace::tests::receive_trace_stays_armed_between_receives \
  ebpf::real::receive_trace::tests::receive_trace_ignores_other_processes; do
  test "$("$HONK_CORE_TEST_BIN" "$real_test" --exact --ignored --list --format terse)" = "$real_test: test"
done
"$HONK_CORE_TEST_BIN" ebpf::real::receive_trace::tests --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-receive-trace.log"
"$HONK_CORE_TEST_BIN" \
  ebpf::real::routing::tests \
  --ignored --test-threads=1 2>&1 | tee "$log_dir/honk-core-routing.log"
"$HONK_DATAPATH_TEST_BIN" --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/ebpf-datapath.log"
"$HONK_NFQUEUE_TEST_BIN" nfqueue_service_isolated_netns_kernel_contract \
  --ignored --test-threads=1 2>&1 | tee "$log_dir/honk-nfqueue.log"
for ownership_test in \
  control::tests::tcp_binding::netns_tcp_accepted_fd_proves_original_syn \
  control::tests::tcp_tuple_reuse::netns_tcp_reuses_tuple_during_daens_time_wait \
  control::tests::udp_fullcone::netns_udp_full_cone_source_contract; do
  test "$("$HONK_CORE_TEST_BIN" "$ownership_test" --exact --ignored --list --format terse)" = "$ownership_test: test"
done
"$HONK_CORE_TEST_BIN" netns --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-netns.log"
watcher_test=ebpf::real::iface_watch::tests::route_only_change_wakes_network_subscription
test "$("$HONK_CORE_TEST_BIN" "$watcher_test" --exact --ignored --list --format terse)" = "$watcher_test: test"
"$HONK_CORE_TEST_BIN" "$watcher_test" --exact --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-iface-watch.log"
native_lifecycle_test=control::lifecycle::tests::ordinary_shutdown_preserves_live_tcp_until_graceful_completion
test "$("$HONK_CORE_TEST_BIN" "$native_lifecycle_test" --exact --ignored --list --format terse)" = "$native_lifecycle_test: test"
"$HONK_CORE_TEST_BIN" control::lifecycle::tests --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-native-lifecycle.log"
race_test=control::connection::tcp::dial_permit_scope_tests::direct_race_preserves_per_flow_marks
test "$("$HONK_CORE_TEST_BIN" "$race_test" --exact --ignored --list --format terse)" = "$race_test: test"
"$HONK_CORE_TEST_BIN" "$race_test" --exact --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-core-socket-marks.log"
mark_test=proxy::packet::socket_mark_tests::socket_marks_preserve_global_and_direct_flow_isolation
test "$("$HONK_OUTBOUND_TEST_BIN" "$mark_test" --exact --ignored --list --format terse)" = "$mark_test: test"
"$HONK_OUTBOUND_TEST_BIN" "$mark_test" --exact --ignored --test-threads=1 \
  2>&1 | tee "$log_dir/honk-outbound-socket-marks.log"
HONK_XDP_CORE_TEST_BIN="$HONK_CORE_TEST_BIN" HONK_XDP_XSK_TEST_BIN="$HONK_XSK_TEST_BIN" HONK_XDP_ARTIFACT_ROOT="$log_dir" \
  bash "$repo/.github/ci/xdp-daemon-smoke.sh" "$HONK_XDP_DAEMON" \
  2>&1 | tee "$log_dir/honk-xdp-daemon.log"
