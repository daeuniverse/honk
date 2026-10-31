#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "${CARGO_TARGET_DIR:?}/kernel-test-bins.env"
test -x "$HONK_CORE_TEST_BIN"
test -x "$HONK_DATAPATH_TEST_BIN"
test -x "$HONK_NFQUEUE_TEST_BIN"
test -x "$HONK_OUTBOUND_TEST_BIN"
test -x "$HONK_BPF_CLI_TEST_BIN"
test -x "$HONK_TOOL_BIN"
export HONK_TEST_TOOL="$HONK_TOOL_BIN"
export HONK_TEST_BPF_OBJECT="$repo/crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf"
test -r "$HONK_TEST_BPF_OBJECT"

cd "$repo"
test "$(id -u)" -eq 0
kernel=$(uname -r)
printf 'Guest uname -r: %s\n' "$kernel" >> "${GITHUB_STEP_SUMMARY:?}"
test "$kernel" = "${HONK_CI_EXPECTED_KERNEL:?}"
test -d "/lib/modules/$kernel"
modprobe -a tun veth bonding bridge sch_ingress cls_bpf nf_tables nfnetlink_queue nft_queue 8021q macsec
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
  ebpf::real::tests::bindings::private_netns_binding_is_owned_and_detached_by_true_ifindex \
  ebpf::real::tests::bindings::unchanged_plan_keeps_link_ids_and_leaves_foreign_hooks \
  ebpf::real::tests::bindings::role_and_framing_change_updates_links_in_place \
  ebpf::real::tests::bindings::watcher::watcher_reconcile_binds_reprograms_writes_accept_ra_and_releases \
  ebpf::real::tests::bindings::moved_device_recreated_with_same_name_and_index_is_rebound \
  ebpf::real::tests::bindings::full_chain_fails_one_direction_and_retry_does_not_stack \
  ebpf::real::tests::bindings::observation_follows_add_replace_remove \
  ebpf::real::tests::bindings::failure::rejected_update_keeps_old_link_and_commits_the_healthy_direction \
  ebpf::real::tests::bindings::failure::device_deleted_before_verified_apply_reports_failure_without_recreating \
  ebpf::real::tests::bindings::failure::rename_after_planning_is_not_confirmed_and_update_rolls_back \
  ebpf::real::tests::bindings::failure::device_deleted_before_attach_is_a_topology_change_not_an_attach_failure \
  ebpf::real::tests::bindings::lazy::absent_interfaces_start_pending_then_bind_release_and_rebind \
  ebpf::real::tests::bindings::lazy::startup_refuses_nested_entry_while_binding_the_ordinary_lan \
  ebpf::real::tests::bindings::lazy::only_one_interface_missing_binds_the_down_one_at_startup \
  ebpf::real::tests::bindings::lazy::startup_attach_failure_degrades_and_recovers_without_stacking \
  ebpf::real::tests::bindings::lazy::bridge_member_leaving_releases_master_links_and_a_recreated_bridge_rebinds \
  ebpf::real::tests::bindings::lazy::accept_ra_and_rp_filter_are_written_on_sight_for_dotted_names \
  ebpf::real::tests::bindings::lazy::watcher_binds_on_an_event_from_the_subscription_startup_opened \
  ebpf::real::tests::bindings::framing::gre_binds_l3_only_when_point_to_point \
  ebpf::real::tests::bindings::framing::collect_md_gre_binds_l3 \
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
tool_tests=(
  capture_releases_kernel_owners_before_output
  disable_releases_kernel_owners_before_output
  cleanup_failure_releases_kernel_owners_before_error_output
)
for tool_test in "${tool_tests[@]}"; do
  test "$("$HONK_BPF_CLI_TEST_BIN" "$tool_test" --exact --ignored --list --format terse)" = "$tool_test: test"
done
for tool_test in "${tool_tests[@]}"; do
  "$HONK_BPF_CLI_TEST_BIN" "$tool_test" --exact --ignored --test-threads=1 \
    2>&1 | tee "$log_dir/honk-tool-$tool_test.log"
done
"$HONK_NFQUEUE_TEST_BIN" nfqueue_service_isolated_netns_kernel_contract \
  --ignored --test-threads=1 2>&1 | tee "$log_dir/honk-nfqueue.log"
# Exact checks keep the substring-selected routing/netns runs from silently omitting a case.
for kernel_test in \
  control::tests::bond_binding::netns_bond_lan_tcp_udp_master_reply_and_failover \
  control::tests::bond_binding::netns_bond_wan_only_local_failover \
  control::tests::bond_binding::netns_bond_inactive_member_respects_receive_admission \
  control::tests::bond_binding::netns_bond_bridge_port_keeps_native_udp_reverse_path \
  control::tests::bond_binding::netns_bond_non_lacp_modes_proxy_tcp_udp \
  control::tests::tcp_binding::netns_tcp_accepted_fd_proves_original_syn \
  control::tests::tcp_tuple_reuse::netns_tcp_reuses_tuple_during_daens_time_wait \
  control::tests::udp_fullcone::netns_udp_full_cone_source_contract \
  control::tests::vlan_frames::netns_vlan_client_on_parent_lan_is_forwarded_natively \
  control::tests::vlan_frames::netns_vlan_device_lan_is_proxied_beside_its_parent \
  control::tests::vlan_frames::netns_vlan_priority_tagged_lan_client_is_still_proxied \
  control::tests::vlan_frames::netns_vlan_host_connection_on_parent_wan_is_native \
  control::tests::vlan_frames::netns_vlan_device_wan_intercepts_host_connection \
  control::tests::vlan_frames::netns_macsec_upper_device_lan_flow_is_classified \
  ebpf::real::routing::tests::dns_ownership::tcx::unsupported_lan_ingress_frames_continue_tcx_without_marking; do
  test "$("$HONK_CORE_TEST_BIN" "$kernel_test" --exact --ignored --list --format terse)" = "$kernel_test: test"
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
