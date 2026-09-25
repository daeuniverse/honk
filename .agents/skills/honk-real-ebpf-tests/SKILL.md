---
name: honk-real-ebpf-tests
description: Use to choose native Linux, CI-shaped VM or unavailable-environment paths for real eBPF tests.
---

Read first: `AGENTS.md`, `.agents/rules/real-ebpf.md` and `.agents/rules/test-locations.md`.
Test policy and general gates: `AGENTS.md`, "Testing instructions" and "Current validation guidance".

## Native Linux

This path needs Linux 6.12+ and root for the test runs. Build prerequisites are in `.agents/rules/real-ebpf.md`.
If this path could not run, put this exact sentence in the PR's Verified section: "Native eBPF tests: not run (needs Linux 6.12+ and root)".

Use `just test-routing`. Without `just`, run its `Justfile` commands below from the checkout root. The subshell keeps that working directory; `$PWD` replaces `{{justfile_directory()}}`.

```bash
(cd crates/honk-ebpf && CARGO_TARGET_DIR=target/routing-test env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo build --release -Zbuild-std=core --target bpfel-unknown-none --features routing-test)
HONK_ROUTING_TEST_OBJECT="$PWD/crates/honk-ebpf/target/routing-test/bpfel-unknown-none/release/honk-ebpf" CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib ebpf::real::routing::tests -- --ignored --test-threads=1
```

Use `just test-netns`, which includes `test-routing`. Without `just`, run the block above, then these remaining `Justfile` commands:

```bash
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-nfqueue --lib nfqueue_service_isolated_netns_kernel_contract -- --ignored --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib netns -- --ignored --test-threads=1
test "$(CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib ebpf::real::iface_watch::tests::route_only_change_wakes_network_subscription -- --ignored --exact --list --format terse)" = "ebpf::real::iface_watch::tests::route_only_change_wakes_network_subscription: test"
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib ebpf::real::iface_watch::tests::route_only_change_wakes_network_subscription -- --ignored --exact --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib ebpf::real::tests -- --ignored --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --test ebpf_datapath_test -- --ignored --test-threads=1
test "$(CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib control::connection::tcp::dial_permit_scope_tests::direct_race_preserves_per_flow_marks -- --ignored --exact --list --format terse)" = "control::connection::tcp::dial_permit_scope_tests::direct_race_preserves_per_flow_marks: test"
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-core --features ebpf --lib control::connection::tcp::dial_permit_scope_tests::direct_race_preserves_per_flow_marks -- --ignored --exact --test-threads=1
test "$(CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-outbound --lib proxy::packet::socket_mark_tests::socket_marks_preserve_global_and_direct_flow_isolation -- --ignored --exact --list --format terse)" = "proxy::packet::socket_mark_tests::socket_marks_preserve_global_and_direct_flow_isolation: test"
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p honk-outbound --lib proxy::packet::socket_mark_tests::socket_marks_preserve_global_and_direct_flow_isolation -- --ignored --exact --test-threads=1
```

The routing object path above is a build output, not a checked-in file.

## CI-shaped VM

This path follows the `ebpf` job in `.github/workflows/ci.yml` on an Ubuntu Linux host. Dependency installation and KVM setup need host root; the guest runs as root. KVM is optional: the workflow falls back to TCG software emulation.
If this path could not run, put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

1. Follow the workflow's toolchain and dependency steps, including "Install pinned virtme-ng", "Install pinned bpf-linker" and the geo asset installation. `.github/ci/pins.env` owns the download versions and checksums. Outside Actions, set `GITHUB_WORKSPACE` to the checkout root, `RUNNER_TEMP` to a temporary directory and `GITHUB_STEP_SUMMARY` to a writable file. Export the values the workflow writes to `GITHUB_ENV` and add the directory it writes to `GITHUB_PATH` to `PATH`. Set `CARGO_PROFILE_TEST_DEBUG=0` for the host test builds.
2. Follow "Configure KVM". Set `HONK_CI_VNG_DISABLE_KVM=0` only when KVM is accessible; otherwise set it to `1` for TCG.
3. Follow "Build eBPF object", "Build routing-test eBPF object separately", "Verify eBPF objects have BTF" and "Run eBPF-feature unit tests" on the host. These produce the two objects used below.
4. Run `.github/ci/run-vm-gate.sh floor` from the checkout root. It compiles the four test executables, writes `target/kernel-test-bins.env` with unique-executable checks, verifies the kernel packages from `pins.env`, and boots the guest. `.github/ci/ebpf-vm-tests.sh` is the guest gate; never run it directly on the host. It checks the expected kernel and modules, prepares bpffs and runs the eight real-kernel invocations serially, including exact, nonempty route-only watcher and SO_MARK socket selections. Logs go to `target/vm-tests/floor/`; the KVM selection and guest kernel go to `GITHUB_STEP_SUMMARY`.

## No suitable environment

On macOS, Windows or a machine without the root access or VM setup above, do not run these gates. Put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

## Checklist

- [ ] Selected the native, VM or unavailable-environment path.
- [ ] Native commands include the routing dependency before the remaining netns checks.
- [ ] The VM path builds the executables and manifest on the host, then runs the guest gate only inside the VM.
- [ ] Unavailable paths have their exact Verified sentence; reporting follows the named root sections.
