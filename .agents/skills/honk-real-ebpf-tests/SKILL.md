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
(cd crates/honk-ebpf && CARGO_TARGET_DIR=target/routing-test env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none --features routing-test)
HONK_ROUTING_TEST_OBJECT="$PWD/crates/honk-ebpf/target/routing-test/bpfel-unknown-none/release/honk-ebpf" CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo +stable test -p honk-core --features ebpf --lib ebpf::real::routing::tests -- --ignored --test-threads=1
```

Use `just test-netns`, which includes `test-routing`. Without `just`, run the block above, then these remaining `Justfile` commands:

```bash
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo +stable test -p honk-nfqueue --lib nfqueue_service_isolated_netns_kernel_contract -- --ignored --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo +stable test -p honk-core --features ebpf --lib netns -- --ignored --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo +stable test -p honk-core --features ebpf --lib ebpf::real::tests -- --ignored --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 cargo +stable test -p honk-core --features ebpf --test ebpf_datapath_test -- --ignored --test-threads=1
```

The routing object path above is a build output, not a checked-in file.

## CI-shaped VM

This path follows the `ebpf` job in `.github/workflows/ci.yml` on an Ubuntu Linux host. Dependency installation and KVM setup need host root; the guest runs as root. KVM is optional: the workflow falls back to TCG software emulation.
If this path could not run, put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

1. Follow the workflow's toolchain and dependency steps, including "Install virtme-ng 1.41", "Install bpf-linker 0.11.0" and the geo asset installation. Use its pinned downloads and checksums. Outside Actions, set `GITHUB_WORKSPACE` to the checkout root and `RUNNER_TEMP` to a temporary directory. Export the values the workflow writes to `GITHUB_ENV` and add the directory it writes to `GITHUB_PATH` to `PATH`. Set `CARGO_BUILD_JOBS=1` and `CARGO_PROFILE_TEST_DEBUG=0` as the job does.
2. Follow "Configure KVM". Set `HONK_CI_VNG_DISABLE_KVM=0` only when KVM is accessible; otherwise set it to `1` for TCG.
3. Follow "Build eBPF object", "Build routing-test eBPF object separately", "Verify eBPF objects have BTF" and "Run eBPF-feature unit tests" on the host. These produce the two objects used below.
4. Build the three test executables on the host with the workflow's commands, from the checkout root:

   ```bash
   cargo +stable test -p honk-core --features ebpf --lib --test ebpf_datapath_test --no-run --message-format=json
   cargo +stable test -p honk-nfqueue --lib --no-run --message-format=json
   ```

   Pipe their combined JSON output through the `jq -sr` block in "Compile real-kernel test binaries on the host". It writes the generated `target/kernel-test-bins.env` file with shell-quoted `HONK_CORE_TEST_BIN`, `HONK_DATAPATH_TEST_BIN` and `HONK_NFQUEUE_TEST_BIN`. Use that block's unique-executable checks rather than choosing a binary by filename glob.
5. Follow "Fetch verified Linux 6.12 image and modules". Keep its image, modules and checksum checks together. Export the resulting `HONK_CI_KERNEL_IMAGE` value.
6. Boot with the workflow's command below. `HONK_ROUTING_TEST_OBJECT` points to the routing-test build output. `.github/ci/ebpf-vm-tests.sh` is the guest gate; never run it directly on the host. It checks the pinned guest kernel and modules, prepares bpffs and runs the real-kernel binaries serially.

   ```bash
   kvm_args=()
   if test "${HONK_CI_VNG_DISABLE_KVM:-0}" = 1; then
     kvm_args+=(--disable-kvm)
   fi
   vng -r "$HONK_CI_KERNEL_IMAGE" \
     "${kvm_args[@]}" \
     --user root \
     --rwdir "$GITHUB_WORKSPACE" \
     --cpus 2 \
     --memory 4G \
     -- \
     env \
       CARGO_TARGET_DIR="$GITHUB_WORKSPACE/target" \
       RUST_BACKTRACE=1 \
       HONK_ROUTING_TEST_OBJECT="$GITHUB_WORKSPACE/target/honk-ebpf-routing-test/bpfel-unknown-none/release/honk-ebpf" \
       bash "$GITHUB_WORKSPACE/.github/ci/ebpf-vm-tests.sh"
   ```

## No suitable environment

On macOS, Windows or a machine without the root access or VM setup above, do not run these gates. Put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

## Checklist

- [ ] Selected the native, VM or unavailable-environment path.
- [ ] Native commands include the routing dependency before the remaining netns checks.
- [ ] The VM path builds the executables and manifest on the host, then runs the guest gate only inside the VM.
- [ ] Unavailable paths have their exact Verified sentence; reporting follows the named root sections.
