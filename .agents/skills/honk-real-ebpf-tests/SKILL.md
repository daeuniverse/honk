---
name: honk-real-ebpf-tests
description: Use to choose native unprivileged tests, disposable VM real eBPF tests or unavailable-environment reporting.
---

Read first: `AGENTS.md`, `.agents/rules/real-ebpf.md` and `.agents/rules/test-locations.md`.
Test policy and general gates: `AGENTS.md`, "Testing instructions" and "Current validation guidance".

## Native Linux

Native Linux supports builds and unprivileged tests; build prerequisites are in `.agents/rules/real-ebpf.md`. Linux 6.12+ and root alone do **not** make the complete ignored real-kernel suites safe on a shared host. They attach root-cgroup BPF programs, which private network/mount namespaces do not isolate. The routing suite also includes VM-only cases.

Use the disposable VM path below for both `just test-routing` and `just test-netns`. Neither recipe runs ignored tests on the host. Do not run the protected suites directly, weaken their fixture guard, or set `HONK_CI_VM_LANE` / `HONK_CI_EXPECTED_KERNEL` to make a host look like a guest. Those variables belong to the VM launcher.

## CI-shaped disposable VM

This path follows the `ebpf` job in `.github/workflows/ci.yml` on an **x86_64 Ubuntu 24.04 Linux host**. The pinned kernel packages and bpf-linker executable are x86_64; this is not a native aarch64, macOS or Windows runner. The host need not run Linux 6.12+: the guest boots the pinned floor kernel. Installing host dependencies and geo assets requires root; after setup, the launcher runs as the checkout user and the guest runs as root. KVM is optional; inaccessible KVM requires TCG software emulation.

If this path could not run, put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

1. Follow the workflow's Rust toolchain and "Install build and VM dependencies" steps, including the root host toolchain and the eBPF crate's nightly with `rust-src` / `llvm-tools`. Follow "Install pinned virtme-ng", "Install pinned bpf-linker" and the geo asset installation. `.github/ci/pins.env` owns download versions and checksums. These are explicit prerequisites, not installations performed by `just`. On a shared machine, use already provisioned dependencies or a dedicated runner rather than copying CI's host-wide apt-source/KVM permission changes.
2. Outside Actions, export `GITHUB_WORKSPACE` as the absolute checkout root, `RUNNER_TEMP` as an existing temporary directory, and `GITHUB_STEP_SUMMARY` as a writable file. Export the values the workflow writes to `GITHUB_ENV` and add the virtme-ng directory it writes to `GITHUB_PATH` to `PATH`. Use the checkout's default `target` directory (unset inherited `CARGO_TARGET_DIR`); the executable manifest and guest paths use it. Set `CARGO_PROFILE_TEST_DEBUG=0` for host test builds.
3. Follow "Configure KVM"'s accessibility decision: set `HONK_CI_VNG_DISABLE_KVM=0` only when the launcher user can read/write `/dev/kvm`; otherwise set it to `1` for TCG. Do not change shared-host device permissions just to run this gate.
4. Follow "Build eBPF object", "Build routing-test eBPF object separately", "Verify eBPF objects have BTF" and "Run eBPF-feature unit tests" on the host. Clear inherited `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` for the object builds so they retain BTF. The objects must be at `crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf` and `target/honk-ebpf-routing-test/bpfel-unknown-none/release/honk-ebpf`. These are build outputs, not checked-in files.
5. Run `just test-netns` from the checkout root. Its `test-routing` dependency invokes the existing `.github/ci/run-vm-gate.sh floor` **once**; `just test-routing` deliberately runs that same complete gate because routing now contains root-cgroup cases. Without `just`, use:

   ```bash
   CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 .github/ci/run-vm-gate.sh floor
   ```

The launcher compiles four test executables without executing ignored tests on the host, writes `target/kernel-test-bins.env` with unique-executable checks, downloads missing pinned kernel packages into `RUNNER_TEMP`, verifies their checksums and boots virtme-ng. `.github/ci/ebpf-vm-tests.sh` is the guest-only gate; never invoke it directly on the host. It checks the expected guest kernel/modules, prepares bpffs and runs the real backend, compiled routing, datapath, NFQUEUE and netns suites serially. The netns selection includes TCP accepted-FD child-proof ownership, tuple reuse, UDP fullcone source ownership and real VLAN/macsec frame cases; exact nonempty checks require each of these suite entrypoints, and the routing-substring run must still contain `dns_ownership::tcx::unsupported_lan_ingress_frames_continue_tcx_without_marking`. Exact, nonempty route-only watcher, native lifecycle and SO_MARK selections remain required. Logs go to `target/vm-tests/floor/`; KVM selection and the guest kernel go to `GITHUB_STEP_SUMMARY`. CI uses the same launcher for `floor` and, in the full lane, `recent`.

## No suitable environment

On non-Linux or non-x86_64 hosts, in restricted containers without the VM prerequisites, or on a machine where the required dependencies/root setup are unavailable, do not run these gates or substitute direct host execution. Put this exact sentence in Verified: "eBPF VM tests: not run (needs Linux root or a VM; CI runs them)".

## Checklist

- [ ] Selected native unprivileged tests, the disposable VM gate, or unavailable-environment reporting.
- [ ] Both `test-routing` and `test-netns` use the same VM gate, including compiled routing before completion.
- [ ] The VM prerequisites and both BTF objects are ready; host execution only builds the ignored suites, and the guest gate runs only inside the VM.
- [ ] Unavailable paths have their exact Verified sentence; reporting follows the named root sections.
