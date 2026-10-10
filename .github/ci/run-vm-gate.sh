#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
source .github/ci/pins.env
lane=${1:?usage: run-vm-gate.sh <lane>}
prefix="KERNEL_${lane^^}"
declare -n base="${prefix}_BASE" image="${prefix}_IMAGE" modules="${prefix}_MODULES"
declare -n image_sha256="${prefix}_IMAGE_SHA256" modules_sha256="${prefix}_MODULES_SHA256"
declare -n release="${prefix}_RELEASE"
kernel_dir="${RUNNER_TEMP:?}/kernel-$lane"
log_dir="${GITHUB_WORKSPACE:?}/target/vm-tests/$lane"
mkdir -p "$kernel_dir" "$log_dir"

{
  cargo test -p honk-core --features ebpf,native-api --lib --test ebpf_datapath_test --no-run --message-format=json
  cargo test -p honk-nfqueue --lib --no-run --message-format=json
  cargo test -p honk-outbound --lib --no-run --message-format=json
} | jq -sr '
  def executable($name):
    [.[] | select(.reason == "compiler-artifact" and .target.name == $name and .executable != null) | .executable]
    | unique | if length == 1 then .[0] else error("missing or ambiguous test executable: " + $name) end;
  "HONK_CORE_TEST_BIN=" + (executable("honk_core") | @sh),
  "HONK_DATAPATH_TEST_BIN=" + (executable("ebpf_datapath_test") | @sh),
  "HONK_NFQUEUE_TEST_BIN=" + (executable("honk_nfqueue") | @sh),
  "HONK_OUTBOUND_TEST_BIN=" + (executable("honk_outbound") | @sh)
' > "$GITHUB_WORKSPACE/target/kernel-test-bins.env"

if ! test -f "$kernel_dir/$image"; then
  curl -fsSL --retry 3 --retry-all-errors -o "$kernel_dir/$image" "$base/$image"
fi
if ! test -f "$kernel_dir/$modules"; then
  curl -fsSL --retry 3 --retry-all-errors -o "$kernel_dir/$modules" "$base/$modules"
fi
echo "$image_sha256  $kernel_dir/$image" | sha256sum -c -
echo "$modules_sha256  $kernel_dir/$modules" | sha256sum -c -
dpkg-deb --extract "$kernel_dir/$image" "$kernel_dir/root"
dpkg-deb --extract "$kernel_dir/$modules" "$kernel_dir/root"

printf 'HONK_CI_VNG_DISABLE_KVM=%s\n' "${HONK_CI_VNG_DISABLE_KVM:-0}" >> "${GITHUB_STEP_SUMMARY:?}"
kvm_args=()
if test "${HONK_CI_VNG_DISABLE_KVM:-0}" = 1; then
  kvm_args+=(--disable-kvm)
fi
# Only the workspace is writable in the guest; copy its summary back on failure too.
status=0
: > "$log_dir/summary.md"
vng -r "$kernel_dir/root/boot/vmlinuz-$release" \
  "${kvm_args[@]}" \
  --user root \
  --rwdir "$GITHUB_WORKSPACE" \
  --cpus 2 \
  --memory 4G \
  -- \
  env \
    GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    GITHUB_STEP_SUMMARY="$log_dir/summary.md" \
    CARGO_TARGET_DIR="$GITHUB_WORKSPACE/target" \
    RUST_BACKTRACE=1 \
    HONK_CI_VM_LANE="$lane" \
    HONK_CI_EXPECTED_KERNEL="$release" \
    HONK_ROUTING_TEST_OBJECT="$GITHUB_WORKSPACE/target/honk-ebpf-routing-test/bpfel-unknown-none/release/honk-ebpf" \
    bash "$GITHUB_WORKSPACE/.github/ci/ebpf-vm-tests.sh" || status=$?
if test -f "$log_dir/summary.md"; then
  cat "$log_dir/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi
exit "$status"
