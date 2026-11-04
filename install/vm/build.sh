#!/usr/bin/env bash
# Build the honk VM image for one architecture: a minimal kernel, an initrd
# holding only honk-vm-init, honk-core and CA certificates (no shell), and on
# x86_64 a UEFI disk image for bhyve.
#
# Usage: install/vm/build.sh <x86_64|aarch64|riscv64> <honk-core> <out-dir>
# Needs: clang, lld, llvm, flex, bison, bc, pahole, zstd, zig and the Rust
# musl target; x86_64 also needs sfdisk, mkfs.vfat and mtools.
set -euo pipefail

arch=${1:?usage: build.sh <x86_64|aarch64|riscv64> <honk-core> <out-dir>}
honk=$(realpath "${2:?missing honk-core}")
out=$(realpath -m "${3:?missing out-dir}")
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$here/../.." && pwd -P)
work=$(realpath -m "${WORK:-$root/target/vm}")
# shellcheck source=.github/ci/pins.env
source "$root/.github/ci/pins.env"

case $arch in
  x86_64) karch=x86_64 image=arch/x86/boot/bzImage target=bzImage rust=x86_64-unknown-linux-musl ;;
  aarch64) karch=arm64 image=arch/arm64/boot/Image.gz target=Image.gz rust=aarch64-unknown-linux-musl ;;
  riscv64) karch=riscv image=arch/riscv/boot/Image target=Image rust=riscv64gc-unknown-linux-musl ;;
  *) echo "unknown architecture: $arch" >&2; exit 2 ;;
esac
mkdir -p "$work" "$out"

src=$work/linux-$VM_KERNEL_VERSION
if [[ ! -d $src ]]; then
  tarball=$work/linux-$VM_KERNEL_VERSION.tar.xz
  [[ -f $tarball ]] || curl -fsSL --retry 3 -o "$tarball" \
    "https://cdn.kernel.org/pub/linux/kernel/v${VM_KERNEL_VERSION%%.*}.x/linux-$VM_KERNEL_VERSION.tar.xz"
  echo "$VM_KERNEL_SHA256  $tarball" | sha256sum -c -
  tar -xJf "$tarball" -C "$work"
fi

build=$work/build-$arch
kmake() { make -C "$src" O="$build" ARCH="$karch" LLVM=1 -j"$(nproc)" "$@"; }
fragments=("$here/kernel/common.config" "$here/kernel/$arch.config")

configure() {
  kmake tinyconfig > /dev/null
  # merge_config.sh leaves temporary files in its working directory.
  (cd "$build" && "$src/scripts/kconfig/merge_config.sh" -m .config "${fragments[@]}" "$@" > /dev/null)
  kmake olddefconfig > /dev/null
  # A dependency the fragments miss silently drops an option; fail instead.
  local missing=0 line
  while read -r line; do
    grep -qxF "$line" "$build/.config" || { echo "kernel config lacks $line" >&2; missing=1; }
  done < <(cat "${fragments[@]}" "$@" | grep -E '^CONFIG_[A-Z0-9_]+=y$')
  return "$missing"
}

configure
kmake "$target"
install -m 0644 "$build/$image" "$out/vmlinuz"
install -m 0644 "$build/.config" "$out/kernel.config"

# honk-vm-init: cross-built with the same zig wrappers as honk-core.
zig_target=${rust/-unknown/}
zig_target=${zig_target/riscv64gc/riscv64}
upper=$(printf '%s' "$rust" | tr 'a-z-' 'A-Z_')
env -u RUSTFLAGS ZIGCC_TARGET="$zig_target" \
  "CARGO_TARGET_${upper}_LINKER=$root/ci/zigcc" \
  "CARGO_TARGET_${upper}_RUSTFLAGS=-C link-self-contained=no" \
  CARGO_TARGET_DIR="$work/init-target" \
  cargo build --release --locked --manifest-path "$here/init/Cargo.toml" --target "$rust"
init=$work/init-target/$rust/release/honk-vm-init

# The kernel's own gen_init_cpio needs neither root nor a cpio tool.
list=$work/initramfs-$arch.list
cat > "$list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /bin 0755 0 0
dir /etc 0755 0 0
dir /etc/honk 0755 0 0
dir /etc/ssl 0755 0 0
dir /etc/ssl/certs 0755 0 0
dir /proc 0555 0 0
dir /sys 0555 0 0
dir /run 0755 0 0
dir /tmp 1777 0 0
dir /mnt 0755 0 0
dir /var 0755 0 0
dir /var/lib 0755 0 0
file /init $init 0755 0 0
file /bin/honk-core $honk 0755 0 0
file /etc/honk/default.dae $here/default.dae 0644 0 0
file /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt 0644 0 0
EOF
"$build/usr/gen_init_cpio" "$list" | zstd -19 -T0 -q > "$out/initrd.img"
sed "s/@ARCH@/$arch/" "$here/run.sh" > "$out/run.sh"
chmod 0755 "$out/run.sh"

[[ $arch == x86_64 ]] || exit 0

# bhyve has no direct kernel boot: its UEFI firmware starts the EFI stub from a
# GPT disk, so this kernel carries the initramfs and the command line itself.
efi_fragment=$work/efi.config
cat > "$efi_fragment" <<EOF
CONFIG_INITRAMFS_SOURCE="$list"
CONFIG_INITRAMFS_COMPRESSION_ZSTD=y
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE="console=ttyS0 panic=-1 quiet loglevel=3"
EOF
configure "$efi_fragment"
kmake bzImage
esp=$work/esp.img
rm -f "$esp"
esp_mib=$(( $(stat -c %s "$build/$image") / 1048576 + 8 ))
mkfs.vfat -C -n HONK "$esp" $(( esp_mib * 1024 )) > /dev/null
mmd -i "$esp" ::/EFI ::/EFI/BOOT
mcopy -i "$esp" "$build/$image" ::/EFI/BOOT/BOOTX64.EFI
disk=$out/honk-efi.img
rm -f "$disk"
truncate -s $(( esp_mib + 2 ))M "$disk"
printf 'label: gpt\nstart=2048, size=%d, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI"\n' \
  $(( esp_mib * 2048 )) | sfdisk -q "$disk"
dd if="$esp" of="$disk" bs=1M seek=1 conv=notrunc status=none
install -m 0755 "$here/run-bhyve.sh" "$out/run-bhyve.sh"
