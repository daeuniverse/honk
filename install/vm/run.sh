#!/usr/bin/env bash
# Start the honk VM with QEMU. The configuration enters through fw_cfg; there is
# no configuration disk and no shell in the guest.
# Usage: ./run.sh --config FILE [--include FILE ...] [--api-port 9527]
#                 [--fwd HOST:GUEST ...] [--accel auto|kvm|hvf|whpx|tcg]
#                 [--mem 384M] [--9p DIR] [--append ARGS]
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
arch=@ARCH@
config='' includes=() api=9527 fwds=() accel=auto mem=384M ninep='' append=''
while (( $# )); do
  case $1 in
    --config) config=$2; shift 2 ;;
    --include) includes+=("$2"); shift 2 ;;
    --api-port) api=$2; shift 2 ;;
    --fwd) fwds+=("$2"); shift 2 ;;
    --accel) accel=$2; shift 2 ;;
    --mem) mem=$2; shift 2 ;;
    --9p) ninep=$2; shift 2 ;;
    --append) append=$2; shift 2 ;;
    -h | --help) sed -n 2,6p "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n $config || -n $ninep ]] || { echo 'need --config FILE or --9p DIR' >&2; exit 2; }

host=$(uname -m)
[[ $host != arm64 ]] || host=aarch64
if [[ $accel == auto ]]; then
  accel=tcg
  if [[ $host == "$arch" ]]; then
    if [[ -w /dev/kvm ]]; then accel=kvm
    elif [[ $(uname) == Darwin ]]; then accel=hvf
    fi
  fi
fi
if [[ $accel == tcg ]]; then
  accel_args=(-accel "tcg,thread=multi,tb-size=256" -cpu max)
else
  accel_args=(-accel "$accel" -cpu host)
fi

# q35 describes fw_cfg in ACPI (as bhyve does); virt describes it in the device tree.
case $arch in
  x86_64) machine=(-M q35) console=ttyS0 virtio=pci ;;
  aarch64) machine=(-M virt) console=ttyAMA0 virtio=device ;;
  riscv64) machine=(-M virt) console=ttyS0 virtio=device ;;
esac

hostfwd="hostfwd=tcp:127.0.0.1:$api-:9527"
for fwd in "${fwds[@]}"; do hostfwd+=",hostfwd=tcp:127.0.0.1:${fwd%%:*}-:${fwd##*:}"; done
extra=()
[[ -z $config ]] || extra+=(-fw_cfg "name=opt/honk/config,file=$config")
for include in "${includes[@]}"; do
  extra+=(-fw_cfg "name=opt/honk/conf.d/$(basename "$include"),file=$include")
done
[[ -z $ninep ]] || extra+=(-fsdev "local,id=cfg,path=$ninep,security_model=none"
  -device "virtio-9p-$virtio,fsdev=cfg,mount_tag=honkcfg")

echo "[run.sh] $arch accel=$accel api=http://127.0.0.1:$api" >&2
exec "qemu-system-$arch" "${machine[@]}" "${accel_args[@]}" -m "$mem" -smp 2 \
  -nographic -no-reboot -nodefaults -serial stdio \
  -kernel "$here/vmlinuz" -initrd "$here/initrd.img" \
  -append "console=$console quiet loglevel=3 panic=-1 $append" \
  -netdev "user,id=net0,$hostfwd" -device "virtio-net-$virtio,netdev=net0" \
  "${extra[@]}"
