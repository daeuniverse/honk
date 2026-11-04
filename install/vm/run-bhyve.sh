#!/bin/sh
# Start the honk VM under bhyve (FreeBSD 14.0 or later, amd64). bhyve has no
# direct kernel boot, so the UEFI firmware (sysutils/edk2, bhyve flavour) boots
# honk-efi.img; the configuration and the static address enter through fw_cfg.
# Usage: ./run-bhyve.sh -c FILE -t TAP -i ADDR/PREFIX -g GATEWAY [-d DNS]
#                       [-m 512M] [-n NAME]
set -eu
here=$(cd -- "$(dirname -- "$0")" && pwd)
firmware=${FIRMWARE:-/usr/local/share/uefi-firmware/BHYVE_UEFI.fd}
config='' tap='' ip='' gw='' dns='' mem=512M name=honk
while getopts c:t:i:g:d:m:n:h opt; do
  case $opt in
    c) config=$OPTARG ;;
    t) tap=$OPTARG ;;
    i) ip=$OPTARG ;;
    g) gw=$OPTARG ;;
    d) dns=$OPTARG ;;
    m) mem=$OPTARG ;;
    n) name=$OPTARG ;;
    *) sed -n 2,7p "$0"; exit 2 ;;
  esac
done
if [ -z "$config" ] || [ -z "$tap" ] || [ -z "$ip" ] || [ -z "$gw" ]; then
  sed -n 5,6p "$0" >&2
  exit 2
fi
set -- -f "name=opt/honk/config,file=$config" \
  -f "name=opt/honk/ip,string=$ip" -f "name=opt/honk/gw,string=$gw"
[ -z "$dns" ] || set -- "$@" -f "name=opt/honk/dns,string=$dns"

trap 'bhyvectl --destroy --vm="$name" 2> /dev/null || true' EXIT
bhyve -c 2 -m "$mem" -H -A -P \
  -s 0,hostbridge -s 31,lpc -l com1,stdio \
  -l "bootrom,$firmware" -l fwcfg,qemu "$@" \
  -s 2,virtio-net,"$tap" -s 3,virtio-blk,"$here/honk-efi.img" \
  "$name"
