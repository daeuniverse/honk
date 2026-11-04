# VM image

Each release ships `honk-vm-<tag>-<arch>.tar.gz` for `x86_64`, `aarch64` and `riscv64`. It runs honk in a small VM on hosts whose kernel cannot run honk's eBPF datapath, such as macOS, Windows and FreeBSD.

The archive contains:

- `vmlinuz`: Linux 6.12 built from `tinyconfig` plus [`install/vm/kernel/`](../../../install/vm/kernel/), without modules. `kernel.config` is the exact configuration.
- `initrd.img`: `/init` ([`honk-vm-init`](../../../install/vm/init/)), the static musl `honk-core` full build with mimalloc, CA certificates and a fallback configuration. There is no shell and no BusyBox.
- `run.sh`: a QEMU launcher.
- `x86_64` only: `honk-efi.img`, a UEFI disk for bhyve, and `run-bhyve.sh`.

[`install/vm/build.sh`](../../../install/vm/build.sh) builds the same files locally.

## Running with QEMU

```sh
./run.sh --config my.dae [--include rules.dae ...] [--api-port 9527] [--fwd HOST:GUEST ...]
```

`run.sh` uses `q35` on `x86_64` and `virt` on `aarch64` and `riscv64`. It picks KVM, or HVF on macOS, when the host architecture matches the image, and TCG otherwise; `--accel` overrides the choice. QEMU user networking forwards only the API port and every `--fwd` port to `127.0.0.1` on the host.

A configuration that serves the API through the forwarded port must allow the forwarded host name, for example `allowed_hosts: '127.0.0.1:9527'`.

## Configuration

`/init` installs the first source it finds:

1. fw_cfg `opt/honk/config`, copied to `/etc/honk/config.dae`; every `opt/honk/conf.d/<name>` becomes `/etc/honk/conf.d/<name>`. `run.sh --config` and `--include` pass these.
2. Kernel command line `honk.cfg_b64=<base64>`, for small configurations.
3. `config.dae` on a virtio-9p share tagged `honkcfg` (`run.sh --9p DIR`), used in place so API edits persist.
4. The built-in fallback, which exposes no API.

fw_cfg is read-only and the guest has no other disk, so API changes to sources 1 and 2 last until the VM stops.

`eth0` gets a static IPv4 address; there is no DHCP client. The defaults match QEMU user networking (`10.0.2.15/24`, gateway `10.0.2.2`, DNS `10.0.2.3`). fw_cfg `opt/honk/ip`, `opt/honk/gw` and `opt/honk/dns`, or the kernel command line `honk.ip=`, `honk.gw=` and `honk.dns=`, override them.

When `honk-core` exits, `/init` powers the VM off. Without a shell, inspect the VM through the serial console log and the API.

## FreeBSD

QEMU on FreeBSD has no hardware accelerator, so `run.sh` uses TCG there. honk spends most of its start in the eBPF verifier, which is slow under TCG.

bhyve accelerates `x86_64` guests and has QEMU-compatible fw_cfg since FreeBSD 14.0, but it cannot boot a kernel directly. `honk-efi.img` therefore holds a kernel with the initramfs and command line built in, booted by the bhyve UEFI firmware (`sysutils/edk2`):

```sh
./run-bhyve.sh -c my.dae -t tap0 -i 192.0.2.10/24 -g 192.0.2.1 [-d 192.0.2.1]
```

The tap interface must already be in a bridge that reaches the gateway. The address options become fw_cfg `opt/honk/ip`, `gw` and `dns`.
