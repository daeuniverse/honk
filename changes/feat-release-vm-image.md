Added

- Releases ship a static `riscv64gc` musl full build and a QEMU VM image for `x86_64`, `aarch64` and `riscv64`: a minimal kernel and a shell-free initrd whose Rust `/init` reads the configuration from fw_cfg. The `x86_64` image also has a UEFI disk for bhyve.
