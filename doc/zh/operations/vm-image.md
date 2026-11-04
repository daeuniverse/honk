# VM 镜像

每个 release 都附带 `honk-vm-<tag>-<arch>.tar.gz`，架构为 `x86_64`、`aarch64` 和 `riscv64`。宿主内核跑不了 honk 的 eBPF 数据面时（例如 macOS、Windows、FreeBSD），可以用它在小型 VM 里运行 honk。

压缩包内容：

- `vmlinuz`：Linux 6.12，在 `tinyconfig` 基础上叠加 [`install/vm/kernel/`](../../../install/vm/kernel/) 构建，不带模块。`kernel.config` 是完整配置。
- `initrd.img`：包含 `/init`（[`honk-vm-init`](../../../install/vm/init/)）、静态 musl 的 `honk-core` full 版（mimalloc）、CA 证书和兜底配置。不含 shell，也不含 BusyBox。
- `run.sh`：QEMU 启动脚本。
- 仅 `x86_64`：`honk-efi.img`（供 bhyve 使用的 UEFI 磁盘）和 `run-bhyve.sh`。

在本地用 [`install/vm/build.sh`](../../../install/vm/build.sh) 可以构建出同样的文件。

## 用 QEMU 运行

```sh
./run.sh --config my.dae [--include rules.dae ...] [--api-port 9527] [--fwd 宿主端口:客户端口 ...]
```

`run.sh` 在 `x86_64` 上使用 `q35`，在 `aarch64` 和 `riscv64` 上使用 `virt`。宿主架构与镜像一致时，使用 KVM（macOS 上用 HVF），否则使用 TCG；可用 `--accel` 指定。QEMU 用户态网络只把 API 端口和各个 `--fwd` 端口转发到宿主的 `127.0.0.1`。

通过转发端口访问 API 时，配置里必须放行转发后的主机名，例如 `allowed_hosts: '127.0.0.1:9527'`。

## 配置

`/init` 按以下顺序取第一个存在的来源：

1. fw_cfg `opt/honk/config`，复制为 `/etc/honk/config.dae`；每个 `opt/honk/conf.d/<名字>` 复制为 `/etc/honk/conf.d/<名字>`。`run.sh --config` 和 `--include` 传入的就是这两类条目。
2. 内核命令行 `honk.cfg_b64=<base64>`，适合小配置。
3. tag 为 `honkcfg` 的 virtio-9p 共享目录中的 `config.dae`（`run.sh --9p DIR`），直接使用原文件，通过 API 做的修改会保留。
4. 内置兜底配置，不开放 API。

fw_cfg 只读，客户机也没有其他磁盘，所以对来源 1、2 的 API 修改在 VM 停止后丢失。

`eth0` 使用静态 IPv4 地址，没有 DHCP 客户端。默认值与 QEMU 用户态网络一致（`10.0.2.15/24`，网关 `10.0.2.2`，DNS `10.0.2.3`）。fw_cfg 条目 `opt/honk/ip`、`opt/honk/gw`、`opt/honk/dns`，或内核命令行 `honk.ip=`、`honk.gw=`、`honk.dns=` 可以覆盖默认值。

`honk-core` 退出后 `/init` 会关机。没有 shell，排查问题请看串口日志和 API。

## FreeBSD

FreeBSD 上的 QEMU 没有硬件加速，`run.sh` 只能用 TCG。honk 启动的大部分时间花在 eBPF verifier 上，这一步在 TCG 下很慢。

bhyve 可以硬件加速 `x86_64` 客户机，从 FreeBSD 14.0 起也支持与 QEMU 兼容的 fw_cfg，但它不能直接引导内核。所以 `honk-efi.img` 中的内核内置了 initramfs 和命令行，由 bhyve 的 UEFI 固件（`sysutils/edk2`）引导：

```sh
./run-bhyve.sh -c my.dae -t tap0 -i 192.0.2.10/24 -g 192.0.2.1 [-d 192.0.2.1]
```

tap 接口必须事先加入一个能到达网关的 bridge。地址参数会以 fw_cfg 条目 `opt/honk/ip`、`gw`、`dns` 传入。
