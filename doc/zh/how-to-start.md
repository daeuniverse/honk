# honk 直通手册

honk 是 Linux 上的实验性 eBPF 透明代理引擎。本文说明普通用户需要的安装、配置和启动步骤；配置字段与实现细节见文末链接。

> **注意**
>
> honk 当前仍处于 alpha 阶段。真实模式会加载 eBPF、挂接 TC/cgroup hook、创建 `dae0`/`daens`、调整 sysctl，并在默认配置下占用 NFQUEUE 320。首次部署请保留带外管理通道。

## Linux 内核要求

### 内核版本

```shell
uname -r
```

- 仅支持 Linux；真实透明代理必须以 `root` 运行。
- 编译式路由及其 map-in-map 同步发布保证要求 Linux `6.12+`。旧内核会在附着前被拒绝。
- `netkit` 不是必需项；内核不支持时 honk 自动回退到 veth。

`lan_interface` 用于代理从局域网进入网关的流量，`wan_interface` 用于代理网关本机发起的流量：

- 只配置 LAN：只代理转发流量。
- 只配置 WAN：只代理本机流量。
- 两者都配置：同时代理转发和本机流量。
- `wan_interface: auto` 跟随最低 metric 的 IPv4 默认路由。

### 内核配置

桌面和服务器发行版通常已经启用所需功能；OpenWrt、Armbian、VyOS 等精简系统需要额外确认。查看当前内核配置：

```shell
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

真实 datapath 至少需要对应下列能力的内核选项：

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_SCHED=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_XGRESS=y
CONFIG_NET_NS=y
```

TCX 后端需要由 `CONFIG_NET_CLS_ACT` 选中的隐藏选项 `CONFIG_NET_XGRESS`，不要求旧式 `CONFIG_NET_CLS_BPF` 或 `CONFIG_NET_SCH_INGRESS`。参见[挂钩与 qdisc 所有权](./design/datapath.md#接口挂钩集合)。

默认启用的 held-first-packet UDP 还需要：

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NFT_CT=y|m
CONFIG_NFT_QUEUE=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
```

必须启用 cgroup v2 与 `CONFIG_CGROUP_BPF`。真实 datapath 会在根 cgroup 上挂载 socket 身份 hook 与 TCP `sock_ops` 程序 `honk_tcp_passive`，缺少时直接拒绝启动。若根 cgroup 的 `sock_ops` 槽位已被旧式（flags=0）程序占用，例如用 `bpftool cgroup attach` 挂载的程序，启动同样失败。`honk_tcp_passive` 会被主机上每一次 TCP `sock_ops` 回调调用（每条连接若干次），对不属于 honk 命名空间的 socket 立即返回。TCP 归属证明不需要内核自带 BTF、不需要 ftrace，也不要求内置 IPv6，因此只有外部原始 BTF 文件的内核也能运行。启动时总会加载原始 BTF（eBPF 加载器的目标 BTF，以及进程名与接收追踪的偏移），来源依次为 `HONK_VMLINUX_BTF` 指定的文件、`/sys/kernel/btf/vmlinux`、`/usr/lib/debug/boot/vmlinux`（OpenWrt `vmlinux-btf` 包的安装位置）。

只有可选的 `native-api` UDP 接收追踪回退（UDP 接收优先级辅助元数据不可用时使用）会挂载 fentry/fexit 程序。它需要内核自带 BTF（`HONK_VMLINUX_BTF` 不能替代）与 ftrace，缺少时降级运行：

```text
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
```

`udp_recvmsg` 或 `udpv6_recvmsg` hook 缺失或不兼容时，只禁用对应 socket 地址族的 fallback；两个地址族都依赖共享的 `__skb_recv_udp` hook。Fallback 部分成功或失败后不会在 listener 重载时重试；修改内核/BTF 支持后需重启。见[接收追踪所有权](./design/control-plane.md#启动与关闭)。

### bpffs

eBPF map 必须 pin 在 bpffs，不能使用普通目录：

```shell
sudo install -d -m 0755 /sys/fs/bpf
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
mountpoint /sys/fs/bpf
```

若系统不会自动挂载，可加入 `/etc/fstab`：

```fstab
bpf /sys/fs/bpf bpf defaults 0 0
```

## 安装

### 预编译二进制

从 [GitHub Releases](https://github.com/daeuniverse/honk/releases) 下载与设备架构匹配的包。每个包名都以变体结尾（旧版本的 full 构建不带后缀）：

| 变体 | 包后缀 | Release 标签 | 内容 |
|---|---|---|---|
| full | `-full` | `fullapi` | Clash API、原生 API 与内嵌 doona UI（`x86_64`/`aarch64`，gnu 与 musl） |
| clash-api | `-clash-api` | `clashapi` | 仅 Clash API；不含原生 API 与内嵌 UI（仅 musl） |
| native-api | `-native-api` | `nativeapi` | 仅原生 API；不含 Clash API 与内嵌 UI（仅 musl） |

musl 包是静态二进制，适合网关部署。无 `-stock` 后缀的包使用 mimalloc，优先考虑吞吐（标签 `mimalloc`）；`-stock` 包使用系统 allocator，更适合关注内存峰值的小内存设备（标签 `stockalloc`）。每个 release 的 Downloads 一节按 `{allocator}-{API}-{arch}-{libc}` 标签列出全部归档。

精简变体按 fail-closed 处理：在 `-clash-api` 上启用 `experimental.native_api`，或没有 `native-ui` 却设置 `ui: embedded`，都会启动失败。`--store db` 与原生配置管理需要 `native-api`。

```shell
pkg=honk-core-<version>-<target>-full   # 或按下载的包改为 -stock-full、-clash-api、-stock-native-api 等
sha256sum -c --ignore-missing SHA256SUMS   # SHA256SUMS 从同一个 release 下载
tar -xzf "$pkg.tar.gz"
sudo install -m 0755 "$pkg/honk-core" /usr/local/bin/honk-core
honk-core --version
```

装有 GitHub CLI 时，还可以用 `gh attestation verify "$pkg.tar.gz" -R daeuniverse/honk` 确认该包由本仓库的发布 workflow 构建。

release binary 已内嵌 eBPF object，不需要单独安装 `honk-ebpf`。运行时也不会调用 `ip`、`nft`、`iptables` 或 `nsenter` 子进程。

### 从源码构建

源码构建需要：

- 根目录 `rust-toolchain.toml` 中固定的 Rust stable 版本（`rustfmt`、`clippy`）；
- `crates/honk-ebpf/rust-toolchain.toml` 中固定的 nightly 版本（`rust-src`、`llvm-tools`）；
- `.github/ci/pins.env` 中固定的 `bpf-linker` 版本；
- C/C++ toolchain、CMake、Clang、LLVM、libclang、libbpf headers、binutils、pkg-config、Git；
- 可访问 crates.io 和 GitHub 的网络。

Debian/Ubuntu：

```shell
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm libbpf-dev pkg-config \
  cmake libclang-dev binutils git curl ca-certificates
```

Arch Linux/CachyOS：

```shell
sudo pacman -S --needed \
  base-devel clang llvm libbpf cmake pkgconf git curl ca-certificates
```

克隆仓库，然后安装仓库指定的 Rust 工具链：

```shell
git clone https://github.com/daeuniverse/honk.git
cd honk
rustup toolchain install $(grep -oP '^channel\s*=\s*"\K[^"]+' rust-toolchain.toml) \
  --profile minimal --component rustfmt --component clippy
rustup toolchain install $(grep -oP '^channel\s*=\s*"\K[^"]+' crates/honk-ebpf/rust-toolchain.toml) \
  --profile minimal --component rust-src --component llvm-tools
source .github/ci/pins.env
cargo install bpf-linker --version "$BPF_LINKER_VERSION"
```

构建当前 `main`：

```shell
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
(
  cd crates/honk-ebpf
  cargo build --release \
    -Zbuild-std=core --target bpfel-unknown-none
)

readelf -S crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf \
  | grep -q '\.BTF'
cargo build --release -p honk-core --features ebpf
sudo install -m 0755 target/release/honk-core /usr/local/bin/honk-core
```

`RUSTFLAGS` 会覆盖 eBPF crate 的 BTF 参数；Aya 无法加载缺少 `.BTF` 的 object，因此不要省略清理和检查步骤。

## 最小配置

先用 direct-only 配置确认 datapath 能正常启动，再加入订阅或代理节点。把 `br-lan` 替换为客户端流量实际进入的 LAN 接口；只代理本机时删除 `lan_interface`。

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    data_dir: '/var/lib/honk'
    log_level: info
    dial_mode: domain
    auto_config_kernel_parameter: true
}

routing {
    fallback: direct
}
```

安装配置：

```shell
sudo install -d -m 0700 /etc/honk /var/lib/honk
sudo install -m 0600 /path/to/config.dae /etc/honk/config.dae
```

默认运行时根目录是 `/var/lib/honk`。旧根目录 `/var/share/honk` 中的已有资源会按各路径规则继续使用；honk 不会自动迁移它们；可写状态仍在原位置更新。自定义 `data_dir` 也遵循相同的回退顺序。相对缓存、订阅存储、ECH/UI 与其他只读依赖依次检查配置目录、`/var/share/honk`，再检查调用方的旧候选路径；相对日志只会在配置目录下创建。

前台启动：

```shell
sudo /usr/local/bin/honk-core --config /etc/honk/config.dae
```

看到 `honk-core is running` 后，从真实 LAN 客户端确认联网，再加入 node、subscription、group、routing 和 DNS。一个最小代理结构如下；地址必须替换成真实节点：

```dae
node {
    edge: 'socks5://user:password@proxy.example.com:1080'
}

group {
    proxy {
        filter: name('edge')
        policy: fixed(0)
    }
}

routing {
    fallback: proxy
}
```

代理服务器使用域名时，应在 `global` 中配置独立 bootstrap resolver，避免 DNS 自拦截：

```dae
bootstrap_resolver: '1.1.1.1:53'
```

完整配置方法见[中文配置指南](configuration.md)。仓库中的 `config.dae`、`config.min.dae` 和 `example.dae` 包含示例接口或节点，部署前必须按实际网络修改。

### GeoIP 和 Geosite

只有配置引用 `geoip:` 或 `geosite:` 时才需要下载：

```shell
sudo curl -fL --retry 3 -o /var/lib/honk/geosite.dat \
  https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -fL --retry 3 -o /var/lib/honk/geoip.dat \
  https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
```

引擎按以下顺序选择第一个已存在的普通文件：`$DAE_LOCATION_ASSET/<name>`、`<data_dir>/<name>`、`/var/share/honk/<name>`、`./<name>`、`/usr/local/share/honk/<name>`、`/usr/share/honk/<name>`、`/usr/local/share/dae/<name>`、`/usr/share/dae/<name>`，最后是 `/etc/dae/<name>`。

## 使用 systemd 运行

创建 `/etc/systemd/system/honk-core.service`：

```ini
[Unit]
Description=honk transparent proxy engine
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=root
WorkingDirectory=/var/lib/honk
ExecStart=/usr/local/bin/honk-core --config /etc/honk/config.dae --disable-timestamp
ExecReload=/usr/local/bin/honk-core reload
Restart=on-failure
RestartSec=2s
TimeoutStopSec=30s
LimitNOFILE=1048576
LimitMEMLOCK=infinity
UMask=0077

[Install]
WantedBy=multi-user.target
```

启动并设为开机自启：

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now honk-core
sudo systemctl status honk-core
sudo journalctl -xefu honk-core
```

不要在未验证前添加严格的 capability bounding、只读 `/proc/sys` 或 `NoNewPrivileges=yes`；启动需要 BPF、网络管理、网络命名空间、挂载、sysctl 和 transparent socket 权限。

## 检查运行状态

进程启动不等于 datapath 可用。日志应显示 real eBPF backend、接口 hook、listeners 和 control plane 均已 ready。

```shell
ip link show dae0
sudo bpftool prog show
sudo bpftool map show
sudo journalctl -u honk-core --since '5 minutes ago'
```

若从源码构建了 `honk-tool`，可执行一次只读诊断：

```shell
cargo build --release -p honk-tool
sudo ./target/release/honk-tool diagnose \
  --api http://127.0.0.1:9090 --pin-root /sys/fs/bpf
```

最终必须从真实客户端分别验证应直连和应代理的 TCP、UDP、DNS，以及部署需要的 IPv4/IPv6。`dae0` 存在或 API 可访问不能替代端到端验证。

## 热重载和停止

```shell
sudo systemctl reload honk-core
# 或
sudo /usr/local/bin/honk-core reload
```

是否应用成功以运行日志中的 `applied` 或 `rejected` 为准。接口、TPROXY、`data_dir`、NFQUEUE 开关、DNS bind、Clash API listener/secret、cache 等进程级设置发生变化时，需要重启。

正常停止：

```shell
sudo systemctl stop honk-core
```

不要使用 `kill -9` 做日常停止。honk 会先关闭 datapath admission，再 fence NFQUEUE 并拆除 hook/link。同一主机只能运行一个真实 datapath 实例；`/run/honk-core.lock` 用于阻止资源冲突。

## 无 root 开发

`--mock-ebpf` 可以验证配置、API、DNS 和用户态出站，但不会拦截任何真实流量。

将以下内容保存为 `/tmp/honk.dae`：

```dae
global {
    data_dir: '/tmp/honk'
    nfqueue_enable: false
    preconnect_node_count: 0
    udp_warm_node_count: 0
}

routing {
    fallback: direct
}
```

```shell
cargo run --release -p honk-core -- \
  --config /tmp/honk.dae --mock-ebpf
```

## 当前能力和限制

- 出站支持 Direct、Block、SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess 和 VLESS。
- UDP 支持 Direct、SOCKS5、Shadowsocks、Trojan、AnyTLS、Hysteria2、TUIC、Juicity，以及独立 packet 权限已开启的 VLESS。VLESS 的回退 encoding 与 multiplex carrier 是另外两个独立选择；VMess 仍仅支持 TCP。见 [VLESS 节点参考](reference/nodes.md#vless-udp-and-multiplexing)。
- group 支持 Selector、URLTest、LoadBalance、Fallback 和 Score。
- DNS 上游支持 UDP、TCP、DoT、DoH、DoH3 和 DoQ，也可经 node/group 出站。
- `direct` 和 `block` 是内建节点，不要在配置中重复声明。
- `nfqueue_enable` 默认开启，固定使用 queue 320，并独占 `inet honk_nfqueue` / `udp_decision`。同一网络命名空间中的防火墙管理器不能改动这些对象。
- mock 或未启用 Cargo `ebpf` feature 的构建不会提供透明代理。普通 `cargo build --release` 不包含真实 datapath；必须使用 `--features ebpf`。
- 当前没有 VMess UDP、rootless datapath、Dockerfile 或 docker-compose 配置，也不支持非 Linux 系统。

## 常见问题

| 现象 | 处理 |
| --- | --- |
| `bpf-linker` 不存在 | 按源码构建章节安装，并将 Cargo 的 bin 目录加入 PATH。 |
| `no BTF parsed for object` | 清除 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS`，重新构建 eBPF object，并用 `readelf` 确认 `.BTF`。 |
| 内核或 verifier 拒绝编译式路由 | 使用支持 BPF/BTF 和 freplace 的 Linux `6.12+`，保留完整 verifier 日志及生成规则定位信息，不要绕过启动失败。 |
| pin map 报 `Invalid argument` | `/sys/fs/bpf` 不是 bpffs；按上文重新挂载。 |
| mock 启动成功但流量不经过 honk | 这是预期行为；使用含 `ebpf` feature 的构建并以 root 启动。 |
| NFQUEUE disabled 或 queue busy | 检查 nftables/NFQUEUE 内核支持、queue 320 占用者和残留 honk 实例；确实不需要时设置 `nfqueue_enable: false`。 |
| LAN 流量未被代理 | `lan_interface` 为空或接口名错误；它不会自动使用 `lo`。 |
| VLESS/VMess 报 `No handler for protocol` | 构建缺少 `rprx`；使用默认 features，或显式加入 `rprx`。 |
| Geo rule 加载失败 | 将 `geoip.dat`/`geosite.dat` 放入配置的 `data_dir`，或检查文档所列的旧目录/共享目录搜索位置；不需要时删除未使用的 Geo rule。 |
| GNU binary 在 VyOS/精简系统无法执行 | 改用同架构的 musl release。 |

## 继续阅读

- [配置指南](configuration.md)
- [全局配置](reference/global.md)
- [节点和协议](reference/nodes.md)
- [分组策略](reference/groups.md)
- [路由规则](reference/routing.md)
- [DNS 配置](reference/dns.md)
- [CLI](reference/cli.md)
- [架构概览](design/overview.md)

## 检查解析器改动

在仓库根目录执行 `just parser-ci`，需要固定版本的 stable Rust、Go 1.26 或更新、Python 3.11 或更新，以及网络。它会构建固定版本的 dae oracle，按 manifest 里的 SHA-256 拉取上游示例，比较解码后的结构与已记录的方言差异，然后重放保存的 fuzz 输入。`just fuzz-replay` 只需要 stable Rust（Cargo 依赖已缓存时），使用与 fuzz target 相同的断言；重放失败会打印输入路径，输入卡住则在五秒后失败。案例写法见 `crates/honk-config/conformance/README.md`，oracle 及其许可证见 `tools/dae-parse/README.md`。

`parser` CI lane 在配置代码、oracle、fuzz 输入、语料来源文档及其构建输入改动时执行，也随 `ci:full` 执行。普通的工作区命令不会启用 `conformance` 或 `fuzz-checks`，既不需要 Go 也不需要 nightly。每周任务使用 `crates/honk-ebpf/rust-toolchain.toml` 里的 nightly 通道和 `.github/ci/pins.env` 里固定版本的 cargo-fuzz，对 `document`、`share_link`、`lexer` 各执行 480 秒、两个 worker，并上传发现与语料。把保留的发现放到 `fuzz/artifacts/<target>/` 下，就能在 stable 上重放。只有 sanitizer 才能发现的问题仍需 nightly 的 fuzz target。
