# honk 直通手册

honk 是 Linux 上的实验性 eBPF 透明代理引擎。本文只说明普通用户需要的安装、配置和启动步骤；配置字段与实现细节请查阅文末链接。

> **注意**
>
> honk 当前仍是 `v0.0.1-alpha`。真实模式会加载 eBPF、挂接 TC/cgroup hook、创建 `dae0`/`daens`、调整 sysctl，并在默认配置下占用 NFQUEUE 320。首次部署请保留带外管理通道。

## Linux 内核要求

### 内核版本

```shell
uname -r
```

- 仅支持 Linux；真实透明代理必须以 `root` 运行。
- 当前 eBPF 程序使用 `bpf_loop`，无发行版 backport 时需要 Linux `5.17+`。
- 推荐 Linux `6.8+`。`bpf_redirect_peer` 快路径也可用于带安全 backport 的 `5.15.164+`、`6.1.99+` 和 `6.6.40+`；其他受支持内核自动使用普通 redirect。
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
CONFIG_NET_CLS_BPF=y|m
CONFIG_NET_SCH_INGRESS=y|m
CONFIG_NET_CLS_ACT=y
CONFIG_NET_NS=y
```

默认启用的 held-first-packet UDP 还需要：

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
CONFIG_NFNETLINK_QUEUE=y|m
```

`pname(...)` 路由需要 cgroup v2。缺少 cgroup v2 时，其余功能仍可启动，但进程名路由会被禁用。

### bpffs

eBPF map 必须 pin 在 bpffs，而不是普通目录：

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

从 [GitHub Releases](https://github.com/daeuniverse/honk/releases) 下载与设备架构匹配的包：

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`

musl 包是静态二进制，适合网关部署。无 `-stock` 后缀的包使用 mimalloc，吞吐优先；`-stock` 包使用系统 allocator，更适合关注内存高水位的小内存设备。

```shell
tar -xzf honk-core-<版本>-<目标>.tar.gz
sudo install -m 0755 honk-core-<版本>-<目标>/honk-core /usr/local/bin/honk-core
honk-core --version
```

release binary 已内嵌 eBPF object，不需要单独安装 `honk-ebpf`。运行时也不会调用 `ip`、`nft`、`iptables` 或 `nsenter` 子进程。

### 从源码构建

源码构建需要：

- Rust stable；
- `nightly-2026-07-20`、`rust-src`、`llvm-tools-preview`；
- `bpf-linker 0.10.3`；
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

安装 Rust 工具链：

```shell
rustup toolchain install stable --profile minimal
rustup toolchain install nightly-2026-07-20 --profile minimal \
  --component rust-src --component llvm-tools-preview
cargo install bpf-linker --version 0.10.3
```

构建当前 `main`：

```shell
git clone https://github.com/daeuniverse/honk.git
cd honk

# 当前 eBPF Cargo 配置含维护者机器上的 linker 路径；干净环境改用 PATH。
sed -i 's|linker=/root/.cargo/bin/bpf-linker-wrapper|linker=bpf-linker|' \
  crates/honk-ebpf/.cargo/config.toml

unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
(
  cd crates/honk-ebpf
  cargo +nightly-2026-07-20 build --release \
    -Zbuild-std=core --target bpfel-unknown-none
)

readelf -S crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf \
  | grep -q '\.BTF'
cargo +stable build --release -p honk-core --features ebpf
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
ExecStart=/usr/local/bin/honk-core --config /etc/honk/config.dae
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

不要在未验证前添加严格的 capability bounding、只读 `/proc/sys` 或 `NoNewPrivileges=yes`；启动需要 BPF、网络管理、network namespace、mount、sysctl 和 transparent socket 权限。

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
cargo +stable build --release -p honk-tool
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

是否应用成功以运行日志中的 `applied` 或 `rejected` 为准。接口、TPROXY、`data_dir`、NFQUEUE 开关、DNS bind、Clash API listener/secret、cache 等进程级设置发生变化时，需要 restart。

正常停止：

```shell
sudo systemctl stop honk-core
```

不要使用 `kill -9` 做日常停止。honk 会先关闭 datapath admission，再 fence NFQUEUE 并拆除 hook/link。同一主机只能运行一个真实 datapath 实例；`/run/honk-core.lock` 用于阻止资源冲突。

## 无 root 开发

`--mock-ebpf` 可以验证配置、API、DNS 和 userspace 出站，但不会拦截任何真实流量。

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
cargo +stable run --release -p honk-core -- \
  --config /tmp/honk.dae --mock-ebpf
```

## 当前能力和限制

- 出站支持 Direct、Block、SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess 和 VLESS。
- UDP 支持 Direct、SOCKS5、Shadowsocks、Trojan、AnyTLS、Hysteria2、TUIC、Juicity，以及非 legacy 模式的 VLESS；VMess 和 legacy VLESS 仅支持 TCP。
- group 支持 Selector、URLTest、LoadBalance、Fallback 和 Score。
- DNS 上游支持 UDP、TCP、DoT、DoH、DoH3 和 DoQ，也可经 node/group 出站。
- `direct` 和 `block` 是内建节点，不要在配置中重复声明。
- `nfqueue_enable` 默认开启，固定使用 queue 320，并独占 `inet honk_nfqueue` / `udp_decision`。同一 network namespace 中的防火墙管理器不能改动这些对象。
- mock 或未启用 Cargo `ebpf` feature 的构建不会提供透明代理。普通 `cargo build --release` 不包含真实 datapath；必须使用 `--features ebpf`。
- 当前没有 VMess UDP、rootless datapath、Dockerfile 或 docker-compose 配置，也不支持非 Linux 系统。

## 常见问题

| 现象 | 处理 |
| --- | --- |
| `bpf-linker-wrapper` 不存在 | 按源码构建章节把维护者路径替换为 PATH 中的 `bpf-linker`。 |
| `no BTF parsed for object` | 清除 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS`，重新构建 eBPF object，并用 `readelf` 确认 `.BTF`。 |
| verifier 报 `unknown bpf func`/`bpf_loop` | 升级内核，或使用明确 backport 该 helper 的发行版内核。 |
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
