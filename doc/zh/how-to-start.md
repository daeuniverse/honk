# honk 直通手册

按本页安装、配置并启动 honk。honk 是 Linux 上的实验性 eBPF 透明代理引擎，配置字段与实现细节见文末链接。

> 注意
>
> honk 仍处于 alpha 阶段。真实模式会加载 eBPF、挂接 TC/cgroup hook、创建 `dae0`/`daens`、调整 sysctl，默认还占用 NFQUEUE 320。首次部署时请保留一条带外管理通道。

## Linux 内核要求

### 内核版本

```shell
uname -r
```

- 仅支持 Linux；真实透明代理必须以 `root` 运行。
- 编译式路由及其 map-in-map 同步发布保证要求 Linux `6.12+`。旧内核会在挂接前被拒绝。
- `netkit` 不是必需项；内核不支持时 honk 自动回退到 veth。

`lan_interface` 用于代理从局域网进入网关的流量，`wan_interface` 用于代理网关本机发起的流量：

- 只配置 LAN：只代理转发流量。
- 只配置 WAN：只代理本机流量。
- 两者都配置：同时代理转发和本机流量。
- `wan_interface: auto` 跟随最低 metric 的 IPv4 默认路由。

### 内核配置

桌面和服务器发行版通常已经启用所需 feature；OpenWrt、Armbian、VyOS 等精简系统需要额外确认。查看当前内核配置：

```shell
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

真实数据路径至少需要以下内核选项提供的 capability：

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

TCX 后端需要 `CONFIG_NET_XGRESS`。这个选项是隐藏的，由 `CONFIG_NET_CLS_ACT` 选中；旧的 `CONFIG_NET_CLS_BPF` 和 `CONFIG_NET_SCH_INGRESS` 都不需要。参见 [hook 与 qdisc 所有权](./design/datapath.md#接口-hook-集合)。

默认启用首包保留的 UDP 还需要：

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NFT_CT=y|m
CONFIG_NFT_QUEUE=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
```

必须启用 cgroup v2 和 `CONFIG_CGROUP_BPF`。真实数据路径会在根 cgroup 上挂接 socket 身份 hook 和 TCP `sock_ops` 程序 `honk_tcp_passive`。两项缺任何一项，启动都会失败。根 cgroup 的 `sock_ops` 槽位如果已经被 flags=0 的旧式程序占着，启动同样会失败，用 `bpftool cgroup attach` 挂上的程序也算。

`honk_tcp_passive` 会收到主机上每次 TCP `sock_ops` 回调，每条连接若干次；遇到不属于 honk 命名空间的 socket 就直接返回。TCP 归属证明不需要内核自带 BTF、ftrace 或内置 IPv6，有外部原始 BTF 文件就够了。

启动时总会加载原始 BTF。eBPF 加载器把它当作目标 BTF，并从里面取进程名和接收追踪所需的偏移。选择文件的顺序如下：

1. `HONK_VMLINUX_BTF` 指定的文件。
2. 未设置覆盖路径时，读取 `/sys/kernel/btf/vmlinux`。
3. 前一默认路径不可读时，读取 `/usr/lib/debug/boot/vmlinux`。OpenWrt 的 `vmlinux-btf` 包将文件安装在此处。

只有可选的 `native-api` UDP 接收追踪回退会挂接 fentry/fexit 程序，用于 UDP 接收优先级辅助元数据不可用的情况。它需要内核自带 BTF 和 ftrace，`HONK_VMLINUX_BTF` 替代不了内核自带 BTF；缺了就降级运行：

```text
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
```

`udp_recvmsg` 或 `udpv6_recvmsg` hook 缺失或不兼容时，只会禁用对应 socket 地址族的回退机制；两个地址族都依赖共享的 `__skb_recv_udp` hook。回退机制部分成功或失败后，listener reload 不会重试，改完内核或 BTF 支持要重启。见[接收追踪所有权](./design/control-plane.md#启动与关闭)。

### bpffs

eBPF map 必须固定在 bpffs，不能使用普通目录：

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

从 [GitHub Releases](https://github.com/daeuniverse/honk/releases) 下载与设备架构匹配的包。每个包名都以变体后缀结尾；旧版本的 full 构建没有后缀：

| 变体 | 包后缀 | Release 标签 | 内容 |
|---|---|---|---|
| full | `-full` | `fullapi` | Clash API、原生 API 与内嵌 doona UI；平台为 `x86_64` 和 `aarch64`，libc 为 gnu 和 musl |
| clash-api | `-clash-api` | `clashapi` | 仅 Clash API；不含原生 API 与内嵌 UI，只发布 musl 包 |
| native-api | `-native-api` | `nativeapi` | 仅原生 API；不含 Clash API 与内嵌 UI，只发布 musl 包 |

musl 包是静态二进制，适合网关部署。

| 内存分配器变体 | 发布标签 | 适用场景 |
| --- | --- | --- |
| 无 `-stock` 后缀：jemalloc | `jemalloc` | 优先考虑吞吐。 |
| `-stock`：系统内存分配器 | `stockalloc` | 更关注 RSS 峰值的小内存设备。 |

每个发布版本的 Downloads 一节按 `{allocator}-{API}-{arch}-{libc}` 标签列出全部归档。

精简变体一律 fail-closed。在 `-clash-api` 上启用 `experimental.native_api` 会启动失败；没有 `native-ui` 却设置 `ui: embedded` 或 `ui: embedded-lite`，同样会失败。`--store db` 和原生配置管理需要 `native-api`。`embedded-lite` 选择更轻量的 doona lite 预览版。

```shell
pkg=honk-core-<version>-<target>-full   # 或按下载的包改为 -stock-full、-clash-api、-stock-native-api 等
awk -v file="$pkg.tar.gz" '$2 == file' SHA256SUMS | sha256sum -c -   # SHA256SUMS 从同一个 release 下载
tar -xzf "$pkg.tar.gz"
sudo install -m 0755 "$pkg/honk-core" /usr/local/bin/honk-core
honk-core --version
```

装有 GitHub CLI 时，还可以用 `gh attestation verify "$pkg.tar.gz" -R daeuniverse/honk` 确认该包由本仓库的发布工作流构建。

发布二进制已内嵌 eBPF 目标文件，不需要单独安装 `honk-ebpf`。运行时也不会调用 `ip`、`nft`、`iptables` 或 `nsenter` 子进程。

### 发行版软件包

正式版本还附带 `x86_64` 与 `aarch64` 静态 musl full 构建的软件包：Debian 和 Ubuntu 用 `.deb`，Fedora 和 RHEL 用 `.rpm`，Arch Linux 用 `.pkg.tar.zst`。软件包会安装 `/usr/bin/honk-core`、`honk-core.service` 和 `/etc/honk/example.dae`，因此不需要再按[使用 systemd 运行](#使用-systemd-运行)操作。

```shell
sudo apt install ./honk-core-<version>-x86_64.deb       # Debian、Ubuntu
sudo dnf install ./honk-core-<version>-x86_64.rpm       # Fedora、RHEL
sudo pacman -U ./honk-core-<version>-x86_64.pkg.tar.zst # Arch Linux
sudo cp /etc/honk/example.dae /etc/honk/config.dae      # 然后按需修改
sudo systemctl enable --now honk-core
```

升级软件包会重启正在运行的 `honk-core.service`，卸载软件包会停止并禁用该服务。honk 与 dae 挂接到同一批网卡上，不能同时运行：该服务声明了 `Conflicts=dae.service`，启动其中一个就会停止另一个。从 dae 切换过来时，还要执行 `sudo systemctl disable dae`，避免 dae 开机自启。

### 从源码构建

编译带真实 eBPF 的源码版本需要下面这些工具：

- 根目录 `rust-toolchain.toml` 中固定的 Rust stable，含 `rustfmt` 和 `clippy`；
- `crates/honk-ebpf/rust-toolchain.toml` 中固定的 nightly，含 `rust-src` 和 `llvm-tools`；
- `.github/ci/pins.env` 中固定的 `bpf-linker` 版本；
- C/C++ 工具链、CMake、Clang、LLVM、libclang、libbpf 头文件、binutils、pkg-config 和 Git；
- 能访问 crates.io 和 GitHub 的网络。

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

`RUSTFLAGS` 会覆盖 eBPF crate 的 BTF 参数，而 Aya 加载不了缺少 `.BTF` 的目标文件，所以清理环境变量和检查 `.BTF` 这两步不能省。

## 最小配置

先用仅直连的配置确认数据路径能正常启动，再加入订阅或代理节点。把 `br-lan` 替换为客户端流量实际进入的 LAN 接口；只代理本机时删除 `lan_interface`。

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

默认运行时根目录是 `/var/lib/honk`。旧根目录 `/var/share/honk` 里的资源仍可按各路径规则继续使用；旧缓存和订阅导入会把符合条件的状态复制到 `state/honk.db`。自定义 `data_dir` 也遵循同样的回退顺序。缓存、订阅存储、ECH/UI 和其他只读依赖如果是相对路径，会依次在 `global.data_dir` 选定的运行时目录、`/var/share/honk` 和调用方的旧位置查找，取第一个存在的。相对日志只在该运行时目录下创建，不会写到配置文件所在目录。

前台启动：

```shell
sudo /usr/local/bin/honk-core --config /etc/honk/config.dae
```

日志出现 `honk-core is running` 后，先用真实 LAN 客户端确认能上网，再添加节点、订阅、代理组、路由和 DNS。按下面几步换成最小代理配置：

1. 保留仅直连配置的 `global` 小节。
2. 添加示例中的 `node` 和 `group` 小节。
3. 将整个 `routing { fallback: direct }` 小节替换为 `routing { fallback: proxy }`。不要追加第二个 `routing` 小节。
4. 将示例地址和凭据替换为真实节点的信息。

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

### 旁路由

honk 不支持这种部署，相关的提问和问题报告不予答复。

单臂网关也常叫旁路由：`lan_interface` 和 WAN 是同一个接口或网桥，客户端把 honk 主机设为网关，主机再从同一接口把流量转给上游路由器。这类主机要设置下面三个内核参数。honk 不会自己设置，`auto_config_kernel_parameter` 也不改这三项，见[全局配置参考](reference/global.md)。

- 开启 `send_redirects` 时，内核会向客户端发 ICMP 重定向，让客户端把流量直接发给上游路由器，流量就绕过了 honk。`all` 和接口的值只要有一个是 `1`，内核就会发重定向，所以两者都要设为 `0`。
- honk 只把第一个已绑定 LAN 接口的 `rp_filter` 设为 `0`，但内核取 `all` 和接口两者中较大的值，所以 `all` 上的 `1` 或 `2` 会覆盖这个设置。要把 `all` 设为 `0`。

把 `br-lan` 替换为 `lan_interface` 中的接口名，然后加载该文件：

```shell
sudo tee /etc/sysctl.d/60-honk-single-arm.conf <<'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.br-lan.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
EOF
sudo sysctl -p /etc/sysctl.d/60-honk-single-arm.conf
```

该文件在每次开机时也会生效。检查取值，三项均应为 `0`：

```shell
sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.br-lan.send_redirects net.ipv4.conf.all.rp_filter
```

收到过重定向的客户端可能还会用学到的路由一段时间，测试前先让它重新连一次网络。

#### 直连流量不通

症状是客户端能打开走代理的网站，打不开直连的网站，`ping` 也不通，而 honk 主机本身访问正常。走代理的 TCP 和 UDP 由 honk 在主机上接管，再由主机另建连接；直连流量和 ICMP 则由主机转发，因此丢弃转发流量的防火墙只影响后者。以下两种防火墙设置会造成这种情况。

Docker 通常会把 iptables `FORWARD` 链的默认策略设为 `DROP`，所有转发流量都会被丢弃。先检查默认策略，如果第一条命令输出 `-P FORWARD DROP`，就在 Docker 的 `DOCKER-USER` 链中放行从 LAN 接口进出的流量：

```shell
sudo iptables -S FORWARD | head -1
sudo iptables -I DOCKER-USER -i br-lan -o br-lan -j ACCEPT
```

另一些防火墙会丢弃连接跟踪标记为 `INVALID` 的数据包，OpenWrt 的默认区域就是这样。上游路由器和客户端在同一网段，会直接回复客户端，于是主机只看到直连连接的一个方向，连接跟踪就会把这条连接后续的数据包标成 `INVALID`。给转发流量做地址伪装后，回复会经主机返回；代价是上游路由器把所有客户端都看成主机的地址：

```shell
sudo iptables -t nat -A POSTROUTING -o br-lan -j MASQUERADE
```

OpenWrt 上改为在 LAN 区域开启 IP 动态伪装。以上 iptables 规则重启后都会失效，请把需要的那条写入主机的防火墙配置。

### 网页界面与 API

把下面任意一种配置加入配置文件，然后重启 honk。这些示例只监听本机地址；其他字段和反向代理要求见 [experimental 参考](reference/experimental.md)。

doona 通过原生 API 提供。下例使用内嵌界面的 `full` 发布版本；构建时启用 `native-api` 的版本也可以用单独安装的 doona 目录，把 `ui` 设为该目录的路径即可。

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        password_auth: true
        config_write: true
        ui: 'embedded'
    }
}
```

启动后打开 `http://127.0.0.1:9527/ui/`。

- `enabled` 启用原生 API listener；`listen` 指定监听地址和端口。
- `password_auth` 启用密码登录。首次访问时创建管理员账号，账号保存在 `data_dir` 下的 `state/honk.db` 里，不在配置文件中。
- `config_write` 允许通过认证的用户写入配置并 reload。含 listener 凭据的源文件仍然只读。
- `ui: 'embedded'` 提供二进制程序内嵌的标准版 doona，启动时不下载面板。

doona lite 是更轻量的预览版，构建要求、访问地址和登录步骤与上面的内嵌示例相同。用下面的配置替换标准版 doona 配置：

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        password_auth: true
        config_write: true
        ui: 'embedded-lite'
    }
}
```

Clash 面板要通过 Clash API 访问。使用启用了 `clash-api` 的构建，例如 `full` 或 `clash-api` 发布版本，并把 secret 换成一个足够长的随机字符串：

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: '<a long random string>'
    }
}
```

`external_controller` 启用 Clash listener，`external_ui` 指定面板目录。首次启动时如果目录不存在或为空，honk 会下载 zashboard。打开 `http://127.0.0.1:9090/ui/`，在面板里填入配置的 `secret` 连接 API。API 用它认证，静态界面文件不需要认证就能访问。

同时包含两种 API feature 的构建可以一起运行，例如 `full`。把 `native_api` 和 `clash_api` 并排写在同一个 `experimental` 小节里，各自使用不同的监听端口。

### GeoIP 和 Geosite

只有配置引用 `geoip:` 或 `geosite:` 时才需要下载：

```shell
sudo curl -fL --retry 3 -o /var/lib/honk/geosite.dat \
  https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -fL --retry 3 -o /var/lib/honk/geoip.dat \
  https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
```

引擎按以下顺序选择第一个已存在的普通文件：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`
4. `./<name>`
5. `/usr/local/share/honk/<name>`
6. `/usr/share/honk/<name>`
7. `/usr/local/share/dae/<name>`
8. `/usr/share/dae/<name>`
9. `/etc/dae/<name>`

## 使用 systemd 运行

创建 `/etc/systemd/system/honk-core.service`：

```ini
[Unit]
Description=honk transparent proxy engine
Wants=network-online.target
After=network-online.target
Conflicts=dae.service

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

严格的 capability bounding、只读 `/proc/sys` 和 `NoNewPrivileges=yes` 都要先验证再加。启动需要 BPF、网络管理、网络命名空间、挂载、sysctl 和透明 socket 权限。

## 使用 Docker 运行

[GitHub Container Registry](https://github.com/daeuniverse/honk/pkgs/container/honk) 上的镜像 `ghcr.io/daeuniverse/honk` 包含 musl `full` 发布版二进制，以及仓库固定版本的 GeoIP 和 Geosite 文件，构建时对每个下载文件做 SHA-256 校验。镜像标签是去掉 `v` 的版本号，例如 `ghcr.io/daeuniverse/honk:0.1.0-beta.4`；`latest` 只指向正式版，不含预发布版。镜像有 linux/amd64 和 linux/arm64 两种架构，拉取不需要登录。

honk 要加载并挂接 eBPF 程序、创建 `dae0` 和 `daens` 命名空间、修改 sysctl，还要在宿主机的 bpffs 上固定 map，所以容器以特权模式运行，并共享宿主机的网络和 PID 命名空间。它对宿主机的改动和直接安装一样，没有任何隔离。宿主机必须满足[内核要求](#linux-内核要求)，包括 Linux 6.12+ 和已挂载的 bpffs。

按[最小配置](#最小配置)准备 `/etc/honk/config.dae` 和 `/var/lib/honk`，然后在 `.env` 中写入发布版本号，再启动仓库中的 `docker-compose.yml`：

```shell
curl -fLO https://raw.githubusercontent.com/daeuniverse/honk/main/docker-compose.yml
echo 'HONK_VERSION=<version>' > .env   # 例如 0.1.0-beta.4
sudo touch /run/honk-core.lock
sudo docker compose up -d
sudo docker compose logs -f
```

该文件把宿主机的 `/sys`、`/etc/honk`、`/var/lib/honk` 挂载进容器，并以只读方式挂载 `/etc/localtime`，让容器的日志时间戳和 geodata 更新时间跟随宿主机时区。宿主机没有 `/etc/localtime` 时，删除这项挂载，改在服务的 `environment` 里把 `TZ` 设为 `CST-8` 这类 POSIX 字符串。配置目录的挂载会覆盖镜像里仅直连的默认配置；`/var/lib/honk` 保存运行时状态，例如原生 API 的管理员账户，重启或升级后仍然保留。要 reload 配置，执行 `sudo docker compose exec honk honk-core reload`。镜像自带 iproute2 和 nftables，容器又和宿主机共用网络命名空间，所以 `sudo docker compose exec honk ip rule`、`ip route show table all`、`tc filter show dev <网卡> ingress` 和 `nft list ruleset` 显示的就是宿主机的状态。

锁文件挂载让容器和原生实例共用 `/run/honk-core.lock`，容器因此无法接管正在运行的数据路径。停止后也要保留这个文件，不要删除、替换或截断仍可能被实例持有的锁。每次开机都要先创建锁文件，再启动容器。使用 systemd 的宿主机可以配置不截断已有文件的开机创建规则：

```shell
echo 'f /run/honk-core.lock 0600 root root -' | sudo tee /etc/tmpfiles.d/honk-container.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/honk-container.conf
```

其他 init 系统也要在开机启动容器之前，用不截断的方式创建这个文件。直接用 `docker run` 或 `podman run` 部署时，同样要挂载这个锁文件。

如果宿主机用外部原始 BTF 文件，而不是 `/sys/kernel/btf/vmlinux`，把下面内容保存为 `docker-compose.yml` 同目录的 `docker-compose.override.yml`。Compose 的每条命令都会加载它，升级也一样。把 `source` 改成宿主机的原始 BTF 文件路径，环境变量写容器内的挂载路径：

```yaml
services:
  honk:
    environment:
      HONK_VMLINUX_BTF: /run/honk-vmlinux
    volumes:
      - type: bind
        source: /usr/lib/debug/boot/vmlinux
        target: /run/honk-vmlinux
        read_only: true
        bind:
          create_host_path: false
```

升级时修改 `.env` 中的 `HONK_VERSION`，然后重新创建容器：

```shell
sudo docker compose pull
sudo docker compose up -d
```

在仓库检出目录里执行 `sudo docker compose build`，可以直接用已发布的版本构建同一个镜像，不必拉取。

## 检查运行状态

进程启动不等于数据路径可用。日志应显示真实 eBPF 后端、接口 hook、listener 和控制面均已就绪。

接口绑定状态对应以下日志：

| 接口状态 | 日志级别与频率 | 消息 |
| --- | --- | --- |
| hook 已就绪 | 绑定时记录一次 `info` | `configured interface is bound` |
| 接口不存在，或 `auto` 没有默认路由 | 一次 warning，之后为 `debug` | `configured interface is not bound yet` |
| 挂接失败 | 一次 warning，之后为 `debug` | `configured interface attach failed; retrying` |
| 不支持的链路类型 | 一次 error | `configured interface is not supported` |

`GET /runtime` 会在 `interface_binding` 中以降级状态报告未绑定的接口。见 [API 参考](./reference/api.md#原生-api)。

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

## 热 reload 和停止

```shell
sudo systemctl reload honk-core
# 或
sudo /usr/local/bin/honk-core reload
```

是否应用成功，看运行日志里的 `applied` 或 `rejected`。接口、TPROXY、`data_dir`、NFQUEUE 开关、DNS 绑定、Clash API listener/secret、缓存等进程级设置发生变化时，需要重启。运行期间出现或消失的接口不用 reload，接口观察器会自动绑定和释放它们。

正常停止：

```shell
sudo systemctl stop honk-core
```

不要用 `kill -9` 做日常停止。honk 会先关闭数据路径 admission，再 fence NFQUEUE，然后拆掉 hook 和 link。同一主机只能运行一个真实数据路径实例，`/run/honk-core.lock` 用来避免固定资源冲突。

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

## 当前 capability 和限制

- 出站支持 Direct、Block、SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess 和 VLESS。
- UDP 支持 Direct、SOCKS5、Shadowsocks、Trojan、AnyTLS、Hysteria2、TUIC、Juicity，以及独立 packet permission 已开启的 VLESS。VLESS 的回退编码和多路复用 carrier 是两个独立选择；VMess 仍只支持 TCP。见 [VLESS 节点参考](reference/nodes.md#vless-udp-and-multiplexing)。
- 组支持 Selector、URLTest、LoadBalance、Fallback 和 Score。
- DNS 上游支持 UDP、TCP、DoT、DoH、DoH3 和 DoQ，也可经 node/group 出站。
- `direct` 和 `block` 是内置节点，不要在配置中重复声明。
- `nfqueue_enable` 默认开启，固定使用队列 320，并独占 `inet honk_nfqueue` / `udp_decision`。同一网络命名空间中的防火墙管理器不能改动这些对象。
- mock 构建，以及没有启用 Cargo `ebpf` feature 的构建，都不提供透明代理。普通 `cargo build --release` 不含真实数据路径，必须加 `--features ebpf`。
- 当前没有 VMess UDP 和无 root 数据路径，也不支持非 Linux 系统。

## 常见问题

| 现象 | 处理 |
| --- | --- |
| `bpf-linker` 不存在 | 按源码构建章节安装，并把 Cargo 的 bin 目录加入 PATH。 |
| `no BTF parsed for object` | 清除 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS`，重新构建 eBPF 目标文件，并用 `readelf` 确认 `.BTF`。 |
| 内核或 verifier 拒绝编译式路由 | 使用支持 BPF/BTF 和 freplace 的 Linux `6.12+`；保留完整的 verifier 日志和生成规则的定位信息，不要绕过启动失败。 |
| pin map 报 `Invalid argument` | `/sys/fs/bpf` 不是 bpffs；按上文重新挂载。 |
| mock 启动成功但流量不经过 honk | 这是预期行为；改用含 `ebpf` feature 的构建，并以 root 启动。 |
| NFQUEUE disabled 或 queue busy | 检查 nftables/NFQUEUE 内核支持、队列 320 的占用者和残留的 honk 实例；确实不需要时设置 `nfqueue_enable: false`。 |
| LAN 流量未被代理 | `lan_interface` 为空或接口名错误；honk 不会自动改用 `lo`。接口名无误时看下一项。 |
| `GET /runtime` 出现 `interface_binding` 降级 | 某个已配置的接口还没绑定，日志里有接口名。`pending`：接口不存在，或 `auto` 条目没有 IPv4 默认路由。`unsupported_type`：链路类型被拒绝，例如 `lo`、VRF 设备或 `dae0`，请改成受支持的接口或其成员。`attach_failed`：TCX link 无法创建、更新或校验，原因见日志中的 warning。接口状态字段见[原生 API 参考](./reference/api.md#原生-api)。 |
| 旁路由的客户端绕过 honk，或转发的流量被丢弃 | 把 `all` 和 LAN 接口的 `send_redirects` 设为 `0`，并把 `net.ipv4.conf.all.rp_filter` 设为 `0`，见[旁路由](#旁路由)；直连流量仍不通时，见[直连流量不通](#直连流量不通)。 |
| VLESS/VMess 报 `No handler for protocol` | 构建缺少 `rprx`；使用默认 feature，或显式加上 `rprx`。 |
| Geo 规则加载失败 | 把 `geoip.dat`/`geosite.dat` 放进配置的 `data_dir`，或检查文档列出的旧目录和共享目录；不需要 Geo 规则就删掉。 |
| GNU 二进制在 VyOS/精简系统无法执行 | 改用同架构的 musl 发布版本。 |

## 继续阅读

- [配置指南](configuration.md)
- [全局配置](reference/global.md)
- [节点和协议](reference/nodes.md)
- [订阅](reference/subscription.md)
- [分组策略](reference/groups.md)
- [路由规则](reference/routing.md)
- [DNS 配置](reference/dns.md)
- [CLI](reference/cli.md)
- [架构概览](design/overview.md)

## 检查解析器改动

在仓库根目录执行 `just parser-ci`，需要固定版本的 stable Rust、Go 1.26 或更高版本、Python 3.11 或更高版本，以及网络。案例写法见 `crates/honk-config/conformance/README.md`；oracle 及其许可证见 `tools/dae-parse/README.md`。

该命令依次执行以下检查：

1. 构建固定版本的 dae oracle。
2. 拉取上游示例，并校验清单中的 SHA-256。
3. 比较解码后的结构与已记录的方言差异。
4. 重放保存的模糊测试输入。

Cargo 依赖已缓存时，`just fuzz-replay` 只需要 stable Rust。它使用与模糊测试目标相同的断言。重放失败会打印输入路径；输入处理停滞时，五秒后判定失败。

配置代码、oracle、模糊测试输入、语料来源文档或它们的构建输入发生变化时，会执行 `parser` CI 任务；指定 `ci:full` 时也会执行。普通工作区命令不启用 `conformance` 和 `fuzz-checks`，所以不需要 Go 或 nightly。

每周模糊测试任务使用以下设置：

| 设置 | 值 |
| --- | --- |
| Rust 通道 | `crates/honk-ebpf/rust-toolchain.toml` 中固定的 nightly |
| cargo-fuzz 版本 | 由 `.github/ci/pins.env` 固定 |
| 目标 | `document`、`share_link`、`lexer` |
| 时长与并发 | 每个目标执行 480 秒，两个 worker |
| 上传的产物 | 发现的问题与语料文件 |

将保留的问题输入放在 `fuzz/artifacts/<target>/` 下，即可在 stable 上重放。仅由 sanitizer 检出的问题仍需使用 nightly 模糊测试目标。
