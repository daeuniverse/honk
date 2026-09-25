# 命令行参考

本文档覆盖当前的 `honk-core` 引擎 CLI 与 `honk-tool` 诊断工具箱。

## `honk-core`

`honk-core` 加载配置、初始化控制面，并选择真实 eBPF 后端或 mock 后端。

### 调用格式

```text
honk-core [OPTIONS] [COMMAND]
```

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `-c`, `--config PATH` | `/etc/honk/config.dae` | 配置入口文件。`mode`、`proxy` 和 `delay` 也读取此路径。`reload` 忽略此项，仅向运行中实例发送信号；运行实例重载其启动时使用的路径。 |
| `--log-file PATH` | 未设置 | 仅为本次引擎进程覆盖 `global.log_file`，不重写配置文件。相对路径在 `global.data_dir` 下解析，控制台日志保持启用。设置后，SIGHUP 会忽略被遮蔽配置值的变化，除非实际生效的目标发生改变。 |
| `-b`, `--bpf-object PATH` | 内嵌目标文件 | 覆盖 `ebpf` 构建内嵌的目标文件。仅真实后端使用。 |
| `--bpf-pin-root PATH` | `/sys/fs/bpf` | eBPF map 的 pin 根目录。 |
| `--disable-timestamp` | 关 | 控制台日志行不再带时间戳。在 systemd 或其他自带时间戳的日志系统下使用；`--log-file` 或 `global.log_file` 指定的文件仍带时间戳。 |
| `-d`, `--debug` | 关 | 当 `RUST_LOG` 未提供有效 filter 时，选择 `debug` 作为默认控制台 filter。 |
| `--mock-ebpf` | 关 | 使用 `MockEbpfBackend`，不加载内核 eBPF。若配置请求 `global.nfqueue_enable: true`，honk 会记录 warning 并仅在本进程关闭 NFQUEUE 暂存。 |

两个二进制都提供 `-h`/`--help` 和 `-v`/`--version`。

请使用匹配版本的 core、`honk-tool` 和 BPF 对象；不兼容对象及 pinned handoff 布局按[数据路径 ABI 契约](../design/datapath.md#map-清单)拒绝。

CLI 与 Clash API 共用构建时版本号：发布构建使用 GitHub tag 名；本地 Git 构建使用 `git describe --tags --always --match 'v*'`（tag，或最近 tag 加提交距离与哈希）。没有可用 Git 元数据时使用 Cargo 包版本。运行时不依赖 Git。

### 日志级别优先级

源码注释记载的预期顺序是 `--debug` → `RUST_LOG` → `global.log_level` → `info`。当前可执行文件会先选择 debug/配置默认值，再调用 `EnvFilter::try_from_default_env()`，因此有效的 `RUST_LOG` 目前优先：

| 当前优先级 | 来源 | 行为 |
| --- | --- | --- |
| 1 | `RUST_LOG` | 有效的 tracing filter 覆盖所有默认值，包括 `--debug`。 |
| 2 | `--debug` | `RUST_LOG` 不存在或无效时使用 `debug`。 |
| 3 | `global.log_level` | 未指定 `--debug` 且没有有效 `RUST_LOG` 时使用。 |
| 4 | `info` | `global.log_level` 为空时使用。 |

`log_level` 见[全局配置参考](./global.md)。

### 子命令

| 命令 | 当前行为 | 持久化 / 运行时影响 |
| --- | --- | --- |
| `reload` | 从已加锁的 `/run/honk-core.lock` 读取 PID 并发送 `SIGHUP`。 | 只报告信号成功送达；运行中进程随后记录 `applied` 或 `rejected`。mock 实例不持有该锁。 |
| `mode <rule\|global\|direct>` | 加载 `--config`，将参数字符串赋给 `experimental.clash_api.default_mode`，并在重写结构化格式文件前完成校验。`.dae` 文件会被拒绝且保持不变，因为 writer 无法保留 dae 语法、注释或 include；请直接编辑这些源文件，或使用 `.toml`、`.yaml`、`.json`。 | 仅修改文件；不联系运行中的引擎，也不更改 dial mode。接受的字符串不同于正常 dial mode 值 `ip`、`domain`、`domain+`、`domain++`。 |
| `proxy <group> <node>` | 检查组名和节点名各自存在，然后打印请求的选择；不检查节点是否属于该组。 | 不写入任何内容，也不联系运行中的引擎。 |
| `delay <node> [-u\|--url HOST:PORT]` | 建立一次原始 TCP 连接，超时五秒，并打印耗时毫秒数。未给 `--url` 时使用节点服务端地址。 | 不经过代理，不是 HTTP URLTest，也不联系运行中的引擎。 |

[编译路由发布计数器](../design/routing.md#同步槽与原子发布)耗尽后需重启；它与普通 SIGHUP 及 DNS runtime 重载分开计数。

真实数据面进程在其生命周期内持有该锁。`reload` 会先确认文件仍被锁定，再信任其中的 PID；`kill(2)` 成功送达并不表示候选配置通过校验或需重启字段检查。

## 环境变量

| 变量 | 作用范围 | 当前行为 |
| --- | --- | --- |
| `RUST_LOG` | 两个二进制 | Tracing filter。对 `honk-core` 采用上述当前有效优先级；`honk-tool` 在未设置时默认 `warn`。 |
| `HONK_UI_DOWNLOAD_URL` | 启用 `clash-api` 的 `honk-core` | dashboard ZIP URL 的最高优先级覆盖；已配置的外部 UI 目录需要下载时，它会覆盖 `external_ui_download_url`。 |
| `HONK_POOL_DISABLE=1` | `honk-core` | 绕过 Ready stream 与裸 TCP 两类池，每次全新拨号。代码也接受不区分大小写的 `true`；首次使用后缓存该值。 |
| `HONK_QUIC_GSO=0|1` | QUIC 出站 | 强制关闭/开启 UDP GSO。未覆盖时，保守的 1252-byte MTU 保持关闭；显式设置更大的 `mtu` 时自动开启，并把批量限制为最多 16 个 segment。 |
| `HONK_MI_COLLECT_SECS` | 启用 `mimalloc` 的 `honk-core` | 每个 owner worker 的空闲回收间隔。周期性 rendezvous 仅在其余 worker 均空闲时唤醒持续 park 的 owner，强制回收仍由各 owner 的 park 钩子执行。默认 `60`；`0` 同时关闭钩子与 rendezvous；无效值回退为 `60`。 |
| `HONK_VMLINUX_BTF` | 启用 `ebpf` 的 `honk-core` | 覆盖解析进程名字段偏移所用的原始内核 BTF 文件。未设置时，honk 依次检查 `/sys/kernel/btf/vmlinux` 与 `/usr/lib/debug/boot/vmlinux`；若运行时 BTF 偏移或内核 argv 访问无法通过 verifier，pname 同步回退到调用线程的 `comm`。 |
| `DAE_LOCATION_ASSET` | 两个二进制的 Geo 加载 | 最先检查其中的 `geoip.dat` 与 `geosite.dat`。 |

UDP NFQUEUE 没有环境变量开关，默认由 `global.nfqueue_enable` 开启；设置为 `false` 可关闭。见[全局配置参考](./global.md)与 [NFQUEUE 设计](../design/nfqueue.md)。

## eBPF 与运行时路径

| 项 | 控制方式 | 当前不变量 |
| --- | --- | --- |
| eBPF 目标文件 | 内嵌目标文件或 `--bpf-object PATH` | 启用 `ebpf` feature 时，`build.rs` 提供由 `include_bytes!` 内嵌的目标文件；该参数在运行时替换这些字节。未启用 `ebpf` 的构建使用 mock 后端。 |
| 内核 BTF | `HONK_VMLINUX_BTF` 或常用路径搜索 | 仅用于解析 `pname` 的内核字段偏移。未覆盖时，honk 先尝试 `/sys/kernel/btf/vmlinux`，再尝试 `/usr/lib/debug/boot/vmlinux`。 |
| Pin 根目录 | `--bpf-pin-root PATH` | 默认 `/sys/fs/bpf`，传给真实后端用于 pin map。 |
| Bypass mark | `global.so_mark_from_dae` | 拨号、探测、DNS 与下载使用的精确 socket mark；零值选择默认 `0x100`。修改需重启，见[套接字 mark](./global.md#套接字-mark)。 |
| TPROXY mark | 编译期常量与配置校验 | `TPROXY_MARK = 0x08000000`；`global.tproxy_mark` 必须等于该值。 |
| Geo 资源 | 运行时路径搜索 | 依次检查 `DAE_LOCATION_ASSET`、[`global.data_dir`](./global.md)、旧根目录 `/var/share/honk`、工作目录、`/usr/local/share/honk`、`/usr/share/honk`、`/usr/local/share/dae`、`/usr/share/dae`、`/etc/dae`；每个候选都必须是普通文件。 |

## `honk-tool`

`honk-tool` 是用于订阅探测、pin map 检查、引擎健康检查与离线 Geo 资源搜索的诊断工具箱。它不加载或挂载 eBPF 程序。

### 构建与部署

普通开发构建：

```bash
cargo build --release -p honk-tool
```

部署到网关时，使用仓库的 Zig 包装器构建静态 musl 目标，并复制单个二进制：

```bash
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl=$PWD/ci/zigcc \
CXX_x86_64_unknown_linux_musl=$PWD/ci/zigcxx \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$PWD/ci/zigcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$(ci/zig-bindgen-env x86_64-linux-musl)" \
cargo build --release -p honk-tool --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/honk-tool root@GATEWAY:/tmp/
```

当前 `just build-musl` 与 `just deploy-vyos` recipe 只构建和部署 `honk-core`，不包含 `honk-tool`。GNU 链接的构建可能无法在纯 musl 网关上执行。

### 命令族

| 命令族 | 用途 |
| --- | --- |
| `sub` | 拉取或解析节点，并探测 TCP 地址族、URLTest 与受支持的 UDP 路径。 |
| `bpf` | 读取并解码运行中引擎已经 pin 的 map。 |
| `diagnose` | 执行只读的引擎、网络设施、map 与 API 健康检查。 |
| `geosite` | 列出、检查和反向搜索 `geosite.dat`。 |
| `geoip` | 列出、检查和最长前缀搜索 `geoip.dat`。 |

二进制提供 `-h`/`--help` 和 `-v`/`--version`，每个命令族与 action 也有帮助信息。构建版本与 `honk-core` 一致。

### `sub`

```text
honk-tool sub <url|file|-> [--target HOST:PORT] [--url TEST_URL]
              [--udp-check HOST[:PORT]]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--tls-implementation tls|utls] [--utls-imitate PROFILE]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `<url\|file\|->` | 必填 | HTTP(S) 订阅 URL、已有本地订阅文件，或 `-`。`-` 从 stdin 读取且只接受一个 HTTP(S) 订阅 URL；不会从 stdin 读取订阅正文。 |
| `--target HOST:PORT` | `cp.cloudflare.com:443` | 主机用于地址族探测的 HTTPS 请求 URL（TLS SNI 和 Host 标头）；主机和端口用于 QUIC 探测。未指定 `--v4-target`/`--v6-target` 地址覆盖时，地址族探测解析此主机并使用此端口。UDP DNS 探测目标由 `--udp-check` 单独指定。 |
| `--udp-check HOST[:PORT]` | `dns.google:53`、`8.8.8.8`、`2001:4860:4860::8888` | UDP DNS 检查目标，默认取自 `honk-config` 中的引擎列表。可重复指定或用逗号分隔。优先采用首个可解析为 IP 地址或套接字地址的目标，否则仅在节点支持 UDP DNS 探测时解析列表首项。省略端口时使用 `53`。 |
| `--url TEST_URL` | `https://www.gstatic.com/generate_204` | 经代理的 URLTest 目标。 |
| `--timeout SECS` | `5` | 每项探测的超时。 |
| `--concurrency N` | `10` | 同时进行的节点探测任务上限。 |
| `--limit N` | `0` | 仅探测前 `N` 个节点；`0` 表示全部。 |
| `--ua UA` | 未设置 | 远程订阅拉取使用的 `User-Agent`。 |
| `--tls-implementation tls\|utls` | `tls` | 探测使用的进程级 TLS ClientHello 实现。 |
| `--utls-imitate PROFILE` | `chrome_auto` | `utls` 使用的指纹 profile；当前校验器只接受以 `chrome` 开头的名称。 |
| `--v4-target IP:PORT` | `1.1.1.1:443` | v4 连通性探测使用的显式 IPv4 地址。 |
| `--v6-target [IP]:PORT` | `[2606:4700:4700::1111]:443` | v6 连通性探测使用的显式 IPv6 地址。 |

远程订阅与本地文件共享引擎的自动格式识别：编码/原始分享链接、Clash YAML/JSON、SIP008、sing-box JSON，以及受支持的 Surge/Surfboard/Loon/Quantumult X 记录。不支持的节点会被跳过，不打印原始输入。使用 `-` 可避免把含凭据的 provider URL 放入 argv 和进程列表。

对每个节点，命令报告服务端地址族、完整的代理 IPv4/IPv6 交换、代理 URLTest 延迟、经 packet handler 的 DNS 查询，以及经该 handler 的真实 QUIC 握手。VLESS 行使用以下脱敏 shape，不包含端点、UUID、REALITY key、SNI 或 URL query：

```text
vless/{plain|tls|reality}/{tcp|ws|grpc}[/vision]/tcp={plain|h2mux|mux-cool}/{udp-fallback=auto|native|xudp|uot-v2|udp=disabled}[/padding=true|false][/mux=TCP:UDP:POLICY]
```

`tcp=` 表示有效 TCP 路径。即使 H2MUX 或 Xray mux 当前接管目标 UDP 路径，`udp-fallback=` 仍表示规范化后的回退字段；`udp=disabled` 表示不允许 packet 拨号。`padding=` 只对 H2MUX 出现。对 Xray mux，`TCP` 为每条 TCP carrier 的有效逻辑 child 并发（`0` 表示关闭），`UDP` 为 `protocol`、`shared` 或独立 UDP pool 的逐 carrier 逻辑 child 并发，`POLICY` 为 UDP/443 的 `reject`、`skip` 或 `allow`。示例 shape 包括 `vless/tls/tcp/tcp=plain/udp-fallback=native`、`vless/reality/grpc/tcp=h2mux/udp-fallback=auto/padding=true` 与 `vless/tls/tcp/vision/tcp=plain/udp-fallback=auto/mux=0:8:allow`。

探测资格状态码为 `supported`、`invalid-uuid`、`invalid-reality`、`invalid-config`、`unsupported-transport`、`unsupported-flow`、`vision-without-tls`/`vision-non-tcp`；无效或有意不支持的条目仍会显示，但不会执行网络操作。Vision 的 TCP 只能使用符合条件的 direct carrier，UDP-only Xray mux 仍然有效。VLESS Encryption 可以与 Vision 组合；只有未加密 Vision 还要求 raw TCP 上使用 TLS 1.3 或 REALITY。

`n/a` 表示探测不适用，例如 packet 拨号被关闭，或 UDP/443 策略拒绝该目标。本地 carrier 容量拒绝是已尝试后的 terminal failure，显示为 `FAIL(...)` 而不是 `n/a`，且对远程端点健康保持中立。之所以需要区分，是因为共享的全局文件描述符预算所能接纳的物理 VLESS carrier 可能少于各节点 mux 上限之和。

UDP DNS 目标解析、packet transport 建立、发送与接收共用一个 `--timeout` 预算。解析失败或超时只体现在 DNS 列，TCP、URLTest 和 QUIC 探测继续进行。不支持 UDP 的节点跳过该解析；主机名解析失败时不会替换为另一个目标。

UDP DNS 主机名目标使用共享异步解析器，读取 `/etc/resolv.conf` 中首个数字形式的 nameserver（UDP 端口 `53`），并在 `/etc/hosts` 存在时加载它，不执行阻塞的 NSS 查询。此路径不应用 NSS 插件或解析器搜索后缀。解析器不可用时，DNS 列报告 `resolve`，不会回退到公共解析器；字面量目标不需要解析器。

VLESS carrier/session 按 runtime 与规范化 wire shape 复用，因此更改规范 UDP/mux query 可能更改节点身份与 pool 复用。共享物理 carrier 容量是全局的；XUDP 的 8-byte Global ID 则按 honk 的 runtime/client/path/destination source identity 确定作用域，不作为进程级无碰撞 NAT key。见[节点参考](./nodes.md#vless-udp-and-multiplexing)与规范的 [VLESS 出站设计](../design/outbound.md#sourcesession-ownership-and-capacity)。

探测失败码为 `resolve`、`timeout`、`exchange`、`handler` 与 `admission`。凭据、端点详情、SNI、REALITY key、URL query 数据和原始错误绝不会输出。

### `bpf`

```text
honk-tool bpf show <conn-state|redirect-track|domain-routing|routing-handoff>
                   [--ip IP] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
```

| 命令 / 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `show <map>` | 必填 | 解码一个受支持的 pin map。 |
| `show --ip IP` | 未设置 | 按源或目的 IP 过滤 tuple map；对 `domain-routing` 按精确 IP key 过滤。 |
| `show --limit N` | `50` | 最多打印的条目数；`0` 表示全部。 |
| `show --pin-root PATH` | `/sys/fs/bpf` | 所选 map 的 pin 根目录。 |
| `stats --pin-root PATH` | `/sys/fs/bpf` | 统计 map 的 pin 根目录。 |

| `show` map | 解码内容 |
| --- | --- |
| `conn-state` | Tuple、出站、mark、must 标记、状态与最近出现时间戳。 |
| `redirect-track` | 回包改写源/目的地址、出站、WAN 方向、接口与最近出现时间戳。 |
| `domain-routing` | 从 DNS 或嗅探结果学习的 IP，以及活动 policy 的域名谓词位图索引；已知但全零的条目仍会显示。 |
| `routing-handoff` | Tuple 与待处理的 eBPF 到控制面路由结果。 |

实现通过原始 `bpf(2)` 操作打开 pin；不使用 aya、不加载程序，也不挂载 hook。`stats` 打印 conn-state 与辅助 map 的溢出/插入失败计数、`CONN_STATE_OCCUPANCY` 插入/删除水位计，以及非零的每出站包/字节计数。读取 map 通常需要 root 或合适的 BPF capability。

`routing-handoff` 在读取前检查[handoff ABI](../design/datapath.md#map-清单)；请将工具与引擎/对象一起升级。

`stats` 要求 `/sys/devices/system/cpu/possible` 可读且为内核的真实导出文件。每 CPU 缓冲区按该掩码中的 CPU 数量分配，不采用 present 或 online CPU 数量。`CONN_STATE_OCCUPANCY` 和 `OUTBOUND_STATS` 必须为每 CPU 数组，键均为 4 字节，值分别为 8 字节和 32 字节。CPU 列表不可读、格式无效或 map 元数据不兼容时，命令在每 CPU 查找前报错，不回退到猜测的 CPU 数量。

### `diagnose`

```text
honk-tool diagnose [--api URL] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark VALUE]
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--api URL` | `http://127.0.0.1:9090` | 明文 HTTP Clash API 基础 URL。空值跳过 API 检查；内置客户端不支持 HTTPS。 |
| `--secret TOKEN` | `HONK_API_SECRET`（若已设置） | Clash API 的 Bearer 令牌。命令行参数优先于环境变量。 |
| `--pin-root PATH` | `/sys/fs/bpf` | 检查 pin map 是否存在及读取统计时使用的根目录。 |
| `--tproxy-mark VALUE` | `134217728`（`0x08000000`） | `daens` 策略规则中预期的 fwmark。 |

该检查只读。它查找引擎进程（`honk-core`、`honk` 或 `dae`）、`/var/run/netns/daens`、`/sys/class/net/dae0`、`daens` 内的 fwmark 规则、必需的 pin map、可读取的占用/溢出统计，并检查 `<api>/version` 是否返回成功的 HTTP 响应。API 返回 2xx 状态码时打印 `[ok]` 和响应正文；返回非 2xx 状态码时打印 `[FAIL]` 和状态文本。标准输出末尾为 `diagnose: all checks passed` 或 `diagnose: N issue(s) found`。存在失败检查时，退出状态为 `1`，错误信息包含问题数量；全部通过时，退出状态为 `0`。

统计检查与 `bpf stats` 对 possible CPU 文件和 pin map 布局的要求相同。准备失败时打印 `[FAIL] map stats read`，计入问题数量，并以非零状态退出。

### `geosite` 与 `geoip`

```text
honk-tool geosite [--file PATH] list [FILTER]
honk-tool geosite [--file PATH] show <category> [--attr ATTR]
honk-tool geosite [--file PATH] find <domain>
honk-tool geoip [--file PATH] list [FILTER]
honk-tool geoip [--file PATH] show <code>
honk-tool geoip [--file PATH] lookup <ip>
```

| 命令 | 行为 |
| --- | --- |
| `geosite list [FILTER]` | 列出类目 code 与条目数；可选 filter 为不区分大小写的子串。 |
| `geosite show <category> [--attr ATTR]` | 打印一个类目的条目。`--attr` 不区分大小写地保留含该属性 key 的条目，与路由的 `category@attr` 谓词一致。 |
| `geosite find <domain>` | 按类目打印匹配该域名的 full、suffix、keyword 与 regex 条目。 |
| `geoip list [FILTER]` | 列出 code 与 CIDR 数；可选 filter 为不区分大小写的子串。 |
| `geoip show <code>` | 打印一个 code 中的全部 CIDR。 |
| `geoip lookup <ip>` | 返回最长匹配前缀上并列的全部 code/CIDR。 |
| `--file PATH` | 对应 `.dat` 文件的命令族全局覆盖路径。 |

未给 `--file` 时，工具按以下顺序搜索第一个已存在的普通文件：`$DAE_LOCATION_ASSET/<name>.dat`、`/var/lib/honk/<name>.dat`、旧根目录 `/var/share/honk/<name>.dat`、`./<name>.dat`、`/usr/local/share/honk/<name>.dat`、`/usr/share/honk/<name>.dat`、`/usr/local/share/dae/<name>.dat`、`/usr/share/dae/<name>.dat`，最后是 `/etc/dae/<name>.dat`。与 `honk-core` 不同，该工具不加载配置，因而无法获知自定义 `global.data_dir`。输出每行一条记录；下游管道关闭时不会 panic。

## 相关文档

- [全局配置参考](./global.md)
- [Experimental 配置参考](./experimental.md)
- [Clash API 参考](./api.md)
