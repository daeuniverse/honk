# 命令行参考

`honk-core` 提供引擎命令行接口，`honk-tool` 提供诊断工具。

## `honk-core`

`honk-core` 加载配置、初始化控制面，然后选择真实 eBPF 后端或 mock 后端。

### 调用格式

```text
honk-core [OPTIONS] [COMMAND]
```

| 参数 | 默认值 | 作用 |
| --- | --- | --- |
| `-c`, `--config PATH` | `/etc/honk/config.dae` | 配置入口文件。用 `--store db` 时，只在数据库为空或由 API 导入配置时读取。文件模式下，`mode`、`proxy` 和 `delay` 也读这个路径。`reload` 忽略此项，只给运行中的实例发信号；运行中的实例按启动时用的路径执行 reload。 |
| `--log-file PATH` | 未设置 | 只覆盖本次引擎进程的 `global.log_file`，不改配置文件。相对路径在 `global.data_dir` 下解析，控制台日志照常启用。设置之后，SIGHUP 会忽略被覆盖配置值的变化，除非实际生效的目标变了。 |
| `-b`, `--bpf-object PATH` | 内嵌目标文件 | 覆盖 `ebpf` 构建内嵌的目标文件，只在真实后端使用。 |
| `--bpf-pin-root PATH` | `/sys/fs/bpf` | eBPF map 的 pin 根目录。 |
| `--disable-timestamp` | 关 | 控制台日志行不再带时间戳。systemd 这类自带时间戳的日志系统适用。`--log-file` 或 `global.log_file` 指定的文件仍然带时间戳。 |
| `-d`, `--debug` | 关 | `RUST_LOG` 没提供有效过滤器时，把 `debug` 当作默认控制台过滤器。 |
| `--mock-ebpf` | 关 | 使用 `MockEbpfBackend`，不加载内核 eBPF。配置要求 `global.nfqueue_enable: true` 时，honk 记一条 warning，然后只在本进程关闭 NFQUEUE 暂存。 |
| `--store file\|db` | `file` | `db` 从 `<data-dir>/state/honk.db` 里的修订版本加载配置，数据库为空时导入 `-c`，构建时需要包含 `native-api`。见[配置数据库](./api.md#配置数据库--store-db)。 |
| `--data-dir PATH` | `/var/lib/honk` | 数据目录，状态数据库在它下面的 `state/honk.db`。`--store db`、`config export` 和 `admin reset` 会用到。用 `--store db` 时必须和 `global.data_dir` 相同；文件模式启动忽略此选项。 |

两个二进制都提供 `-h`/`--help` 和 `-v`/`--version`。

core、`honk-tool` 和 BPF 对象的版本要匹配；honk 会按[数据路径 ABI 契约](../design/datapath.md#map-清单)拒绝不兼容的对象和 pinned handoff 布局。

CLI 和 Clash API 共用构建时确定的版本号：发布构建用 GitHub 标签名。本地 Git 构建用 `git describe --tags --always --match 'v*'`，结果是标签，或者最近标签加提交距离和 hash。没有可用的 Git 元数据时，用 Cargo 包版本。运行时不依赖 Git。

### 日志级别优先级

源码注释写的预期顺序是 `--debug` → `RUST_LOG` → `global.log_level` → `info`。当前可执行文件先选出 debug 或配置的默认值，再调用 `EnvFilter::try_from_default_env()`，所以有效的 `RUST_LOG` 现在优先：

| 当前优先级 | 来源 | 行为 |
| --- | --- | --- |
| 1 | `RUST_LOG` | 有效的 tracing 过滤条件覆盖所有默认值，包括 `--debug`。 |
| 2 | `--debug` | `RUST_LOG` 不存在或无效时使用 `debug`。 |
| 3 | `global.log_level` | 未指定 `--debug` 且没有有效 `RUST_LOG` 时使用。 |
| 4 | `info` | `global.log_level` 为空时使用。 |

`log_level` 见[全局配置参考](./global.md)。

各级别含义固定，因此默认的 `info` 保持低频：

| 级别 | 含义 |
| --- | --- |
| `error` | 配置要求的功能在人工处理前无法恢复：激活已提交但 degraded、进程停止、子系统永久停止，或内部不变量被破坏。 |
| `warn` | 降级但仍在运行。honk 在进入这种状态时记录一次：采用回退路径、资源达到上限、节点或代理组不可用、新配置被拒而旧配置继续运行。每个 DNS 查询都会重复的失败，例如 SERVFAIL 和 singleflight 饱和，最多每 10 秒记一次 warning。 |
| `info` | 启动、停止、激活、运维操作，以及从 warning 状态恢复。 |
| `debug` | 单个连接、请求和 DNS 查询的结果，包括单次拨号和转发失败，以及周期维护结果。原生流也记录同样的逐流结果。 |

### 子命令

| 命令 | 当前行为 | 持久化 / 运行时影响 |
| --- | --- | --- |
| `reload` | 从已加锁的 `/run/honk-core.lock` 读取 PID，发送 `SIGHUP`。 | 只报告信号送达成功；运行中的进程随后记录 `applied` 或 `rejected`。mock 实例不持有这把锁。 |
| `mode <rule\|global\|direct>` | 加载 `--config`，把参数字符串写进 `experimental.clash_api.default_mode`，并在重写结构化格式文件之前完成校验。`.dae` 文件会被拒绝并保持原样，因为 writer 保留不了 dae 语法、注释和 include；这类源文件请直接编辑，或者改用 `.toml`、`.yaml`、`.json`。 | 只改文件；不联系运行中的引擎，也不改 dial mode。该命令接受的字符串，和正常的 dial mode 值 `ip`、`domain`、`domain+`、`domain++` 不同。 |
| `proxy <group> <node>` | 检查组名和节点名都存在，然后打印按请求做出的选择；不检查节点是否属于该组。 | 不写任何内容，也不联系运行中的引擎。 |
| `config export --out PATH [--without-secrets]` | 构建时需要包含 `native-api`。把配置数据库当前的修订版本写成一份 `.dae` 文件；没给 `--without-secrets` 时，把 listener secret 补回去。不管守护进程是否在运行，都通过一个以读写方式打开的 query-only 连接读数据库。关闭这个连接不会执行检查点，也不会删除 `honk.db-wal`；除了 SQLite 可能创建的 `-shm` 索引，唯一可能的写入是回滚崩溃遗留的日志。文件写完才会发布。 | 以 0600 权限新建 `PATH`，已存在的文件会被拒绝。 |
| `admin reset` | 从 `--data-dir` 下的状态数据库删除密码模式管理员，下次启动时重新开放 setup。 | 任何 honk-core 打开该状态数据库时都会拒绝执行，mock 模式也一样。 |
| `delay <node> [-u\|--url HOST:PORT]` | 解析地址后直连 TCP，打印耗时毫秒数，含解析时间。没给 `--url` 时用节点服务端地址。解析出的多个地址会并行竞速，同时最多两个，间隔 250 ms，每次尝试超时五秒。 | 不经过代理，不是 HTTP URLTest，也不联系运行中的引擎。 |

[编译路由发布计数器](../design/routing.md#同步槽与原子发布)用尽后需要重启；它和普通 SIGHUP 及 DNS 运行时 reload 分开计数。

用 `--store db` 时，`proxy` 和 `delay` 读当前修订版本，构建时需要包含 `native-api`；`mode` 会拒绝执行。

真实数据面进程在它整个生命周期里持有这把锁。`reload` 先确认文件仍被锁定，再信任里面的 PID。`kill(2)` 成功送达，并不表示候选配置通过了校验，也不表示需重启字段检查过。

## 环境变量

| 变量 | 作用范围 | 当前行为 |
| --- | --- | --- |
| `RUST_LOG` | 两个二进制 | tracing 过滤条件。`honk-core` 按上面说的当前有效优先级处理；`honk-tool` 没设置时默认 `warn`。 |
| `NO_COLOR` | `honk-core` 控制台 | 非空值关闭 ANSI 颜色。否则只在 stdout 是终端时启用颜色。 |
| `HONK_UI_DOWNLOAD_URL` | 启用 `clash-api` 的 `honk-core` | dashboard ZIP URL 的最高优先级覆盖。配置的外部 UI 目录需要下载时，它覆盖 `assets.ui.url`。 |
| `HONK_POOL_DISABLE=1` | `honk-core` | 绕过 Ready 流和裸 TCP 两类池，每次都重新拨号。honk 也接受不区分大小写的 `true`；第一次使用后缓存该值。 |
| `HONK_QUIC_GSO` | QUIC 出站 | `1` 或不区分大小写的 `true` 强制开启 UDP GSO；其他任何值都强制关闭，空值也一样。该值第一次使用后缓存。没覆盖时，GSO 在保守的 1252 字节 MTU 下保持关闭；显式设了更大的 `mtu`，honk 就自动开启 GSO，并把批量限制在最多 16 个 segment。 |
| `HONK_QUIC_BBR=v1\|v3` | QUIC 出站 | 选择 `bbr` 拥塞控制背后的实现，适用于 TUIC 的 `congestion_control: bbr`、Juicity，以及没有设置上传速率的 Hysteria2。`v3` 是 BBRv3。`v1` 是 quinn 原有的 BBR，不响应丢包；在高带宽时延积路径上，quinn-proto 0.11.16 及以上的接收端可能以 `too many gaps in stream buffer` 中止它的上传。默认 `v3`；其他值会触发 warning，并保持默认。 |
| `TOKIO_WORKER_THREADS` | `honk-core` | Tokio 的 worker 数量。`honk-core` 用默认多线程运行时，默认数量等于核数。值必须是正整数：`0` 或非数字会让 Tokio 在启动时 panic。每个 worker 持有独立的分配器堆，在多核网关上把值调小可以降低 RSS。实验室测量用 4 核主机、120 条连接和 DNS：16 个 worker 约 85 MiB，8 个约 66 MiB，4 个约 60 MiB。CPU 差异在噪声范围内。中继路径运行在这些 worker 上，应按流量设置。 |
| `HONK_VMLINUX_BTF` | 启用 `ebpf` 的 `honk-core` | 覆盖进程名路由和原生 UDP 接收追踪共用的原始内核 BTF。文件必须匹配运行中的内核。显式指定的文件不可读或无效时，honk 会拒绝启动真实后端，不会自行改用其他文件。TCP 归属证明不读取内核结构，也不依赖它。 |
| `DAE_LOCATION_ASSET` | 两个二进制的 Geo 加载 | `honk-core` 和 `honk-tool` 最先检查里面的 `geoip.dat` 和 `geosite.dat`。 |

UDP NFQUEUE 没有环境变量开关，由 `global.nfqueue_enable` 控制，默认开启；设为 `false` 即可关闭。见[全局配置参考](./global.md)和 [NFQUEUE 设计](../design/nfqueue.md)。

## eBPF 与运行时路径

| 项 | 控制方式 | 当前不变量 |
| --- | --- | --- |
| eBPF 目标文件 | 内嵌目标文件或 `--bpf-object PATH` | 启用 `ebpf` feature 时，`build.rs` 通过 `include_bytes!` 内嵌目标文件；这个参数在运行时替换这些字节。honk 在 probe/loading 之前就拒绝对象声明的 `ByName` pinning：要用未 pin 的 map 重新构建，把 pin 路径交给 core 管理。没启用 `ebpf` 的构建用 mock 后端。 |
| 内核 BTF | `HONK_VMLINUX_BTF`、`/sys/kernel/btf/vmlinux` 或 `/usr/lib/debug/boot/vmlinux` | 没覆盖时，honk 读 `/sys/kernel/btf/vmlinux`；不可读时再读 `/usr/lib/debug/boot/vmlinux`，也就是 OpenWrt 的 `vmlinux-btf` 包。只接受原始 BTF；如果只有 ELF 格式的 debug vmlinux，先提取它的 `.BTF` 段，再用该变量指向提取结果。选定的 BTF 统一提供内核字段偏移、Aya loader 的目标 BTF 和接收追踪的函数签名。BTF 缺失或无效时，honk 拒绝启动。内核 argv 捕获不可用时，仍可回退到线程的 `comm`。原生 UDP 接收追踪还需要内核自带的 BTF 和 ftrace，缺了就降级运行；外部文件替代不了它们。 |
| Pin 根目录 | `--bpf-pin-root PATH` | 默认 `/sys/fs/bpf`，传给真实后端用于 pin map。 |
| Bypass mark | `global.so_mark_from_dae` | 拨号、探测、DNS 和下载使用的精确 socket mark；零值表示用默认的 `0x100`。修改需要重启，见[socket mark](./global.md#socket-mark)。 |
| TPROXY mark | 编译期常量与配置校验 | `TPROXY_MARK = 0x08000000`；`global.tproxy_mark` 必须等于该值。 |
| Geo 资源 | 运行时路径搜索 | honk 依次检查 `DAE_LOCATION_ASSET`、[`global.data_dir`](./global.md)、旧根目录 `/var/share/honk`、工作目录、`/usr/local/share/honk`、`/usr/share/honk`、`/usr/local/share/dae`、`/usr/share/dae`、`/etc/dae`；每个候选都必须是普通文件。 |

## `honk-tool`

`honk-tool` 负责订阅探测、已固定 map 检查、引擎健康检查和离线 Geo 资源搜索，不加载也不挂接 eBPF 程序。

### 构建与部署

普通开发构建：

```bash
cargo build --release -p honk-tool
```

部署到网关时，用仓库的 Zig 包装器构建静态 musl 目标，再复制单个二进制：

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

现在的 `just build-musl` 和 `just deploy-vyos` 只构建和部署 `honk-core`，不含 `honk-tool`。用 GNU 链接器构建的二进制，可能无法在纯 musl 网关上执行。

### 命令族

| 命令族 | 用途 |
| --- | --- |
| `sub` | 拉取或解析节点，并探测 TCP 地址族、URLTest 和受支持的 UDP 路径。 |
| `bpf` | 读取并解码运行中引擎已经 pin 的 map。 |
| `diagnose` | 执行只读的引擎、网络设施、map 和 API 健康检查。 |
| `geosite` | 列出、检查和反向搜索 `geosite.dat`。 |
| `geoip` | 列出、检查和最长前缀搜索 `geoip.dat`。 |

二进制提供 `-h`/`--help` 和 `-v`/`--version`。每个命令族和操作也都有帮助信息。构建版本和 `honk-core` 一致。

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
| `--target HOST:PORT` | `cp.cloudflare.com:443` | 其中的主机用作地址族探测的 HTTPS 请求 URL、TLS SNI 和 Host header；主机和端口用于 QUIC 探测。地址族探测仍然连接 `--v4-target` 和 `--v6-target`，所以改目标时这两项也要改。UDP DNS 探测目标由 `--udp-check` 单独指定。 |
| `--udp-check HOST[:PORT]` | `dns.google:53`、`8.8.8.8`、`2001:4860:4860::8888` | UDP DNS 检查目标，默认取自 `honk-config` 里的引擎列表。可以重复指定，也可以用逗号分隔。优先采用第一个能解析成 IP 地址或 socket 地址的目标；否则，只有节点支持 UDP DNS 探测时，才解析列表第一项。省略端口时用 `53`。 |
| `--url TEST_URL` | `https://www.gstatic.com/generate_204` | 经代理的 URLTest 目标。 |
| `--timeout SECS` | `5` | 每项探测的超时。`0` 表示零超时，不表示不限时。 |
| `--concurrency N` | `10` | 并发节点探测任务上限。`0` 不执行任何探测，只输出空摘要，不表示不限并发。 |
| `--limit N` | `0` | 仅探测前 `N` 个节点；`0` 表示全部。 |
| `--ua UA` | 未设置 | 远程订阅拉取使用的 `User-Agent`。 |
| `--tls-implementation tls\|utls` | `tls` | 探测使用的进程级 TLS ClientHello 实现。 |
| `--utls-imitate PROFILE` | `chrome_auto` | `utls` 使用的指纹配置方案；当前校验器只接受 `chrome` 开头的名称。 |
| `--v4-target IP:PORT` | `1.1.1.1:443` | v4 探测连接的数字 IPv4 地址，不检查地址族。 |
| `--v6-target [IP]:PORT` | `[2606:4700:4700::1111]:443` | v6 探测连接的数字 IPv6 地址，不检查地址族。 |

自定义目标并给出对应的地址族地址：

```bash
honk-tool sub nodes.txt --target one.one.one.one:443 \
  --v4-target 1.0.0.1:443 --v6-target '[2606:4700:4700::1001]:443'
```

远程订阅和本地文件共用引擎的自动格式识别：

- 编码后的分享链接，或原始分享链接。
- Clash YAML/JSON、SIP008 和 sing-box JSON。
- 受支持的 Surge/Surfboard/Loon/Quantumult X 记录。

`honk-tool` 跳过不支持的节点，不打印原始输入。用 `-` 可以避免把含凭据的 provider URL 放进 argv 和进程列表。

订阅加载成功后，即使探测全部失败或节点全部被跳过，退出状态仍是 `0`。探测任务崩溃时打印 `probe task failed`，退出状态同样是 `0`。脚本要靠摘要行判断连通性。

对每个节点，命令报告：

- 服务端地址族。
- 完整的代理 IPv4/IPv6 交换。
- 经代理的 URLTest 延迟。
- 经数据包 handler 的 DNS 查询。
- 经该 handler 的真实 QUIC 握手。

VLESS 行用下面的脱敏格式，不含 endpoint、UUID、REALITY key、SNI 或 URL 查询参数：

```text
vless/{plain|tls|reality}/{tcp|ws|grpc|xhttp}[/vision]/tcp={plain|h2mux|mux-cool}/{udp-fallback=auto|native|xudp|uot-v2|udp=disabled}[/padding=true|false][/mux=TCP:UDP:POLICY]
```

| VLESS 输出字段 | 含义 |
| --- | --- |
| `tcp=` | 有效 TCP 路径。 |
| `udp-fallback=` | 规范化后的回退值，即使 H2MUX 或 Xray 多路复用已经接管目标 UDP 路径。 |
| `udp=disabled` | 禁止数据包拨号。 |
| `padding=` | 仅在 H2MUX 中出现。 |
| Xray 多路复用 `TCP` | 每条 TCP carrier 的有效逻辑 child 并发数；`0` 表示关闭。 |
| Xray 多路复用 `UDP` | `protocol`、`shared`，或独立 UDP 池中每条 carrier 的逻辑 child 并发数。 |
| Xray 多路复用 `POLICY` | UDP/443 策略：`reject`、`skip` 或 `allow`。 |

输出格式示例：

- `vless/tls/tcp/tcp=plain/udp-fallback=native`
- `vless/reality/grpc/tcp=h2mux/udp-fallback=auto/padding=true`
- `vless/tls/tcp/vision/tcp=plain/udp-fallback=auto/mux=0:8:allow`

`xhttp` 表示 H2 XHTTP 传输；这一行不暴露 path、HTTP host、自定义 header 或填充内容。模式和受支持的参数见[节点参考](./nodes.md#h2-上的-xhttp)。

| 探测资格状态码 | 网络操作 |
| --- | --- |
| `supported` | 可执行探测。 |
| `invalid-uuid`、`invalid-reality`、`invalid-config` | 条目仍然显示，但不执行网络操作。 |
| `unsupported-transport`、`unsupported-flow`、`vision-without-tls`、`vision-non-tcp` | 条目仍然显示，但不执行网络操作。 |

Vision 的 TCP 路径要求符合条件的直接 carrier；只有 UDP 的 Xray 多路复用仍然有效。VLESS Encryption 可以和 Vision 组合。未加密的 Vision 还要求裸 TCP 使用 TLS 1.3 或 REALITY。

`n/a` 表示探测不适用，比如数据包拨号已关闭，或者 UDP/443 策略拒绝该目标。本地 carrier 容量拒绝发生在尝试之后，属于 terminal failure，显示成 `FAIL(...)` 而不是 `n/a`，也不影响远程 endpoint 的健康状态。共享的全局文件描述符预算能接纳的物理 VLESS carrier，可能少于各节点 mux 上限之和。

UDP DNS 的目标解析、数据包传输建立、发送和接收共用同一个 `--timeout` 预算。解析失败或超时只体现在 DNS 列，TCP、URLTest 和 QUIC 探测照常继续。不支持 UDP 的节点跳过这项解析；主机名解析失败时，也不会改用另一个目标。

| 探测列 | 时限 |
| --- | --- |
| 每个非 QUIC 列 | 各自以 `--timeout` 加一秒为上限。 |
| QUIC | 额外留两秒等清理完成。清理耗时不计入延迟样本。 |

URLTest 和地址族探测的拨号、目标 TLS、每次交换各有独立的 `--timeout`。所以较慢的冷启动 carrier 建立时，可能达到列时限。这一列报告 `timeout`；UDP 策略拒绝目标时报告 `n/a`。其他列保留各自的结果。

UDP DNS 的主机名目标用共享异步解析器：读 `/etc/resolv.conf` 里第一个数字形式的 nameserver，UDP 端口 `53`，`/etc/hosts` 存在时也加载它，不做阻塞的 NSS 查询。这条路径不用 NSS 插件，也不用解析器搜索后缀。解析器不可用时，DNS 列报告 `resolve`，不会回退到公共解析器；字面量目标不需要解析器。

VLESS carrier 和 session 按运行时和规范化的线协议形态复用。所以改动规范 UDP/多路复用查询参数，可能改变节点身份和连接池复用。

共享物理 carrier 的容量是全局的。XUDP 的 8 字节 Global ID 按 honk 的运行时、客户端、路径和目的地源身份划分作用域，不是进程级的无碰撞 NAT key。见[节点参考](./nodes.md#vless-udp-and-multiplexing)和规范的 [VLESS 出站设计](../design/outbound.md#sourcesession-ownership-and-capacity)。

探测失败码有 `resolve`、`timeout`、`exchange`、`handler` 和 `admission`。探测结果行绝不输出凭据、endpoint 详情、SNI、REALITY key、URL 查询参数数据和原始错误。唯一的例外在 stderr：探测运行时清理失败时打印 `probe runtime cleanup failed: <error>`，带上原始错误。

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
| `conn-state` | Tuple、出站、mark、must 标记、状态、最近出现的时间戳和追踪 ID。 |
| `redirect-track` | 回包改写的源/目的地址、出站、WAN 方向、接口和最近出现的时间戳。 |
| `domain-routing` | 从 DNS 或嗅探结果学到的 IP，以及活动 policy 的域名谓词位图索引；已知但全零的条目仍会显示。 |
| `routing-handoff` | Tuple、待处理的 eBPF 到控制面路由结果、最近出现的时间戳、路由 generation 和追踪 ID。 |

`conn-state`、`redirect-track` 和 `routing-handoff` 通过带 `BPF_F_LOCK` 的 `BPF_MAP_LOOKUP_BATCH` 读取。内核不支持时报错 `safe external map snapshot requires BPF_MAP_LOOKUP_BATCH ...`，不会回退到不加锁的读取。

命令通过原始 `bpf(2)` 读取 pin，不加载程序，也不挂接 hook；通常需要 root 或合适的 BPF capability。`stats` 为下面这些计数器逐行输出规范标签和计数，还打印 `CONN_STATE_OCCUPANCY` 插入/删除水位计，以及非零的每出站包/字节计数。`BPF_STATS_MAP` 必须有九个槽位：工具和引擎版本不匹配时，会以 `unexpected map layout for BPF_STATS_MAP: expected max_entries=9 found 7` 失败，旧版工具则反过来，这样就不会错误标注计数器。工具、引擎和对象要一起升级。

| Key | 规范标签 | 计数对象 |
| --- | --- | --- |
| `0` | `udp_conn_overflow` | 没有已有 tuple 时，UDP conn-state 插入失败。 |
| `1` | `tcp_conn_overflow` | TCP conn-state 插入失败。 |
| `2` | `redirect_track_insert_failure` | Redirect-track 发布失败：map 插入失败，或准备 scratch 不可用。 |
| `3` | `routing_handoff_insert_failure` | Routing-handoff 发布失败：map 插入失败，或准备 scratch 不可用。 |
| `4` | `socket_identity_capture_failure` | socket 进程身份捕获或存储失败。 |
| `5` | `tcp_child_proof_storage_failure` | 已接受 TCP child 的归属证明存储失败。 |
| `6` | `tcp_publisher_claim_failure` | TCP SYN 发布排他声明插入失败，不含普通的同 tuple 冲突，也就是 `EEXIST`。 |
| `7` | `new_flow_rate_limited` | 因单源、每 CPU 的新流限制被丢弃的 LAN 流尝试。 |
| `8` | `udp_reverse_learning_suspended` | conn 压力下，conn-state 查询未命中后被跳过的反向 UDP 学习尝试。 |

`routing-handoff` 在读取前检查[handoff ABI](../design/datapath.md#map-清单)。

`stats` 要求 `/sys/devices/system/cpu/possible` 可读，而且是内核真实导出的文件。每 CPU 缓冲区按这个掩码里的 CPU 数量分配，不用 present 或 online 的 CPU 数量。`CONN_STATE_OCCUPANCY` 和 `OUTBOUND_STATS` 必须是每 CPU 数组，key 都是 4 字节，值分别是 8 字节和 32 字节。CPU 列表不可读、格式无效，或者 map 元数据不兼容时，命令在每 CPU 查找之前就报错，不会退回去猜 CPU 数量。

### `diagnose`

```text
honk-tool diagnose [--api URL] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark VALUE]
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--api URL` | `http://127.0.0.1:9090` | 明文 HTTP Clash API 基础 URL，必须写端口，例如 `http://panel.example:80`；不支持 HTTPS。空值跳过 API 检查。 |
| `--secret TOKEN` | `HONK_API_SECRET`，如果设置了的话 | Clash API 的 Bearer token。命令行参数优先于环境变量。 |
| `--pin-root PATH` | `/sys/fs/bpf` | 检查 pin map 是否存在、读取统计时用的根目录。 |
| `--tproxy-mark VALUE` | `134217728`，等于 `0x08000000` | `daens` 策略规则里预期的 fwmark，以十进制 32 位整数给出，不接受十六进制。 |

API 检查没有超时，对端卡住会让命令一直挂起；需要的话用 `timeout(1)` 包一层，或者传 `--api ''` 跳过。`diagnose` 会调用 `ip`；执行不了 `ip` 就以非零状态退出，后面的检查不再执行，也不输出摘要。

该命令只读，检查以下项目：

- 名为 `honk-core`、`honk` 或 `dae` 的引擎进程；
- `/var/run/netns/daens` 和 `/sys/class/net/dae0`；
- `daens` 内的 fwmark 规则；
- 必需的已固定映射，以及可读取的占用/溢出统计；
- `<api>/version` 的成功 HTTP 响应。

| 结果 | 输出 |
| --- | --- |
| API 返回 2xx | `[ok]`，后跟响应正文。 |
| API 返回非 2xx | `[FAIL]`，后跟状态文本。 |
| 全部检查通过 | 标准输出以 `diagnose: all checks passed` 结束，退出状态为 `0`。 |
| 存在失败检查 | 标准输出以 `diagnose: N issue(s) found` 结束，退出状态为 `1`，错误信息包含问题数量。 |

统计检查和 `bpf stats` 对 possible CPU 文件和 pin map 布局的要求一样。准备失败时，命令打印 `[FAIL] map stats read`，计入问题数量，并以非零状态退出。

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
| `geosite list [FILTER]` | 列出类目 code 和条目数；过滤条件可选，是不区分大小写的子串。 |
| `geosite show <category> [--attr ATTR]` | 打印一个类目的条目。`--attr` 按不区分大小写匹配，保留含该属性 key 的条目，和路由里 `category@attr` 谓词一致。 |
| `geosite find <domain>` | 按类目打印匹配该域名的 full、suffix、keyword 和 regex 条目。 |
| `geoip list [FILTER]` | 列出 code 和 CIDR 数；过滤条件可选，是不区分大小写的子串。 |
| `geoip show <code>` | 打印一个 code 里的全部 CIDR。 |
| `geoip lookup <ip>` | 返回最长匹配前缀上并列的全部 code/CIDR。 |
| `--file PATH` | 为对应 `.dat` 文件提供命令族级别的覆盖路径。 |

`show` 指定的类目或 code 不存在时，命令以非零状态退出。`list`、`find` 或 `lookup` 没有匹配时不输出内容，退出状态为 `0`。

没指定 `--file` 时，工具按下面的顺序选第一个已存在的普通文件：

1. `$DAE_LOCATION_ASSET/<name>.dat`
2. `/var/lib/honk/<name>.dat`
3. `/var/share/honk/<name>.dat`，旧根目录
4. `./<name>.dat`
5. `/usr/local/share/honk/<name>.dat`
6. `/usr/share/honk/<name>.dat`
7. `/usr/local/share/dae/<name>.dat`
8. `/usr/share/dae/<name>.dat`
9. `/etc/dae/<name>.dat`

和 `honk-core` 不同，这个工具不加载配置，所以不知道自定义的 `global.data_dir`。每条记录输出一行。下游管道关闭不会导致 panic。

| 命令 | 行格式 |
| --- | --- |
| `geosite list` | `CATEGORY ENTRY_COUNT` |
| `geosite show`、`geosite find` | `CATEGORY KIND VALUE [@ATTR ...]`，`KIND` 为 `domain`、`full`、`keyword` 或 `regexp` |
| `geoip list` | `CODE CIDR_COUNT` |
| `geoip show`、`geoip lookup` | `CODE CIDR` |

## 相关文档

- [全局配置参考](./global.md)
- [Experimental 配置参考](./experimental.md)
- [Clash API 参考](./api.md)
