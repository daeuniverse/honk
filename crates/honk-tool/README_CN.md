# honk-tool

`honk-tool` 是 [honk](../..) 的 CLI 工具箱，放那些不属于 `honk-core`
引擎二进制的诊断工具：订阅可用性检测、引擎 eBPF map 快速查询、一键体检。

产物是 **musl 静态二进制**——本地开发可跑，也可以单个文件直接 scp 到
生产网关（VyOS/Debian）上使用。

## 构建

```bash
# 开发机（glibc）
cargo build --release -p honk-tool

# 网关用 musl 静态构建（需要 zig 0.14+，使用 ci/ 包装器）
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl=$PWD/ci/zigcc \
CXX_x86_64_unknown_linux_musl=$PWD/ci/zigcxx \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$PWD/ci/zigcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$(ci/zig-bindgen-env x86_64-linux-musl)" \
cargo build --release -p honk-tool --target x86_64-unknown-linux-musl

scp target/x86_64-unknown-linux-musl/release/honk-tool vyos@<网关>:/tmp/
```

> gnu 构建在纯 musl 系统上无法执行（加载器报 "No such file or
> directory")——部署到网关请一律使用 musl 构建。

## 子命令

### `sub` — 订阅可用性检测

```bash
honk-tool sub <url|file> [--target HOST:PORT] [--url TEST_URL]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

拉取订阅（自动识别 base64 / 原始行 / Clash YAML）或读取本地分享链接文件，
打印协议分布，然后并发探测每个节点：

默认目标沿用 dae 的 `tcp_check_url` 三件套：`cp.cloudflare.com:80` 作测试主机、
`1.1.1.1:80` 探测 v4、`[2606:4700:4700::1111]:80` 探测 v6——即使解析器不返回
AAAA（如 `ipversion_prefer: 4`）族探测也能工作。可用
`--target/--v4-target/--v6-target` 覆盖。

- 服务器地址族（节点域名是否解析出 v4/v6);
- **IPv4 / IPv6 双栈**到测试主机的代理连通性——经节点完成一次完整协议
  拨号（TLS 协议族含 TLS 握手）;
- 经 `urltest_node` 的代理延迟（默认目标
  `https://www.gstatic.com/generate_204`);
- UDP 探活：经节点 `dial_udp_transport` 发送最小 DNS A 查询，以及一次**真实 QUIC
  握手**(h3，跳过证书验证）——复用 honk-outbound 的
  `quic::quic_handshake_probe`（在隧道上叠自定义 `AsyncUdpSocket` 驱动
  quinn)。

末尾输出双栈存活数和延迟中位数。

**v6 显示 `no-AAAA`?** v4/v6 探测通过解析测试主机挑选对应族的地址。当解析器
不返回 AAAA 时（典型场景：honk DNS 配置 `ipversion_prefer: 4`,AAAA 应答被抑制）,v6
显示 `no-AAAA`。可用 dae 风格显式目标跳过 DNS:
`--v4-target 1.1.1.1:443 --v6-target '[2606:4700:4700::1111]:443'`。

```text
$ honk-tool sub https://example.com/sub --limit 3
fetched 200 node(s) in 22ms
protocols: anytls×3

🇭🇰 hk.147   anytls   v4   v4: 41ms   v6: 0ms   urltest: 120ms
...
== 3 node(s): v4-proxied 3, v6-proxied 3, urltest-ok 3, median latency 120ms
```

### `bpf` — 引擎 eBPF map 快速查询

```bash
honk-tool bpf show <map> [--ip ADDR] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
```

通过裸 `bpf(2)` 系统调用直读 `/sys/fs/bpf` 下 pin 的 map（不依赖 aya、
不加载程序），解码内核/用户态共享的线结构。需要 root（或 `CAP_BPF`)。

`show` 支持的 map:

| 名称             | 内容                                              |
| ---------------- | ------------------------------------------------- |
| `conn-state`     | conntrack 条目（outbound/mark/must/状态）          |
| `redirect-track` | 回包改写跟踪（outbound、from_wan、ifindex)         |
| `domain-routing` | DNS 学习到的 IP → 规则位图                         |
| `routing-handoff`| 待消费的 eBPF → 控制面路由 handoff                 |

`stats` 输出 conntrack 溢出计数、`CONN_STATE_OCCUPANCY` 水位计
（数据平面累计插入/删除）以及全部非零的每出口收发计数。

### `diagnose` — 一键体检

```bash
honk-tool diagnose [--api http://127.0.0.1:9090] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark 0x8000000]
```

Clash API 启用认证时，可传入 `--secret TOKEN` 或设置 `HONK_API_SECRET`。
命令行参数优先；令牌通过 `Authorization: Bearer` 发送。

只读检查，逐项打印 `[ok]` / `[FAIL]`:

1. 引擎进程存活（`/proc` 中找 `honk-core`/`dae`);
2. `daens` 命名空间与 `dae0` veth 存在；
3. daens 内 fwmark 策略路由规则存在；
4. 必需的 pin map 存在（`CONN_STATE_MAP`、`REDIRECT_TRACK`、
   `ROUTING_HANDOFF_MAP`、`CONN_STATE_OCCUPANCY`);
5. conntrack 水位/溢出计数可读；
6. clash API 返回 2xx 状态码（`/version`），打印响应正文；
   非 2xx 状态码则打印 `[FAIL]` 和状态文本。

标准输出末尾为 `diagnose: all checks passed`（退出状态 `0`）或
`diagnose: N issue(s) found`（退出状态 `1`，错误信息包含问题数量）。

## 设计说明

- 依赖 `honk-config`、`honk-outbound`、`honk-ebpf-common`，以及
  `default-features = false` 的 `honk-core`（不引入 axum/aya)。
- map 读取路径是约 100 行的 libc `bpf(2)` 实现而非 aya:aya 的 typed-map
  构造器和 `sys` 辅助函数都是 crate 私有，外部工具无法通过其公开 API
  打开 pin 的 map。另外注意 `BPF_OBJ_GET` 的 attr 布局独立（pathname 在
  偏移 0)，与 map 操作布局不通用。
- 线结构（`TuplesKey`、`ConnState` 等）在 `honk-ebpf-common` 中带有
  `aya::Pod` 实现，供需要类型化 API 的调用方使用。

## 许可证

GPL-3.0-only，与 honk 相同。
