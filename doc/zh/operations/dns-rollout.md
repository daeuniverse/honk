# DNS 灰度与回滚操作手册

本手册给出 DNS 子系统的灰度部署和回滚步骤。子系统本身见 [DNS 设计](../design/dns.md)。

本清单只覆盖部署流程，尚未在本地开发环境执行。真实 eBPF 加载与挂接、网络命名空间变更、透明 socket 和路由 map 发布，都需要一台隔离、经明确授权且具备 root 权限的 Linux 主机。

## 前置条件

- 一台可丢弃或隔离的授权主机，一条带外恢复通道，以及一个维护窗口。首次灰度不要用共享生产网关。
- 只有特权灰度需要以下条件：root 或免密 `sudo`；支持 cgroup v2 和原始 BTF 的 Linux 内核，BTF 可以来自内核自带、OpenWrt 的 `/usr/lib/debug/boot/vmlinux`，或用 `HONK_VMLINUX_BTF` 指定的外部文件；以及真实冒烟检查所需的目标接口、路由和 DNS 客户端。
- Rust stable、项目 nightly 工具链、`rust-src`、`bpf-linker`、CMake、C/C++ 编译器、libclang/bindgen 依赖和 `readelf`。
- 当前二进制、配置、BPF 目标文件和持久化状态的确切路径。状态在 `<data_dir>/state/`，使用状态数据库之前是 `cache.db`。还要留出足以保存只读回滚副本的空间，并记下上一份已知可用二进制与配置的校验和。
- 观察服务日志和主机健康的渠道。DNS 计数器和结构化日志只供内部诊断，没有新增公开的 DNS 指标 endpoint。

## 部署前与备份

1. 记录主机、内核、接口、当前二进制与配置的校验和、日志中的当前路由 generation、服务命令和 UTC 时间。
2. 用候选版本的确切源码做一次无特权独立 DNS 冒烟检查：

   ```bash
   just dns-smoke
   ```

   该命令构建 debug 版 `honk-core`，并用 `--mock-ebpf` 启动真实进程。它分别通过 UDP 和一条持久 TCP 连接，在配置不变的 SIGHUP 前后各验证一次配置中的 loopback listener。命令返回前会停止进程并清除全部临时资源。
3. 用常规服务管理器暂停已安装的服务，把当前二进制和配置复制到带时间戳的只读回滚路径。
4. 服务暂停期间备份持久化状态（`<data_dir>/state/` 或 `cache.db`），并保留所有权和权限模式。启用 `global.store_subscribe` 时，还要备份旧订阅存储，也就是 `<data_dir>/.sub`、`/var/share/honk/.sub` 与 `./.sub` 里第一个找到的私有 `.sub` 目录。带状态数据库的候选版本首次启动时会导入并删除其中的 `*.sub` 正文。记录二进制、配置、状态和 `.sub` 备份的校验和。不要删除、改写、压缩整理或迁移数据库。
5. 重启旧版本，做完 UDP 和 TCP 的 DNS 冒烟检查，确认回滚文件可用后再继续。

## 特权灰度

> 状态：本地开发环境为 **NOT EXECUTED**。下面的步骤只能在满足全部前置条件、隔离且经明确授权的主机上执行。

1. 在授权主机上构建并检查候选版本：

   ```bash
   just build-ebpf
   cargo build --release -p honk-core --features ebpf
   ```

   确认 eBPF 目标文件含 `.BTF`，并保留构建日志。
2. 正常停止旧服务。安装候选二进制，不要覆盖回滚副本，然后用主机的服务管理器，以保留的生产配置和显式指定的 BPF 目标文件启动。
3. 确认加载和挂接成功，接口和策略路由正常，新的路由 generation 已发布。不要运行 `just clean-all`，也不要删除已固定的 map、命名空间、路由或缓存行。
4. 从授权客户端各发一个 UDP 和一个 TCP DNS 查询，都走拦截路径。如果原本就启用了 Clash，再执行 `/dns/query` 和 `/cache/dns/flush`；不要只为灰度临时启用 Clash。
5. 用常规 SIGHUP 或服务管理器 reload 未修改的配置并重复查询，再做一次预先批准且可逆的策略变更，reload 后验证新的完整路由 generation。
6. 观察内部的低基数诊断：缓存命中、未命中、过期；flight 饱和、取消、重试；持久化 drop/flush 失败；运行时退役；传输初始化与重置；投影的旧 generation、写入失败、重试；DNS 结果分类。任何持续增长的失败或重试计数、退役超时、map 满、DNS 应答回归或路由不一致，都判定灰度失败。

## 回滚

1. 正常停止候选版本并保留日志。不要清理 BPF 状态，也不要修改持久化状态。
2. 从已验证的回滚副本恢复旧二进制和配置。只有灰度损坏或替换了数据库时才恢复数据库备份，通常保留当前数据库。带状态数据库的候选版本首次启动时会导入并删除 `cache.db`，启用 `global.store_subscribe` 时还会删除旧 `.sub` 订阅正文；所以回滚到没有状态数据库的版本时，要恢复 `cache.db` 和 `.sub` 备份。
3. 用旧配置和 BPF 目标文件启动旧二进制，再触发一次常规配置 reload，让它重新推送旧路由 generation。重新开放流量前，先从日志确认 generation 已提交。
4. 重复 UDP 和 TCP 的 DNS 冒烟检查、路由检查，以及原本已配置时的 Clash 冒烟检查。确认主机健康，并把计数器和日志与部署前的记录比较。
5. 为事件复盘保存候选日志、校验和、构建输出和查询结果。绝不能把破坏性清理当作回滚方式。

## 证据记录

在部署工单中记录每条命令、退出状态、时间戳、校验和、路由 generation、查询结果，以及相关计数器和日志快照。除非已在隔离的授权主机上满足全部前置条件，否则必须把特权清单标记为 `NOT EXECUTED`。

## 相关文档

- [DNS 设计](../design/dns.md)
- [DNS 配置参考](../reference/dns.md)
- [实验性配置参考](../reference/experimental.md)
