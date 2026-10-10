# DNS 灰度与回滚操作手册

本手册用于部署 [DNS 设计](../design/dns.md)所述的子系统。

本清单只用于部署，未在本地开发环境执行。真实 eBPF 加载与挂接、网络命名空间
变更、透明套接字和路由 map 发布需要隔离、明确授权且具备 root 权限的 Linux
主机。

## 前置条件

- 一台可丢弃或隔离的授权主机、带外恢复通道和维护窗口。不要把共享生产网关
  作为首次灰度主机。
- 仅特权灰度需要 root 或免密 `sudo`、带 BTF 的受支持 Linux 内核，以及真实
  smoke 所需的目标接口、路由与 DNS 客户端。
- Rust stable、项目 nightly toolchain、`rust-src`、`bpf-linker`、CMake、C/C++
  编译器、libclang/bindgen 依赖与 `readelf`。
- 当前 binary、config、BPF object 与持久化状态（`<data_dir>/state/`，状态数据库之前为 `cache.db`）的准确路径；足够保存只读回滚
  副本的空间；上一已知良好 binary 与 config 的 checksum。
- 观察服务日志与主机健康的渠道。DNS 计数器和结构化日志用于内部诊断；没有新增
  公开 DNS metrics endpoint。

## 部署前与备份

1. 记录主机、内核、接口、当前 binary/config checksum、日志中的当前 routing
   generation、服务命令与 UTC 时间。
2. 使用候选版本的准确源码执行无特权独立 DNS smoke：

   ```bash
   just dns-smoke
   ```

   此命令构建 debug `honk-core`，通过 `--mock-ebpf` 启动实际进程。它在配置不变的
   SIGHUP 前后，经 UDP 与一条持久 TCP 连接验证配置的 loopback 监听器。命令返回前
   会停止进程并移除所有临时资源。
3. 使用正常 service manager 暂停已安装服务。把当前 binary 与 config 复制到带
   时间戳、只读的回滚路径。
4. 服务暂停期间备份持久化状态（`<data_dir>/state/` 或 `cache.db`），保留 owner 与 mode。记录三个回滚 artifact 的
   checksum。不要删除、改写、compact 或迁移数据库。
5. 重启旧版本并验证其 UDP/TCP DNS smoke 后再继续，确认回滚文件可用。

## 特权灰度

> 状态：本地开发环境中 **NOT EXECUTED**。只有在满足以上全部前置条件、隔离且明确授权的
> 主机上才能执行以下步骤。

1. 在授权主机上构建并检查候选版本：

   ```bash
   just build-ebpf
   cargo build --release -p honk-core --features ebpf
   ```

   确认 eBPF object 含 `.BTF` 并保留构建日志。
2. 正常停止旧服务。安装候选 binary，但不得覆盖回滚副本；随后通过主机的 service
   manager，使用保留的生产 config 和显式 BPF object 启动。
3. 确认加载与挂接成功、接口与策略路由正常，并已发布新的 routing generation。
   不要运行 `just clean-all`，也不要删除 pinned map、namespace、route 或 cache 行。
4. 从授权客户端经拦截路径各发一个 UDP 与 TCP DNS 查询。若原本已启用 Clash，
   还要执行 `/dns/query` 和 `/cache/dns/flush`；不要只为灰度临时启用 Clash。
5. 通过正常 SIGHUP/service-manager 路径重载未变 config 并重复查询；再做一次预先
   批准且可逆的策略变更，重载后验证新的完整 routing generation。
6. 观察内部低基数诊断：cache hit/miss/stale、flight 饱和/取消/重试、持久化
   drop/flush 失败、runtime 退役、transport init/reset、projection 旧 generation/
   写失败/重试与 DNS 结果分类。任何持续增长的失败/重试计数、退役 timeout、
   map-full、DNS 应答回归或路由不一致都判定灰度失败。

## 回滚

1. 正常停止候选版本并保留日志。不要清理 BPF 状态或修改持久化状态。
2. 从已验证的回滚副本恢复旧 binary 与 config。仅当灰度损坏或替换了数据库时才
   恢复数据库备份；通常保留当前数据库。带状态数据库的候选版本首次启动时会导入
   并删除 `cache.db`，因此回滚到没有状态数据库的版本时，需要恢复 `cache.db` 备份。
3. 使用旧 config 与 BPF object 启动旧 binary。再触发一次常规 config reload，
   使其重新推送旧 routing generation；重新开放流量前从日志验证 generation commit。
4. 重复 UDP/TCP DNS、路由，以及原本已配置时的 Clash smoke。确认主机健康，并把
   counters/logs 与部署前记录比较。
5. 为事件复盘保存候选日志、checksum、构建输出和查询结果。绝不能把破坏性清理
   当作回滚方式。

## 证据记录

在部署工单中记录每条命令、退出状态、时间戳、checksum、routing generation、
查询结果与相关 counter/log 快照。除非在隔离授权主机上满足全部前置条件，否则
必须把特权清单标记为 `NOT EXECUTED`。

## 相关文档

- [DNS 设计](../design/dns.md)
- [DNS 配置参考](../reference/dns.md)
- [实验性配置参考](../reference/experimental.md)
