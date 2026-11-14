# 客户端 DNS TCP syslog 审计

`dns-syslog` 是可选的 feature，可以和原有的 eBPF/API 编译选项组合，构建时显式打开：

```sh
cargo build --release -p honk-core --features dns-syslog
```

这个 feature 默认关闭，`native-api` 和 `native-ui` 都不会自动带上它。如果二进制
没编入这个 feature，又开启了 DNS 审计，启动会报错；审计入口是空实现，不创建队列，
也不创建发送任务。发布构建的 feature 列表保持不变，要用 DNS 审计，得换成显式启用
了该 feature 的构建。

在 `global` 配置 TCP syslog 接收端：

```dae
global {
    syslog_addr: '192.0.2.10:514'
    syslog_dns_enabled: true
    syslog_cee_enabled: true
    syslog_hostname: 'router01'
    syslog_app_name: 'honk'
}
```

IPv6 写成 `[2001:db8::10]:514`。审计默认关闭，地址默认为空；启用时必须配一个数字
单播 IP 和非零端口。地址、发送开关、CEE 模式，以及 hostname/app_name 的修改，都
需要重启。

`syslog_hostname` 默认为空。为空时，启动会读 `/proc/sys/kernel/hostname`，去掉结
尾的一个 LF 再校验；读失败或值非法就回退成 `-`。这是运行 honk 的设备名，不是客户
端名。显式配置的 hostname 必须是 1–255 字节、不含空格的可打印 ASCII。
`syslog_app_name` 默认是 `honk`，要求 1–48 个同样类型的字节。显式的空白、控制字
符和 Unicode 会被拒绝，不做 trim。发送端身份只写进 RFC5424 消息头；JSON 正文不再
带 `hostname` 和 `app_name`，免得接收端解析后出现重复字段。

## 采集和事件格式

DNS 控制器和独立 `dns.bind` 的 UDP/TCP 入口，会捕获实际客户端、前端开始处理的时
间，以及最终生成的应答。每个请求或 TCP 帧产生一个逻辑事件，覆盖缓存命中、负应答、
可解析的拒绝和失败。上游重试不增加事件；客户端重发则分别记录。应答生成前被取消时，
记为 `result: "cancelled"`、`rcode: null`。无法投影的查询计数后跳过。开始时间是
审计入口开始处理的时间，不是内核收包时间。

审计和 `native-api`、UI、`record_dns_log`、512 条历史记录、日志级别都无关。诊断
调用、后台刷新和引擎内部解析不记录。只有原样 direct/group TCP/UDP 中继、没有经过
DNS 控制器的 53 端口流量不在覆盖范围内，原有路由策略也不变。

输出用固定的 RFC5424 头：PRI134（local0/info）、UTC 时间、配置的身份、MSGID
`dns.query`，后面跟完整的紧凑 JSON 事件。`syslog_cee_enabled` 默认 false，以兼容
普通的 JSON 接收端；像上例那样设为 true 时，会在消息前加 `@cee: ` 前缀，供支持
CEE 的接收端解析：

```text
<134>1 2026-11-02T12:00:00.010000Z router01 honk - dns.query - @cee: {JSON正文}
```

```json
{
  "schema_version": 1,
  "event": "dns.query",
  "message": "DNS 192.168.1.100 example.com. A IN: NOERROR answers=1",
  "event_id": "process-uuid:1",
  "query_time": "2026-11-02T12:00:00.000000Z",
  "completed_at": "2026-11-02T12:00:00.010000Z",
  "duration_ms": 10.0,
  "upstream": "default",
  "client_ip": "192.168.1.100",
  "client_port": 53120,
  "transport": "udp",
  "domain": "example.com.",
  "qtype": "A",
  "qclass": "IN",
  "result": "response",
  "rcode": "NOERROR",
  "response_truncated": false,
  "answers": [
    {"name":"example.com.","type":"A","class":"IN","ttl":60,"data":"203.0.113.20"}
  ],
  "answers_omitted": null,
  "answer_ips": ["203.0.113.20"],
  "answer_cnames": [],
  "answer_types": ["A"]
}
```

`duration_ms` 是数值型的处理耗时，单位为毫秒，截取到微秒精度。单调时钟从审计
admission 开始计时，在最终响应准备完成或请求取消时停止，排除响应审计数据复制、向客户端
发送响应及后台日志排队。UTC 时间字段仍使用系统时钟，不通过两个时间戳相减计时。
`upstream` 取最终结果的上游配置名称；正常缓存和过期缓存应答统一写 `"cache"`。
本地答案、拒绝、取消等没有上游元数据的结果写 null。不输出最初上游或重查询历史。

`transport` 描述客户端与 honk 之间的 DNS 传输方式；审计输出本身始终使用 TCP。完整
答案保留名称、类型、类别、TTL 和内容，未知类型用 RFC3597 文本。honk 生成按首次出现
顺序去重的数组：`answer_ips` 提取 A/AAAA data，`answer_cnames` 提取 CNAME 目标，
`answer_types` 提取全部类型，无匹配时输出空数组。不删除或改写原始答案。应答校验只
检查记录边界，不检查每条记录的内容；已经发送给客户端的应答仍可能无法渲染。此时事件
保留其他字段，`answers` 为 null、数组为空，`answers_omitted` 为 `"invalid"`（投影
超过事件上限时为 `"budget"`）；其他情况 `answers_omitted` 为 null。TC 描述实际
客户端应答，可能受客户端 UDP 大小限制。捕获在应答发送前，不证明客户端已收到。进程
UUID 重启后变化，序号标识生成的事件，不为 admission 失败编号，也不证明无丢失。

## 分帧与组批

分帧使用 [RFC6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587)：先写
完整 RFC5424 消息的十进制字节数，再写一个 ASCII 空格，然后是消息内容。长度包含消
息头、CEE 前缀和 JSON，不包含长度前缀本身；按 UTF-8 字节计数，不按字符，也不添加
换行或 NUL。一批里拼接多条独立分帧的事件：

```text
<长度1> <消息头和JSON1><长度2> <消息头和JSON2>
```

接收端必须支持长度前缀，不能直接把 HTTP JSON Lines 接口拿来用。不发送 UDP，也不
做应用层分片；超过 8192 字节的事件，只要在 4 MiB 上限内，仍是一整帧。重复的字段
名、展开的名称、检索数组、长 TXT，以及二进制或未知的记录，都会让体积变大。

每个目标有一个异步任务，按需建立并复用一条 TCP 连接。批量目标是 128 KiB，或者从
第一条已准备的消息起满 1 秒就刷新；后来到达的消息不会重置这个期限。单条消息超过
批量目标时，单独完整发送。完整的 RFC5424 消息上限是 4 MiB：分配答案之前先检查有
限的投影预算，序列化本身也有上限。超过投影预算的答案按上文省略；仍然超过消息上限
的事件整体丢弃并计数，不会静默截断答案。这些是起始参数，不是吞吐保证。

## admission 与故障

DNS 路径只提交不可变的报文，不等待网络。正在捕获或等待处理的事件最多 1,024 个；
原始请求和应答、复制的上游名称，加上条目核算，一共限制在 8 MiB。应答字节的
admission 不等待，失败时丢弃整个事件，不会误记成取消。队列满时丢弃新事件并计数，
不拖慢 DNS。关闭这个 feature 后不复制报文，也不启动任务。

8 MiB 是原始数据的 admission 限制，不是总内存。后台还会另外持有：有界的投影和
JSON、分帧用的复制、通常不超过 128 KiB 的批次或一条不超过 4 MiB 的事件，以及刷新
时最多一条已准备好的下一帧。大批次占用的容量用完就释放。

连接 socket 之前，先设置实际的 `global.so_mark_from_dae`，并开启 TCP_NODELAY。接
收端的域名不解析，流量也不走代理；mark 设置失败时不允许退回无标记。连接和批次写
入的超时都是 3 秒。连接失败时保留有界批次、停止消费队列，然后按 250 ms 到 30 秒
的指数退避重连。断线期间保证不了 1 秒刷新；只有整批写入成功才重置退避，连接成功
本身不重置。

写入出错或超时的时候，批次可能已经发出去一部分，所以会丢弃这个不确定的批次、关闭
连接，不重放。后续排队的事件改用下一条连接。不承诺恰好一次，也不承诺应用层确认或
接收端已经持久化。写入成功只算 submitted，不等于确认入库。

关闭会立即取消连接、写入和退避，关闭 admission，并丢弃待发送的内容。1 秒是等待或
终止任务的上限，不是最后一次刷新的宽限期。owner Drop 会终止任务；reload 不会重复
创建发送器。关闭时会报告丢弃、无效、提交的事件，以及连接和写入的失败。接收端开始
故障时记一条带错误的 WARN，之后批次写入成功时记 INFO，中间的重试记 DEBUG；队列上
限导致的丢弃最多每 10 秒 WARN 一次，无法编码的事件记 DEBUG。本地不落盘，留存、轮
转和检索都由远端负责。

## 展示消息

完整 JSON 事件里有一个非空的 `message` 摘要，写明规范化后的客户端 IP、查询问题、
应答状态，或者 `cancelled`，以及答案数量。已有的结构化字段和完整答案继续用于审计
检索；摘要也计入整条消息的字节上限。

打开 `syslog_cee_enabled: true` 后，VictoriaLogs 的 syslog 接收器展开 CEE JSON
时会把 `message` 映射到 `_msg`，日志列表展示的就是这个字段。缺少该字段的旧事件可
能显示默认的缺失消息占位，其他字段仍会保存。参见 [VictoriaLogs
syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
及[消息字段](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field)。

## 固定格式与配置变更

消息头布局和 JSON 字段结构是固定的，见上文。不提供消息模板、JSON 模板、标签、格
式版本或 CEF 模式。序列化在后台发送任务里做；普通配置 reload 既不改变事件格式，
也不重启 TCP 发送器。上面那五项设置就算在审计关闭时改动，也仍然需要重启。

### 从较早的 fork 构建迁移

原来从 JSON 正文读 `hostname` 或 `app_name` 的接收端，应当改成读解析后的 RFC5424
头部对应字段。已有的历史日志不受影响。

`syslog_dns_template` 和 `syslog_dns_json` 已经删除。dae 配置和结构化配置只要出
现旧 key 就拒绝，空字符串、false 和 null 也不能保留。如果要保持上一版固定 CEE 输
出，显式设置 `syslog_cee_enabled: true`；否则默认发送普通 JSON。开启审计之前，还
要确认二进制已经编入 `dns-syslog` feature。
