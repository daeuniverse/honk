# 客户端 DNS TCP syslog 审计

在 `global` 配置 TCP syslog 接收端：

```dae
global {
    syslog_addr: '192.0.2.10:514'
    syslog_dns_enabled: true
    syslog_hostname: 'router01'
    syslog_app_name: 'honk'
}
```

IPv6 写作 `[2001:db8::10]:514`。审计默认关闭，地址默认空；启用时必须配置数字
单播 IP 和非零端口。地址、发送开关及 hostname/app_name 默认值修改需重启；完整
消息模板和 JSON 模板支持热重载，重载与原生 API 写入前校验均会先编译模板。
本次不包含 IP 访问记录器或其开关。

`syslog_hostname` 默认空：启动时读取 `/proc/sys/kernel/hostname`，移除结尾的一个
LF 后校验，读取失败或非法时回退 `-`。这是运行 honk 的设备名，不是客户端名。
显式 hostname 为1–255字节、不含空格的可打印 ASCII。`syslog_app_name` 默认 `honk`，
要求1–48个同类字节。显式空白、控制字符和 Unicode 会被拒绝，不做 trim。
默认消息头和 JSON 使用同一身份；自定义模板可使用固定头字段或重新映射 JSON 键。

## 采集和事件格式

DNS 控制器以及独立 `dns.bind` 的 UDP/TCP 入口捕获实际客户端、前端处理开始时间和
最终生成的应答。每个请求或 TCP 帧产生一个逻辑事件，包含缓存命中、负应答、可解析
拒绝和失败。上游重试不增加事件，客户端重发分别记录。应答生成前取消时记录
`result: "cancelled"`、`rcode: null`。无法解析出问题的报文计数后跳过。开始时间是
审计入口处理时间，不是内核收包时间。

审计独立于 `native-api`、UI、`record_dns_log`、512条历史队列和日志级别。
诊断调用、后台刷新及引擎内部解析不记录。仅原样 direct/group TCP/UDP 中继、未由
DNS 控制器处理的53端口流量不在覆盖范围内，不改变原有路由策略。

默认输出使用 RFC5424 头：PRI134（local0/info）、UTC 时间、配置的身份、MSGID
`dns.query`，正文为紧凑 JSON：

```text
<134>1 2026-11-02T12:00:00.010000Z router01 honk - dns.query - {JSON正文}
```

```json
{
  "schema_version": 1,
  "event": "dns.query",
  "message": "DNS 192.168.1.100 example.com. A IN: NOERROR answers=1",
  "hostname": "router01",
  "app_name": "honk",
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
  "answer_ips": ["203.0.113.20"],
  "answer_cnames": [],
  "answer_types": ["A"]
}
```

`duration_ms` 是数字类型的处理耗时，单位毫秒，截取到微秒精度。单调时钟从审计
准入开始计时，在最终响应准备完成或请求取消时固定，排除响应审计数据复制、向客户端
发送响应及后台日志排队。UTC 时间字段仍使用系统时钟，不通过两个时间戳相减计时。
`upstream` 取最终结果的上游配置名称；正常缓存和过期缓存应答统一写 `"cache"`。
本地答案、拒绝、取消等没有上游元数据的结果写 null。不输出最初上游或重查询历史。

`transport` 描述客户端 DNS 方式，审计输出始终使用 TCP。完整答案保留名称、类型、
类别、TTL 和内容，未知类型用 RFC3597 文本。honk 生成按首次出现顺序去重的数组：
`answer_ips` 提取 A/AAAA data，`answer_cnames` 提取 CNAME 目标，`answer_types`
提取全部类型，无匹配时输出空数组。不删除或改写原始答案。TC 描述实际客户端应答，
可能受客户端 UDP 大小限制。捕获在应答发送前，不证明客户端已收到。进程 UUID
重启后变化，序号标识生成的事件，不为准入失败编号，也不证明无丢失。

## 分帧与组批

使用 [RFC6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587)：完整 RFC5424
消息的十进制字节数、一个 ASCII 空格、消息内容。长度包含消息头和 JSON，不包含
前缀本身，按 UTF-8 字节计数而非字符，不添加换行或 NUL。一批拼接多条独立分帧事件：

```text
<长度1> <消息头和JSON1><长度2> <消息头和JSON2>
```

接收端必须支持长度前缀，不能直接使用 HTTP JSON Lines 接口。不发送 UDP 或
应用层分片；超过8192字节的事件仍为完整一帧。测试中100条压缩 AAAA 答案的 DNS
应答为2831字节，审计 JSON 约10.3kB。重复字段名、展开名称、检索数组、长 TXT 和
二进制或未知记录都会增加体积。

每个目标一个异步任务，按需建立并复用一条 TCP 连接。组批目标128KiB，或从首条
已准备消息起满1秒刷新；后续到达不重置期限。单条超过批量目标时单独完整发送。
完整 RFC5424 消息上限4MiB：答案分配前检查有限投影预算，序列化也有上限。
超限事件整体丢弃并计数，不静默截断答案。这些是起始参数，不是吞吐保证。

## 准入与故障

DNS 路径只提交不可变报文，不等待网络。最多允许1024个捕获中或待处理事件，原始
请求/应答、复制的上游名称及条目核算限制8MiB。应答字节准入不等待，失败丢弃整个事件，不误记取消。
队列满丢弃新事件并计数，不拖慢 DNS。关闭功能不复制报文、不启动任务。

8MiB 是原始数据准入限制，不是总内存。后台额外持有有界投影/JSON、分帧复制、
普通不超过128KiB的批次或一条不超过4MiB的事件，以及刷新时最多一条已准备的下一帧。
大批次容量使用后释放。

套接字 connect 前设置实际 `global.so_mark_from_dae`，开启 TCP_NODELAY。
不解析接收端域名、不走代理，mark 失败不允许无标记回退。连接和批次写入超时3秒。
连接失败保留有界批次、停止消费队列，以250ms到30秒指数退避重连。断线时无法保证
1秒刷新；仅整批写入成功才重置退避，连接成功本身不重置。

写入错误或超时可能已发送部分批次，因此丢弃不确定批次、关闭连接，不重放。
后续排队事件使用下一条连接。不承诺恰好一次、应用层确认或接收端持久化证明。
写入成功计为 submitted，不等于确认入库。

关闭立即取消连接、写入和退避，关闭准入并丢弃待发送内容；1秒是等待/终止任务上限，
不是最后一次刷新的宽限期。owner Drop 终止任务，重载不重复创建发送器。
关闭时报告丢弃、无效、提交事件及连接/写入失败，运行告警限频。本地不落盘，
远端负责留存、轮转和检索。

## 展示消息

默认完整事件在普通 JSON 和 CEE JSON 模式下均包含非空 `message` 摘要，描述规范化客户端 IP、
查询问题、应答状态（或 `cancelled`）和答案数量。已有结构化字段和完整答案继续用于
审计检索；摘要同样计入整条消息的字节上限。

VictoriaLogs 的 syslog 接收器展开 CEE JSON 后，将 `message` 映射到 `_msg`，用于日志
列表展示；自定义 JSON 模板需要自行保留 `message` 字段以提供此展示内容。
缺少该字段的旧事件可能显示默认的缺失消息占位提示，其他字段仍已保存。
参见 [VictoriaLogs syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
及[消息字段](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field)。

## 模板与热重载

`syslog_dns_template` 控制完整 RFC 5424 消息，包括 PRI、时间、主机名、应用名、
PROCID、MSGID、结构化数据和正文。RFC 6587 的十进制字节数及空格由程序在渲染后
自动添加，模板中无需填写。默认配置为：

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - ${json}'
    syslog_dns_json: ''
}
```

`${json}` 序列化配置的 JSON 对象。`syslog_dns_json` 为空时，保留上面的完整原始
事件及其字段类型。使用 CEE 与自定义嵌套结构的示例：

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - @cee: ${json}'
    syslog_dns_json: '{"message":"${message}","time":"${query_time}","client":{"ip":"${client_ip}","port":"${client_port}"},"dns":{"name":"${domain}","answers":"${answers}","ips":"${answer_ips}"},"format":"${template_version}"}'
}
```

原事件的所有键均可作为标签，包括 `${duration_ms}` 和 `${upstream}`，还提供
`${version}`（程序版本）、`${template_version}`
（64 位十六进制 SHA256）及 `${json}`（仅限完整消息的正文）。标签读取规范事件字段，
不会引用其他自定义输出键。JSON 键为固定文本，任意层级的重复键都会拒绝；根节点
必须为对象。整个值只有一个无过滤器标签时，如 `"${client_port}"`，保留数字、布尔、
null、数组或对象类型；嵌入文本或使用过滤器时输出字符串。`$$` 输出字面美元符，
因此 `$${domain}` 输出 `${domain}`。未知标签、过滤器及未闭合标签会拒绝候选配置，
关闭审计时也会校验。

过滤器使用 `${字段|过滤器}`：

- `text`：字符串原值；其他类型转换为紧凑 JSON 文本。
- `json`：JSON 编码，字符串包含引号；可用于手工编写文本正文。结构化 JSON 模板
  已经自动转义字符串。
- `cef_header`：转义 CEF 头字段中的反斜线、竖线、CR 和 LF。
- `cef_ext`：转义 CEF 扩展值中的反斜线、等号、CR 和 LF。
- `sd`：转义 RFC 5424 结构化数据值中的反斜线、引号和右方括号，拒绝控制字节；
  在带引号的 SD 值中使用此过滤器。

CEE 和 CEF 均由模板正文决定，无单独的格式开关。CEF 示例：

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - CEF:0|GhostStar|honk|${version|cef_header}|dns.query|DNS query|1|src=${client_ip|cef_ext} dhost=${domain|cef_ext} msg=${message|cef_ext}'
}
```

编译及渲染后都会校验 RFC 5424 version 1 消息头：头字段不能注入空格或控制字节，
长度符合对应 RFC 限制；时间为 `-` 或最多六位小数的 RFC3339；SD-ID 和各 SD 元素内
的参数名各自唯一。包含结构化数据的头部前缀上限为 8 KiB。动态值非法时整条事件
丢弃并增加 `invalid`，JSON 不会被截断。消息整体仍限制为 4 MiB，包含头部和固定
前缀。两个模板的源文本合计最多 64 KiB，嵌套深度 16、编译节点 1024、标签 2048。

模板在配置激活前编译，在现有配置/DNS 成功提交点一起发布。已经提交但运行降级的
激活同样使用新模板；被拒绝的重载保留旧配置和旧模板。每个客户端请求在开始审计时
固定模板，透明 UDP 在分发任务前完成捕获。正在处理和排队的事件，包括取消事件，
继续使用旧模板；后续请求使用新模板，已经组装好的批次保持原样。同一 TCP 连接中
可能短暂出现两种格式。`${template_version}` 为两个原始源字符串分别加上大端 u64
字节长度后的 SHA256；无关配置重载不会改变它，默认事件也不会自动新增此字段。

最多同时保留八个编译快照，包含当前和候选版本。排队或处理中请求占满快照名额时，
新模板重载会被拒绝，待旧引用释放后可重试；模板未变无需新名额。没有历史模板缓存
或本地落盘。序列化、文本插值和转义均在后台发送任务中完成。

### 从较早的 fork 构建迁移

删除 `syslog_cee_enabled`，结构化配置中显式的 `false` 或 `null` 也要删除；旧键会
触发明确的迁移错误。原来设为 `true` 时使用上述 CEE 消息模板，设为 `false` 时使用
默认模板。目标地址、发送开关和身份默认值仍需重启；模板修改使用普通配置重载，
发送任务和连接继续复用。
