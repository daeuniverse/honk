# honk 的 dae 配置方言

honk 读取 dae 的配置语法，但它是一种方言：honk 与 dae 对同一段文本的解析结果不同时，以 honk 的解析为准，这些差异不按 dae 的行为调整。本页列出所有已知差异，便于把为其中一方写的文件对照另一方检查。dae 一栏只陈述 dae 文法（`dae_config.g4`）的规定，不描述 dae 的取值转换；honk 一栏是本页编写时所依据提交（合并 #190 后的 `main`，`66fc946`）上解析器的行为：每个示例都经 `parse_dae_config` 加载并记录结果，任何一行都可以用同样的文本重新验证。

## 词法规则

| 输入 | dae 文法 | honk |
|---|---|---|
| 裸值内的 `#`，`log_file: /tmp/a#b` | `#` 是裸字面量内的安全字符，值为 `/tmp/a#b` | 标量设置在引号外第一个 `#` 处截断，不论是否紧贴：`/tmp/a`。要保留 `#` 就给值加引号。 |
| 路由规则里紧贴出站名的 `#`，`domain(x) -> proxy#c` | 一个裸字面量 `proxy#c` | 路由语句在任何引号外的 `#` 处截断：出站是 `proxy`。 |
| `/* … */` | 块注释，跳过 | 不识别，也不跳过：`/* log_level: debug */` 这一行的键是 `/* log_level`，未知因而忽略；但这类文本里的花括号或合法的 `key: value` 会被当作配置读取。 |
| 声明后的 `[key: value]`，`filter: name(x) [add_latency: -500ms]` | 作为注解接受 | 不识别；该过滤条件被报告为无法解析并忽略。honk 没有按节点的延迟偏置。 |
| 标量里不成对的引号，`log_file: /tmp/don't` | 词法错误 | 普通文本：`/tmp/don't`。路由语句里的未闭合引号是错误（`routing line N: unterminated quote`）。 |
| 引号内的花括号，`secret: 'a}b'` | 数据 | 数据。未加引号的行尾注释里的花括号仍参与块结构，这类注释请独占一行。 |
| 块起始符前没有空格，`global{ … }` | 空白被跳过，仍是块 | 错误 ``unexpected `{` ``：行内起始符前需要空白；行尾的 `{` 不需要。 |
| 多余的 `}`，或空文件 | 多余的 `}` 被拒绝；空输入或只有注释的输入被接受 | 多余的 `}` 被忽略并报告诊断；没有 `{` 与 `}` 的文件报错 `not a dae config file`。 |
| 块名，`123 {`、`香港 {`、`Hong Kong {` | 块名必须是一个 `ID` | 行尾的 `{` 之前的任何文本都作为块名。 |
| 一行两个声明，`global { log_level: debug log_file: x }` | 空白分隔的两个声明 | 一个声明：`log_level` 的值是 `debug log_file: x`。每行一个 `key: value`；单行块只容纳一条语句。 |
| 起始花括号另起一行，`global` 换行 `{` | 空白（含换行）被跳过 | 错误 ``unexpected `{` at line 2``：块在带 `{` 的那一行开始。只有顶层 `include` 可以把 `{` 放在下一行。 |

## 标量与列表

| 输入 | dae 文法 | honk |
|---|---|---|
| 带冒号的裸值，`bind: 127.0.0.1:53` | 不是一个字面量，必须加引号 | 接受裸写：值是第一个 `:` 之后的全部文本。 |
| 调用形态的值，`client_subnet: auto(9.9.9.9)` | 函数表达式 | 文本 `auto(9.9.9.9)` 就是值，由该设置自行解析。 |
| 带引号的列表项，`lan_interface: 'eth0', 'eth1'` | 两个字面量 | 接口列表先剥去整个值两端的引号再按逗号拆分，各项不再去引号，因此得到 `eth0'` 与 `'eth1`。`tcp_check_url` 与 `udp_check_dns` 会额外逐项剥去单引号。列表项请裸写：`lan_interface: eth0, eth1`。 |
| 布尔值 `t`、`y`、`f`、`n` | 裸字面量 | 宽松设置（不区分大小写）：`true`、`yes`、`1`、`on` 为真；`false`、`f`、`no`、`n`、`0`、`off`、`t`、`y` 为假；其他写法为假并报告诊断。`global.nfqueue_enable` 与旧版 `experimental.udp_nfqueue.enabled` 是严格解析：`t`、`y`、`f`、`n` 及未知写法都是错误。 |
| mark，`so_mark_from_dae: 0x10` 与 `so_mark_from_dae: 10` | 裸字面量 | 两者都按十六进制读取：16 与 16。无法解析的 mark 回退为 0 并报告诊断。 |
| 毫秒设置里的小数秒，`check_tolerance: 1.5s` | 裸字面量 | 1500 毫秒。无法解析的毫秒时长（`check_tolerance`、`sniffing_timeout`）回退到该设置的默认值并报告诊断；无法解析的秒时长（`check_interval`、订阅 `interval`）回退为 `0` 并报告诊断。 |
| `fixed_domain_ttl` 条目 `x: 60#note`、`y: '60'`、`z: 60 ignored` | `60#note` 与 `'60'` 是字面量，`60 ignored` 是两个词法单元 | `x`、`y` 被报告并忽略（值必须是裸十进制）；`z` 存为 60，尾部文本忽略。 |
| 未知的 `policy`，`policy: mystery(...)` | 任意函数表达式 | 回退为 `selector` 并报告诊断；参数文本不会被回显。 |

## node 与 subscription 条目

| 输入 | dae 文法 | honk |
|---|---|---|
| 分享链接或订阅上的标签 | `ID ':' literal`；裸字面量不能含 `:`，所以链接要加引号 | 第一个 `:` 之前的文本是标签，除非该冒号是 `://` 的开头；链接可以裸写；标签与链接都可以加引号。仅在 `subscription` 里，整体加引号且内含标签的值（`'paid:https://…'`）会在去引号后再拆分，无标签的条目以 URL 主机名命名；在 `node` 里加引号的值就是整个链接（`'paid:socks5://…'` 是未知协议）。 |
| 条目行的行尾注释 | `#` 作为词法单元开头时是注释 | 前面是空格或制表符的 `#` 结束该行；裸链接里紧贴的 `#` 留在链接里（`…#hk1`、`?filter=(hk)#token`）。无 tag 且加引号的 node 只取引号内的部分，其后的文本忽略。带引号的订阅 URL 之后，紧跟结束引号或 `(UA)` 后缀的 `#` 也是注释。 |
| 订阅链接后的 `'url'(User-Agent)` | 不在文法内 | honk 扩展：括号内文本是 User-Agent；未加引号的括号内前有空格的 `#` 会结束该行，这类 User-Agent 请加引号。 |
| 订阅块：`paid: {` 之后各占一行的 `url: …`、`ua: …`、`interval: …` 与 `}` | `ID ':' '{'` 不是声明 | honk 扩展：订阅的块形式；其设置与其他块一样每行一条。 |
| `node` 里冒号前带空格的裸标签，`edge : 'socks5://…'` | 标签为 `edge` | 整行被当作链接，被分享链接解析器拒绝并跳过，stderr 输出一条消息，文件其余部分正常加载。请写 `edge: …` 或给标签加引号。 |

## 路由

| 输入 | dae 文法 | honk |
|---|---|---|
| 裸前缀匹配器，`!geosite:cn -> proxy`、`domain:example.com -> proxy` | 不是函数调用，拒绝 | 接受为匹配器（`geosite`、`geoip`、`domain`、`suffix`、`keyword`、`regex`、`full` 前缀）。 |
| 两个箭头，`domain(x) -> proxy->backup` | 拒绝 | 出站是字面文本 `proxy->backup`。 |
| `-> proxy( must )` | 带参数 `must` 的调用 | 只有精确后缀 `(must)` 是 must 标记；`proxy( must )` 是名为 `proxy( must )` 的出站。 |
| 括号前有空格，`dport (443) -> proxy` | 接受 | 匹配器不被识别，条件被丢弃：规则加载后没有端口条件。请写 `dport(443)`。 |
| 合取里的未知匹配器，`dport(443) && domian(x) -> direct` | 文法接受，校验在文法之外 | 未知匹配器被丢弃，规则按 `dport(443) -> direct` 加载。请检查拼写；见 issue #161。 |
| 含多个冒号的参数，`dip(2001:db8::/32)`、`mac(00:11:22:33:44:55)` | 不是字面量，需要加引号 | 整体保留：只有识别的 `prefix:`（`geosite:`、`geoip:`、`domain:`、`suffix:`、`keyword:`、`regex:`、`full:`）才在其冒号处拆分。 |

## DNS

| 输入 | dae 文法 | honk |
|---|---|---|
| request 或 response 规则里未加引号的 `//` | 不是注释 | 注释，优先于 `#`；引号内的 `//` 是数据。 |
| request 或 response 规则里的 `#`，`qname(a#b) -> reject # note` | `a#b` 是字面量，`# note` 是注释 | 只检查引号外第一个 `#`，且仅在其前面是空格时才是注释：此例它紧贴前文，因此不截断，动作变成文本 `reject # note`，不等于 `reject`。注释请独占一行。 |
| request 或 response 规则里的 `->` | 一个箭头 | 规则在第一个引号外的 `->` 处拆分，后续箭头留在动作里（`-> up->stream` 是名为 `up->stream` 的上游）。整个动作文本会转为小写：`Reject` 即 `reject`，`-> MixedCase` 指向名为 `mixedcase` 的上游，与声明为 `MixedCase` 的上游不匹配。 |
| 跨行的匹配器调用，`qname(` 换行 `a.example) -> reject` | 空白（含换行）被跳过 | request 与 response 规则逐行读取，两行都不是完整规则，该规则被丢弃且没有诊断。 |
| 带出站的上游，`u: 'udp://1.1.1.1:53' -> proxy` 或 `u: 'udp://1.1.1.1:53' outbound: proxy` | 箭头形式被拒绝（声明不能带 `->`）；`outbound: proxy` 形式是相邻的两个声明 | honk 扩展：两种形式都让上游 `u` 经出站 `proxy` 拨号。 |
| 匹配器调用后的文本，`dport(443)junk -> proxy`、`qname(a.example)junk -> reject` | 拒绝：箭头必须紧接调用 | 第一个引号外 `)` 之后的文本被忽略，匹配器仍然生效（路由与 DNS 规则；节点过滤条件 `name(...)`/`subtag(...)` 则要求调用结束整个表达式）。 |
| 上游行的行尾注释，`v: 'udp://8.8.8.8:53' # note` | 注释 | 不剥除：地址变成 `8.8.8.8:53' # note`。上游的注释请独占一行。 |
| 带引号的上游 URL 内的 `->` 或 `outbound:` | 数据 | 上游读取器搜索整行，包括引号内：`'https://dns.example/q?x=outbound:proxy#frag'` 变成地址 `dns.example/q?x=`、出站 `proxy#frag`。不要在上游 URL 里放这两个分隔符。 |
| `qtype(...)` | 函数参数 | 名称 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY`、`*`（不区分大小写）或十进制 `u16`；未知名称静默省略，列表为空的 `qtype` 仍保留为一个不匹配任何类型的条件。`qtype('a,aaaa')` 把带引号的文本按逗号拆分。 |

## 组

| 输入 | dae 文法 | honk |
|---|---|---|
| `group('hk,jp')` | 一个字面量 | 两个子组标签，按 `,` 与 `\|` 拆分。 |
| `filter: group()` | 无参数的调用 | 空的子组过滤条件被丢弃；没有其他 `filter:` 行时组回退为全部节点。见 issue #161。 |

## 配置段与 include

| 输入 | dae 文法 | honk |
|---|---|---|
| `experimental` 里的未知内容 | 任意声明 | 直接位于 `experimental` 下的未知行是错误（`unknown experimental setting: …`）；`clash_api` 与 `cache_file` 里的未知键被忽略；旧版 `udp_nfqueue` 里的未知键是错误。 |
| `global`、`dns`、`routing` 里的未知嵌套块 | 任意表达式 | 其中的行按处于该配置段层级读取。 |
| `include { … }` | 与其他块相同的块 | 只在加载文件时展开模式，规则见[配置指南](../configuration.md)；解析配置字符串时仍扫描该块的花括号（未闭合的 include 是错误），但不读取其中的模式。include 块内未加引号的 `#` 结束一个模式。 |
