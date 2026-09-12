# honk 的 dae 配置方言

honk 读取 dae 配置语法，形成自己的方言：两者对同一段文本的解析结果不同时，以 honk 文档规定的行为为准。本页描述基于源文本的解析器当前采用的规则。dae 一栏只描述其文法（`dae_config.g4`），不涉及值转换。

## 词法规则

| 输入 | dae 文法 | honk |
|---|---|---|
| 裸值内的 `#`，如 `log_file: /tmp/a#b`、`use_host: /tmp/a#b` 或 `group(hk#suffix)` | `#` 是裸字面量内的安全字符 | 紧贴前文的 `#` 是数据，在旧版截断处产生 `legacy-glued-hash` 警告。标量路径保留为 `/tmp/a#b`，子组名称为 `hk#suffix`。需要注释时，请在 `#` 前加空白。 |
| 路由规则里紧贴出站名的 `#`，`domain(x) -> proxy#c` | 一个裸字面量 `proxy#c` | 字面目标为 `proxy#c`，产生 `legacy-glued-hash` 警告，仍须通过通常的目标校验。注释请写成 `-> proxy # comment`。 |
| `/* … */` | 块注释，跳过 | 不支持块注释。以 `/*` 开头的语句产生 `unsupported-comment` 警告并被忽略，后续物理行仍按配置读取。需要多行注释时，请每行使用 `#`。 |
| 声明后的 `[key: value]`，`filter: name(x) [add_latency: -500ms]` | 作为注解接受 | 不识别；该过滤条件被报告为无法解析并忽略。honk 没有按节点的延迟偏置。 |
| 裸标量内的撇号，如 `log_file: /tmp/don't`，或已开启的流量参数引号 | 裸值内的撇号是词法错误 | `/tmp/don't` 是字面值。普通引号只在词法单元开头，或紧接引号外的 `(`、`,` 时开启；顶层 `include` 额外识别相邻的带引号路径。流量规则中未在同一物理行闭合的引号产生带位置的 `unterminated-quote` 错误；请闭合引号，不要依赖花括号恢复结构。 |
| 引号或注释内的花括号，如 `secret: 'a}b'` | 数据 | 引号内和词法单元开头注释内的花括号都是数据。条目尾部紧贴 `#` 的兼容截断不会隐藏独立的结构花括号。旧版注释花括号解释发生变化时产生 `legacy-comment-brace` 警告；真正的右花括号须放在注释外。 |
| 块起始符前没有空格，`global{ … }` | 空白被跳过，仍是块 | 无论位于行内还是行尾，都产生 `block-delimiter-spacing` 错误。块头与花括号之间须留空白；仍接受 `global {}` 这样的紧凑空块。 |
| 多余的 `}`，或空文件 | 多余的 `}` 被拒绝；空输入或只有注释的输入被接受 | 多余的右花括号产生 `unmatched-close` 警告并被忽略；没有配置块的文档被拒绝。首次 PR2 发布后再评估多余右花括号的兼容行为。 |
| 组名，`123 {`、`香港 {`、`Hong Kong {` | 块名必须是一个 `ID` | 独立 `{` 之前的原始块头是动态组名。未知顶层名称产生诊断并被跳过，不会作为插件加载。 |
| 一行两个声明，`global { log_level: debug log_file: x }` | 空白分隔的两个声明 | 一个声明：`log_level` 的值是 `debug log_file: x`。每行一个 `key: value`；单行块只容纳一条语句。 |
| 起始花括号另起一行，`global` 换行 `{` | 空白（含换行）被跳过 | 普通块的起始花括号不能另起一行。只有顶层 `include` 保留此兼容语法，允许中间有空行或注释行，并产生带位置的 `legacy-include-opener` 警告。请把 `{` 放在 `include` 块头所在行；首次 PR2 发布后再评估这项兼容行为。 |

## 标量与列表

| 输入 | dae 文法 | honk |
|---|---|---|
| 带冒号的裸值，`bind: 127.0.0.1:53` | 不是一个字面量，必须加引号 | 接受裸写：值是第一个 `:` 之后的全部文本。 |
| 调用形态的值，`client_subnet: auto(9.9.9.9)` | 函数表达式 | 文本 `auto(9.9.9.9)` 就是值，由该设置自行解析。 |
| 带引号的列表项，`lan_interface: 'eth0', 'eth1'` | 两个字面量 | 先拆分列表，再逐项移除一对包围该项的引号，结果为 `eth0`、`eth1`。解析结果与旧版不同的引号写法产生 `legacy-list-quoting` 警告。检查目标列表仍兼容整体加引号的逗号列表，并产生 `legacy-quoted-list` 警告；建议逐项加引号或裸写。 |
| 布尔值 `t`、`y`、`f`、`n` | 裸字面量 | 宽松设置不区分大小写：`true`、`yes`、`1`、`on` 为真；`false`、`f`、`no`、`n`、`0`、`off`、`t`、`y` 为假。四种单字母简写产生 `legacy-bool-shorthand` 警告；未知写法为假并报告诊断。建议使用 `true` 或 `false`。`global.nfqueue_enable` 与旧版 `experimental.udp_nfqueue.enabled` 仍严格解析，拒绝简写。 |
| mark，`so_mark_from_dae: 0x10` 与 `so_mark_from_dae: 10` | 裸字面量 | 两者都按十六进制读取：16 与 16。无法解析的 mark 回退为 0 并报告诊断。 |
| 毫秒设置里的小数秒，`check_tolerance: 1.5s` | 裸字面量 | 1500 毫秒。无法解析的毫秒时长（`check_tolerance`、`sniffing_timeout`）回退到该设置的默认值并报告诊断；无法解析的秒时长（`check_interval`、订阅 `interval`）回退为 `0` 并报告诊断。 |
| `fixed_domain_ttl` 条目 `x: 60#note`、`y: '60'`、`z: 60 ignored` | `60#note` 与 `'60'` 是字面量，`60 ignored` 是两个词法单元 | 值必须恰好是一个十进制标量。`y` 存为 60 并产生 `legacy-ttl-quoting`；`x` 因 `invalid-ttl` 被省略，`z` 因 `trailing-value` 被省略。请使用 `60` 或带引号的 `60`，说明文字放在 ` # ` 后。 |
| 未知的 `policy`，`policy: mystery(...)` | 任意函数表达式 | 回退为 `selector` 并报告诊断；参数文本不会被回显。 |

## node 与 subscription 条目

| 输入 | dae 文法 | honk |
|---|---|---|
| 分享链接或订阅上的标签 | `ID ':' literal`；裸字面量不能含 `:`，所以链接要加引号 | 裸写的开头以第一个 `:` 之前的文本为标签，除非该冒号是 `://` 的开头；加引号的开头只有紧跟在闭引号后的 `:` 才声明标签，未加引号的 User-Agent 或注释后缀里的冒号只是后缀数据。链接可以裸写；标签与链接都可以加引号。仅在 `subscription` 里，整体加引号且内含标签的值（`'paid:https://…'`）会在去引号后再拆分，无标签的条目以 URL 主机名命名；在 `node` 里加引号的值就是整个链接（`'paid:socks5://…'` 是未知协议）。 |
| 条目行的行尾注释 | `#` 作为词法单元开头时是注释 | 前面是空格或制表符的 `#` 结束该行。裸值内紧贴的 `#` 是数据（`…#hk1`、`?filter='hk'#token`、`/tmp/a#b`）。节点或链接的结束引号后，或订阅的一个完整 `(UA)` 后缀后，紧贴的 `#` 以 `legacy-glued-hash` 警告截断条目尾部，但并非词法注释：其后的独立花括号仍改变块结构。需要注释时，请在 `#` 前加空白。其他尾随文本使条目被跳过，并产生 `trailing-entry-text` 或 `legacy-ua-boundary` 诊断。 |
| 订阅链接后的 `'url'(User-Agent)` | 不在文法内 | honk 扩展：括号内文本是 User-Agent；未加引号的括号内前有空格的 `#` 会结束该行，这类 User-Agent 请加引号。 |
| 订阅块：`paid: {` 之后各占一行的 `url: …`、`ua: …`、`interval: …` 与 `}` | `ID ':' '{'` 不是声明 | honk 扩展：订阅的块形式；其设置与其他块一样每行一条。 |
| `node` 里冒号前带空格的裸标签，`edge : 'socks5://…'` | 标签为 `edge` | 冒号两侧的空白会被规范化：保留节点，标签为 `edge`，并产生 `entry-tag-normalized` 信息级诊断。仍接受 `edge: …` 和带引号的标签。 |

## 路由

| 输入 | dae 文法 | honk |
|---|---|---|
| 裸前缀匹配器，`!geosite:cn -> proxy`、`domain:example.com -> proxy` | 不是函数调用，拒绝 | 接受为匹配器（`geosite`、`geoip`、`domain`、`suffix`、`keyword`、`regex`、`full` 前缀）。 |
| 两个箭头，`domain(x) -> proxy->backup` | 拒绝 | 出站为字面文本 `proxy->backup`，产生 `legacy-arrow-target` 警告。保留此兼容写法，仍须通过通常的目标校验。 |
| `-> proxy( must )` | 带参数 `must` 的调用 | 只有精确后缀 `(must)` 是 must 标记；`proxy( must )` 是名为 `proxy( must )` 的出站。 |
| 括号前有空格，`dport (443) -> proxy` | 接受 | 返回带位置的 `unknown-traffic-predicate` 错误。请删除匹配器名称与左括号之间的空格。 |
| 合取里的未知匹配器，`dport(443) && domian(x) -> direct` | 文法接受，校验在文法之外 | 返回带位置的 `unknown-traffic-predicate` 错误，取反条件也不例外。请修正匹配器；不再静默丢弃单个条件。 |
| 含多个冒号的参数，`dip(2001:db8::/32)`、`mac(00:11:22:33:44:55)` | 不是字面量，需要加引号 | 整体保留：只有识别的 `prefix:`（`geosite:`、`geoip:`、`domain:`、`suffix:`、`keyword:`、`regex:`、`full:`）才在其冒号处拆分。 |

## DNS

| 输入 | dae 文法 | honk |
|---|---|---|
| request 或 response 规则里未加引号的 `//` | 不是注释 | `//` 是数据，不是注释。`-> asis // note` 这类行尾斜杠注释文本使规则无效，产生 `legacy-slash-comment` 警告并省略整条规则；引号内的斜杠保持字面含义。请将 DNS 行尾 `//` 注释改为 `#`。 |
| `request` 或 `response` 规则里的 `#`，`qname(a#b) -> reject # note` | `a#b` 是字面量，`# note` 是注释 | 只有引号外词法单元开头的 `#` 开始注释，前面可以是空格或制表符。模式保持为 `a#b`，动作为 `reject`；与旧版读取结果不同的写法产生 `legacy-dns-hash`。字面字符 `#` 可紧贴前文；注释须在引号外用空白分隔。 |
| request 或 response 规则里的 `->` | 一个箭头 | 规则在第一个引号外的 `->` 处拆分；后续箭头留在动作里，并产生 `legacy-arrow-target` 警告。整个动作转为小写，随后必须与上游声明名称精确匹配：`MixedCase` 选择 `mixedcase`，不匹配名为 `MixedCase` 的声明。此动作与引用名称规则不变。 |
| 跨行的匹配器调用，`qname(` 换行 `a.example) -> reject` | 空白（含换行）被跳过 | DNS 不合并物理行。每条不完整的非空行都被省略，并产生带位置的 `incomplete-dns-rule`，因此此例产生两条警告。请将 DNS 调用和动作放在同一行。未闭合引号只产生一条词法诊断，不再附加不完整行警告；只有所有块都在引号外闭合时才能恢复解析。 |
| 带出站的上游，`u: 'udp://1.1.1.1:53' -> proxy` 或 `u: 'udp://1.1.1.1:53' outbound: proxy` | 箭头形式被拒绝（声明不能带 `->`）；`outbound: proxy` 形式是相邻的两个声明 | honk 扩展：两种形式都让上游 `u` 经出站 `proxy` 拨号；两个后缀都只在 URI 引号外读取。 |
| 匹配器调用后的文本，`dport(443)junk -> proxy`、`qname(a.example)junk -> reject` | 拒绝：箭头必须紧接调用 | 流量路由以带位置的 `trailing-matcher-text` 错误拒绝配置；DNS 发出警告并省略整条规则。请删除匹配器后的多余文本。 |
| 上游行的行尾注释，`v: 'udp://8.8.8.8:53' # note` | 注释 | 引号外词法单元开头的 `#` 开始注释，因此地址为 `8.8.8.8:53`；行为变化产生 `legacy-upstream-comment`。可以使用普通行尾 `#` 注释；引号保护地址数据。 |
| 带引号的上游 URL 内的 `->` 或 `outbound:` | 数据 | 只有引号外的描述符后缀选择出站；`'https://dns.example/q?x=outbound:proxy#frag'` 保持为一个 URI。与旧版拆分结果不同的写法产生 `legacy-upstream-separator` 警告；出站后缀请放在 URL 引号外。 |
| `qtype(...)` | 函数参数 | 名称 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY`、`*`（不区分大小写）或十进制 `u16`；未知名称产生 `invalid-qtype` 警告并省略整条规则，混合列表和取反条件也不例外。请修正名称或使用数字类型码。显式 `qtype()` 仍不匹配任何类型；`qtype('a,aaaa')` 仍选择两种类型，并产生 `legacy-quoted-list` 警告。建议裸写或逐项加引号。 |

## 组

| 输入 | dae 文法 | honk |
|---|---|---|
| `group('hk,jp')` | 一个字面量 | 两个子组标签，按 `,` 与 `\|` 拆分。 |
| `filter: group()` | 无参数的调用 | 显式 `group()` 不选择任何节点，并产生 `empty-subgroup` 警告；序列化后再反序列化以及刷新后均保留此行为。需要全部节点时请删除该过滤器。 |

## 配置段与 include

| 输入 | dae 文法 | honk |
|---|---|---|
| `experimental` 里的未知内容 | 任意声明 | 未知外层配置项及旧版 `udp_nfqueue` 中不支持的内容（包括嵌套块）都是错误。`clash_api` 与 `cache_file` 中的未知标量键产生 `unknown-key` 警告并被忽略；这项前向兼容规则不放宽 NFQUEUE 校验。 |
| `global`、`dns`、`routing`、组设置或已知实验子块中的未知嵌套块 | 任意表达式 | 在块头产生一次 `unknown-block` 警告，跳过整个已闭合子树，DNS 子块也遵循此规则。子树中的设置和规则不再影响父块；请将已知设置移到文档规定的层级。 |
| `node` 和 `subscription` 包装块及 `subscription` 设置中的嵌套包装块 | 没有独立的包装块语法 | 保留有界的兼容遍历，每个包装块产生 `legacy-wrapper` 警告。`group` 根层的任意名称都是实际组名，不是包装块。首次 PR2 发布后再评估包装块兼容行为。 |
| 未知根语句和标量键 | 任意标识符 | 结构识别成功后产生警告并忽略；未知根块按完整子树跳过。组名、条目标签、上游名和 TTL 所属域名是动态名称，不是未知配置键。没有箭头的流量语句会被诊断并忽略，但 `fallback` 声明除外。 |
| `include { … }` | 与其他块相同的块 | 只在加载文件时展开模式，顺序与目录限制见[配置指南](../configuration.md)；字符串解析检查结构，但不打开文件。两种模式都会在首次获取词法单元时识别 `'first.dae''quoted # name.dae'` 这样的相邻带引号路径，保留引号内的 `#` 和花括号；每个引号必须在同一物理行闭合。只有词法单元开头的 `#` 引入注释；`absolute.dae#note` 是字面模式并产生 `legacy-include-hash`，仍按 `.dae` 扩展名筛选。 |
