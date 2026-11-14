# 路由參考

`routing { ... }` 按順序匹配流量，再把命中的流量交給指定的出站。

## 完整範例

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    # 範圍過寬的私網 must 也會繞過 LAN 私網 DNS；要保留接管時，顯式加上 && !dport(53)。
    dip(geoip: private) -> direct(must)
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    mac(aa:bb:cc:dd:ee:ff) && ipversion(4) -> direct
    domain(
        full: api.example.com,
        suffix: example.org,
        keyword: tracker,
        regex: '^bad[0-9]+\.example$',
        geosite: category-games@cn
    ) -> proxy
    dip(geoip: cn, 203.0.113.0/24) && sport(1024-65535) && dscp(46) -> hk
    l4proto(tcp) && dport(80, 443, 8080-8090) -> proxy
    !domain(geosite: category-ads-all) && !dip(geoip: cn) -> resilient
    fallback: resilient
}
```

這裡 `proxy`、`hk` 和 `resilient` 都是群組名。

## 條件函式

| 函式 | 引數 | 內部 `RoutingCondition` 欄位 |
| --- | --- | --- |
| [`domain(...)`](#domain) | 按裸值或字首模式匹配流量網域。 | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| [`dip(...)`](#dip) | 匹配目的 IP 位址或 CIDR，或 GeoIP 程式碼。 | `ip`, `geo_ip` |
| `sip(...)` | 匹配源 IP 位址或 CIDR，解析方式同 [`dip(...)`](#dip)。 | `source_ip` |
| `dport(...)` | 匹配十進位目的埠，或 `0` 到 `65535` 的閉區間 `start-end`，且 `start <= end`。 | `port` |
| `sport(...)` | 匹配十進位源埠，或 `0` 到 `65535` 的閉區間 `start-end`，且 `start <= end`。 | `source_port` |
| `l4proto(...)` | 匹配 `tcp` 或 `udp`，不區分大小寫。 | `protocol` |
| [`pname(...)`](#pname) | 把子串模式按 15 位元組正規化後，匹配 `argv[0]` 裡執行檔的 basename。 | `process_name` |
| `mac(...)` | 匹配源 MAC 位址，寫作 `aa:bb:cc:dd:ee:ff`、`aa-bb-cc-dd-ee-ff`、`aabb.ccdd.eeff` 或 `aabbccddeeff`，不區分大小寫。 | `mac` |
| `ipversion(...)` | 匹配 `4`/`ipv4` 或 `6`/`ipv6`，不區分大小寫。 | `ip_version` |
| `dscp(...)` | 匹配十進位或帶 `0x`/`0X` 字首的十六進位 DSCP 值；封包的取值為 `0` 到 `63`。 | `dscp` |

每個正向欄位在 `RoutingCondition.not` 下都有對應列表；解析器把 `!matcher(...)` 放入該列表。同一欄位中的多個值互為備選。

### domain

`domain(...)` 按裸值（原始字尾）或以下字首匹配流量網域：`suffix:` 表示原始字尾，`keyword:` 表示子串，`full:` 表示支援 `*` 和 `?` 的整名 glob，`regex:` 表示 Rust 正規表示式，`geosite:` 表示 geosite 程式碼。

同一次呼叫裡的各種模式條件共享一個條件，因此 `domain(geosite: netflix, suffix: imgur.com)` 命中任一即可。同一規則裡的多個 `domain(...)` 呼叫寫入相同欄位，同樣互為備選。

`full:`、`suffix:` 和 `keyword:` 區分大小寫。`full:` 匹配整個名稱：`*` 匹配任意字元序列，`?` 匹配一個字元，其他字元都按字面處理。`suffix:` 依原始文字比較字尾，因此 `suffix: example.com` 也會匹配 `notexample.com`。要按標籤邊界匹配網域本身及其子網域，使用 `domain(regex: '(^|\.)example\.com$')`。geosite 條目不區分大小寫，並按標籤邊界匹配字尾。

`regex:` 使用 [Rust regex 語法](https://docs.rs/regex/latest/regex/#syntax)，不是 glob 語法。無效模式會使 honk 建構路由器時失敗。帶字首的空值會保留：`domain(suffix: '')` 匹配所有網域，與 `domain()` 不同。

dae 也接受獨立的 `geosite:`、`geoip:`、`domain:`、`suffix:`、`keyword:`、`full:` 和 `regex:` 謂詞，可加字首 `!` 並參與合取。`domain:example.com` 表示字尾匹配，不是 `full:` 匹配。

```dae
routing {
    domain(full: '*.example.com') -> proxy
    domain(regex: '(^|\.)example\.com$') -> proxy
    domain(suffix:'example.com') -> proxy
    !geosite:cn -> proxy
    fallback: direct
}
```

上面的 glob 匹配子網域，但不匹配 `example.com` 本身；正規表示式同時匹配兩者。與 `suffix: example.com` 不同，兩者均不匹配 `notexample.com`。

### dip

`dip(...)` 按 IPv4/IPv6 位址、CIDR 或 `geoip: cn` 這類 GeoIP 程式碼匹配目的位址。它不接受主機名稱。單個位址轉換為 `/32` 或 `/128`；CIDR 的主機位會被清零。

```dae
routing {
    dip(geoip: cn, 203.0.113.0/24) -> proxy
}
```

### pname

`pname(...)` 把子串模式按 15 位元組正規化，再匹配 `argv[0]` 裡執行檔的 basename。

執行時沒有 BTF 偏移，或沒有 verifier 允許的核心 argv 存取方式時，cgroup hook 同步改用呼叫執行緒的 `comm`。只匹配 honk 所在主機上的行程，不匹配 LAN 用戶端上的應用。

```dae
routing {
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
}
```

## 規則語法

```text
condition [&& condition ...] -> outbound[(must)]
condition [&& condition ...] -> direct(mark: value[, must])
fallback: outbound[(must)] | direct(mark: value[, must])
```

- 規則按 `priority` 升序執行，數值越小越先匹配。同優先順序保持原始碼順序。dae 解析器按原始碼順序分配 `0, 1, ...`。honk 不會自行插入本地介面路由規則。
- `default:` 是 `fallback:` 的別名。沒有規則做出最終決定時，使用 fallback 目標；省略時預設為 `direct`。
- 同一個 matcher 內以逗號分隔的引數互為備選。一行裡每個非空 matcher 都必須匹配。
- matcher 的括號引數列表可以在同一來源檔內跨行。語句一直延續到右括號和 `-> outbound`。被包含的檔案不能補全另一檔案中未完成的呼叫。
- 成對的單引號或雙引號保留內部的全部位元組，包括空白、`#`、花括號、`,`、`)`、`&&` 和 `->`。引號在詞法單元開頭，或緊接未加引號的 `(`、`,`、`:` 時開啟，因此 `domain(suffix:'example.com')` 等同於 `domain(suffix: 'example.com')`。反斜槓保留原樣，不作轉義解碼。已開啟的引號必須在同一行內閉合，否則設定以 `unterminated-quote` 錯誤失敗。
- 字首 `!` 只對緊隨其後的單個 matcher 取反。規則僅在正向條件匹配且所有取反 matcher 都未命中時匹配。
- 流量缺少網域、行程名、MAC 或 DSCP 後設資料時，對應的 matcher 算作未命中，加上 `!` 的寫法反而會命中：尚未嗅探出網域的流量滿足 `!domain(...)` 和 `!geosite:...`，沒有行程名的流量滿足 `!pname(...)`。
- 未知的非空 matcher、matcher 名稱與左括號之間的空格、呼叫後的多餘文字均使設定驗證失敗，並產生帶位置的診斷。合取中不支援的非空條件不會被單獨丟棄。
- 空項、單獨的 `!` 和空引數會被跳過：`domain() && dport(443)` 等同於 `dport(443)`。沒有剩餘條件的規則永不匹配；保底請用 `fallback:`。
- `dip(...)` 和 `sip(...)` 中的無效位址、無效的 MAC 或 DSCP 值，以及不支援的 `l4proto` 或 `ipversion` 值，都會被直接丟棄，不報錯。沒有剩下有效值的 matcher 不匹配任何流量，其取反形式則匹配滿足規則其餘條件的全部流量。
- 格式錯誤的埠以 `Invalid port` 失敗。核心路由策略編譯器會拒絕 `443-80` 這樣的反向區間。
- 引號外、詞法單元開頭的 `#` 才開始註解。緊貼前文的 `#` 是資料：`domain(x) -> proxy#c` 指向字面名稱 `proxy#c`，並產生 `legacy-glued-hash` warning。註解請寫成 `-> proxy # comment`。第一個引號外的箭頭分隔動作，後續箭頭保留在目標名稱中，並產生 `legacy-arrow-target` warning。

```dae
routing {
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    default: proxy
}
```

## 出站目標與 must

| 目標 | 含義 |
| --- | --- |
| `direct` | 內建直連出站 |
| `block` | 內建阻斷出站 |
| 代理群組名 | 依該出站群組及其策略解析 |

`Config::validate` 拒絕裸節點名作出站目標。先把節點加入群組，例如用 `filter: name('node')` 建一個群組，再引用群組名。群組與節點也不允許同名。每份設定最多可定義 250 個頂層使用者群組；更高的路由序號由 ABI 保留。

### must

在目標後追加 `(must)`，命中的結果會立即結束規則搜尋，並跳過嗅探與後續的網域重路由，語義同 `no_sniff`。選中的 direct、block 或 group 動作照常執行，`must` 並不等於整體繞過 honk。Clash 的 `Global` 和 `Direct` 模式都無法覆蓋 must 結果或 `block`。它也不是歷史上那個先設定 must、再繼續掃描的內部 `MustRules` opcode。

### 埠 53 所有權

`mac(...)` 規則命中後，`direct(must)` 可以讓該用戶端繞過透明 DNS；普通 `direct` 不行。LAN/WAN 的 TCP/UDP 目的埠 `53` 在完成既有入口與控制面排除後，會執行一次正常的有序流量策略，不單獨掃描 must 規則。LAN 埠 `53` 跳過本地 socket 探測，即使 dnsmasq 或 `dns.bind` 已監聽該目的位址也不例外。

| 流量策略結果 | DNS 所有權 |
| --- | --- |
| `direct(must)` | 跳過 DNS 控制器。LAN 流量及無 mark 的 WAN 流量使用 Linux 原生交付；非零 mark 的 WAN 結果由帶 mark 的直連 socket 重新執行策略路由查詢。 |
| `block(must)` | 丟棄封包。 |
| `group(must)` | 透過該群組的原始傳輸（TCP relay 或 UDP `PacketTransport`）轉發。這條路徑跳過 `DnsController`、快取、hosts、請求/回應策略和路由投影。 |
| 任何非 `must` 結果，包括普通 `block` | 有效 DNS 查詢進入 `DnsController`。Clash 模式直連 offload 不會剝奪接管權限。 |

畸形的非 `must` UDP53 負載走通用 UDP 回退，不進入 `DnsController`。表中的控制器行只描述合法 DNS，並不表示埠 53 上的所有負載都是 DNS。路由後設資料的 admission 遵循[控制面的 TCP/UDP 區分](../design/control-plane.md#透明代理入口)。

LAN 本地 socket 優先接收封包這條規則，只適用於非 53 目的埠，並按傳輸分別判斷。通配繫結還要求完整 FIB 查詢結果為 `NOT_FWDED`，非 DNS 的 TCP 純 SYN 仍然跳過探測。繫結 `:53` 的 socket 不能先於上述策略結果。透明 LAN 與原生/loopback 交付的區別，見[DNS 所有權狀態機](../design/dns.md#dns-所有權狀態機)。

admission 與策略規模限制見 [LAN 單源新流預算](../design/datapath.md#單源新流限制)和[編譯策略容量](../design/routing.md#受限原生後端)。

## 嗅探

honk 只嗅探資料路徑交給控制面的流量；TC hook 留在 Linux 原生路徑上的流量不經過嗅探。

- TCP：最多讀取 4096 位元組，提取 TLS SNI 或 HTTP `Host`。讀到的位元組在中繼開始前寫入選中的出站，所以嗅探不消費應用資料。
- UDP：解密 QUIC v1/v2 的 Initial packet，提取 TLS ClientHello 的 SNI。

以下情況跳過嗅探：

- `dial_mode` 為 `ip`。
- 資料路徑的 handoff 已是最終的 `direct` 或 `block`。
- 命中的規則以 `(must)` 結尾。
- 僅 TCP：同一目的位址和出站簽名連續三次失敗後進入 negative cache，十分鐘內不再嗅探。

嗅探到的名稱如何使用取決於 `dial_mode`，見[撥號模式](./global.md#撥號模式)；`domain` 模式下名稱要先通過 DNS reality check。`sniffing_timeout` 是相容欄位，控制面不讀取它。上限與逾時見[嗅探與流初始化](../design/control-plane.md#嗅探與流初始化)。

## 策略路由 mark

`direct(mark: 512)` 與 `direct(mark: 0x200)` 選擇相同的直連 mark。無字首數字按十進位解析，包括前導零；`0x`/`0X` 字首表示十六進位。範圍為 `0..=0x3fffffff`；`0xc0000000` 位屬於資料路徑，不供使用者策略使用。二進位/八進位字首、底線、正負號、溢位、未知選項以及重複的 `mark`/`must` 選項均拒絕設定；與全域 mark 純量不同，格式錯誤的直連 mark 不會靜默變為零。mark 只支援 `direct`，不支援代理目標和群組目標。

`direct(mark: 0x200, must)` 與 `direct(must, mark: 0x200)` 等價，直連選項列表內部允許空白。`fallback:` 及其別名 `default:` 接受相同形式。合併 include 後，最後出現的 fallback 會替換整個回退動作，普通 `direct` 不保留 mark 與 `must`。fallback 只在全部普通規則之後生效，即使來源檔裡有些規則宣告在它後面。

在 IPv4/IPv6 的 TCP 和 UDP 上，非零直連 mark 替換全域 socket mark 的策略有效位，**不與 `so_mark_from_dae` 或 `0x100` 按位元 OR**。原生直連、NFQUEUE 批准的直連以及使用者態直連 socket，會在低 30 位策略值之外額外保留 `CLASSIFIED_MARK`，這個位是 `0x40000000`。例如設定 `0x200` 時可觀測到 `0x40000200`，Linux 策略路由規則必須用遮罩排除保留位。`mark: 0` 表示未指定：使用者態發起的直連 socket 使用全域 mark，原生直連不新增使用者 mark。代理 carrier、bootstrap 和 DNS 控制器上游使用全域值，不繼承被攔截流量規則的 mark。

例如，選擇兩個由使用者設定的 WAN 路由表：

```dae
global {
    so_mark_from_dae: 0x200
}
routing {
    domain(suffix: example.net) -> direct(mark: 0x300)
    fallback: direct(mark: 0x200)
}
```

```sh
ip -4 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -6 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -4 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
ip -6 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
```

請為表 `100`、`200` 分別設定對應位址族的直連路由和預設路由，並處理各 WAN 的源位址、NAT 與防火牆權限；honk 不管理這些路由表。LAN 原生直連在 Linux 轉發路由查詢前設定 mark。主機/WAN 出站命中非零直連 mark 時，會經過使用者態直連轉發，由新 socket 觸發帶 mark 的路由查詢，不會保留用戶端的原始源 socket；這條路徑也適用於 `must`，包括原始埠 53 的流量。`must` 仍跳過 DNS 控制器。未指定 mark 的原生 `direct(must)` 保持既有的源位址保留路徑。修改全域 mark 需要重啟，流量規則可以 reload。編譯策略最多允許 256 個不同的非零 `direct(mark: ..., must)` 值，包括帶 mark 的 `must` fallback。WAN 原始 UDP/53 封包攜帶一個 mark 表索引，該索引隨它的路由 generation 固定，不會借用其他封包 tuple handoff 的 mark。

## Geo 資源

`geoip:` 和 `geosite:` 條件使用 `geoip.dat` 與 `geosite.dat`。引擎按以下順序選擇第一個已存在的普通檔案：

| 優先順序 | 位置 |
| --- | --- |
| 1 | `$DAE_LOCATION_ASSET/<file>` |
| 2 | `global.data_dir/<file>` |
| 3 | `/var/share/honk/<file>`（`LEGACY_DATA_DIR`） |
| 4 | 行程工作目錄中的 `./<file>` |
| 5 | `/usr/local/share/honk/<file>` |
| 6 | `/usr/share/honk/<file>` |
| 7 | `/usr/local/share/dae/<file>` |
| 8 | `/usr/share/dae/<file>` |
| 9 | `/etc/dae/<file>` |

執行時資源解析規則見[全域參考](./global.md)。`geoip: private` 使用內建 CIDR 集，不需要 `geoip.dat`。

`private` 不限於 RFC 1918 LAN 位址，還包括 CGNAT、loopback、連結本機、文件與多播等範圍：

| 位址族 | CIDR |
| --- | --- |
| IPv4 | `10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.88.99.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`、`255.255.255.255/32` |
| IPv6 | `::1/128`、`fc00::/7`、`fe80::/10` |

找不到被引用的 Geo 資源時，引擎會記一條帶缺失檔名的 warning，並以空的 matcher 啟動。沒有規則引用的資源不會產生缺失檔案 warning。空的 Geo matcher 不匹配任何流量，因此 `!domain(geosite: ...)` 或 `!dip(geoip: ...)` 會匹配滿足規則其餘條件的全部流量：資源缺失只會擴大取反規則的範圍，不會讓規則失效。

geosite 類目和 GeoIP 程式碼不區分大小寫。geosite 程式碼可以用 `category@attr` 選擇屬性，屬性 key 不區分大小寫。第一個 `@` 之後的全部內容都是選擇器，包括後續的 `@`。未知的 geosite 類目、未知的 GeoIP 程式碼，或不匹配任何條目的選擇器，都會記一條 warning 並按空 matcher 處理，對取反規則的影響同上。

## 顯式本地路由

honk 不會在啟動、reload 或介面變化時注入介面位址的 `direct(must)` 規則。也沒有隱藏的核心位址白名單可以替代，原生 `.dae` 規則順序保持由使用者編寫。介面位址仍用於拓撲檢測、ECS 重新整理和健康探測，但 honk 不會據此生成路由規則。要讓閘道器管理存取不隨代理健康狀態消失，請按所需順序自己寫一條直連規則，例如：

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

這是一條可選的使用者規則，honk 不會自動插入。它把埠 `53` 留給透明 DNS 接管，除非另一條終局 `must` 結果接管了該埠。本地 socket 優先接收非 53 目的埠，這是入口歸屬判斷，並不意味著所有閘道器位址都強制直連；探測使用封包所在的當前網路命名空間。非 DNS 的 TCP 純 SYN 仍沿用現有探測策略，因此不加設定時，honk 不保證閘道器管理面始終可達。

使用真實 LAN 繫結時，honk 會按編譯後規則的實際順序檢查覆蓋情況。如果無法確認下列條件成立，它就發出 warning：設定中已觀測到的 LAN/WAN 網路卡位址，在 TCP 和 UDP 的目的埠 `1–65535` 上都有無條件的 `direct(must)` 覆蓋，埠 `53` 除外。`direct(must)` fallback 也算覆蓋。

檢查在啟動時、成功應用流量路由變化後，以及觀測到網路變化時執行；無變化或僅節點變化的 reload 不會重複檢查。尚不存在的網路卡或尚未取得的位址，會在發現後重新檢查。

這只是提示，不阻止啟動或 reload，也不改變顯式阻斷和規則順序。依賴來源、網域、行程等條件的規則，以及拆分的埠覆蓋，可能是有意設定的合法策略，仍可能被判為無法確認。該 warning 不證明 listener、防火牆或端到端管理存取可達。

範圍過寬的私網 `direct(must)` 規則也會繞過 LAN 私網 DNS。要保留這部分 DNS 接管，必須在規則裡顯式加上 `&& !dport(53)`；honk 不會改寫這條規則。原生 `direct(must)` 不會由 honk 改寫用戶端源 IP/埠，但是否仍發生 SNAT/MASQUERADE，取決於其他防火牆和網路設定。被繞過的應答如何投影，以及它與 `asis` 有何區別，見[DNS 來源邊界](../design/dns.md#入口路徑)。

## Fail-closed 行為

健康檢查把一個出站標記為失效後，eBPF 資料面通常會用 `TC_ACT_SHOT` 丟棄路由到它的新流，絕不會靜默洩漏到 `direct`。未設定 `final`、且只有一個唯一葉節點的 TCP 群組是例外：它仍把這個代理作為最後嘗試，讓真實流量有機會證明恢復。UDP 和全部葉節點都失效的多葉節點群組仍保持 fail-closed。含有 `direct` 或 `block` 內建成員的群組則永遠不會失效，因為內建節點從不被判定失效，group-OR 槽始終開放。目的埠 `53` 在 TCP 和 UDP 上都豁免這種健康檢查丟包。這種豁免不會覆蓋使用者終局的 `must` 結果；沒有終局使用者 `must` 結果時，DNS 仍可到達控制面。

為應對節點故障，可以設定以下路徑：

- 新增 `dip(geoip: private) -> direct(must)`，讓私有網路流量不依賴代理健康狀態。這條規則也會繞過 LAN 私網 DNS，要保留接管就顯式加上 `&& !dport(53)`。
- 讓 `fallback:` 指向至少包含兩個節點的 [`fallback` 代理群組](./groups.md)，而不是單個節點。
- 至少保留一個走直連路徑的 DNS 上游。

## 相關文件

- [路由設計](../design/routing.md)
- [全域參考](./global.md)
- [群組參考](./groups.md)
