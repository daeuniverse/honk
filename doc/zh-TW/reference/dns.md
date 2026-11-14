# DNS 設定參考

`dns { ... }` 用 dae 語法設定 DNS，涵蓋命名上游、request 和 response 路由、hosts、EDNS Client Subnet、快取和可選的獨立 listener。

## 範例

```dae
dns {
    # 省略 bind 可保持獨立 listener 關閉。
    # bind: 'tcp+udp://:1053'
    use_host: true
    ipversion_prefer: 4

    upstream {
        default: 'udp://223.5.5.5:53'
        cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
        google_doh: 'https://dns.google/dns-query' -> proxy
    }

    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> google_doh
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> default
            qtype(https) -> reject
            fallback: default
        }
        response {
            upstream(google_doh) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> google_doh
            fallback: accept
        }
    }

    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

## 欄位

| Key | 預設值 | 意義 |
| --- | --- | --- |
| `bind` | `省略`（`""`） | 可選的獨立 DNS listener；空值只關閉這個 listener。見 [`bind`](#獨立-listenerbind)。 |
| `use_host` | `省略`（`false`） | 可重複設定的 hosts 來源：`true` 或路徑 `/etc/hosts` 按標準 hosts 語法讀取，其他路徑按 OxiDNS 相容的規則檔案讀取。見 [`use_host`](#hosts-快照use_host)。 |
| `client_subnet` | `省略`（`""`） | 命名上游使用的可選 EDNS Client Subnet 預設值，可取 IPv4、IPv4 CIDR、`auto` 或 `auto(IPv4)`。見 [`client_subnet`](#edns-client-subnetclient_subnet)。 |
| `upstream { ... }` | `省略`（`default: 'udp://223.5.5.5:53'`） | 命名上游伺服器，即 Clash 設定中的 `nameserver`；第一個明確 `upstream` 區塊會替換內建條目。見 [上游](#上游)。 |
| `routing { ... }` | `省略`（無規則；request fallback 為 `default`；response fallback 為 `accept`） | 有序的 request 和 response 路由，第一條匹配的規則生效。見 [DNS 路由](#dns-路由)。 |
| `ipversion_prefer` | `省略`（`both`） | 位址族偏好；honk 解析不了的值保持 `both`，並輸出診斷。見 [`ipversion_prefer`](#ipversion_prefer)。 |
| `optimistic_cache` | `省略`（`true`） | 啟用正、負快取的讀取和寫入。見 [`optimistic_cache`](#optimistic_cache)。 |
| `optimistic_cache_ttl` | `省略`（`600` 秒） | 除 NXDOMAIN、SERVFAIL 和 NODATA 外，把所有應答的快取 TTL 和訊息 TTL 設為固定值；寫 `0` 用上游應答裡的最小 TTL。見 [`optimistic_cache_ttl`](#optimistic_cache_ttl)。 |
| `optimistic_stale_reply_ttl` | `省略`（`30` 秒） | serve-stale 正應答使用的 TTL；非零值替換每個非 OPT RR 的 TTL，寫 `0` 保留快取裡已按策略改寫的 wire TTL。見 [`optimistic_stale_reply_ttl`](#optimistic_stale_reply_ttl)。 |
| `max_cache_size` | `省略`（`10000`） | 快取條目數上限，最大 100,000；它也決定分片位元組預算。見 [`max_cache_size`](#max_cache_size)。 |
| `fixed_domain_ttl { domain: seconds }` | `省略`（空） | 按域名覆寫正應答和 NODATA 的 TTL；寫 `0` 時，所有回應碼的應答都不快取。見 [`fixed_domain_ttl`](#fixed_domain_ttl)。 |

所有 key 都是可選的。預設值欄寫 `省略`，表示該 key 可以省略，括號裡是它的預設值或等效寫法。標量的延伸範圍、註釋規則和布林取值見[解析規則](#解析規則)。

SIGHUP reload 會把 `bind` 的主機、埠或傳輸集合變化當作需重啟項並拒絕；見 [`bind`](#獨立-listenerbind)。

## 獨立 listener（`bind`）

獨立 listener 用主機網路名稱空間裡的普通 socket，不設定 bypass mark。關閉它不影響透明 TCP/UDP 53 埠攔截；透明路徑遵循[流量規則所有權](./routing.md#出站目標與-must)。

| 值 | 結果 |
| --- | --- |
| 省略或 `""` | 不建立獨立 listener。 |
| 數字 `IP:port`，如 `127.0.0.1:1053` 或 `[::1]:1053` | UDP listener。 |
| `udp://host:port` | UDP listener。 |
| `tcp://host:port` | TCP listener。 |
| `tcp+udp://host:port` | 在同一位址和埠建立 TCP 和 UDP listener。 |

主機名必須帶 scheme，例如 `udp://localhost:1053`。IPv6 字面量必須加方括號。`tcp+udp://:1053` 這種空 host 表示通配位址。每種形式都要明確寫出十進位 `u16` 埠。埠寫 `0` 表示申請臨時埠，honk 會記錄最終選定的位址。

裸主機名無效。解析器還會拒絕 userinfo、path、query、fragment、反斜線、IPv6 zone identifier、錯誤的方括號、不支援的 scheme 和超範圍的埠。用主機名時，honk 按系統解析順序逐個嘗試位址，選出第一個能讓所有請求傳輸都繫結成功的位址。繫結是同步執行的，而且必須全部成功；有一個失敗，honk 就關閉其他已選的 socket，讓啟動失敗。

listener 歸行程所有。SIGHUP reload 接受語義等價的不同寫法；但主機、埠或傳輸集合只要變了，就算需重啟項，SIGHUP 會拒絕。通配繫結或綁在 LAN 側會暴露一個無認證的遞迴解析器，必須用主機防火牆限制來源，絕不能暴露到不可信網路。

監聽 `:53` 不會搶在 LAN 流量策略之前收到查詢。即使 dnsmasq 或 `dns.bind` 佔著這個 socket，不帶 `must` 的 LAN TCP/UDP53 查詢仍然進入 honk 透明 DNS。主機 loopback 上的查詢，以及明確原生 `direct(must)` 交付的查詢，仍能到達這個普通 listener；見[listener 矩陣](../design/dns.md#dns-所有權狀態機)。

```dae
dns {
    bind: 'tcp+udp://127.0.0.1:1053'
}
```

## Hosts 快照（`use_host`）

`use_host` 可以重複設定。不區分大小寫的 `true`、`yes`、`1` 或 `on` 會把 `/etc/hosts` 加進來。`false`、`no`、`0`、`off` 或空值不加來源，也不會移除此前的來源。其他值都是路徑。`/etc/hosts` 不管是用 `true` 加入還是直接寫成路徑，都按標準 `IP canonical-name aliases...` 語法讀取；其他路徑都是 OxiDNS 相容的 `matcher target...` 規則檔案。honk 按宣告順序把每個來源讀一次，合併成一份快照；後面的來源會覆寫前面相同的精確名稱或 matcher。同一路徑只載入一次。

```dae
dns {
    use_host: true
    use_host: false # 不會移除上面加入的 /etc/hosts。
    use_host: 'hosts.txt'
}
```

絕對路徑保持原樣。相對路徑依次在 `global.data_dir` 下、`/var/share/honk` 下和工作目錄裡找已有的副本；三處都沒有時，路徑仍定位到 `global.data_dir` 下。查詢時只用產生好的不可變快照，不做檔案 I/O。

自訂 matcher 支援 `full:example.com`，也可以只寫不帶字首的精確名稱；`domain:example.com` 匹配該名稱以及標籤邊界內的所有子域；另外支援 `keyword:text` 和 `regexp:pattern`。匹配優先順序依次是精確名稱、最長的 domain 字尾、第一個匹配的 regexp、第一個匹配的 keyword。同一 matcher 定義多次時，後者替換它的目標。full、domain 和 keyword 名稱按 ASCII 大小寫不敏感處理，末尾點會正規化。regexp 保持大小寫敏感，匹配的是不帶末尾點的小寫名稱；需要忽略大小寫時寫 `(?i)`。honk 會去掉重複位址。

規則檔案每行一個 matcher，後面跟一個或多個 IPv4/IPv6 位址，或者恰好一個別名目標主機名。`#` 總是開始註釋，也沒有引號機制，所以 matcher 裡不能有空白或 `#`。`hosts.txt` 範例：

```text
full:api.example.com 192.0.2.10 2001:db8::10
domain:example.org 192.0.2.20
keyword:internal 192.0.2.30
regexp:^(foo|bar)\.example$ 192.0.2.40 # 共用位址
```

`ipv4only`/`ipv6only` 的硬位址族過濾之後，已知名稱的 IN class A 或 AAAA 查詢優先於 request 規則、快取查詢和上游交換，`reject` 規則也不例外。位址條目沒有所請求的位址族時，honk 返回 NOERROR/NODATA，不查上游。其他 class 和 qtype 照常走正常管線。本機位址記錄用 60 秒 TTL，hosts 應答不走 honk 的 DNS 快取。

honk 在 OxiDNS 格式上做了擴充套件：規則可以只寫域名、不寫位址，此時這個名稱就成為該域名的別名：

```text
full:a.example b.example
domain:corp.example gateway.example
```

目標和 matcher 名稱一樣要正規化，並且必須是有效主機名。名稱與位址混寫、寫兩個域名，或者精確名稱以自身為別名，都是無效規則。查詢別名的 A 或 AAAA 記錄時，honk 用相同 qtype 讓目標走完整管線：hosts、request 規則、快取、上游。應答先給出從查詢名稱經各級別名到目標的 `CNAME` 記錄，再附上目標應答裡的 CNAME 和所請求的位址記錄。本機別名 CNAME 和本機位址記錄用 60 秒 TTL；來自目標應答的記錄沿用目標自己的 TTL 策略。合成的應答不快取；目標查詢保留呼叫者的快取策略，明確繞過快取也一樣。

派生的目標查詢要求恰好一個問題，即 `QD=1`；answer 和 authority section 為空，即 `AN=NS=0`；additional section 為空，或恰好包含一個 OPT，即 `AR=0` 或 `1`。派生查詢替換 QNAME，保留交易 ID、全部 header flags、QTYPE 和 QCLASS。有 OPT 時，精確保留它的 class、TTL 和選項位元組，根名稱 owner 單獨編碼，不依賴原問題的編碼方式。其他 section 形狀會讓查詢在發往目標前就失敗；honk 不會把記錄直接丟棄，也不會退回去查原名稱。

目標為 NODATA 時，honk 返回只含 CNAME 鏈的 NOERROR；目標為 NXDOMAIN 時，按 RFC 6604 返回帶 CNAME 鏈的 NXDOMAIN。其他完整的 12 位 RCODE 不帶 answer 記錄：EDNS 客戶端收到完整 RCODE；客戶端沒用 EDNS、無法表示該 RCODE 時，返回不帶記錄的 SERVFAIL。目標查詢失敗，本次查詢就失敗。合成應答保留目標最終應答的 `TC` 位，即使合成後的封包沒有超出客戶端的大小限制。

全部來源合併後，每個別名目標都必須在 8 級以內走到一個不是別名的名稱。出現環路，或者鏈更長，都算無效設定，錯誤訊息會給出對應的 matcher 和目標。經[節點域名 hook](#節點伺服器域名) 解析的域名也遵守別名規則。

SIGHUP 會建構新快照。啟動時任一來源不可讀，或者自訂規則無效，啟動就失敗。reload 時，新的執行時 generation 會在釋出前失敗，目前的執行時 generation 繼續執行。

## EDNS Client Subnet（`client_subnet`）

ECS 會把近似的客戶端網路告訴上游權威伺服器。只有 CDN 本地性確實需要時才設定 `client_subnet`，否則留空。該設定只作用於命名上游。

- 明確值：IPv4 位址表示 `/32`；honk 會把 IPv4 CIDR 正規化為網路位址，所以 `203.0.113.7/24` 實際傳送 `203.0.113.0/24`。寫 IPv6、主機名或埠會讓設定失敗。
- 自動值：不區分大小寫的 `auto` 會帶 bypass mark 向 `1.1.1.1` 的 `33434` 到 `33469` 埠發 UDP 探測；`auto(IPv4)` 只替換目標位址。路由選出的本地位址是公網位址時，honk 直接用它。否則每個 TTL 用 3 個獨立 UDP 流，最多檢查 12 個 TTL，選第一個公網 ICMP 路由跳點。結果總是 `/24`。推斷在 2 秒後放棄。探測不依賴 DNS 或 HTTP 服務。
- 重新整理：啟動時、SIGHUP 時，以及路由、鏈路或位址變化時，honk 都會為新的 DNS 執行時 generation 解析出一個不可變值。有界探測失敗時，這個 generation 不產生 ECS。

改用其他探測目標：

```dae
dns {
    client_subnet: auto(9.9.9.9)
}
```

客戶端自己帶的 ECS，honk 不會覆寫，`/0` 也不覆寫。客戶端查詢只要帶任何 EDNS 選項，包括自帶的 ECS，就既不快取也不合併；honk 自己新增的 ECS 不影響快取。產生的 ECS 按下面的規則走：

- 明確 `-> tag` 選擇和普通流量路由都走完後，以最終解析出的撥號路徑為準。直連嘗試可以注入 ECS，`-> direct` 也算；走代理葉節點的嘗試不注入。
- 每次 UDP 位址重試，honk 都單獨判斷。失敗的直連嘗試帶上的 ECS 不會進入後續代理重試。
- 查詢沒有 ECS、又發往合格的命名上游時，honk 在 cache/singleflight admission 之後加上設定的選項，驗證上游回傳的 ECS，並在快取或回覆之前只移除自己注入的狀態。
- 有效字首參與 DNS 策略身分，所以自動字首變化前後的應答不會交叉重用。`asis` 請求保持逐位元組不變。

## 上游

每行寫 `name: 'uri'`，後面可選 `-> node-or-group`：

```dae
upstream {
    default: 'udp://223.5.5.5:53'
    google_doh: 'https://dns.google/dns-query' -> proxy
}
```

上游宣告保留名稱原來的拼寫。dae 的請求動作和應答動作解析器先去掉首尾空白，再呼叫 Rust 的 `to_lowercase()`，然後識別關鍵字或產生上游目標。查詢時，轉換後的目標必須和宣告的名稱完全一致。宣告名稱建議用小寫：宣告 `alidns`、動作寫 `AliDNS` 能匹配；兩邊都寫 `AliDNS` 反而匹配不上。舊版結構化目標不做大小寫轉換。

啟動和 reload 時，完整設定驗證會檢查生效的請求規則、應答規則，以及 `fallback` 引用的每個上游名稱。只解析設定的 API 不做這項驗證。第一個明確 `upstream` 區塊會替換內建條目，所以必須保留名為 `default` 的宣告，或者選一個已宣告的回退上游，或者把請求 `fallback` 設為 `reject`、`asis`。即使請求規則覆蓋了所有查詢，`fallback` 驗證也免不掉。

後續的 `upstream` 區塊，honk 會追加到第一個區塊後面。同一名稱宣告多次時，以最後一條為準。

### URI scheme 與預設值

| URI 形式 | 執行時協議 | 預設埠 / path |
| --- | --- | --- |
| `host[:port]` 或 `udp://host[:port]` | UDP；應答帶 `TC` 時改用 TCP 重試 | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` 或 `udp+tcp://host[:port]` | 與 UDP 相同 | `53` |
| `tls://host[:port]` | DNS over TLS（DoT） | `853` |
| `https://host[:port][/path]` | DNS over HTTPS（DoH，HTTP/2） | `443`，path 為 `/dns-query` |
| `h3://host[:port][/path]` 或 `http3://host[:port][/path]` | DNS over HTTP/3（DoH3） | `443`，path 為 `/dns-query` |
| `quic://host[:port]` | DNS over QUIC（DoQ） | `853` |

scheme 只能小寫。未知或大寫的 scheme，honk 不會拒絕，而是把整個字串當作 UDP 位址，所以要自己檢查拼寫。

帶埠的 IPv6 字面量要加方括號，例如 `[2606:4700:4700::1111]:53`；不帶埠的 IPv6 字面量用預設埠。

```dae
upstream {
    default: 'udp://[2606:4700:4700::1111]:53'
    cloudflare_v6_dot: 'tls://[2606:4700:4700::1111]:853?tls_server_name=cloudflare-dns.com'
}
```

基於 TLS 的協議由解析器從主機名派生 `tls_server_name`。憑證驗證需要 DNS 名稱時，IP 字面量 endpoint 要明確寫 query 參數：

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

這個參數會從撥號位址裡移除，並覆寫從主機名派生的值。key 名區分大小寫，值不做百分號解碼，出現多次時最後一個非空值生效。其他 query 項留在位址裡；寫在 DoH 或 DoH3 路徑之後時，它們會成為請求 URI 的一部分。

DoH 和 DoH3 用 `application/dns-message` 發 `POST` 請求。HTTP authority 是 endpoint 的主機和埠。`tls_server_name` 只改 SNI 和憑證驗證，所以 IP 字面量形式的 DoH 伺服器必須接受把這個 IP 當作 authority。

### 出站選擇

末尾的 `-> tag` 強制該上游走指定的節點或代理群組。`-> direct` 直接撥號，不經過流量路由；`-> block` 讓每個查詢都失敗。tag 與任何節點或群組都不匹配，或者群組裡沒有可用節點時，查詢失敗，不會退回直連。省略字尾時，honk 解析上游目的位址，再套用普通流量的 `routing { ... }` 規則；這條路由仍然可以選到代理葉節點。舊版的同行寫法 `name: 'uri' outbound: tag` 也還接受。

```dae
upstream {
    default: 'udp://223.5.5.5:53' -> direct
}
```

流量路由把上游當作 honk 自己發起的流量。輸入有上游主機名、解析出的 IP 和埠、來源 `0.0.0.0:0`，還有 `l4proto`；上游主機名只在寫明了的時候才有。`l4proto` 的取值是：UDP、DoQ 和 DoH3 為 `udp`，TCP、DoT 和 DoH 為 `tcp`。即使選中的代理用 TCP-DNS 承載，UDP 上游仍按 `udp` 路由。

只有引號外的 `->` 和 `outbound:` 字尾才選出站。它們寫在 URI 引號裡仍算資料；如果這種寫法與舊版的拆分結果不同，會產生 `legacy-upstream-separator` warning。引號外的詞法單元開頭出現 `#`，就開始行尾註釋，行為有變化時會產生 `legacy-upstream-comment`。註釋和出站字尾都應寫在 URI 引號外。

| 協議 | 經過選定的節點或群組 |
| --- | --- |
| UDP（`udp`、裸位址、`tcp+udp`、`udp+tcp`） | 通過該出站承載為 TCP-DNS。 |
| TCP | 支援通過出站 TCP stream。 |
| DoT | 支援；TLS 在出站 TCP stream 上執行。 |
| DoH | 支援；TLS 與 HTTP/2 在出站 TCP stream 上執行。 |
| DoQ | 支援經出站的 UDP-capable `PacketTransport`。 |
| DoH3 | 支援經出站的 UDP-capable `PacketTransport`。 |

## DNS 路由

`routing` 裡是排好序的 `request` 和 `response` 規則，第一條匹配的生效。同一個條件裡的引數按 OR 組合；用 `&&` 連起來的條件按 AND 組合。條件前加 `!` 表示取反。

在 `request` 和 `response` 規則裡，matcher 引數內的單引號或雙引號可以保護 `,`、`)`、`&&`、`->`、`#` 和 `//`。只有引號外、詞法單元開頭的 `#` 才開始註釋，前面的空格或 Tab 可以留。緊貼前文的 `#` 仍是資料。`//` 不是註釋：行尾寫斜線註釋會讓規則無效，產生 `legacy-slash-comment` warning，整條規則被省略；應改用 `#`。`qtype('a,aaaa')` 仍然選中兩種型別，並產生 `legacy-quoted-list` warning；建議裸寫，或者逐項加引號。

未知、格式錯誤或不支援的條件會產生帶位置的 warning，整條規則被省略，不會只丟棄合取裡的一個條件。未知的 QTYPE 名稱產生 `invalid-qtype`，混合清單和取反條件也一樣；應改正名稱或改用數字型別碼。明確寫的 `qtype()` 仍不匹配任何型別。無效的 `qname` 或 `subtag` 正規表示式，以及空的 `sip()`，能通過解析，但會讓啟動或 reload 失敗。

每條完整呼叫和它的動作必須寫在同一物理行上。不完整的非空行會被省略，並產生帶位置的 `incomplete-dns-rule`；DNS 不會把這些行拼起來。完整 matcher 後面多了文字，會產生 `trailing-matcher-text`，整條規則省略。詞法單元開頭和引數位置的引號，都必須在同一行閉合。未閉合引號會產生一條詞法診斷；只有每個區塊都保留了有效的右大括號時，honk 才省略該行並繼續處理，否則整個文件失敗。未閉合引號覆蓋到的右大括號不算區塊結束符。

### 條件

| 語法 | 範圍 | 意義 |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request 與 response | 點邊界字尾；裸引數也表示字尾。 |
| `qname(keyword: ads)` | Request 與 response | 子串匹配。 |
| `qname(full: api.example.com)` | Request 與 response | 精確域名匹配。 |
| `qname(regex: ...)` | Request 與 response | Rust 正規表示式匹配；包含括號時需加引號。 |
| `qname(geosite: cn)` | Request 與 response | 匹配指定 geosite 類別展開出來的域名；`category@attr` 只保留帶該屬性的條目。 |
| `qtype(a, aaaa, ...)` | Request 與 response | 匹配 QTYPE 名稱或數字 `u16`。可識別名稱為 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY` 和 `*`。`*` 是 `ANY` 的別名，不是萬用字元。 |
| `sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32)` | 僅 request | 把邏輯客戶端來源和列出的任一個 IP 主機位址或 CIDR 匹配。 |
| `subtag(MyAirport, keyword: Air, regex: ^Paid)` | 僅 request | 匹配[節點伺服器域名](#節點伺服器域名)查詢所屬訂閱的 tag：精確值、`keyword:` 或 `regex:`，區分大小寫。 |
| `upstream(name, ...)` | 僅 response | 匹配產生目前應答的上游。名稱精確比較，且不像動作目標那樣轉為小寫。 |
| `ip(192.0.2.0/24, geoip: private, ...)` | 僅 response | 任一應答 IP 屬於所列 CIDR 或 GeoIP 集時匹配。 |

`qname` 用去掉末尾點的小寫查詢名稱匹配。`full:` 和 `suffix:` 的模式會轉成小寫，但模式裡的末尾點會保留，所以帶末尾點的模式永遠匹配不上。`keyword:` 和 `regex:` 模式區分大小寫；應寫小寫，或者加 `(?i)`。

第一個沒加引號的 `)` 會結束條件，所以含括號的正規表示式要加引號：

```dae
dns {
    routing {
        request {
            qname('regex: ^(foo|bar)\.example$') -> default
            qname(geosite: geolocation-!cn@cn) -> default
            qtype(*) -> reject
            qtype(a, aaaa) -> default
        }
    }
}
```

`geosite.dat` 或 `geoip.dat` 不可用時，對應的展開結果不匹配任何內容。未知的類別、程式碼或屬性會產生 warning，同樣不匹配任何內容，所以單獨把它們取反，條件就恆為真。`geoip: private` 是內建集合，不需要資源檔；見[資源位置](./global.md#資料目錄與資源路徑)。

整個 `subtag` 引數加引號時表示精確 tag：`subtag('keyword: Air')` 匹配名為 `keyword: Air` 的 tag，而 `subtag(keyword: Air)` 匹配包含 `Air` 的任意 tag。

透明 53 埠和 `dns.bind` 入口的邏輯來源是 socket peer。為已通過 admission 的 TCP/UDP 流做 DNS 解析時，邏輯來源是這條流的客戶端位址。內部查詢、bootstrap 查詢、prefetch 和 Clash API 查詢都沒有邏輯來源。來源未知時，正向和取反的 `sip` 條件都是 false，請求路由繼續看下一條規則或 fallback。response 路由不接受 `sip`。

DNS 的 `sip()` 和 `ip()` 共用同一個 IP/CIDR 解碼器。裸 IPv4 和 IPv6 位址分別表示 `/32` 和 `/128`；honk 會把 CIDR 裡的主機位清零，並產生 `dns-network-host-bits` warning。無效網路會產生帶位置的 `invalid-dns-network` 診斷，整條 dae 規則被省略；用程式碼建構的無效路由則在路由器或策略建構時失敗。等價的網路寫法使用相同的策略識別碼，引數順序不變，重複引數也不會刪除。

### 節點伺服器域名

節點伺服器域名經 `global.bootstrap_resolver`、`/etc/hosts` 和系統 nameserver 解析，不走 DNS 路由。含 `subtag(...)` 的 request 規則會接管匹配訂閱裡節點的伺服器域名，XHTTP 下載域名也包括在內：

```dae
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        providerdoh: 'https://doh.provider.example/dns-query' -> direct
    }
    routing {
        request {
            subtag(MyAirport) && qname(suffix: private.provider.example) -> providerdoh
            fallback: alidns
        }
    }
}
```

- 節點域名只匹配含 `subtag()` 的規則；普通規則、fallback 和沒匹配上的域名仍走 bootstrap 解析。其他查詢不帶訂閱，對它們來說 `subtag()` 和 `!subtag()` 都是 false。
- 被接管的查詢只發往選中的上游，遵守 `strategy` 和 `use_host`，不走快取和 response 規則，也不回退：查詢失敗就表示物理節點連線或探測連線失敗。
- 接管按域名生效，不是端到端的下載目標解析策略。下載時為選路而預先解析 URL 域名，只是盡力而為；代理下載的 URL 域名仍由代理解析，而承載代理自身的節點伺服器解析遵守這條規則。明確使用 bootstrap 解析器的下載繞過這個 hook。
- tag 屬於主機名，不屬於節點：不同訂閱裡共用同一主機名的節點，各自的 tag 會合併，所以第一條匹配的規則就為這個主機名選定一個上游。
- 這條規則只能和 `qname()` 組合，而且所選上游的每條宣告都必須是 `-> direct`，否則驗證報錯：`subtag-dns-condition`、`subtag-dns-action` 或 `subtag-dns-upstream-route`。
- 上游自身的域名、ECH 發現和離線 `delay` 子命令仍使用 bootstrap 解析器。
- 域名匹配到 `use_host` 中的[別名](#hosts-快照use_host)時，honk 改為解析別名目標。別名鏈停在位址條目上，就直接用這些位址；否則把目標域名當作節點域名解析，也就是交給接管該目標的 `subtag()` 規則，沒有接管就走 bootstrap。直接匹配原始域名的位址條目不會經這個 hook 接管；honk 用的是別名鏈終點的位址條目。所有被接管的查詢，包括本機位址結果和 bootstrap 目標，都遵守 DNS 執行時 admission 與取消機制。目標或 subtag 路徑一旦選定，該路徑失敗就是最終結果。查詢執行前 reload 刪掉了這個別名時，原域名按沒有別名的情況解析。
- 別名匹配所有交給 bootstrap 解析器的域名，不限於節點伺服器域名：沒有指定明確 bootstrap 解析器的訂閱、Geo 資料和外部 UI 下載的 URL 域名，SOCKS5 節點的 UDP 中繼域名，以及健康檢查、延遲測試、連通性探測和內部解析回退到 bootstrap 時的域名。DNS 上游自身的域名和 ECH 發現不走這個 hook。
- 每個 DNS generation 根據訂閱 tag 和有序規則，預先算出節點域名的策略結果，包括沒匹配上的結果。用到這些結果時，原生流追蹤會以 `not_instrumented` 標成 `partial`：節點域名的規則決策證據還沒有收集。

### Request 動作

| 動作 | 結果 |
| --- | --- |
| `reject` | 返回空的成功應答。 |
| `asis` | 用 honk 自己發起的 socket，向攔截時得到的原始 DNS 目的位址重新查詢，不保留客戶端的網路來源 IP 和埠。透明查詢保留入口 transport；UDP 應答帶 `TC` 時，對同一目的位址改用 TCP 重試。獨立查詢沒有原始目的位址，會直接失敗，不會遞迴撥回 listener。 |
| 上游名 | 查詢該命名上游。 |
| `fallback: reject\|asis\|<upstream>` | 沒有 request 規則匹配時使用的動作；預設用上游 `default`。 |

兩個路由區塊都接受 `default:` 作為 `fallback:` 的舊版別名。

代表已通過 admission 的流執行、帶有來源的查詢，沒有攔截時得到的 DNS 伺服器原始目的位址。如果它的 request 策略選了 `asis`，解析按 fail-closed 處理，絕不會退回到相容的預設上游。

原生 `direct(must)` 的繞過與 `asis` 重新查詢不同；見[DNS 來源/NAT 與投影限制](../design/dns.md#入口路徑)。

### Response 動作

| 動作 | 結果 |
| --- | --- |
| `accept` | 返回目前應答。 |
| `reject` | 把目前應答換成空的成功應答。 |
| 上游名 | 通過該命名上游重新查詢，然後再次執行 response 路由。 |
| `fallback: accept\|reject\|<upstream>` | 沒有 response 規則匹配時使用的判定或命名上游；預設是 `accept`。 |

`NXDOMAIN` 和 `SERVFAIL` 略過應答規則和回退動作。對可快取的查詢，如果上游交換失敗或返回 `SERVFAIL`，而[過期應答](#快取與固定-ttl)還在，honk 就改為返回它；本機封包拒絕不會觸發這一行為。

一輪 response 最多查三個上游，初始上游也算在內；第四次交換 honk 會拒絕。重新查詢形成環路時，honk 同樣拒絕。

## 位址族策略

### ipversion_prefer

`ipversion_prefer` 設定 A 和 AAAA 查詢的位址族偏好。

| dae 設定 | 內部策略 | 行為 |
| --- | --- | --- |
| 省略 | `both` | 並行執行符合條件的 A 和 AAAA 查詢，不壓制任何位址族。 |
| `ipversion_prefer: 0` | `both` | dae 的無偏好取值，行為與省略相同。 |
| `ipversion_prefer: 4` | `preferipv4` | 偏好 IPv4，同時保留 IPv6 回退。 |
| `ipversion_prefer: 6` | `preferipv6` | 偏好 IPv6，同時保留 IPv4 回退。 |

`ipversion_prefer` 預設 `both`。honk 解析不了的值保持 `both`，並輸出診斷。內部的 `ipv4only` 和 `ipv6only` 模式無法用 dae 的 `ipversion_prefer` 語法表達。

```dae
dns {
    ipversion_prefer: 4
}
```

### 偏好族查詢

偏好模式下，兩個位址族仍可查詢。收到非偏好族的 A/AAAA 請求時，honk 會讓偏好族的 sibling query 走同一條管線，並保留呼叫方的邏輯來源、原始目的位址、入口 profile，以及除 QTYPE 外的 wire profile。偏好族有位址時，honk 把非偏好族應答壓制為 NODATA；偏好族沒有位址，或者 sibling 遇到普通的可用性失敗時，就返回非偏好族的應答。typed local packet refusal 會按原始原因終止解析，carrier Capacity 也算在內，honk 不會拿過期快取應答替換它。相關快取未命中時，這樣做會多出一次上游查詢。

### bootstrap 撥號順序

同一策略也決定上游主機名經 bootstrap 解析後的撥號順序。`both` 和 `preferipv4` 先撥 IPv4，`preferipv6` 先撥 IPv6。TCP、DoT、DoH、DoQ、DoH3 以及經代理承載的 DNS，在撥號失敗後會繼續試後面的位址。直連 UDP 把那唯一一次重試優先給另一個位址族，再考慮同族的其他位址，並重用連線成功的 socket。`ipv4only` 和 `ipv6only` 只在相容格式裡可用，會把上游撥號候選限制在對應位址族。

## 快取與固定 TTL

### optimistic_cache

啟用正、負快取的讀取和寫入。預設 `true`；設為 `false` 時，回覆保留上游 TTL。

```dae
dns {
    optimistic_cache: false
}
```

### optimistic_cache_ttl

設定除 NXDOMAIN、SERVFAIL 和 NODATA 外所有應答的快取生命週期和回覆裡的 RR TTL；這三類回應碼按[負應答](#負應答)處理。預設 `600` 秒。寫 `0` 用上游應答裡的最小 TTL。只接受十進位秒數：`10m` 這類值會產生診斷，並回落到 `60`，不是 `600`。

```dae
dns {
    optimistic_cache_ttl: 600
}
```

### optimistic_stale_reply_ttl

設定 serve-stale 正應答使用的 TTL。預設 `30` 秒。非零值替換每個非 OPT RR 的 TTL。寫 `0` 時保留快取裡已按策略改寫的 wire TTL，不用權威 TTL。此時 outcome TTL 從該 wire 的 `extract_min_ttl` 得出，沒有正 TTL 時回落到 60 秒。非零時，即使沒有正 TTL，outcome TTL 仍是設定值。值無效會產生診斷，並回落到 `30`。

```dae
dns {
    optimistic_stale_reply_ttl: 30
}
```

### max_cache_size

設定快取條目數上限和每個分片的應答位元組預算。預設 `10000`。條目上限最多分攤到 16 個分片，每個分片的預算按 `max(條目容量 × 1 KiB, 65,535 位元組)` 計算；honk 按 LRU 淘汰，直到兩個上限都滿足。單條超過 65,535 位元組的應答不快取。大於 100,000 的值會被鉗到 100,000，`0` 會被鉗成一個條目；兩種情況都產生 warning。無法解析的值會觸發診斷，並回落到 `10000`。

```dae
dns {
    max_cache_size: 20000
}
```

### fixed_domain_ttl

按域名覆寫正應答和 NODATA 的 TTL，先於 `optimistic_cache_ttl` 應用。預設空。寫 `0` 時，所有回應碼的應答都不快取，NXDOMAIN 和 SERVFAIL 也一樣。key 只匹配一個精確名稱，用不帶末尾點的小寫形式，不覆寫子域。

例如，`www.example.com` 需要單獨的條目：

```dae
dns {
    fixed_domain_ttl {
        example.com: 120
        www.example.com: 120
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

每個固定 TTL 必須正好是一個無符號 32 位十進位標量。裸值和帶引號的值都接受，包括 `0` 和 `4294967295`；新接受的帶引號十進位值會產生 `legacy-ttl-quoting` warning。值無效或溢位會產生 `invalid-ttl`，多出詞法單元會產生 `trailing-value`，兩種情況都會省略該條目。說明文字寫在 ` # ` 後面，不要緊貼數值。

### 快取條目與過期

Request 路由在快取查詢之前執行。查詢除交易 ID 外完全相同，走同一類入口，又選中相同的 DNS 策略和相同的上游或 `asis` 目的位址時，客戶端才共享快取條目；原始客戶端來源不參與快取 key。偏好位址族的渲染仍保留來源中繼資料，所以依賴來源的 sibling 策略不會經由 foreground singleflight 洩漏。

設了 `optimistic_cache_ttl: 0`，又沒有 `fixed_domain_ttl` 覆寫時，`NOERROR` 正應答取 answer、authority 和 additional 段裡所有非 OPT 記錄的最小 TTL。快取這份應答時，honk 把每個非 OPT 記錄的 TTL 改寫成這個最小值。只要有一條記錄的 TTL 為零，honk 就不快取該應答，並移除精確快取槽，避免舊位址或更早的負應答再次返回。非零的設定 TTL 或固定 TTL 仍能覆寫零值。

honk 只在快取應答時改寫回復 TTL；不可快取的查詢，或者 `optimistic_cache: false` 時，保留上游 TTL。除 `NXDOMAIN` 和 `SERVFAIL` 外的失敗碼，例如 `REFUSED`，按 `optimistic_cache_ttl` 處理，預設快取 600 秒。

即使回應策略 `reject` 把回覆換成合成的 NOERROR，快取生命週期仍按原始上游應答的分類、回應碼和 TTL 決定。所以被拒絕的 REFUSED 保留失敗回應碼的 TTL 規則；沒有設定 TTL 或固定 TTL 覆寫時，被拒絕的 NOERROR 正應答用原始 TTL。

快取命中時，訊息裡的記錄 TTL 不會遞減。這種改寫只發生在記憶體裡，已儲存的持久化行不會被刪。

### 負應答

NXDOMAIN 的快取時間是 `min(SOA TTL, SOA MINIMUM, 300)` 秒。缺少 SOA，或者 SOA 生命週期為零時，honk 不快取，並移除精確快取 key 下已有的正、負快取，避免舊位址又作為過期應答返回。前景結果替換當時已有的寫入結果；背景重新整理只移除它開始時讀到的那一版。`fixed_domain_ttl: 0` 禁止快取，但已有的條目不刪。除此之外，SERVFAIL 仍按 SOA 算出的生命週期處理，預設 60 秒，並限制在 `1..=300` 秒。

這裡的 NODATA 指沒有 answer 記錄的 NOERROR 應答，即 `ANCOUNT=0`。answer 非空時，honk 仍把它歸為正應答，只含 CNAME/DNAME 的也算。NODATA 的完整訊息留在正快取槽裡，生命週期是 `min(SOA TTL, SOA MINIMUM, 300)` 秒。非零的 `fixed_domain_ttl` 優先於 SOA 和上限，即使缺 SOA 也生效。沒有這個覆寫值時，缺 SOA 或生命週期為零的 NODATA 和 NXDOMAIN 一樣處理：移除精確快取槽，新應答不保留。

快取的 NODATA 仍能作為過期應答返回；過期應答改寫的是 SOA 記錄 TTL，不是 SOA MINIMUM。對上游 NODATA 套用回應策略 `reject`，會產生空的 NOERROR 訊息；它的快取生命週期按同樣的 TTL 規則算，SOA 取被拒絕的應答，不取合成訊息。後續請求在這個生命週期內重用合成應答。

### serve-stale 與重新整理

過期應答，包括快取的 `NODATA`，到期後 1 小時內還能用於 serve-stale，除非已經被淘汰。`optimistic_stale_reply_ttl` 只設定回覆 TTL，不管這個視窗。快取命中時，剩餘時間不超過 `max(原 TTL / 10, 1)` 秒就啟動一次背景重新整理。

### 路由投影

不保留快取不等於關閉 DNS 路由投影。已接受但不可快取的正應答，`fixed_domain_ttl: 0` 的結果也算，用 wire 裡非 OPT 記錄的最小正 TTL 作為投影壽命；這些 TTL 全為零時回落到 60 秒。這條規則不改寫應答，也不會讓應答變得可快取；快取命中的剩餘壽命和 served-stale 壽命都不變。

## 解析規則

### 標量與註釋

標量值佔掉該物理行剩下的部分，只在 key 後面的冒號處切開，所以裸寫的 IPv6 位址和 `client_subnet: auto(9.9.9.9)` 都能保持完整。解析器只去掉包圍整個值的一對匹配引號。值一旦以引號開頭，就必須在同一行閉合，否則設定失敗。

標量設定裡，只有引號外、詞法單元開頭的 `#` 才開始註釋。`use_host: /tmp/a#b` 選的是字面路徑 `/tmp/a#b`，並產生 `legacy-glued-hash` warning；註釋要寫成 `use_host: /tmp/a # comment`。重複的 `use_host` 宣告按來源順序保留，去重行為與原來一樣。

### 布林值

`optimistic_cache` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不區分大小寫。其他值會關閉快取，並產生診斷。

對 `optimistic_cache`，布林簡寫 `t`、`y`、`f`、`n` 仍表示假，但會產生 `legacy-bool-shorthand` warning；應改用 `true` 或 `false`。

### 未知 key 與已移除的 key

`dns` 裡的未知 key、區塊和語句會產生 `unknown-key`、`unknown-block` 或 `unknown-statement` warning，honk 直接忽略。`dns.routing` 只接受 `request` 和 `response` 區塊。

`hosts_file` 已移除，改用 `use_host` 路徑；設定裡仍寫著它時，honk 以 `removed-dns-hosts-file` 報錯，設定失敗。

## 舊版轉換

相容性設定裡保留扁平的 `routing.rules` 條目，欄位是 `domain` 和 `upstream`，另外還有命名 `fallback`。這些是結構化相容欄位，不是目前 dae 語法裡的附加語句。`suffix:`、`keyword:`、`full:` 和 `regex:` 字首用來選匹配方式；不帶字首的舊版域名按 `full` 精確匹配。

結構化的 YAML、TOML 或 JSON 輸入不能包含 request 或 response 規則：`dns.routing.request` 和 `dns.routing.response` 必須省略，或者寫成 `null`。這類規則請用 dae 寫。

生效的請求路由按下面的優先順序選：

1. 新式 `request.rules` 非空時，用新式規則和它的回退動作，忽略所有舊版欄位。
2. 新式規則為空、舊版 `rules` 非空時，把舊版規則轉換成請求規則，舊版回退名稱保留原來的拼寫。即使另外配了新式回退動作，也以舊版為準。
3. 兩組規則都為空時，用已設定的請求路由。只有回退動作是 `Upstream("default")`，並且舊版回退值不是 `""`、`"upstream"` 或 `"default"` 時，才用舊版值替換它。

`"upstream"` 只在第三個分支裡當哨兵值忽略；有舊版規則時，它就是普通的上游名稱，必須有對應宣告。舊版目標按原樣精確匹配，不套用 dae 動作的大小寫轉換規則。

驗證診斷保留原始欄位路徑。新式規則和回退用 `dns.routing.request.rules[i].action` 和 `dns.routing.request.fallback`；轉換後的舊版規則用 `dns.routing.rules[i].upstream`；轉換或提升的回退用 `dns.routing.fallback`。

舊版規則生效時，預設回退的 `upstream` 沒宣告會報告 `missing-dns-fallback`；空回退沒有匹配宣告會報告 `empty-dns-fallback`；其他沒宣告的目標會報告 `unknown-dns-upstream`。診斷保留欄位路徑，但不顯示目標名稱，也不列出已宣告的名稱。省略舊版回退等同於明確寫 `upstream`，只要宣告了該上游，兩種寫法都有效。沒有舊版規則時，honk 仍會忽略空值和 `upstream` 哨兵。

## 相關文件

- [DNS 設計](../design/dns.md)
- [實驗性設定參考（`store_dns`）](./experimental.md)
- [全域設定參考](./global.md)
