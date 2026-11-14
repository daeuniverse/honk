# honk 設定指南

安裝步驟，以及只走直連、代理、介面/API 的起步設定，見[啟動指南](./how-to-start.md#最小設定)，各欄位的含義見參考文件。

honk 使用 dae 設定語法的方言，與 dae 的已知差異見[方言參考](./reference/dialect.md)。下表列出執行階段的設定區段和 CLI 入口。`include {}` 用來把設定拆到多個檔案。

| 設定區段 | 用途 | 參考 |
| --- | --- | --- |
| `global` | 選擇介面、撥號行為、健康檢查與執行階段路徑。 | [Global 參考](./reference/global.md) |
| `node` | 用分享連結宣告靜態代理節點。 | [節點參考](./reference/nodes.md) |
| `group` | 在節點與巢狀代理群組之間選擇。 | [代理群組參考](./reference/groups.md) |
| `routing` | 套用有序流量規則與預設出站。 | [路由參考](./reference/routing.md) |
| `dns` | 設定 listener、上游、請求/回應策略與快取行為。 | [DNS 參考](./reference/dns.md) |
| `subscription` | 取得遠端節點清單。 | [訂閱參考](./reference/subscription.md) |
| `assets` | 為 geodata、外部 UI 和訂閱設定下載預設值。 | [Assets 參考](./reference/assets.md) |
| `experimental` | 啟用獨立原生 API、Clash API 或持久化快取。 | [Experimental 參考](./reference/experimental.md) |
| CLI | 選擇設定、後端、目標檔或本機命令。 | [CLI 參考](./reference/cli.md) |

內建出站 `direct` 和 `block` 在啟動時注入，可以用在群組和路由規則裡。

## 設定格式

入口檔案和被包含的 `.dae` 檔案必須使用 UTF-8，其他編碼會被拒絕。

- 設定項放在 `section { ... }` 區塊中，每行一個 `key: value`。也接受 `global { log_level: debug }` 這樣的單行區塊，以及巢狀的單行區塊。
- URL、含空白的值，以及含 `:`、`+`、`#` 這類語法字元的值，建議加引號。純量值以及 `include`、`node`、`subscription` 條目都接受單引號或雙引號。
- 引號內的文字按字面讀取：不解碼 `\n` 等跳脫序列，反斜線只防止下一個引號結束字串。引號必須在同一行閉合。`filter: name(regex: '^edge\.example$')` 向 regex 引擎傳入 `^edge\.example$`。
- 在 matcher 引數和過濾、路由表示式裡，成對的單引號或雙引號內的逗號、右括號、`&&` 和 `->` 都按字面值保留；不過 `group(...)` 和 `qtype(...)` 仍會把帶引號的逗號分隔文字當成清單。
- 設定項或 matcher 接受清單時，用逗號分隔：`lan_interface: eth0, eth1` 或 `dport(80, 443)`。
- `check_interval`、訂閱 `interval` 這類以秒為單位的持續時間只接受整秒，可以不加字尾，也可以加上 `s`、`m`、`h`；`1.5s` 無效。`ms` 值會向上取整到整秒，`500ms` 就是 `1s`。無效值會產生 warning 並變成 `0`，而 `check_interval` 為 `0` 時會回報錯誤 `check_interval must be a positive duration`。
- `check_tolerance` 這類毫秒設定項接受裸毫秒數、帶 `ms` 的整數或帶 `s` 的秒數，`1.5s` 就是 1500 ms。不足 1 ms 的小數部分會捨去；`1.5ms` 和 `m`、`h` 字尾無效。無效值會產生 warning 並保留預設值。
- 引號外、token 開頭的 `#` 開始註解；值內部的 `#` 視為資料保留。連結的結束引號或訂閱 `(UA)` 字尾後面緊貼的 `#` 也算註解，但會產生 `legacy-glued-hash` warning，所以註解前要留空白。token 開頭的註解裡，大括號不會閉合設定區塊。
- 成對單引號或雙引號內的大括號視為資料。多餘的右大括號 `}` 會被忽略，並回報一筆診斷；有未閉合的區塊時，整個文件都會被拒絕。解析器能定位時，診斷會附上實體行號；錯誤文字不會回顯任意輸入內容。
- 解析器遇到未知的純量 key 會回報診斷並忽略。未知巢狀區塊整個子樹跳過，不會把裡面的內容當成父區塊內容讀取；只有文件列出的 `node` 和 `subscription` 包裝區塊保留相容走訪。以下情況都是錯誤：未知的 `experimental` 外層設定、`experimental.native_api` 裡的未知內容、舊版 NFQUEUE 中不支援的內容，以及用 `tolerance` 這類群組純量命名的區塊。見[方言參考](./reference/dialect.md#設定區段與-include)。

### 使用 `include {}` 拆分設定

```dae
include {
    config.d/*.dae
    config.d/*/*.dae
    'config.d/extra config.dae'
}
```

`include` 條目是檔案模式，不加引號或加引號都行，支援 `*`、`?`、`[]` glob。空路徑、巢狀區塊和無效 glob 都是設定錯誤。模式依宣告順序逐一執行，每個模式的相符項目依字典序載入；沒有相符項的模式、目錄，以及副檔名不是 `.dae` 的檔案都會被跳過。路徑分量 `**` 和 `*` 一樣只比對一層目錄，不會遞迴，所以範例用 `config.d/*/*.dae` 載入 `config.d` 下一層目錄裡的檔案。

被包含的空檔案或純註解 `.dae` 檔案不提供設定區段；dae 入口文件必須含區塊的要求不適用於這些片段。

只有頂層 `include` 允許起始大括號另起一行，並會產生 `legacy-include-opener` warning；建議在同一行寫 `include {`。`include` 的註解依 token 規則處理：`path.dae # note` 載入 `path.dae`，而 `path.dae#note` 是字面 glob 模式，並產生 `legacy-include-hash` warning。字面 `#` 可以加引號，以免觸發遷移 warning。字串解析只檢查 `include` 結構，不開啟被包含的檔案；`include` 也不能把片段拼接到尚未閉合的區塊裡。

所有相對 include 都相對於傳給 `--config` 的入口設定所在目錄解析，巢狀 include 檔案裡的也一樣。載入器會正規化入口目錄和每個相符項的路徑；指向該目錄之外的絕對路徑或符號連結會被拒絕。同一個正規化路徑的檔案，不管是直接重複載入還是循環載入，都會被拒絕。

入口檔案自身的設定區段一律最先合併，不受 `include` 區塊位置影響；之後依序合併每個被包含檔案及其子代。後出現的純量 key 會蓋掉先前的值。節點、訂閱、群組、DNS 上游、固定 TTL 和路由規則這類集合條目，依合併順序追加。

## 執行階段資料目錄

`global.data_dir` 是執行階段狀態和相對執行階段資源的程式層級根目錄，預設 `/var/lib/honk`，必須是非空的絕對路徑。修改後要重新啟動。

啟動時，honk 會遞迴建立目錄，然後新建並刪除一個私有檔案，確認目錄能不能用。`data_dir` 不可用時，只有通過同一項檢查的工作目錄可以作為後備；`--store db` 和啟用的原生 API 密碼登入不允許這種後備。

相對路徑的可寫資源和唯讀依賴，依序使用第一個存在的路徑：

1. `<data_dir>/<path>`。
2. `/var/share/honk/<path>`。
3. 呼叫端的舊位置：快取使用原始設定目錄，其他依賴使用工作目錄。

都不存在時，honk 會傳回 `<data_dir>/<path>` 供建立。舊根目錄 `/var/share/honk` 對應常數 `LEGACY_DATA_DIR`，裡面的資源仍可經這些後備路徑使用，但舊快取和訂閱匯入會把符合條件的狀態複製到 `state/honk.db`。相對日誌一律建立在 `<data_dir>/<path>`。絕對路徑保持原樣。

Geo 資源另外依一般檔案尋找：`$DAE_LOCATION_ASSET`、`<data_dir>`、`/var/share/honk`、工作目錄、honk share 目錄，最後是 dae share 目錄。

詳見 [Global 參考](./reference/global.md)。

## 最小設定

部署前要換掉 `eth0` 和範例節點位址。

```dae
# 設定攔截基準。
global {
    # 跟隨 IPv4 預設路由介面。
    wan_interface: auto
    # 攔截來自該 LAN 介面的轉送流量。
    lan_interface: eth0
    # 輸出一般執行日誌。
    log_level: info
    # 同時追加寫入 <data_dir>/honk.log。
    log_file: 'honk.log'
    # 嗅探網域並驗證目的 IP。
    dial_mode: domain
    # 為相容 dae 而保留；honk 依固定規則設定 sysctl。
    auto_config_kernel_parameter: true
    # 解析代理主機名稱時避免自我攔截。
    bootstrap_resolver: '1.1.1.1:53'
}

# 宣告一個靜態代理節點。
node {
    # 將 SOCKS5 分享連結命名為 `edge`。
    edge: 'socks5://192.0.2.2:1080'
}

# 將節點組成可選擇的出站。
group {
    proxy {
        # 只包含指定節點。
        filter: name('edge')
        # 固定第一個符合的成員。
        policy: fixed(0)
    }
}

# 私網目的地直連，Web 流量經由代理群組。
routing {
    # 私網目的地不經過代理。
    # 此規則也會繞過私網 DNS；需要保留接管時，明確加上 && !dport(53)。
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) -> direct(must)
    # 代理常用的 Web 連接埠。
    dport(80, 443) -> proxy
    # 其餘流量直連。
    fallback: direct
}

# 用直連路徑保持 DNS 可用。
dns {
    upstream {
        # 使用一般的直連 DNS 伺服器。
        public: 'udp://1.1.1.1:53' -> direct
    }
    routing {
        request {
            # 未比對到的查詢傳送到 `public`。
            fallback: public
        }
    }
}
```

## 完整設定

本例組合了訂閱、靜態後備節點、`subtag` 過濾、Geo 路由、經代理的 DoH、Clash API 與持久化狀態。

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    log_level: info
    log_file: 'honk.log'
    dial_mode: domain++
    auto_config_kernel_parameter: true
    data_dir: '/var/lib/honk'
    bootstrap_resolver: '1.1.1.1:53'
    store_subscribe: true
}

node {
    backup: 'socks5://192.0.2.2:1080'
}

subscription {
    paid: 'https://subscription.example/sub' {
        interval: 3600s
    }
}

assets {
    subscription {
        ua: 'clash.meta'
    }
    ui {
        url: 'https://example.com/dashboard.zip'
        route: proxy
    }
}

group {
    proxy {
        filter: subtag('paid') && !name(keyword: 'ExpireAt-')
        filter: name('backup')
        policy: fallback
        final: block
    }
}

routing {
    # 此規則也會繞過私網 DNS；需要保留接管時，明確加上 && !dport(53)。
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(geosite: geolocation-!cn) -> proxy
    fallback: proxy
}

dns {
    ipversion_prefer: 4
    # client_subnet: auto  # 選用：為具名上游推斷公網路徑上的一個 /24。
    upstream {
        direct_dns: 'udp://1.1.1.1:53' -> direct
        proxy_doh: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            qname(geosite: geolocation-cn) -> direct_dns
            fallback: proxy_doh
        }
        response {
            fallback: accept
        }
    }
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'ui'
        secret: 'replace-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

## 選擇介面

- `lan_interface` 設為接收 LAN 轉送流量的介面，多個介面用逗號分隔。
- `wan_interface` 設為承載本機發起流量的介面。`auto` 跟隨 IPv4 預設路由介面；沒有預設路由時會保持待定，不會退回 loopback 介面，等到連結、位址或路由變化時再重新協調。
- 只代理本機流量時省略 `lan_interface`：已設定的 WAN hook 仍會處理本機發起的 TCP 和 UDP。不要把 `lo` 當成 LAN 介面加進設定。

介面不存在、遭拒或掛接不上，都不會阻止啟動。遭拒的包括 `lo`、VRF 裝置和 `dae0`。見[介面語義](./reference/global.md#網卡語義)。

介面設定詳見 [Global 參考](./reference/global.md)。

## 選擇撥號模式

| 模式 | 適用場景 |
| --- | --- |
| `ip` | 只依 IP 中繼資料路由，不做網域嗅探。 |
| `domain` | 預設：嗅探網域並驗證目的 IP，只有驗證通過才重新執行路由。沒比對到就繼續套用一般 IP/連接埠規則。代理出站可以依驗證過的名稱撥號。 |
| `domain+` | 嗅探但不對目的 IP 做 reality check，保留初始路由，只把嗅探到的名稱當成代理目標。 |
| `domain++` | 嗅探但不驗證，並強制依 SNI/HTTP Host 重新執行非保留決策。 |

撥號模式詳見 [Global 參考](./reference/global.md)。

## 宣告節點

每個 `node` 行都是一條分享連結，寫成 `tag: 'scheme://...'`，或只寫帶引號的連結。明確的 tag 會成為路由和 API 中使用的名稱，並蓋過連結裡內嵌的名稱；沒有 tag 的連結使用 fragment 或產生的協定/主機名稱。憑證、TLS/REALITY、傳輸和協定調校都放在連結的 userinfo 與查詢參數裡。格式錯誤的連結會附上診斷後跳過。未知或已移除的協定、已移除的 VLESS `vless_mode` 參數，以及單獨的 `mux` 行，都是設定錯誤；`mux=` 要寫在每條 VLESS 連結上。

`direct` 和 `block` 保留給內建出站，不能當作節點名稱。群組名稱不能和節點名稱相同。

詳見 [節點參考](./reference/nodes.md)。

## 建置代理群組

依下列順序建置群組：

1. 選擇成員：靜態名稱使用 `filter: name(...)`，訂閱來源使用 `filter: subtag(...)`，巢狀群組使用 `filter: group(...)`。
2. `name(...)` 和 `subtag(...)` 謂詞用 `&&` 組合表示 AND，用 `!` 否定單一謂詞。`group(...)` 必須獨佔整個 `filter:` 值，與 `&&` 或 `!` 組合在一起的行會附上診斷後被忽略。多個 `filter:` 行之間是 OR。既沒有過濾條件也沒有巢狀群組時會包含全部節點；只有巢狀群組時不會自動包含全部節點。
3. 選擇策略：可用 `selector`/`fixed`、`urltest`/`min_moving_avg`、`loadbalance`/`roundrobin`、`fallback` 或 `score`。用 `final` 指定策略選不出成員時的結果。

群組宣告的區塊標頭，以及 `->`、`fallback:` 後面的群組名稱，即使含空格也不要加引號。這些位置的引號會成為名稱的一部分，所以 `fallback: 'proxy'` 找不到群組 `proxy`。`group(...)`、`final` 和 `default` 會去掉引號。子群組和節點選擇要放在不同的過濾行：

```dae
group {
    Hong Kong {
        filter: name(regex: '^edge\.example$')
    }
    proxy {
        filter: group('Hong Kong')
        filter: name('edge')
    }
}
routing {
    dport(443) -> Hong Kong
    fallback: Hong Kong
}
```

Selector 的 TCP 和 UDP 都跟隨已選成員，不會因為健康狀態切到兄弟成員。同一葉節點的 TCP 最後嘗試也繞不過巢狀 Selector 的選擇。群組撥號最終總是解析到一個葉節點。

每份設定最多可定義 250 個頂層使用者群組；更高的序號由路由 ABI 保留。

詳見 [群組參考](./reference/groups.md)。

## 撰寫路由規則

規則依 `priority` 升序執行，dae 解析器依原始碼順序分配 `0, 1, ...`，同優先順序的規則保持原始碼順序。目標可以是 `direct`、`block` 或群組；直接寫節點名稱會在載入時遭拒，要先把節點加進群組，例如 `filter: name('node')`。`(must)` 決策是最終結果：跳過嗅探，Clash Global/Direct 模式也蓋不過 `must` 或 `block`。GeoIP 用 `dip(geoip: private)`/`dip(geoip: cn)`，geosite 用 `domain(geosite: category)`。

閘道器管理存取和私網 DNS 繞過依[顯式本機路由遷移](./reference/routing.md#顯式本地路由)設定；honk 不會自動產生介面規則。

出站失效時通常按 fail-closed 處理：新流會被丟棄，不會漏到 `direct`。沒設定 `final`、只有一個唯一葉節點的 TCP 群組，只能在目前 Selector 成員路徑內對同一個代理做最後嘗試；UDP 群組和全部葉節點都失效的多葉節點群組仍然 fail-closed。公網 `fallback` 要指向這樣的群組：多成員、`policy: fallback`、帶明確 fail-closed 的 `final`；同時至少保留一個強制經 `direct` 的 DNS 上游。

詳見 [路由參考](./reference/routing.md)。

## DNS 設定

上游可以只寫 `host:port`，預設走 UDP，也可以用 `udp://`、`tcp://`、`tcp+udp://`/`udp+tcp://`、`tls://`、`https://`、`quic://`，以及 `h3://` 或其別名 `http3://`。加上 `-> node-or-group` 可以強制撥號路徑；只要所選葉節點具備對應 capability，上面這些 transport 都能走代理出站。DoQ 和 DoH3 要求葉節點提供支援 UDP 的 `PacketTransport`；缺少代理 registry 或 packet capability 時會 fail-closed。請求路由選擇 `reject`、`asis` 或某個具名上游；回應路由選擇 `accept`、`reject`，或用於有界重新查詢的具名上游：

```dae
dns {
    upstream {
        home: 'udp://223.5.5.5:53' -> direct
        lan_proxy: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> lan_proxy
            sip(127.0.0.0/8, ::1/128) && qname(suffix: example-isp.cn) -> asis
            fallback: home
        }
    }
}
```

`sip(...)` 只能用在 request 裡，把邏輯 DNS 用戶端 IP 與主機位址或 CIDR 比對。透明 53 連接埠和 `dns.bind` 查詢使用 socket peer；為已通過 admission 的 TCP/UDP 流做的 DNS 查詢使用該流的用戶端位址。內部、bootstrap、prefetch 和 Clash API 查詢沒有用戶端來源，所以 `sip(...)` 和 `!sip(...)` 都不會比對到，直接走 fallback。有來源的流查詢仍然沒有被攔截 DNS 伺服器的原始目的位址，所以選 `asis` 會 fail-closed。

`bind` 留空只會關閉獨立 listener，不會關閉透明 53 連接埠攔截；[流量規則所有權](./reference/routing.md#出站目標與-must)仍然適用。

獨立 listener 的每種寫法都要求明確的連接埠。只有裸 `IP:port` 走 UDP，此外也可以寫 `udp://host:port`、`tcp://host:port` 或 `tcp+udp://host:port`；host 為空表示繫結通配位址。除非有主機防火牆保護 LAN 側的暴露，否則只繫結 loopback。不寫 `ipversion_prefer` 時策略是 `both`；設為 `4`/`6` 會同時決定 DNS 結果和 bootstrap 解析出的上游撥號順序，首選位址族撥號失敗時會退回另一個位址族。

`client_subnet` 預設關閉。要確定性的 ECS，就寫固定 IPv4/CIDR；寫 `auto` 則不靠 DNS 或 HTTP，而是把公網路徑上的第一個公網 hop 推斷成 `/24`。自動推斷會在 reload 和網路變化時重新整理，有界探測失敗時不產生 ECS。用戶端自帶的 ECS 一律優先。啟用前先讀參考文件裡的隱私警告。

詳見 [DNS 參考](./reference/dns.md)。

## 訂閱

每個來源寫成 `tag: 'url'`，`subtag(...)` 會比對該標籤。要單獨覆蓋 `ua`、`interval`、`cache` 或 `route`，在帶引號的 URL 後接一個區塊。

- 共用預設值：`assets.subscription` 提供 `ua`、`interval` 和 `cache`；未單獨設定下載出口時使用 `assets.route`。
- 請求身分：請求預設使用 `honk/<version>`，條目或 `assets.subscription` 設定的 `ua` 會蓋過它。快取 key 包含設定中的覆蓋值，因此不同的請求身分會使用不同的已存內容。
- 持久化：`global.store_subscribe` 預設為 `true`。只有它和條目生效的 `cache` 都為 `true` 時，成功取得並解析的原始內容才會存入狀態資料庫。修改 `store_subscribe` 後要重新啟動。
- 啟動與 reload：啟動時先還原有效且非空的已存內容，再於背景重新整理。SIGHUP 沿用作用中的訂閱節點，不從儲存恢復。
- 失敗處理：取得或解析失敗，或沒有可用節點時，作用中的節點和上一次有效的內容都會保留。訂閱節點只存在於執行階段。

詳見 [訂閱參考](./reference/subscription.md)。

## 啟用 Clash API、快取檔與首包保留 UDP

要使用原生 API，編譯時要加上 `native-api`：用 `--features native-api` 或 `--features native-ui` 建置，full 和 `-native-api` 發行產物已經包含它。listener 需要 `experimental.native_api.enabled: true`，還要滿足下列三個條件之一：設定 bearer `secret`、設定 `password_auth: true`，或在 loopback `listen` 上設定 `allow_anonymous_loopback: true`。honk 不限制 `secret` 的最短長度，請用夠長的隨機值。預設監聽位址是 `127.0.0.1:9527`，匿名 loopback 存取只用於本機開發。生效的原生欄位都需要重新啟動。使用者空間觀測、事件和有界歷史獨立於 Clash；流量和記憶體歷史預設最多保留 600 點、600 秒。可選的 `ui` 目錄裡要已經有可讀的 `index.html`；也可以用 `--features native-ui` 配合 `ui: embedded`，內嵌固定版本的 doona。執行階段不會下載也不會建置 UI。`ui: embedded-lite` 會選擇更輕量的 doona lite 預覽版，同樣需要 `native-ui`。

啟動時已經擷取來源的 `.dae` 設定，其來源中繼資料、離線驗證和實際的 reload 操作都走現有的引擎。讀取設定時傳回已接受的內容，只遮蔽 listener secret 的值，重複的、被覆蓋的以及出現在其他位置的值同樣遮蔽。含憑證的原始檔仍然唯讀，hash 仍依原始位元組計算。來源的 `path` 保持相對路徑，`absolute_path` 另外給出正規化後的絕對路徑。通過 admission 的匿名 loopback 請求讀到和 bearer 驗證請求相同的資料。`config_write` 預設 false，需要非空 secret 或 `password_auth` 才能開啟。主檔案裡節點和 provider 的建立與刪除、已授權的整源 PUT，以及對受限群組的 PATCH，都沿用同一套寫入授權。啟用 `config_write` 後，所有已被接受且不含憑證的 include 都能編輯原始檔，但不能藉此刪除專用條目。設定的 geodata 更新會把驗證過的不可變位元組交給同一個 reload owner。啟用失敗後，已寫入的位元組不會自動回滾，所以要避免同時進行外部編輯。詳見[原生設定](./reference/experimental.md#native_api)與[主檔案條目與 geodata 契約](./reference/api.md#主檔案項目與-geodata-管理)。

使用 `--store db` 時，honk 執行資料庫中的目前修訂版；啟動時只在資料庫為空時匯入 `-c` 檔案，見[設定資料庫](./reference/api.md#設定資料庫--store-db)。

`experimental.clash_api.external_controller` 非空時，Clash API 伺服器就會啟用。沒有防火牆和非空 `secret` 保護時，應只繫結 loopback；secret 為空會關閉 API 驗證。`external_ui` 寫相對路徑時，先在 `data_dir` 下找既有的目錄，再找 `/var/share/honk`，最後找工作目錄；都沒有就在 `data_dir` 下下載 dashboard。ZIP 來源由 `assets.ui.url` 決定，下載出口由 `assets.ui.route` 決定，沒設定出口時沿用 `assets.route`。URL 和出口都沒設定時，分別使用內建 URL 和一般流量路由。`HONK_UI_DOWNLOAD_URL` 可以蓋過 ZIP URL。

預設情況下，Selector 選擇和延遲樣本會儲存在 `<data_dir>/state/honk.db`。設定 `experimental.cache_file.enabled: true` 後，如果原生 API 沒啟用，還會儲存 Clash 模式和 GLOBAL 選擇；原生 API 啟用時這兩項只是臨時狀態，不會持久化。再設定 `store_dns: true`，符合條件的 DNS 回應也會持久化；設成 `false` 則這些狀態都不儲存。`path`、`cache_id` 和 `store_fakeip` 已不起作用；首次啟動時 honk 會匯入並刪除舊的 `cache.db`，見[升級說明](./reference/experimental.md#從-cachedb-升級)。

`global.nfqueue_enable` 預設是 `true`，設成 `false` 會關閉有歧義的 LAN 轉送 UDP 的 NFQUEUE 暫存。修改這項設定要重新啟動。用 mock eBPF、建置裡沒有 `ebpf` feature，或固定佇列的前置檢查失敗時，honk 會記一條 warning，只在目前的行程關閉 NFQUEUE，不會改寫設定檔。真實執行個體取得鎖後，啟動會繫結佇列 `320`，並在發布 `inet honk_nfqueue` / `udp_decision` 之前回收殘留的自有 nftables table；honk 執行期間，防火牆管理器不能改這些保留物件。

詳見 [Global 參考](./reference/global.md)、[Experimental 參考](./reference/experimental.md)與 [UDP NFQUEUE 設計](./design/nfqueue.md)。

## 預熱與撥號預算

這些機制彼此獨立，都受已設定群組或明確預算限制，不會隨原始訂閱規模無限成長。隨選 Clash 延遲測試走另一條路徑：冷的 session/QUIC 節點只在臨時 runtime 裡預熱 transport，測量結束後關閉。

| 機制 | 設定項 | 預設 | 行為 |
| --- | --- | --- | --- |
| 裸 TCP 預先連線 | `preconnect_node_count` | `'auto'` | 啟動時執行一輪。`'auto'` 最多試 8 個合格節點，優先採用群組目前的選擇；`0` 關閉。明確的 `N` 可以覆蓋全部合格節點，最多同時 8 個。帶 session 的 AnyTLS/VLESS 模式、QUIC、`direct` 和 `block` 會跳過。 |
| Selector 常駐 | — | 一律啟用 | 讓每個 Selector 已設定的葉節點保持熱態，包括不健康但被明確選中的節點。協定允許時保留可重複使用的 session/client 或一條到伺服器端的裸 TCP；切換選擇和 reload 只轉移所有權，不會中斷作用中的流。 |
| UDP 預熱集合 | `udp_warm_node_count` | `0` | 每個群組每個 IP 族取前 `min(N,3)` 個 UDP 葉節點，最多同時嘗試 4 個，常駐節點不超過 `4×N`。UDP 和 Selector 的所有權互不影響。 |
| 並行撥號上限 | `max_concurrent_dials` | `64` | 依 generation 限制實體代理連線和握手。命中 Ready 池、已熱 transport 上的邏輯流、`direct` 和 `block` 不佔用額度；重疊的 reload generation 還會共用啟動時的描述符 gate。 |

週期性 HTTP 健康檢查和 Clash 延遲測試使用同一條臨時預熱路徑：冷但可重複使用的 transport 在計時之外預熱，結束後關閉。回報的延遲是預熱連線上第二個請求的耗時，也就是一次往返，不含撥號和 TLS 握手。只有預熱後的目標交換成功，才會回報健康並提供選擇 RTT；setup 或交換失敗都會更新活性和冷卻，但不會產生延遲樣本，也不計入排名 strike。掃描不會為每個節點保留一條閒置隧道。

詳見 [群組選擇設計](./design/groups.md)。

## 執行

```bash
# 使用內嵌目標檔案的真實 eBPF。
sudo ./target/release/honk-core --config /etc/honk/config.dae

# 使用外部目標檔案的真實 eBPF。
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# 使用 mock 後端進行非特權開發。
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

詳見 [CLI 參考](./reference/cli.md)。

## 驗證建議

1. 從儲存庫的 `config.min.dae` 或 `config.dae` 開始，換掉其中的介面、endpoint 和憑證。
2. 確認每條路由規則和 `fallback`、DNS `fallback`、群組 `final`，以及 `->` 後面的代理目標，都依情境指向既有的群組、節點、`direct` 或 `block`。
3. 對首次連線的網域規則使用 `dial_mode: domain`/`domain++`，或確保用戶端 DNS 經過 honk，填入網域路由 map。
4. 修改群組或策略後，SIGHUP 會重建 `GroupManager`；仍有效的 Selector 選擇會遷移到新的執行階段 generation。
5. 修改 `global.nfqueue_enable` 後要重新啟動；想啟用暫存，就先確認真實 eBPF 後端和啟動前置條件都滿足，並確認防火牆管理器不會改動 `inet honk_nfqueue` / `udp_decision`。
6. 增改設定 fixture 時，執行 `cargo test -p honk-config`，讓解析器範例保持有效。

## 相關文件

- [設計總覽](./design/overview.md)
- [Global 設定參考](./reference/global.md)
- [DNS 發行維運](./operations/dns-rollout.md)
