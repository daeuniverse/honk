# Experimental 設定參考

`experimental { ... }` 設定 Clash 相容 HTTP API、原生 API 和執行時狀態的持久化。它與 Clash/mihomo 的 `experimental` 設定段同名，但鍵不同。

## 範例

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: 'replace-me'
        default_mode: Rule
    }
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

```dae
assets {
    ui {
        url: 'https://example.com/dashboard.zip'
        route: proxy
    }
}
```

## 巢狀設定段

| 巢狀設定段 | 用途 |
| --- | --- |
| `clash_api` | Clash 相容 HTTP API 與外部面板。 |
| `cache_file` | 把執行時選擇、模式、延遲樣本和可選的 DNS 狀態存進狀態資料庫。 |
| `native_api` | 需明確啟用的觀測、有界診斷、執行時與來源控制，並託管本機 UI 目錄。 |
| `udp_nfqueue` | 已棄用，改用 `global.nfqueue_enable`。見 [`udp_nfqueue`](#udp_nfqueue)。 |

`native_api`、`clash_api` 和 `cache_file` 中仍有效的鍵都只在啟動時生效：改設定後要重新啟動，SIGHUP 會拒絕改動其中任一鍵的候選設定，目前 listener 和設定 generation 保持不變。`cache_file` 的舊版欄位除外，見[舊版欄位](#舊版欄位)。

### `udp_nfqueue`

`udp_nfqueue { enabled: ... }` 已棄用，改用 `global.nfqueue_enable`。dae 載入器和結構化設定載入器仍接受這一段，並輸出遷移 warning。只有沒設定全域鍵時，載入器才把這裡的 `enabled` 值當作 `global.nfqueue_enable`。`enabled` 取布林值，預設 `false`，所以空段 `udp_nfqueue {}` 會關掉 NFQUEUE；想保留預設開啟的全域設定，就把整段刪掉。

下例中全域鍵優先，NFQUEUE 保持關閉：

```dae
global {
    nfqueue_enable: false
}
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

## `native_api`

原生 API 需要明確啟用的 `native-api` Cargo feature。用 `--features native-api` 或 `--features native-ui` 建置，或直接用 full 釋出版本、名稱裡帶 `-native-api` 的釋出版本。它不依賴 `clash-api`。listener 預設關閉；沒編譯該 feature 卻在設定裡啟用時，啟動會報錯。

未知欄位、在純量欄位裡嵌區塊、無效布林值，以及白名單裡的空成員，都會報錯。

布林鍵寫 `true` 或 `false`；載入器也接受 `yes`/`no`、`1`/`0` 和 `on`/`off`，不區分大小寫。其他寫法會報 `invalid-config-value` 錯誤，例如 `t`。採用嚴格解析的設定清單見[設定方言參考](./dialect.md#純量與清單)。

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `enabled` | `false` | 啟動獨立的原生 listener。 |
| `listen` | `"127.0.0.1:9527"` | 數字 IP 加 1–65535 連接埠；不接受主機名稱，也不接受 `:port` 簡寫。 |
| `secret` | `""` | 獨立於 Clash 認證資訊的靜態 Bearer token。見 [`native_api.secret`](#native_apisecret)。 |
| `password_auth` | `false` | 用管理員密碼登入代替 token。見 [`native_api.password_auth`](#native_apipassword_auth)。 |
| `allow_anonymous_loopback` | `false` | loopback listener 上不帶認證資訊的請求。見 [`native_api.allow_anonymous_loopback`](#native_apiallow_anonymous_loopback)。 |
| `allow_origins` | `省略` | 額外放行給瀏覽器頁面的 HTTP(S) Origin。見 [`native_api.allow_origins`](#native_apiallow_origins)。 |
| `allowed_hosts` | `省略` | 額外放行的 HTTP Host 位址。見 [`native_api.allowed_hosts`](#native_apiallowed_hosts)。 |
| `ui` | `""` | 本機面板目錄或內嵌靜態資源。見 [`native_api.ui`](#native_apiui)。 |
| `record_flows` | `true` | 在流診斷需求或明確的執行時設定下，允許記錄有界的使用者態流。 |
| `record_traffic` | `true` | 即使沒有用戶端，也保留 600 秒內的 600 個流量取樣點。 |
| `record_memory` | `true` | 即使沒有用戶端，也保留 600 秒內的 600 個記憶體取樣點。 |
| `record_logs` | `true` | 在獲准的 `/logs` SSE 需求或明確的執行時設定下，允許保留 60 秒內的 512 條結構化日誌。 |
| `record_dns_log` | `true` | 在成功的 `/dns/log` GET 或明確的執行時設定下，允許記錄用戶端 DNS 歷史，最多 512 條、8 MiB。 |
| `config_write` | `false` | 允許整份來源替換並 reload 已接受的主檔案和 `include`。見 [`native_api.config_write`](#native_apiconfig_write)。 |

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        secret: 'operator-supplied-random-token'
        allow_anonymous_loopback: false
        ui: '/usr/share/doona'
    }
}
```

### `native_api.secret`

原生 listener 的靜態 Bearer token，獨立於 Clash 認證資訊。填非空值即選擇 token 模式，token 模式不能和 `password_auth` 同時使用。值必須是可見 ASCII，不能有空白或逗號，與 HTTP Bearer 解析器一致；出現不支援的位元組時，共用的設定 admission 會報錯，而不是啟動一個無法認證的 listener。

原生 API 回應會依值遮蔽本欄位和 `clash_api.secret`。短於 8 位元組的值不遮蔽，啟動時回報。

token 至少 16 位元組，並且不可預測。token 模式下，已啟用的 listener 不在 loopback 上（萬用字元繫結也算非 loopback）而 secret 短於 16 位元組時，honk 在啟動啟用時記一次 WARN，之後每次重新啟用已接受的設定再記一次。這條 WARN 只帶 `listen` 和 `secret_length` 兩個結構化欄位，不記錄 secret，也不拒絕設定。只監聽 loopback 位址或使用密碼模式時不會出現這條 WARN。它與上面短於 8 位元組就不遮蔽的 warning 是兩條獨立的 warning。

### `native_api.password_auth`

設為 `true` 時用管理員密碼登入代替 token，且只在 `secret` 為空時生效。不能和 `allow_anonymous_loopback` 同時使用。預設 `false`。

### `native_api.allow_anonymous_loopback`

設為 `true` 時允許不帶認證資訊的請求，但要同時滿足三個條件：`secret` 為空、`password_auth` 為 `false`、實際監聽 IP 是 loopback 位址。預設 `false`。

```dae
experimental {
    native_api {
        listen: '127.0.0.1:9527'
        allow_anonymous_loopback: true
    }
}
```

### `native_api.allow_origins`

額外放行的完整 HTTP(S) Origin，供瀏覽器頁面使用；不能含路徑、認證資訊、查詢字串、片段、`null` 或萬用字元。省略連接埠時，`http` 按 80 算，`https` 按 443 算。預設空清單。

```dae
experimental {
    native_api {
        allow_origins: 'http://localhost:3000', 'https://panel.example'
    }
}
```

### `native_api.allowed_hosts`

額外放行的 HTTP Host 位址和連接埠；不能含 URL 協定、路徑、認證資訊或萬用字元。省略連接埠時按 80 算，不是按監聽連接埠算。預設空清單。

```dae
experimental {
    native_api {
        allowed_hosts: 'panel.example', 'panel.example:443'
    }
}
```

### `native_api.ui`

`""` 關閉託管。其他值可以是本機目錄，要求目錄可信並含可讀的 `index.html`；也可以是啟用預設關閉的 `native-ui` feature 後的 `embedded` 或 `embedded-lite`。`embedded-lite` 是更輕量的 doona lite 預覽版。啟動階段不下載、不解壓縮，也不建置前端。

```dae
experimental {
    native_api {
        ui: '/usr/share/doona'
    }
}
```

### `native_api.config_write`

允許整份來源替換並 reload 已接受的主檔案和每個已接受的 `include`，也允許新建由 `include` 載入的 `.dae` 檔案。含 listener secret 的來源除外。本鍵要求 `secret` 非空或 `password_auth: true`。

### 認證模式

只能選擇一種認證模式：

- 靜態 token：設定非空 `secret`。
- 密碼登入：`secret` 留空，設定 `password_auth: true`；不能和 `allow_anonymous_loopback` 同時使用。
- 本機無認證開發：`secret` 留空，`password_auth` 保持 false，明確開啟匿名 loopback 存取，並繫結實際的 loopback 位址。

啟用的 listener 不符合任何一條時，設定驗證失敗；`config_write: true` 必須搭配 token 或密碼模式。

範例裡的 secret 要換掉。本機無認證開發時省略 `secret`，明確設定 `allow_anonymous_loopback: true`，並且不要透過反向代理把這種匿名 listener 暴露出去。在非 loopback 網路上用明文 HTTP 加 token 不是安全部署；TLS 應該終止在可信代理上。

### Host 與 Origin 檢查

Host 和 Origin 的檢查獨立於認證：

- 預設情況下，Host 必須對應具體的監聽位址和連接埠。loopback listener 還接受同一連接埠的 `localhost`、`127.0.0.1` 和 `[::1]`。
- 萬用字元繫結接受同一連接埠的任意 IP 字面量 Host 和 `localhost`，因為這些位址都指向接收請求的 listener 自己。DNS 名稱不行，仍要寫進白名單，因為網域名稱可能被重新繫結。
- 只有直接對應的明文 HTTP Origin 會自動放行。萬用字元繫結時，Origin 必須和請求自己的 Host 一致；同一連接埠其他位址上的頁面要寫進 `allow_origins`。
- TLS 反向代理如果保留 `Host: panel.example`，就要設定 `allowed_hosts: 'panel.example'` 和 `allow_origins: 'https://panel.example'`。如果保留 `Host: panel.example:443`，則改用 `allowed_hosts: 'panel.example', 'panel.example:443'`。

轉送的 header 不會帶來額外權限。

兩個清單裡的主機可以寫 IPv4 位址、帶方括號的 IPv6 位址（例如 `[::1]:9527`），或 ASCII DNS 名稱。名稱只能含字母、數字和中間的連字號，不能有底線、空標籤或結尾的點。明確連接埠的範圍是 1 到 65535。

清單用逗號分隔，例如 `allow_origins: 'http://localhost:3000', 'https://panel.example'`。每項可以單獨加引號，也可以不加。省略該項就是空清單。不要寫 JSON 方括號，也不要用一對引號把整個清單包起來。

### UI 目錄查詢

相對的 `ui` 路徑沿用現有的依賴搜尋順序：先在 `global.data_dir` 下找已存在的路徑，再找 `/var/share/honk` 下，最後找工作目錄。三處都沒有時，路徑定位到 `global.data_dir`，啟動時報錯。目錄本身和它的符號連結目標都由可信管理員負責。參見[原生 API 契約](./api.md#原生-api)。

### 內嵌 UI

單一檔案部署可以用 full 釋出產物，也可以執行 `HONK_DOONA_DIR=$(ci/fetch-doona.sh) cargo build -p honk-core --features native-ui` 自行建置，然後把 `ui` 設為 `embedded` 或 `embedded-lite`。`native-ui` 隱含 `native-api`，不需要 Clash。建置產物裡沒有 `native-ui` 卻啟用內嵌託管，啟動會失敗。靜態資源裡不注入認證資訊；用戶端透過公開 discovery 選擇靜態 token 輸入或密碼 setup/login。產物與原始碼的身分、對應原始碼的散布方式和管理契約見 [API 參考](./api.md#內嵌-doona-來源)。

### Geodata 來源

設定檔案裡的 geodata 來源由管理員決定，修改要重新啟動，來源寫入無法改變它。啟用狀態資料庫時，下載還可以用已認證的 URL 覆寫，或改用內建來源。honk 會拒絕 userinfo、fragment、redirect 和 content encoding。直連的網域名稱來源需要設定 `global.bootstrap_resolver`，不會退回系統 DNS。用 `assets.geodata.route` 或已儲存的路由，可以讓下載走路由規則，或改為經過某個代理群組；路由承載不了請求時不會退回直連。每次更新都用當時適用的設定來源、已儲存來源或內建來源。[主檔案項目與 geodata 契約](./api.md#主檔案項目與-geodata-管理)說明了網路期限、依已驗證位元組啟用和部分耐久替換，不承諾復原。

Geodata 的下載 URL 和出口由 [`assets.geodata`](./assets.md) 設定。載入器仍接受舊版 `native_api` 欄位，每個欄位產生一條 warning；哪個欄位替代哪個，見 Assets 參考中的表格。

### 共用取樣與可選歷史

流量歷史和記憶體歷史共用現成的一秒 sampler。歷史只放在記憶體裡，重新啟動即清空。錯過取樣點時留下缺口或 null，honk 既不補零，也不插值。記憶體讀數取自行程 RSS 和可用的 cgroup v2 資料，不採用核心記憶體核算。

`record_flows: false` 禁止記錄流，明確的執行時設定也不例外。`record_logs: false` 禁止擷取日誌，`record_dns_log: false` 禁止記錄 DNS 歷史。`record_traffic: false` 和 `record_memory: false` 關閉對應歷史，並在重新啟動後釋放緩衝。即時計數、runtime 讀數、出站讀數、記憶體讀數、主控台日誌和 Clash 日誌照常可用。

流、日誌和 DNS 日誌三種自動擷取各有獨立的 60 秒寬限期。普通 events 請求只開啟事件擷取。成功的流讀取或明確的流事件過濾器開啟流擷取；`/logs` SSE 開啟日誌擷取；成功的 `/dns/log` GET 開啟 DNS 日誌擷取。其他 API 請求、設定驗證、失敗的 GET 和 HEAD 都不會開啟診斷擷取；執行時的 On/Off 和設定禁止依[使用者態記錄流](./api.md#使用者態記錄流)的契約處理。

`PATCH /api/v1/runtime/settings` 可以臨時調整已支援的日誌、DNS 日誌和流的上限，以及原生日誌等級，但不能開啟已關閉的 recorder。合併後的完整設定在通過驗證後原子生效。已接受的明確啟用（哪怕只是 no-op）會恢復設定值；provider 重新整理或網路重新整理則保留臨時值。啟用恢復語意見 [原生日誌與執行時設定](./api.md#原生日誌與執行時設定)。

### 設定管理的信任邊界

只有在啟動時真正載入 `.dae` 檔案，才能擷取設定來源。在程式碼裡建構的設定和 serde 載入都沒有這種來源快照。

- 讀取操作傳回已接受的內容，只遮蔽宣告過的 listener secret 值。重複宣告的、已被覆寫的，以及同一值在別處出現的，也一併遮蔽。透過檢查的匿名 loopback 請求和 Bearer 認證請求讀到的是同一份資料。
- 含認證資訊的來源檔案保持唯讀，hash 仍依原始位元組計算。
- 來源的 `path` 是相對入口目錄的名稱，`absolute_path` 給出正規化後的絕對路徑。
- 如果主檔案要透過 API 編輯，先在本機把認證資訊移進一個專用的唯讀 `include`，然後重新啟動。API 無法修改或遷移 API 認證資訊和原生設定，這些只能由管理員在本機改完重新啟動。

啟用 `config_write` 後，所有已接受的非認證資訊 `include` 都可寫；普通 `include` 的 glob、排序和無符合語意都不變。已接受的來源和依賴共用同一個 admission 額度：32 個來源、8 MiB；同一個依賴被引用多次時，每次引用都各佔一份。HTTP JSON 內容仍最多 64 KiB。

能不能讀內容和能不能寫入是兩件事。含認證資訊的來源可以讀，但內容被遮蔽，遮蔽後的內容不能回寫。Selector 寫入、受限群組 PATCH，以及主檔案的建立和刪除，都走同一套來源寫入權限。自動策略裡的固定成員只在執行時生效，不寫回來源。

來源 PUT 的 `If-Match` 依磁碟位元組的 SHA-256 求值，遵循 RFC 9110：strong tag、清單或多個 field line、`*` 都能比對，weak tag 永不比對。寫完後還要執行真正的 reload 操作。寫入成功不代表啟用成功；不與其他編輯者協調的外部編輯器仍可能搶在最後一次檢查和改名之間寫入。受限群組 PATCH 重用同一套來源交易，但要求已接受的群組 ETag 或設定 ETag，並在寫入前和啟用前各檢查一次；來源和依賴分別檢查，這個 revision 不是磁碟 hash。具體怎麼從失敗中恢復，見 [API 契約](./api.md#主檔案項目與-geodata-管理)。

### 探測目標

探測目標只來自已接受的設定。honk 仍會解析位址、把 IPv4-mapped IPv6 正規化為 IPv4，並固定選中的 IP。呼叫端不能提供 URL，探測也不跟隨重新導向。探測、geodata 和共享下載都使用設定裡的目標，沒有位址或連接埠白名單：誰能寫設定、誰能控制訂閱內容，誰就決定這些目標；provider 內容按可信設定處理。

`probe_allowed_cidrs` 和 `probe_allowed_ports` 已移除。兩個 key 仍能出現在 dae 設定和相容的結構化載入器裡，每個 key 產生一條 warning。honk 忽略它們的值，可以直接刪掉；序列化設定時也不會輸出這兩個 key。

## `clash_api`

`clash_api` 需要預設啟用的 `clash-api` Cargo feature。沒編譯該 feature 時，`external_controller` 會被忽略。

`--store db` 模式不執行 Clash API。該模式下 `external_controller` 非空會導致啟動被拒，詳見[設定資料庫](./api.md#設定資料庫--store-db)。

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `external_controller` | `""` | 監聽位址，由 IP 和連接埠組成；空值關閉 API 服務。見 [`clash_api.external_controller`](#clash_apiexternal_controller)。 |
| `external_ui` | `""` | 外部面板目錄；空值關閉面板服務和下載。見 [`clash_api.external_ui`](#clash_apiexternal_ui)。 |
| `secret` | `""` | API 認證 token；空值關閉認證。見 [`clash_api.secret`](#clash_apisecret)。 |
| `default_mode` | `"Rule"` | 原生 API 未啟用時的啟動模式。見 [`clash_api.default_mode`](#clash_apidefault_mode)。 |

### `clash_api.external_controller`

監聽位址，由 IP 和連接埠組成，例如 `127.0.0.1:9090` 或 `[::1]:9090`；`:9090` 等於 `0.0.0.0:9090`。不接受主機名稱。空值關閉 API 服務。位址無效時記一條 warning，引擎照常啟動，只是沒有這個 listener。

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
    }
}
```

### `clash_api.secret`

API 認證 token；空值關閉認證。短於 8 位元組的值不會在原生 API 回應裡遮蔽。

```dae
experimental {
    clash_api {
        secret: 'replace-me'
    }
}
```

### 認證與傳輸

`secret` 非空時，API 請求要帶 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。靜態 `/ui` 內容不經過這層認證中介軟體。

內建 listener 只提供明文 HTTP，沒有 TLS。它應該繫結到 `127.0.0.1` 這類 loopback 位址，或者前面放一個帶認證的 TLS 反向代理；不要直接暴露到不可信的網路。endpoint 清單見 [Clash API 參考](./api.md)。

明確啟用的非 loopback 繫結如果 `secret` 為空，honk 會在 `experimental.clash_api.external_controller` 上回報 `unsafe-api-bind`，結構化輸入也一樣。診斷裡不含 endpoint 或 secret。範例設定用的是 loopback 位址，所以不會產生這條 warning。這條 warning 不改變繫結、認證或 CORS 規則。

### `clash_api.external_ui`

`external_ui` 寫絕對路徑就依原值使用。寫相對路徑時，honk 依序在 `global.data_dir` 下、`/var/share/honk` 下和目前工作目錄裡找第一個已存在的路徑，檔案或目錄都算；先找到的是檔案也直接使用。三處都沒有時，honk 在 `global.data_dir` 下建立目標目錄。

面板的下載 URL 和出口見 [`assets.ui`](./assets.md)。目標目錄不存在或為空時，honk 在背景下載 dashboard ZIP。`assets.ui.url` 非空會替換內建的 zashboard URL；`HONK_UI_DOWNLOAD_URL` 比兩者優先順序都高。

`assets.ui.route` 優先於 `assets.route`，初始請求和每次重新導向都依這個優先順序。出口寫 `direct` 就直接下載；路由規則選中 `block` 時中止下載；寫群組名稱時，每次請求都解析出該群組最終選用的葉節點。沒設定出口時，每個 URL 都走普通流量路由。標籤不可用、下載失敗或解壓縮失敗只記日誌，不會停掉引擎。

壓縮檔寫入一個位於目標目錄、沒有檔名的私有檔案，不放在記憶體中；解壓縮完成或下載失敗後，honk 刪掉這個壓縮檔。項目超過 10,000 個或內容超過 128 MiB 時，honk 拒絕繼續解壓縮並清空已寫出的目錄；該上限與壓縮檔本身相同。下次啟動會重新下載。

下載最多跟隨五次重新導向。每次 HTTP 交換逾時 30 秒；經代理時，計時從隧道撥號完成後開始。所有 ZIP 項目都在同一個頂層目錄下時，解壓縮會去掉這一層，`dist/index.html` 變成 `index.html`。路徑裡含空分量、`.`、`..` 或反斜線的項目，honk 會跳過。

### `clash_api.default_mode`

原生 API 沒啟用時，`default_mode` 接受 `Rule`、`Global` 和 `Direct`，不區分大小寫。`cache_file.enabled: true` 且快取裡有有效的 Clash 模式時，以快取為準；快取值或設定值無效時退回 `Rule`。

啟用原生 API 後，兩個 API 共用同一個臨時模式 owner，既不恢復也不持久化模式，啟動時用 `Rule`。已接受的明確啟用（哪怕只是 no-op）都會在後端重置成功後恢復 `Rule`；provider 重新整理或網路重新整理則保留目前模式。如果提交後重置失敗，honk 保留原模式、關閉 admission，並傳回 `CommittedDegraded`。`Global` 模式繫結穩定的節點或群組身分；重新整理把目標移除後，honk 會拒絕新的流量。見[執行時模式](./api.md#連線關閉模式與資料面生命週期)。

## `cache_file`

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `enabled` | `省略` | 把執行時狀態存進狀態資料庫 `<data_dir>/state/honk.db`。見 [`cache_file.enabled`](#cache_fileenabled)。 |
| `store_dns` | `false` | `enabled: true` 時，同時持久化和恢復 DNS 快取應答。見 [`cache_file.store_dns`](#cache_filestore_dns)。 |

### `cache_file.enabled`

`enabled` 決定狀態資料庫儲存哪些執行時快取表。省略時儲存 Selector 選擇和延遲樣本；`true` 還會儲存 Clash 模式和 GLOBAL 選擇，並允許 `store_dns`；`false` 什麼都不存。

升級提示：想儲存 Clash 模式和 GLOBAL 選擇，要把 `enabled` 明確設為 `true`；DNS 應答還要另外開啟 `store_dns: true`。明確寫 `false` 會關掉這些執行時快取儲存，但設定、認證資訊和訂閱各自的儲存不受影響。

```dae
experimental {
    cache_file {
        enabled: true
    }
}
```

### `cache_file.store_dns`

`enabled: true` 時，同時持久化和恢復 DNS 快取應答。預設 `false`。

```dae
experimental {
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

### 舊版欄位

`path`、`cache_id` 和 `store_fakeip` 已不再是設定項。它們仍能解析，但只產生 `legacy-cache-file` warning，不起作用；SIGHUP 也不會因修改它們而拒絕。`path` 和 `cache_id` 只在匯入舊 `cache.db` 時讀取一次，見[從 `cache.db` 升級](#從-cachedb-升級)。

`path` 省略或為空時指 `cache.db`；`cache_id` 省略時為 `""`，也就是 key 不帶字首。

### 持久化的狀態

只要 `enabled` 不是 `false`，honk 就在狀態資料庫裡儲存 TCP 和 UDP 各自的 Selector 選擇，以及每個節點最後一次真實延遲樣本，行為與 mihomo 的 `store-selected` 一致。只有在 `enabled: true` 且原生 API 未啟用時，honk 才恢復並儲存 Clash 模式和 Clash GLOBAL 選擇。原生 API 沒啟用、快取模式也沒恢復時，重新啟動後用 `default_mode`；啟用原生 API 後，啟動始終用 `Rule`。延遲樣本每分鐘批次寫入一次；恢復時丟掉為零的和超過 24 小時的樣本。存活狀態不恢復。

沒設定 `--store db`，也沒啟用 `native_api.password_auth` 時，資料庫故障依下面的方式處理：

- 資料庫損毀：honk 取得實例鎖後，把 `honk.db` 和 `honk.db-wal` 改名成 `honk.db.corrupt` 和 `honk.db.corrupt-wal`，再建一個新檔案。
- 已有 `honk.db.corrupt`：honk 保留這兩份檔案，在刪掉其中一份之前不做持久化。
- 資料庫不可用、不安全，或被重置操作鎖住：honk 記一條 warning，然後在不做持久化的情況下執行。不安全是指資料庫不是 honk 使用者所有的私有檔案；重置鎖由 `honk-core admin reset` 持有。

路徑不安全時，`persistence_unavailable` 降級除了 `reason`，還會帶一個 `rule`，取值是 `not_owner`、`group_or_other_bits`、`not_directory`、`not_file`、`symlink` 或 `identity_changed`。日誌裡給出路徑和修復方法。

如果資料庫來自更新版本的 honk 或其他程式，honk 在任何模式下都拒絕啟動。因為移走該檔案會破壞只有原程式才能解讀的資料。

### 容量限制

維護工作每 60 秒執行一次。Selector 選擇只為設定裡的 Selector 群組保留，延遲樣本只為已設定的節點保留。一個群組或節點要連續兩次維護都不在設定裡，對應的列才會刪除；所以 reload 時短暫移除、後來又恢復的群組或節點，原記錄還在。每次維護都會刪掉超過 24 小時的延遲樣本和已過期的 DNS 列，並把最多 1 MiB 的閒置頁還給檔案系統。DNS 列最多保留 4,096 列，每批寫入後先淘汰最早過期的列。

啟動時，如果 `--store db`、`password_auth`、`store_subscribe` 或 `cache_file` 要求開啟狀態資料庫，下面的設定會清空已存的快取狀態：

| 啟動設定 | 清空的表 |
| --- | --- |
| `enabled: false` | Selector、延遲、Clash 狀態與 DNS |
| 未設定 `enabled` | Clash 狀態與 DNS |
| `store_dns: false` | DNS |
| 啟用原生 API 或未啟用 Clash API | Clash 狀態 |

啟動時沒開啟狀態資料庫，honk 就不會動這個檔案。

狀態資料庫檔案上限是 112 MiB。快取寫入為設定 revision 和訂閱內容預留其中 24 MiB：某批寫入如果會讓已用空間超過 88 MiB，寫入執行緒先把 DNS 列刪到 2,048 列；仍然超出時復原這批寫入。跳過的 DNS 項目計入 `budget_skipped`，不算已寫入。匯入舊 `cache.db` 受同一預算約束：超出預算的複製不提交，下次啟動再試。

### DNS 持久化

`store_dns: true` 時，每條應答是 `dns_answer` 表裡的一列，內容是 `HDNS` version 2 編碼，以精確快取 key 的摘要作 primary key。恢復時只接受同時滿足這些條件的列：沒過期，且 key 摘要、正規化 query wire、response wire 身分和目前的 DNS policy 全部符合。精確 key 裡同時有入口 profile、request scope 和 operation，所以不會在不同 DNS 情境之間混用。編碼後超過 4 KiB 的項目不寫入，並計入 `oversize`。

### 從 `cache.db` 升級

在有狀態資料庫，且 `enabled` 不是 `false` 時，首次啟動會匯入 `path` 指向的舊 `cache.db`。絕對路徑依原樣使用；相對路徑依序在 `global.data_dir` 下、`/var/share/honk` 下，以及原設定目錄的相對位置找已存在的檔案。

honk 只讀本實例 `cache_id` 字首下的 key，複製設定裡 Selector 群組在各網路上的選擇，以及已設定節點 24 小時內的延遲樣本。Clash 模式和 Clash GLOBAL 選擇只在同時滿足三個條件時複製：`enabled: true`、原生 API 未啟用、`clash-api` 建置裡設定了 `external_controller`。狀態資料庫裡已有的列優先。舊版本依名稱儲存的 Selector 選擇、DNS 應答和 FakeIP 記錄不匯入，所以已持久化的 DNS 應答需要重新查詢。

honk 依檔案和 `cache_id` 在狀態資料庫裡記錄匯入進度；舊版本即使重新建了該檔案，也不會再匯入一次。其他 `cache_id` 仍能從保留下來的檔案裡匯入各自的 key。如果 `cache.db` 是符號連結、不是 honk 使用者所有的一般檔案、能被其他使用者寫入，或者無法當作 `cache.db` 讀取，honk 會保留該檔案並記一條 warning，下次啟動再試。

資料庫模式下，上述回退使用目前 revision 儲存的原始入口目錄；即使本次 `-c` 指向其他位置、啟動時不讀取它，也不會改變舊快取的位置。

`cache_id` 為空時，honk 隨後刪掉 `cache.db` 及其 `-wal`、`-shm`，但保留 `cache.db.corrupt-*` 副本。`cache_id` 非空時，這個檔案可能被其他實例共用，honk 會保留它，只記一條 warning。之後舊版本再啟動時找不到 `cache.db`，執行時狀態從空開始。

## 相關文件

- [Clash API 參考](./api.md)
- [NFQUEUE 設計](../design/nfqueue.md)
- [全域設定參考](./global.md)
