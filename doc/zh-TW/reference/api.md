# 原生 API、Clash API 與 `/stats` 參考

原生 API 和已實作的 Clash 相容 HTTP 介面共用同一個引擎 handle 與使用者態統計，但兩者的 Cargo feature、listener、憑證和 HTTP 邊界各自獨立。Clash 相容介面從[啟用與認證](#啟用與認證)開始，路由見 [endpoint 表](#endpoint-表)。

## 原生 API

原生 API 不是預設功能，建置時要明確啟用 `native-api` feature：加上 `--features native-api`，或改用 `native-ui`。不需要 Clash API 時，用 `--no-default-features --features native-api` 單獨建置。發行產物依包含的介面區分：

| 發行產物 | 原生 API | 內嵌 UI | Clash API |
| --- | --- | --- | --- |
| Full | 有 | 有（`native-ui`） | 有 |
| `-native-api` | 有 | 無 | 無 |
| `-clash-api` | 無 | 無 | 有 |

listener 預設關閉，需要在設定裡明確啟用 [`experimental.native_api`](./experimental.md#native_api)。設定格式仍是 `.dae`。取得寫入授權後，原生 API 可以讀取並替換 `-c` 指定的已接受原始檔；也可以加上 `--store db`，把修訂記錄存進 SQLite 設定資料庫，見[設定資料庫](#設定資料庫--store-db)。

原生契約來自 [api-standardize e6b0dbab5599689d965bc18a71be67c809d99d0f](https://github.com/daeuniverse/api-standardize/tree/e6b0dbab5599689d965bc18a71be67c809d99d0f)，涵蓋認證、節點與 provider 管理、geodata 與自動策略覆寫，另有 `read_only_reason`、geodata cron 排程等本地擴充功能。本地測試使用的契約定義在 `crates/honk-core/tests/fixtures/native_api_openapi.yaml`。原生執行模式尚未開放，honk 不宣告 `full_transparency`。

來源管理要求 honk 從真實的 `.dae` 檔案啟動。若要寫入，還需要啟用 `config_write`，並設定非空 `secret` 或 `password_auth`。某項功能是否可用，要看 capability 宣告與每個來源的權限，不要依路由名稱推斷。

| 方法 | 路徑 | 說明 |
| --- | --- | --- |
| GET | `/api` | 公開發現介面。所有請求都能取得認證狀態與登入連結；已放行的請求還會取得固定的 `/api/v1` base 和全部契約連結。 |
| POST | `/api/v1/auth/setup` | 建立第一個密碼模式管理員，並簽發 session。 |
| POST | `/api/v1/auth/login` | 驗證密碼模式管理員，並簽發 session。 |
| POST | `/api/v1/auth/logout` | 撤銷已通過認證的密碼模式 session。 |
| GET | `/api/v1/version` | 回傳原生契約身分、引擎建置版本、建置提交與目標平台；`built_at` 一律為 `null`。 |
| GET | `/api/v1/capabilities` | 回傳已實作的資源與請求上限。 |
| GET | `/api/v1/runtime?detail=summary\|full` | 回傳引擎階段、已接受的 generation，以及帶獨立時間戳記的使用者態流量。 |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | 列出可見的使用中使用者態連線。可選的 `src` 必須是不帶連接埠的 IP literal。 |
| DELETE | `/api/v1/connections/{connection_id}`、`/api/v1/connections` | 確認精確的傳輸 owner 已關閉。批次關閉要帶過濾器，或明確指定 `all=true`。 |
| GET | `/api/v1/flows`、`/api/v1/flows/{flow_id}` | 列出使用中與保留的終態使用者態決策。詳情會帶追蹤，證據按來源記錄。 |
| GET | `/api/v1/nodes` | 回傳穩定的節點 ID、目前的直接成員或來源，以及符合資格要求的測量。 |
| POST | `/api/v1/nodes` | 用 `{name,link}` 在主檔案中建立節點；實際啟用後才回傳 201。 |
| GET | `/api/v1/nodes/{id}` | 回傳單一節點，欄位與清單相同；未知 ID 回傳 404。 |
| DELETE | `/api/v1/nodes/{id}` | 刪除主檔案中的 inline 節點；啟用後回傳 `{deleted:0\|1}`。 |
| GET | `/api/v1/groups`、`/api/v1/groups/{groupId}` | 唯讀的代理群組觀測，含直接成員、設定修訂與擷取的健康資料；清單依設定中的宣告順序排列。 |
| GET | `/api/v1/groups/{groupId}/config` | 回傳群組的 `policy` 與 `config`，並以設定修訂作為 `ETag`。 |
| PUT | `/api/v1/groups/{groupId}/selection` | 依直接成員 ID 設定 `tcp`、`udp` 或 `both` 的選擇。寫入 Selector 會替換它的選擇；寫入自動代理群組會固定成員。 |
| DELETE | `/api/v1/groups/{groupId}/selection` | 清除自動代理群組在 `tcp`、`udp` 或 `both` 上的固定成員。 |
| PATCH | `/api/v1/groups/{groupId}/config` | 對可寫的 `.dae` 來源套用受限的 JSON Patch，並回傳實際執行的更新操作。 |
| GET | `/api/v1/events` | 有界、需認證的 SSE。續傳游標會繫結過濾器。 |
| GET | `/api/v1/runtime/outbounds` | 依 `kind/name` 區分出站計數，生命週期與共用計數器一致。 |
| GET | `/api/v1/runtime/memory` | 回傳實際行程 RSS，以及可讀的 cgroup v2 記憶體資料。 |
| GET | `/api/v1/runtime/traffic/history`、`/api/v1/runtime/memory/history` | 可選 `window_seconds`、`max_points`，預設 600，範圍 1–600。 |
| GET / PUT | `/api/v1/x-honk/runtime/mode` | 失敗回應的契約尚未完整固定，因此一律回傳 `404 capability_not_supported`。 |
| GET / PATCH | `/api/v1/runtime/settings` | 原子讀取或合併受支援的日誌、DNS 日誌與 flow 留存設定。 |
| GET | `/api/v1/datapath?detail=summary\|full` | 有界的後端觀測，預設 `summary`。 |
| POST | `/api/v1/probes` | 對節點或群組做有界的 TCP、HTTP、DNS 測量。 |
| POST | `/api/v1/dns/query` | 明確的 DNS 診斷。 |
| GET | `/api/v1/dns/cache`、`/api/v1/dns/log` | 精確快取快照與用戶端查詢歷史。 |
| DELETE | `/api/v1/dns/cache/{entry_id}`、`/api/v1/dns/cache` | 刪除單一精確的快取 incarnation，或依完整名稱與可選 type 刪除。 |
| POST | `/api/v1/dns/cache/flush` | 等待記憶體快取與已啟用的持久化快取確認失效；不清空網域名稱路由事實。 |
| POST | `/api/v1/routing/trace` | 固定目前 generation 的離線路由模擬，只支援 `resolve=none`。 |
| GET | `/api/v1/rules` | 回傳目前 generation 的完整規則字典、fallback 與可用的來源位置。 |
| GET | `/api/v1/dns/rules` | 回傳目前 generation 的 DNS 請求規則與回應規則，每個清單以 fallback 結尾。 |
| GET | `/api/v1/providers`、`/api/v1/providers/{id}` | 回傳實際訂閱 owner 的狀態；讀取時不抓取。 |
| POST | `/api/v1/providers/{id}/refresh` | 明確重新整理訂閱，並等待實際的執行時發布操作。 |
| POST | `/api/v1/providers` | 用 `{name,kind:"subscription",url}` 建立尚未抓取的主檔案訂閱，可選 `update_interval`、`user_agent`、`cache`。 |
| DELETE | `/api/v1/providers/{id}` | 刪除主檔案的 HTTP(S) 訂閱及其已載入的節點。 |
| GET | `/api/v1/geodata` | 讀取流量與 DNS 路由實際載入的資產所保留的中繼資料。 |
| POST | `/api/v1/geodata/update` | 下載設定資產，完整驗證後透過操作啟用精確的候選位元組。 |
| GET | `/api/v1/logs` | 經過安全投影的結構化原生日誌 SSE，獨立於 Clash 的格式化日誌。 |
| GET | `/api/v1/config` | 認證後回傳已接受的來源快照、設定修訂與安全診斷；只遮蔽 listener secret 值。 |
| GET | `/api/v1/config/sources/{source_id}` | 認證後回傳單一已接受來源的中繼資料與內容；只遮蔽 listener secret 值。 |
| POST | `/api/v1/config/validate` | `syntax` 或離線 `full` 驗證；不寫入磁碟，也不 reload。 |
| PUT | `/api/v1/config/sources/{source_id}` | 在 RFC 9110 `If-Match` 保護下替換單一來源的原文。寫入磁碟後排入實際 reload，並回傳對應操作。 |
| POST | `/api/v1/config/sources` | 新建一個由 include 模式載入的 `.dae` 檔案。寫入磁碟後排入實際 reload，並回傳對應操作。 |
| POST | `/api/v1/operations/reload` | 從磁碟 reload，回傳常駐程式持有的操作。內容留空或為 `{}`。 |
| POST | `/api/v1/operations/suspend`、`/api/v1/operations/resume` | 已註冊但不可用，回傳 `404 capability_not_supported`。 |
| GET | `/api/v1/operations/{id}` | 查詢操作的排隊、執行與終態結果。 |

### 連線觀測

使用 Bearer 認證的請求與已放行的匿名 loopback 請求會讀到同一份連線資料。回傳的顯示欄位會遮蔽 listener secret 值。

| 參數 | 預設值 | 取值 |
| --- | --- | --- |
| `detail` | `summary` | `summary` 省略 `src`、`dst`、`domain`；`full` 會帶上這些欄位。未知網域名稱為 null。 |
| `type` | `all` | `all`、`tcp`、`udp` |
| `limit` | 100 | 1–1000，TCP 與 UDP 共用此上限 |

回傳完整詳情不代表權限更高。API 會拒絕未知參數與重複的單值參數。

`GET /connections?detail=full` 回傳以下結構：

```json
{"observed_at":"2026-11-13T00:00:00Z","instance_id":"instance","visibility":"partial","truncated":false,"tcp":[{"id":"connection-id","flow_id":null,"pname":null,"state":"active","src":"192.0.2.1:50000","dst":"198.51.100.1:443","domain":null,"outbound":"proxy","chain":[],"chain_source":"unknown","rule_id":null,"rule_expression":null,"rule_source":"unknown","ingress":null,"domain_source":null,"started_at":null,"observed_by":"userspace","upload_bytes":"128","download_bytes":"256","upload_bytes_per_second":null,"download_bytes_per_second":null}],"udp":[],"total_tcp":1,"total_udp":0}
```

`total_tcp` 與 `total_udp` 是套用上限之前的匹配數。`src`、`dst`、`domain` 只在 `detail=full` 時出現。位元組計數以十進位字串表示。

過濾發生在總量統計與合計上限檢查之前，總量包含所有匹配的可見記錄。記錄依註冊的觀測時間由新到舊排列；時間相同時，依 ID 字典序由低到高排列。

IPv4 對映的 IPv6 來源依 IPv4 位址比較。

連線中的 `outbound` 是選路當時的群組或動作，既不是目前的葉節點，也不是依現狀重建的選擇。開啟記錄後，`flow_id`、擷取的 root-first 群組與葉 ID、首次觀測的 UTC 時間、網域名稱來源與使用者態 rule ID 都會關聯到保留的證據。缺少證據或證據已被淘汰時保持 unknown。

逐連線速率仍為 null。清單為空只表示 `visibility: partial`，不能據此斷定裝置上沒有連線。Mock 資料面顯示 `disabled` 與 `none`。

真實後端只依實際程式、hook、路由 root、listener 與 admission 的觀測報告狀態。未知項為 unknown 或 null，涵蓋範圍仍是 partial。HTTP 已就緒並不代表資料面已就緒。

TCP 在 copy 讀取成功或 splice 寫入目標 socket 成功時立即計數，成功寫出的嗅探字首只計一次。UDP 仍依逐封包語意計數。行程內只有一個一秒取樣器，以它實際經過的時間間隔計算。

初次取樣、重設與 overflow 時，速率回傳 null，不補零。`counter_since` 屬於共用計數器的生命週期，`sampled_at` 屬於流量樣本，`observed_at` 屬於本次 HTTP 觀察。UInt64 以十進位字串表示，有界的數量仍是 JSON number。

`process.cpu_percent` 在取得兩次可用 CPU 樣本之前為 null，見[出站、記憶體與歷史](#出站記憶體與歷史)。`generation.activated_at` 是目前 generation 的發布時間；啟動時的 generation 取引擎首次進入執行狀態的時間。設定啟用期間，`generation.state` 為 `reloading`；引擎執行且健康時，`lifecycle.state` 也回報 `reloading`。

有來源管理器時，回應會帶設定修訂。`last_reload` 是最近完成的 API reload 操作結果，沒有時為 null。

`GET /runtime` 接受 `detail=summary`（預設）或 `full`。回應包含 `observed_at`、`instance_id`、`lifecycle`、`generation`、`datapath`、`traffic`、`process`、`last_reload` 與 `degradations`：

| 欄位 | 內容 |
| --- | --- |
| `lifecycle` | `state`、UTC `started_at`，以及十進位字串 `uptime_seconds`。`state` 為 `starting`、`running`、`reloading`、`degraded`、`draining` 或 `failed`。 |
| `generation` | `active_id`、可空的 `config_revision`、`state`（`active` 或 `reloading`）與可空的 `activated_at` |
| `datapath` | `kind`、`state`、`visibility` 與 `ebpf`，摘要同 [`GET /datapath`](#連線關閉模式與資料面生命週期) |
| `traffic` | `scope: "visible"`、`observed_by: "userspace"`、`counter_since`、`sampled_at`、`connections`（`tcp`、`udp`、`total`）、`bytes`（`upload`、`download`）與 `rates`（`null`，或含 `window_seconds`、`upload_bytes_per_second`、`download_bytes_per_second`）。首次取樣前，`sampled_at`、計數、位元組與 `rates` 均為 `null`。 |
| `process` | `cpu_percent`；只有 `detail=full` 額外包含 `pid` |

### 執行時降級

`degradations` 列出功能受損的元件。原因有兩種：故障恢復後仍處於降級狀態，或已設定的介面還沒完全繫結。每個元件最多一項。

| 欄位 | 說明 |
| --- | --- |
| `code`、`message`、`details.reason` | 安全的錯誤資訊 |
| `component` | 受影響的元件 |
| `since` | 首次降級時間；重複故障不更新 |

空清單表示沒有已知的降級項目。項目不會改變 `lifecycle.state`：已設定介面還沒繫結時，該狀態仍是 `running`。要監控這類問題，請檢查 `interface_binding`。

項目新增、變化或清除時發布 `runtime.updated`。

| 元件 | 條件 | 重新判定或恢復時機 |
| --- | --- | --- |
| `persistence` | 啟動時無法開啟或重設狀態資料庫。 | 重啟 |
| `state_cache` | 無法開啟狀態資料庫的快取表。 | 重啟 |
| `quic_probe` | Score 群組需要 QUIC 探測，但啟動時的目標或用戶端不可用，詳見下文。 | 已套用的設定不再含 Score 群組，或重啟後目標解析成功時清除。 |
| `pname_routing` | 規則使用 `pname()`，但缺少 cgroup v2 hook 或只能取得執行緒名稱。 | 每次套用設定 |
| `iface_watch` | 真實後端無法訂閱 rtnetlink 事件或註冊輪詢。 | 重啟 |
| `interface_binding` | 某個已設定的 `lan_interface` 或 `wan_interface` 項目尚未完全繫結。 | 所有項目繫結後自動清除。 |
| `udp_trace` | 記錄 flow 時，核心 UDP 接收追蹤不可用。 | 每次啟動 UDP listener |

`quic_probe` 的目標或用戶端故障包括：

- 第一個 `tcp_check_url` 不是 HTTPS URL。
- 目標主機無法解析。
- 無法建立 QUIC 用戶端。

探測目標在啟動時確定。原因 `restart_required` 表示行程啟動時還沒有 Score 群組，是 reload 之後才加進來的。

就 `pname_routing` 而言，缺少 hook 時 `pname()` 條件拿不到行程名稱：肯定條件永遠不匹配，否定條件則一律匹配。原因 `comm_fallback` 表示該條件用的是執行緒名稱，不是 argv。

進入 `iface_watch` 降級後，介面協調改為每 60 秒執行一次，不再接收事件通知。錯誤碼是 `interface_watcher_disabled`，原因為 `subscribe_failed` 或 `poll_setup_failed`。

`interface_binding` 的錯誤碼為 `interface_binding_incomplete`，訊息為 `A configured network interface is not fully bound; traffic interception may be incomplete.`

| `details.reason` | 說明，依優先順序由高到低排列 |
| --- | --- |
| `attach_failed` | TCX 連結建立、更新或驗證失敗。有效 hook 仍可能攔截部分流量。 |
| `unsupported_type` | 項目被[拒絕](./global.md#網卡語義)，包括不支援的巢狀或本身即主介面。 |
| `pending` | 介面不存在，或 `auto` 項目沒有 IPv4 預設路由。 |

多個原因同時存在時，取表中靠前的一個。訊息不含介面名稱，名稱只出現在日誌中。拓撲讀取失敗不會改變這個項目。

`udp_trace` 的錯誤碼固定為 `udp_trace_unavailable`。失敗只影響 IPv4 或 IPv6 其中一個 listener 位址族時，`details.reason` 為 `ipv4_unavailable` 或 `ipv6_unavailable`；兩個都受影響時為 `unavailable`。仍然可用的位址族會繼續記錄核心路由證據。

掛接失敗的 warning 用 `family` 欄位指出缺少的是哪個位址族。listener 的 warning 帶 `ipv4_unavailable` 與 `ipv6_unavailable` 欄位。listener 啟動時會重新判定，但不會重試 fallback hook 的掛接：每個真實後端只嘗試一次，改了核心或 BTF 支援後要重啟。

所有認證模式都公開 `GET /api`，首次設定密碼與登入的 POST 也公開。version、capabilities 與其他 API 資源要求已設定的靜態 Bearer 或有效的密碼 session；明確啟用匿名 loopback 存取時例外。

這些例外只適用於不帶憑證的請求。帶憑證的請求無論介面是否公開都會驗證；憑證錯誤或重複時直接拒絕，不會退回匿名。查詢字串中的 token 一律拒絕。沒有 `secret` 的開發模式要求明確開啟匿名 loopback 授權，並拒絕 `Sec-Fetch-Site: cross-site`。

Host 與 Origin 驗證先於這些認證例外執行，公開靜態檔案也不例外。OPTIONS preflight 不需要 Bearer，但要通過 Host、Origin、方法與 header 白名單。回應不回傳 cookie credentials，也不回傳通配 CORS。

預檢只允許 `Authorization`、`Last-Event-ID`、`Content-Type`、`If-Match`、`Idempotency-Key` 與 `Accept` 這些 header。預檢成功回傳 204。方法不支援回傳 404，header 不允許回傳 403，格式錯誤回傳 400。對允許的 Origin，回應會暴露 `Location`、`Retry-After` 與 `ETag`。401 回應帶 `WWW-Authenticate: Bearer`。

### HTTP 錯誤與上限

錯誤信封為 `{error:{code,message,details},request_id}`。

| 條件 | JSON 回應 |
| --- | --- |
| 已知但不可用的操作 | `404 capability_not_supported` |
| 未知路徑 | `404 resource_not_found` |
| 已知資源不支援的方法 | `405 method_not_allowed`，附帶 `Allow`；GET 資源包含 HEAD |
| 設定來源可讀但未授權寫入 | PUT 回傳 `403 permission_denied` |

HEAD 沿用 GET 的狀態碼與回應 header，但不回傳內容。API 回應帶 `Cache-Control: no-store` 與 `X-Content-Type-Options: nosniff`。

| 應用層限制 | 位元組數 |
| --- | --- |
| 正規化請求目標 | 4096 |
| 正規化 header 名稱與值合計 | 16384 |
| 請求內容，包括分塊傳輸 | 65536 |

已認證的 GET/HEAD 請求如果帶非空的請求內容，會被拒絕。一般的觀測讀取不會觸發探測或選擇變化；`/dns/query` 是會連網的明確診斷請求。

錯誤的 `details` 只指出被拒絕的物件，不會回顯提交的值或設定中的值。請求邊界錯誤會給出 `header`，或請求的部位（`field` 為 `query`、`body` 或 `target`），以及 `kind`。JSON 請求內容無法解析或不符合 schema 時，該 endpoint 回傳 `400 invalid_request`，`details` 為 `{field,kind}`。這裡的 `field` 可以是出錯成員的點分路徑，例如 `sources[0].content`；也可以是含未知 key 的物件，或 `body`。

`kind` 的取值為 `invalid_json`、`missing`、`wrong_type`、`unknown_field`、`duplicate`、`invalid_value` 或 `too_large`。422 的 `unsupported_value` 會給出被拒絕的 `field` 或 `fields`，並視情況附帶受管項目的 `resource` 路徑、`allowed` 可選值或路徑、未通過的 `check`，或能放行該請求的 `settings`。

原生伺服器最多同時接受 64 條 HTTP/1.1 連線，同一個正規化 socket 對端 IP 最多 16 條。達到全域上限時暫停 accept。超過單一對端上限的連線在 accept 後立刻關閉，不回傳 HTTP 回應，並記錄一條 DEBUG 日誌。

Forwarded header 不改變對端位址，因此同一個反向代理後方的用戶端共用該代理的額度。header 讀取的 deadline 是五秒。關閉時所有連線共用五秒的 graceful drain，然後 abort，並逐一等待結束。

30 秒的讀取閒置 deadline 只在連線沒有進行中的請求時計時，從請求內容結束算到回應完成；寫入停滯另受 30 秒 deadline 約束。SSE heartbeat 寫入成功會讓健康的長連線保持活躍，讀取不能延長阻塞 writer 的 deadline。TLS 與 HTTP/2 可以交給可信的反向代理終止。

Forwarded header 不改寫固定的發現介面路徑，也不授予 Host/Origin 權限。

密碼模式下，先關閉憑證 admission，再進行前面說的 HTTP 寬限期，最後等待真實正在執行的阻塞憑證任務結束。五秒的 HTTP 預算不限制最後這段 KDF 或資料庫等待。

HTTP 傳輸邊界：Hyper 可能在應用處理之前就以 400/414/431 或斷線拒絕畸形或硬性超限的 HTTP。這類傳輸層拒絕不保證回傳 JSON 信封或應用 header。

應用層的 target/header 上限針對的是 Hyper 解析並正規化之後的表示，不是原始 wire 位元組。Hyper 可能先去掉 request-target 中的片段，或合併相同的 `Content-Length` 欄位，再交給應用計量。因此這類原始文字即使超過應用上限，也可能得到正常回應而不是 413。

原始輸入仍然受 Hyper 的傳輸處理約束。這是已接受的邊界差異：honk 不另寫 HTTP 解析器，也不承諾原始 wire 大小上的限制。內容限制仍然涵蓋實際交付的全部內容位元組。

設定 `ui` 後，`/` 與 `/ui` 都重新導向到 `/ui/`。外部 UI 目錄託管會保留無副檔名的 SPA fallback。靜態資產、fonts/icons、manifest 或 service worker 缺少時回傳 404，不回傳 HTML。

建置時加上 `--features native-ui`，完整發行產物已經包含這個 feature。再設定 `ui: embedded`，就能直接提供固定的 doona 正式發行版，不解壓到磁碟，也不連網。`ui: embedded-lite` 選用更輕的 doona lite 預覽版，同樣需要 `native-ui`。兩個版本都連線與頁面同源的原生 API。

內嵌 UI 的 hash router 使用 `/ui/#/...`。其他合法的內嵌導覽路徑都重新導向回 `/ui/`，這樣相對資產與 service worker 的路徑才會正確。內嵌 UI 以預先壓縮的形式儲存，瀏覽器接受時以 brotli 或 gzip 傳輸。

外部 UI 目錄託管也依同樣方式提供管理員放好的同名 `.br`/`.gz` 檔案。`assets/` 下檔名帶內容 hash 的依 immutable 快取一年，其他靜態回應使用 `no-cache`。靜態回應帶 `nosniff`，但不帶 framing header，方便 LuCI 之類的面板嵌入 UI。

要防範 clickjacking，請在反向代理上加 `X-Frame-Options` 或 `Content-Security-Policy: frame-ancestors`。公開資產仍要經過 Host/Origin 驗證。發現介面與密碼 setup/login 適用前面說的公開例外；其他 API 請求要求靜態 Bearer 或 session Bearer，明確啟用匿名 loopback 存取時例外。

不向 UI 注入憑證。

### 認證發現與密碼 session

發現介面回傳 `auth: {mode, setup_required, anonymous_loopback}`。設定了非空 `secret`，或使用匿名 loopback 開發模式時，`mode` 為 `token`。`secret` 為空且啟用 `password_auth` 時，`mode` 為 `password`。

只有在密碼模式還沒有管理員記錄時，`setup_required` 才為 true。只有在實際繫結於 loopback 並明確開啟開發模式時，`anonymous_loopback` 才為 true。密碼模式下，`links.auth_setup`、`links.auth_login`、`links.auth_logout` 給出對應 endpoint 的路徑。

其他模式下這三個連結均為 null。

沒有憑證又未獲放行的請求只會取得 `name`、`api_major`、`links.auth_setup`、`links.auth_login`、`auth.mode` 與 `auth.setup_required`，其餘欄位都省略。透過 Bearer、session 或明確的匿名 loopback 放行的請求會取得完整回應。

以下是已放行的 token 模式發現回應，`links` 有刪減：

```json
{"name":"daeuniverse/native","status":"draft","api_major":1,"base_path":"/api/v1",
 "links":{"version":"/api/v1/version","capabilities":"/api/v1/capabilities","runtime":"/api/v1/runtime","operations":"/api/v1/operations/{operation_id}","auth_login":null,"x-honk":{"config_export":"/api/v1/x-honk/config/export"}},
 "auth":{"mode":"token","setup_required":false,"anonymous_loopback":false}}
```

`links` 還包含 `config`、`config_validate`、`runtime_outbounds`、`traffic_history`、`memory_history`、`logs`、`providers`、`rules`、`geodata`、`auth_setup` 和 `auth_logout`；`x-honk` 還包含 `config_import` 和 `config_revisions`。token 模式下 `auth_*` 連結為 `null`。

`GET /version` 回傳：

```json
{"api":{"name":"daeuniverse/native","major":1,"status":"draft"},"engine":{"name":"honk","version":"<build-version>"},"build":{"revision":null,"target":null,"built_at":null}}
```

建置沒有設定 `build.revision` 與 `build.target` 時，兩者為 `null`；`built_at` 一律為 `null`。

`GET /capabilities` 回傳 `observed_at`、`profiles: ["base"]`、`limits` 與 `resources`。`limits` 含 `max_request_target_bytes` 4096、`max_header_bytes` 16384、`max_json_body_bytes` 65536。`resources` 依資源名稱索引，並含 `x-honk` 擴充。使用某個資源之前，先看它的 `available` 與宣告的欄位。

Token 模式不提供三個密碼 endpoint，回傳 `404 capability_not_supported`。密碼模式使用以下契約：

| endpoint | 請求與成功回應 | 模式特定失敗 |
| --- | --- | --- |
| `POST /api/v1/auth/setup` | `{"username":"admin","password":"..."}` → `201 {"token":"hnk1_…","expires_at":"..."}` | 對端位址不符合要求時回傳 `403 permission_denied`；第一個管理員發布後回傳 `409 setup_already_completed`。 |
| `POST /api/v1/auth/login` | 相同內容 → `200 {"token":"hnk1_…","expires_at":"..."}` | 首次設定前回傳 `409 setup_required`；使用者名稱或密碼錯誤都回傳 `401 invalid_credentials`。 |
| `POST /api/v1/auth/logout` | `Authorization: Bearer <session>` → `204` | 無效或過期的 session 依一般 Bearer 認證失敗。 |

`expires_at` 是 RFC 3339 UTC 時間戳記。首次設定與登入使用以下限制：

| 輸入 | 要求 |
| --- | --- |
| `Content-Type` | `application/json` |
| 查詢字串 | 不允許 |
| 未知 JSON 欄位 | 不允許 |
| 請求內容 | 最多 4096 位元組 |
| 使用者名稱 | 區分大小寫的 ASCII，符合 `[A-Za-z0-9_.-]{1,64}` |
| 密碼 | 8–128 個 Unicode 純量值，UTF-8 編碼最多 512 位元組 |

無效的 JSON 或欄位會回傳 `400 invalid_request`。缺少媒體型別或使用其他媒體型別時，回傳 `415 unsupported_media_type`。

Media type 不區分大小寫。`Content-Type` 重複或不是文字時，回傳 `400 invalid_request`。設定、認證、探測與路由診斷共用同一套 JSON/header 解析邊界。

首次設定只看已接受 socket 的對端位址，不讀 `Forwarded`、`X-Forwarded-For` 或其他 header。允許的位址範圍是 `127.0.0.0/8`、`::1`、RFC 1918、`fc00::/7`、`169.254.0.0/16` 與 `fe80::/10`。IPv4-mapped IPv6 歸類為 IPv4。

其他對端在讀取帳戶狀態或處理憑證之前，就會收到 `403 permission_denied`。

首次設定與登入每分鐘依正規化對端 IP 最多接受 5 次嘗試，全域最多 10 次。同一個對端連續 5 次憑證驗證失敗時，只鎖定它 60 秒，從最後一次失敗起算。其他對端的失敗或成功登入都不會延長或清除這把鎖。

成功的 setup/login 只清除該對端的失敗狀態，這次嘗試仍然計入嘗試視窗。被拒絕時回傳 `429 rate_limited` 與 `Retry-After`。計數器與鎖定狀態只儲存在行程的記憶體中。

對端狀態是有界的：嘗試視窗與鎖定都過期之後，honk 丟棄這份狀態。因此閒置的對端即使連續失敗還沒到閾值，記錄也會過期。全域嘗試視窗對所有對端仍然共同生效。

憑證任務最多同時執行一個，放在 Tokio worker 之外執行；重疊的請求回傳 429 與 `Retry-After: 1`。HTTP 請求取消不會釋放這個名額，也不會丟棄它已經算出的憑證處理結果。發現介面只讀取一份短時持有的憑證狀態，不會去等跨越 KDF 或資料庫 I/O 的鎖。

session token 是 `hnk1_…` 形式的不透明值，以 `Authorization: Bearer <session>` 提交。每個 session 固定有效 12 小時。行程只儲存 token 的 SHA-256 摘要，最多保留 32 個有效 session。

簽發新 session 時會淘汰最早的 session，重啟則結束全部 session。session 因登出、過期或被淘汰而結束時，它開啟的 `/events` 與 `/logs` flow 也隨之關閉，用戶端要重新認證後再連。

透過設定的 `secret` 或密碼登入發起的操作屬於管理員，不屬於某個 token，因此登出不會刪除操作。

密碼模式把唯一的憑證記錄儲存在狀態資料庫 `<data_dir>/state/honk.db` 的 `admin` 資料列中，檔案權限 0600、目錄 0700，見[設定資料庫](#設定資料庫--store-db)。記錄格式不對時 honk 拒絕啟動；狀態資料庫損壞時同樣拒絕啟動，密碼模式不會把它移走。

記錄使用 PBKDF2-HMAC-SHA256、100,000 次迭代與新產生的 16 位元組隨機鹽。密碼模式直接使用設定的 `global.data_dir`：該目錄不可用時啟動失敗，不會退回其他目錄，以免在別處把首次設定重新開啟。首次設定只插入這一列，不替換已有記錄，因此兩個行程在同一個狀態資料庫上同時做首次設定時，只有一個會成功。

如果寫入開始前資料庫正忙，或者插入失敗但已復原，首次設定就算失敗，可以重試。如果提交或這次復原本身失敗，就無法確定該列有沒有寫入磁碟，行程在重啟之前會拒絕登入與再次設定。

首次設定一旦佔用憑證狀態，發現介面就回傳 `setup_required:false`，即使持久化結果還沒確認也一樣。無法確認寫入時回傳 503 與 `durability_confirmed:false`，不帶 `Retry-After`，也不會聲稱 `written:true`；要重啟才能重新確認資料庫中的帳戶狀態。

honk 不提供 HTTP 密碼重設。需要恢復存取時，先停掉 honk，執行 `honk-core admin reset`，重啟後重新設定管理員。把 `<data_dir>/state` 整個移走也能恢復，但會丟掉其他所有持久化狀態。

重設命令在檢查資料庫是否存在之前，先取得狀態目錄的排他鎖，因此不會和正在建立資料庫的首次啟動發生 race。

### 使用者態記錄流

已放行的匿名 loopback 請求與 Bearer 認證請求會讀到同一份 flow 資料。

用戶端透過 GET 建立並已放行的 `/events` 或 `/logs` SSE 串流，在連線期間持有通用 attachment。最後一條串流關閉之後，或成功 GET `/flows`、`/flows/{id}`、`/dns/log` 之後，通用 attachment 再保留 60 秒。它只開啟一般事件擷取，不會啟動任何 Auto 診斷記錄器；診斷需求是另一套：

| 已放行請求 | Auto 診斷需求 |
| --- | --- |
| `/events` 帶明確的 flow kinds 或有效的 flow 事件 `flow_id` 過濾器 | 僅 flow |
| 成功 GET `/flows` 或 `/flows/{id}` | 僅 flow |
| GET `/logs` SSE | 僅日誌 |
| 成功 GET `/dns/log` | 僅 DNS 日誌 |
| 無過濾/非 flow 的 `/events`、一般 API、validation、失敗 GET 或 HEAD | 無 |

flow 事件需求指的是：明確的 `kinds` 中包含 `flow.updated` 或 `flow.gap`，或者 `flow_id` 非空白、有效的 kinds 中含 flow 事件。既沒有這個過濾器又省略 `kinds` 時，不會請求 flow 記錄。每條已放行的串流各自持有一份本次請求需要的 lease。

admission 失敗時不會取得 lease；關閉或 Drop 時就釋放，即使從未 poll 過。flow、日誌、DNS 日誌三類需求各自在最後一條對應串流關閉後，或對應 GET 成功後，單獨保留 60 秒寬限期。通用活動和其他需求都不能延長這個期限。

DNS 日誌沒有 SSE 型別。記錄從需求建立時開始，因此第一次讀到的歷史是空的。

`record_flows` 預設為 true，flow 診斷需求有效時允許記錄。把執行時設定明確改成 `record_flows: "on"`，就能在沒有用戶端時持續記錄。執行時設成 `"off"` 強制關閉；設定中寫 `record_flows: false` 則禁止記錄，改了要重啟。

記錄實際停止時會釋放 flow 記錄與快照。行程內最多保留 1024 條 flow，每條 64 個步驟；含快照與核心字典預留在內，總預算 8 MiB。終態最多保留 300 秒，記憶體吃緊時可能提前淘汰，重啟後清空。

清理沿用既有的取樣器，沒有新增計時器。

核心 witness 的產出沿用既有的組合 datapath 旗標，跟隨實際的 flow 記錄狀態。既有取樣器會在之後的 tick 同步這個變化。排程、遙測與發布鎖競爭都可能讓收斂變慢，honk 不承諾一秒內完成。

記錄開啟之前就已經路由的流量，會明確回報核心證據不足。關掉需求不會丟棄已經保留的 witness 與字典，不改變路由或 NFQUEUE 的 authority，也不撤銷操作已經取得的擷取資格。沒有錄製的操作會跳過 witness 解碼。

flow ID 標示的是 incarnation，不是五元組。TCP/UDP flow 記錄會擷取實際執行的路由謂詞與短路、嗅探與驗證、群組選擇、DNS 子查詢、實體嘗試、session 重用與重試，以及終態邊界。撥號失敗或被阻斷時，即使沒有即時 connection，記錄也會保留。

名稱、ID 與 generation 都取自實際使用它們的操作，不會依目前設定或路由模擬重建。DNS lookup 與 parent ID、outbound attempt 與 parent ID 之間保留因果關係。重用 carrier 時記錄為 attachment，不會偽造一次新的實體撥號。

協定的請求、確認階段旗標必須有真實協定證據；DNS 子步驟就緒不能當作業務目標已確認的證據。TCP/UDP 的終態跟隨所屬的清理邊界。核心 offload 的觀察以 unknown 結束，不會偽造成 closed。

只有該 flow 範圍內、截至目前進度已執行的決策全部被擷取，`trace_status` 與 `trace.status` 才是 `complete`。active、failed、closed 狀態都可以是完整。這不代表 flow 成功，也不代表全域涵蓋。

來源缺少或歧義、listener secret 值被遮蔽、擷取預算耗盡時，狀態保持 `partial`，並在 `missing` 中列出原因。達到追蹤上限不會停止轉發。使用者態 TCP/UDP 與攔截 DNS 的整體涵蓋仍是 `partial`，只由核心處理的 direct/block/bypass 仍是 `none`，honk 不開放 `full_transparency`。

每條 flow 的條件表示式採用設定來源中的寫法，快取在編譯 generation 上；GeoIP 保留引用，不展開成網段清單。這樣不會只因為展開就發生截斷，但實際的上限仍然存在：原始設定文字超限、遮蔽、來源缺少、步驟或位元組預算耗盡，仍會回報為 partial 追蹤。

轉交流量的核心規則結果來自編譯程式實際執行到的分支 witness，使用者態不重算。UDP 還必須使用收到的封包裡帶的 capture ID。五元組、decision token、路由 generation 與動作都要與保留的 witness 匹配；同一個五元組後來的 incarnation 不能給舊封包提供證據。

Capture ID 不會繞回。凍結字典最多 16 份，每份 64 KiB，合計 1 MiB，計入記錄器的預留。字典被拒絕或淘汰、witness 缺少、TCP 對應關係有歧義，以及實際執行超過 256 個規則或條件值，都會讓證據不完整。

如果只是未執行的規則超過這個上限，並不代表執行證據遺失。

如果策略的核心追蹤字典會超過 64 KiB，這個策略在啟動與 reload 時都會以關閉核心路由追蹤的方式發布，並記錄一條 warning。它的 flow 會回報 `kernel_trace_not_captured`，不再產生無法解碼的 witness。檢查時依最長的 generation 編號估算規則 ID，因此剛好卡在上限附近的策略，也可能已經以關閉追蹤的方式發布。

原生擴充欄位保留來源細節，不虛構身分：路由輸入可以帶 `ingress`、`domain_fact_bitmap`、`domain_fact_state`，但不會偽造網域名稱 rule ID。DNS association 的 outbound/connection step 帶 `lookup_id`，已知的實體對端帶 `server_addr`。選擇事實保留健康的位址族，以及這個決策是實際套用還是只 peek。

Score 的 `previous_leaf_node_id` 與 `previous_member_id` 分開記錄：只有葉節點歷史，無法重建過去經過的子群組路徑。

flow 分頁結果是 `{instance_id,observed_at,coverage,dropped_records,flows,next_cursor}`。`dropped_records` 是十進位字串，最後一頁的 `next_cursor` 為 `null`。`coverage` 對 `userspace_tcp`、`userspace_udp`、`dns_intercept`、`kernel_direct`、`kernel_block` 與 `kernel_bypass` 分別回報 `partial` 或 `none`。

`GET /flows/{flow_id}` 回傳帶 `input` 與 `trace` 的單筆記錄。清單列只在 `detail=full` 時帶 `input`，從不帶 `trace`：

```json
{"id":"flow-id","instance_id":"instance","revision":1,"network":"tcp","state":"observed","pname":null,"connection_id":null,"outbound":null,"chain":[],"chain_source":"unknown","rule_id":null,"rule_generation_id":null,"rule_expression":null,"rule_source":"unknown","ingress":null,"domain_source":null,"observed_by":"userspace","started_at":"2026-11-13T00:00:00Z","ended_at":null,"trace_status":"partial","input":{"src":"192.0.2.1:50000","dst":"198.51.100.1:443","domain":null,"domain_source":null,"pid":null,"process_path":null,"src_mac":null,"ingress":null,"domain_rule_ids":null,"dscp":null,"mark":null},"trace":{"status":"partial","missing":["not_instrumented"],"steps":[]}}
```

`trace.missing` 的原因為 `not_instrumented`、`started_late`、`buffer_overflow` 與 `redacted`。每個步驟含 `seq`、`observed_at`、可空的 `elapsed_us` 與 `generation_id`、`evidence`、`stage` 與 `data`。`stage` 取 `input`、`route`、`dns`、`datapath`、`dial_mode`、`reroute`、`outbound` 或 `connection`，決定 `data` 中有哪些欄位。

flow 清單接受 `network/state/connection_id/detail/limit/cursor`。最多保留八份有界、不可變的快照，TTL 30 秒；游標繫結 instance 與原來的過濾器及 detail。可識別的游標如果帶著不同的過濾器、詳情或 limit，回傳 `400 invalid_request`。

| 參數 | 預設值 | 取值 |
| --- | --- | --- |
| `network` | `all` | `all`、`tcp`、`udp` |
| `state` | `all` | `all`、`observed`、`routing`、`dialing`、`active`、`closed`、`blocked`、`failed`、`unknown` |
| `detail` | `summary` | `summary`、`full` |
| `limit` | 100 | 1–1000 |
| `connection_id` | 省略 | 非空字串 |
| `cursor` | 省略 | 非空不透明游標 |

表滿時淘汰最舊的快照。只有保留位元組預算耗盡時，才回傳 `503 snapshot_unavailable` 與 Retry-After。過期或已被淘汰的清單回傳 `410 snapshot_expired`；已淘汰的已知 ID 由有界 tombstone 回傳 `410 flow_expired`；未知 ID 回傳 `404 resource_not_found`。

詳情介面不接受查詢參數，一律回傳保留的完整 input 與 trace。計數是十進位字串，revision、seq、elapsed_us 是 safe JSON number。顯示欄位在 512 位元組的 `MAX_TEXT` 上限內保留路徑、`@` 與 URL。

識別符號單獨驗證。無法表示或超限的文字、步驟或位元組預算溢位，都會明確回報為證據不完整，不會丟棄因果 ID 或結果。保留的規則展示屬於擷取時的 generation，不從目前設定重建。

### 節點與代理群組

`Node.stream_transport` 是可選、可為 null 的字串，反映已接受的 Trojan/VMess/VLESS 設定：`tcp`、`ws`、`grpc` 或 `xhttp`，包括 `splithttp` 別名。無法識別或不適用時，honk 回傳 null。這個欄位表示設定中的傳輸方式，不表示協商結果或健康狀態。

`protocol` 與 TCP/UDP 健康傳輸欄位的意義不變。`stream_transport` 不暴露憑證、host、路徑、extra 選項或連結。測試 fixture 來自 doona 契約包，並包含 `read_only_reason`、geodata cron 排程等本地擴充；本地檔案的 SHA-256 是 `444a9e4f6c8d35617cc36590e9d3fb985a164c8fb898cc70696ad1de66b1d0ab`。

這個固定版本不代表已發行的前端版本。

節點讀取接受 `group_id`、`limit`（1–1000）與 `cursor`。篩選只作用於直接成員，不展開葉節點。節點分頁最多使用八份快照、30 秒與 4 MiB，分頁期間凍結觀測。

`limit` 預設 100。分頁結果是 `{observed_at,nodes,next_cursor}`，不含 `total`；最後一頁的 `next_cursor` 為 `null`。節點列含 `id`（UUID）、`name`、`protocol`、可空的 `stream_transport`（僅 XHTTP）、可空的 `subscription_tag`、`provider_id`、`group_ids`（直接所屬的群組）與 `health`。`provider_id` 是訂閱 ID；設定檔中的節點為 `"inline"`，`direct` 與 `block` 為 `null`。

容量不足時回傳 `503 snapshot_unavailable`，帶 `Retry-After`。無法識別的游標回傳 `410 snapshot_expired`；可識別但過濾器或 `limit` 不同的游標回傳 `400 invalid_request`。群組回傳摘要陣列。

群組詳情含 `config_revision`，但不帶 `ETag`。`GET /groups/{groupId}/config` 回傳 `{policy, config}`，並以該修訂作為帶引號的 `ETag`。群組 ID 是行程生命週期內的隨機身分：同名 reload 或重排會保留 ID，刪除後重新新增會取得新 ID，重啟後則要重新發現。它不用位置 UUID，也不用名稱 hash。

| 群組檢視 | 欄位 |
| --- | --- |
| 清單列 | `id`、`name`、可空的 `icon`、`config_revision`、`policy`（`kind`、`native`）、`member_count`、`selection`（`tcp_member_id`、`udp_member_id`，均可空） |
| 詳情 | `id`、`name`、`icon`、`config_revision`、`policy`、`members`、`config`、`runtime`、`capabilities` |
| `members[]` | `id`、`name`、`kind`（`node` 或 `group`） |
| `config` | `default_member_id`、`final_outbound`、`check_url`、`check_interval`、`tolerance`、`idle_timeout`、`interrupt_connections` |
| `runtime` | `selection`（`tcp`、`udp`）與 `health` |
| 執行時選擇 | `null` 或 `{member_id,resolved_leaf_node_id,source}`；`source` 為 `runtime`、`override`、`health` 或 `policy` |
| `capabilities` | `can_select`、`can_override`、`supports_nested_groups`、`mutable_config`、`probe_transports` |

`config.check_interval` 是唯讀的：週期檢查使用全域間隔，值為 0 時讀出來是 `null`。

節點名稱、訂閱標籤、群組名稱與成員名稱、icon、檢查 URL、final 出站標籤以及出站計數名稱，
都以與來源內容、flow 顯示相同的規則遮蔽 listener secret。節點快照在有界序列化之前就遮
蔽憑證，續頁沿用同一份已遮蔽的位元組；不透明 ID、修訂 hash、成員身分與游標繫結都不
受影響。遮蔽閾值沒有變：不足八位元組的 listener secret 值不遮蔽，啟動時會發一條
warning。

健康資料來自生產者已經完成、且符合資格要求的測量。樂觀的存活旗標、跨 IPv4/IPv6 複製過來的排名訊號、合成出來的失敗、從快取還原的延遲，都不算真實測量。

健康列含 `transport`（`tcp`、`udp`）、`purpose`（`data`、`dns`）、`ip_version`（`ipv4`、`ipv6`）、`warmth`（`cold`、`warm`、`unknown`）、`measurement`（`tcp_connect`、`http_headers`、`dns_round_trip`、`quic_handshake`、`mixed`）、`sample_source: "probe"`、`state`（`healthy`、`unavailable`）、可空的 `latency_ms`、`moving_avg_ms` 與 `avg10_ms`、`observed_at` 以及可空的 `error`。群組健康列另含 `member_id`、`resolved_leaf_node_id`，以及為 `null` 的 `sorting_latency_ms` 與 `ranking`。

原始 TCP、HTTP 回應 header、DNS 交換與 QUIC 握手測量會保留實際的目標位址族與完成時間。節點列還帶每個測量維度的兩個平均值；它們只累計成功的原生探測，重啟後歸零：

| 欄位 | 計算方式 |
| --- | --- |
| `moving_avg_ms` | URLTest 排名使用的減半平均 `(previous + sample) / 2` |
| `avg10_ms` | 最近十次成功探測的算術平均；預熱期不足十次時依已有次數計算 |

測量列不可用時兩者為 null；針對特定群組的測量中，兩者恆為 null。未知的排名與冷熱狀態保持 null 或 unknown。針對特定群組的測量保留測量當時的成員與葉節點，不繫結到後來的選擇。

GET 不會推進 URLTest、輪詢或 Score 狀態。`icon` 回傳通過設定驗證、並已遮蔽 listener secret 的 HTTP(S) URL 或 data URI；沒設定時為 null，honk 不會去猜，也不抓取圖示。

在同一個測量 key 上，完成時間早於已保留樣本的健康資料會被丟棄。但如果已保留樣本的時間晚於目前系統時鐘，也就是時鐘回撥過，新樣本會被接受。同一時間戳記的重放只更新該列，不會在平均值中重複計入。針對特定群組的樣本最多保留 4096 個測量 key。

容量滿時採第二次機會替換，而不是嚴格淘汰最久未更新的 key：掃描器自上次經過之後重新整理過的 key 會被跳過，因此一直有在重新整理的 key 比長期沒更新的 key 留得更久。

`PUT /groups/{groupId}/selection` 的請求內容是 `{"member_id":"<direct-member-id>","network":"tcp"}`，`network` 必填，也可以填 `udp` 或 `both`。寫入 Selector 會替換它的選擇，回報 `source: runtime`。TCP 與 UDP 的選擇分開儲存，只寫 TCP 不會動到 UDP；`both` 在發布前一次驗證兩個網路，然後原子發布選擇。

寫入自動代理群組（`can_override: true`）會把該成員固定住，回報 `source: override`。固定成員不可用時，honk 不會改選同群組的其他成員。固定只存在於執行時，不持久化，每次設定啟用都會清除，包括改了節點的訂閱重新整理。

內容沒變或為空的重新整理不會啟用設定，固定保留，健康檢查照常執行。`DELETE /groups/{groupId}/selection?network=` 清除 `tcp`、`udp` 或 `both`（預設）上的固定，回傳 `GroupOverrideCleared` 與各網路目前的選擇。沒有固定的網路保持原選擇；對 Selector 呼叫 DELETE 回傳 `409 state_conflict`。

原生與 Clash 的寫入都由同一個 `control/reload` owner 序列處理，並沿用既有的持久化與預熱邏輯。Clash 的寫入等價於 `both`，讀 `now` 得到的是 TCP 投影。回應回傳獨立的 `selection_revision` 與實際的 `connections_interrupted`，不要把選擇修訂當作設定 ETag。啟用 `interrupt_connections` 時，honk 依流量建立時擷取的群組身分與路徑、以及發生變更的網路關閉舊 owner，而不是依目前可達的葉名稱刪除記錄。

重複寫入目前選擇不會觸發中斷。關閉確認失敗時，報錯可能發生在選擇已經發布之後，honk 不承諾復原。

`member_id` 為 1–256 位元組。PUT 回傳 `{group_id,member_id,network,source,selection_revision,connections_interrupted}`。DELETE 回傳 `{group_id,network,selection_revision,connections_interrupted,selection}`，其中 `selection` 的 `tcp` 與 `udp` 採用前面說的執行時選擇結構。`selection_revision` 與設定修訂互相獨立。

選擇介面會回傳這些錯誤：群組或成員不存在回傳 `404 resource_not_found`；成員或操作不受支援回傳 `422 unsupported_value`；狀態衝突，例如清除 Selector 的覆寫，回傳 `409 state_conflict`；無法確認切換結果回傳 `503 temporarily_unavailable`。

#### 代理群組設定修補

`PATCH /groups/{groupId}/config` 有三項要求：

- `Content-Type: application/json-patch+json`。
- 非空的 RFC 6902 陣列，最多 32 項操作。
- RFC 9110 `If-Match`，依 `GET /groups/{groupId}/config` ETag 中的已接受修訂求值。

`If-Match` 的清單與多個 header 欄位行依合併處理。弱標籤永遠不匹配；`*` 匹配已存在的群組。條件不匹配時回傳 412。

如果偵測到並行來源或依賴變化、但條件仍然匹配，回傳 409。

操作物件中 `op`、`path`、`from`、`value` 以外的成員一律忽略。請求內容錯誤（400、413）先於過期的 `If-Match`（412）回報。`add`、`replace`、`remove`、`test`、`copy`、`move` 都限於以下路徑：

| 路徑 | 接受的值 |
| --- | --- |
| `/policy` | 只能包含 `kind` 與 `native` 兩個字串 key，值必須相同，接受 `selector`、`urltest`、`loadbalance`、`fallback` 或 `score` |
| `/config/default_member_id` | 直接成員 ID |
| `/config/final_outbound` | 已設定的出站名稱 |
| `/config/tolerance` | 非負安全整數，單位毫秒，或 `null`；只有 URLTest 接受非 `null` 值 |
| `/config/idle_timeout` | 非負安全整數，單位秒，或 `null`（1800 秒） |
| `/config/interrupt_connections` | 布林值或 null |
| `/config/check_url` | null 或滿足以下要求的 URL |

`check_url` 必須滿足：

- 以小寫 `http://` 或 `https://` 開頭，且包含主機。
- 不含 userinfo、空白、控制字元或逗號。
- 不同時含單引號和雙引號。
- 正規化後不超過 2048 位元組。

PATCH 儲存的是正規化之後的 URL，GET 顯示的與探測實際傳送的也是這個形式：去掉片段，空路徑補成 `/`，主機轉小寫，預設連接埠省略。`test` 依這個形式比較。Selector 群組也會儲存 `check_url`，但不用它探測。

只有 URLTest 群組會回報並接受 `tolerance`。其他策略回報 null，`mutable_config` 中也沒有這個欄位。把它設成非 null 值會回傳 `422 unsupported_value`；`remove` 是允許的。

在同一個修補中把策略改成 URLTest 時，可以一併設定這個欄位。

刪掉欄位或設成 null 會恢復 dae 的預設值。來源中沒有設定 `tolerance` 或 `interrupt_connections` 時，GET 回報 null，但引擎仍會套用 `global.check_tolerance` 或預設的 `interrupt_connections: false`。

| 失敗原因 | HTTP 狀態 |
| --- | --- |
| 不支援的路徑或值 | 422 |
| 修補格式錯誤 | 400 |
| `test` 失敗 | 409 |
| 缺少前置條件 | 428 |
| 修訂已過期 | 412 |

這個介面不會修改成員清單或圖示。

來源不可寫時 `mutable_config` 為空，PATCH 回傳 `404 capability_not_supported`。PATCH 只改解析器定位到的可寫來源片段，其他原文位元組、註解與 include 結構都保留。權限、完整離線驗證、耐久替換與操作冪等沿用設定來源協調器。

這裡的 `If-Match` 是已接受的群組或設定修訂，不是檔案 SHA-256。寫入前會驗證修訂，同時獨立檢查來源位元組 hash 與依賴拓撲；真正啟用之前，還會在 reload lock 下再檢查一次已接受修訂。並行的 provider 發布可以讓寫入之後的啟用被拒絕，這時回傳 `written:true,committed:false`，磁碟不復原。自動策略的 pin 與 clear 可用（`can_override: true`）。

仍然受限制的只有原生執行時 mode 與完整核心透明性。

### 原生事件

介面需要 Bearer 認證時，請用串流 fetch，帶上 Bearer 與 `Accept: text/event-stream`。瀏覽器的 EventSource 不能設定 Authorization header。可選的 `kinds/flow_id` 會繫結到續傳游標。

`kinds` 是逗號分隔的清單，取值來自 capability 中 `events.kinds` 列出的名稱，不能重複；省略就選全部。無論過濾條件是什麼，每條串流都以 `stream.ready` 開始。`flow_id` 必須是 1–256 位元組，且不含控制字元。過濾條件無效時回傳 `400 invalid_request`。

恢復時，把最後收到的事件 `id` 以 `Last-Event-ID` 傳送：

```http
GET /api/v1/events?kinds=flow.updated,flow.gap&flow_id=flow-id HTTP/1.1
Authorization: Bearer <secret>
Accept: text/event-stream
Last-Event-ID: <previous-opaque-cursor>
```

最多保留 512 個事件、60 秒；同時支援 16 個用戶端，每個用戶端的即時佇列最多 64 條。佇列滿時直接斷開串流，不會悄悄跳過事件。16 個名額用滿後，新連線回傳 `503 temporarily_unavailable`，帶 `Retry-After`。

每 15 秒送一次 heartbeat。每個連線都先送 ready。有效續傳的順序是 ready、重放、即時：ready 保留請求中的游標，之後由重放推進，原子掛接，不留空檔。

游標過期、未知、屬於舊實例或對應不同過濾器時，在 HTTP 200 之前回傳 `409 event_cursor_expired`。

每條事件或日誌記錄最多為它的第一個精確過濾繫結快取一份完整幀，其他繫結仍然各自簽章。既有 2 MiB 的留存 ring 預算會在發布前預留酬載、一份可能的快取幀以及快取 cell，因此接近單條上限的酬載可能在達到條數上限之前就過期。這個 ring 預算不是所有排隊資料或 HTTP 持有引用的行程級記憶體上限。

新連線取得的 ready 游標是一個不透明檢查點，不是保留的事件記錄。舊歷史已經過期時，新簽發的檢查點仍能立即續傳；它不會恢復已淘汰的記錄游標，也不能越過更新事件的遺失。時間、過濾器、instance 與記錄重設的檢查照舊有效。

這裡的順序指投遞與重放的位置，不是游標位元組的排序。

發布的事件有 `stream.ready`、`runtime.updated`、`flow.updated`、`flow.gap`、`generation.changed`，以及反映實際操作狀態變化的 `operation.updated`。操作 store 不依賴有沒有可寫的 `.dae` 來源。generation 事件只來自已接受的發布，不來自收到 reload 請求這個動作。

事件中只有有界的安全 ID 與狀態，不含封包內容或原始設定。flow 與 event 記錄只存在記憶體中，不是持久化日誌。

每個事件的 JSON 資料都含 `instance_id` 與 UTC 的 `observed_at`：

| 事件 | 其他資料欄位 |
| --- | --- |
| `runtime.updated` | `href` |
| `flow.updated` | `resource_id`、安全整數 `revision`、`href` |
| `flow.gap` | 可空的 `resource_id`、`reason`（`buffer_overflow`、`evicted` 或 `recording_changed`）、可空的十進位字串 `dropped_records` |
| `operation.updated` | `resource_id`、`status`（`queued`、`running`、`succeeded` 或 `failed`）、`href` |
| `generation.changed` | `previous_generation_id`、`generation_id` |

`flow.updated` 是一則失效通知：要用它的 `href` 去讀最新的保留修訂。每個用戶端的即時佇列只留同一 flow 還沒送出的最新通知，並依新事件的序號追加到隊尾。修訂號可以跳，但傳送游標保持有序。

發布仍然是即時的，終態更新也一樣，沒有增加批次計時器。事件擷取開啟時，重放環記錄每一次發布，重放時不做合併。其他事件型別與日誌不合併。

不同 flow 的事件、以及其他不可替換的事件，仍然會在即時佇列滿時斷流。flow 資料、修訂與擷取到的追蹤 steps 不變。

用戶端連線著，或者已放行的記錄器透過明確的執行時設定持續開啟時，事件擷取就是開啟的。閒置的事件中心仍接受新串流；停止擷取後，舊事件游標失效。事件擷取開啟時，手動或自動切換記錄狀態會用 `flow.gap` 的 `reason=recording_changed` 表示記錄連續性中斷，它不表示封包遺失，也不表示沒擷取到的 flow 數量。

閒置的事件中心不會重放關閉期間的 gap；重新連線會建立新的記錄邊界。

### 出站、記憶體與歷史

`runtime/outbounds` 沿用逐出站的帳本，不依 HTTP 用戶端建立計數器。`kind` 區分 `builtin`、`node`、`group`，名稱可能相同，因此不能只依 name 合併。累計連線數、upload/download 位元組與錯誤都以完整的 UInt64 十進位字串表示。

`active_connections` 是 safe JSON number。計數與 `counter_since` 屬於共用的 StatsManager 生命週期，reload 不會歸零。

`GET /runtime/outbounds` 回傳 `{observed_at,counter_since,outbounds}`。每列含 `name`、`kind`、數字 `active_connections`，以及十進位字串 `total_connections`、`upload_bytes`、`download_bytes` 與 `errors`。

`GET /runtime/memory` 回傳 `observed_at`、`process`（`rss_bytes`）、`cgroup` 與 `kernel`。`cgroup` 為 `null`，或含 `scope`、`current_bytes`、`limit_bytes` 與 `events`（`high`、`oom`、`oom_kill`）。所有位元組值與事件計數都是十進位字串或 `null`。

兩個歷史介面都回傳 `{observed_at,window_seconds,sampled_every_seconds,samples}`。流量樣本含 `sampled_at`、`upload_bytes_per_second`、`download_bytes_per_second` 與可空的數字 `connections`。記憶體樣本含 `sampled_at`、`rss_bytes`、`cgroup_current_bytes` 與 `kernel_ebpf_bytes`。其餘樣本值是十進位字串或 `null`。

`/runtime` 的 `process.cpu_percent` 以行程 CPU 時間（`CLOCK_PROCESS_CPUTIME_ID`）的增量，除以取樣器實際經過的牆鐘間隔，以單一 CPU 為 100% 計算：一個核心滿載是 100，多執行緒負載可以超過 100。名義取樣週期為一秒。在取得兩次可用樣本之前，或者讀數不可用、時間或計數倒退、牆鐘間隔為零時，回傳 null。

RSS 來自 `/proc/self/status`。cgroup v2 依實際的 membership 與 mountinfo 定位，讀取 `memory.current`、`memory.max` 與 `memory.events`。無法讀取或未知的值一律為 null，不偽造成零。

`memory.max=max` 時 `limit` 為 `null`，cgroup 的 `scope` 保持 `unknown`。capability 中的 `runtime_memory.metrics` 列出已經讀到的指標：初始是啟動時可讀的那些，之後的取樣只會增加名稱，不會刪除。`kernel` 為 `null`，honk 不宣稱做了核心記憶體核算，也不會把 RSS、cgroup 與 kernel 相加。

`record_traffic` 與 `record_memory` 預設為 true。兩種 history 共用既有的那一秒取樣器，錯過 tick 用 Skip，沒有用戶端也照常記錄。各自最多 600 個點、600 秒，只存在記憶體中，重啟後清空。

設成 false 並重啟後，對應的緩衝會釋放，history 回傳 `404 capability_not_supported`，即時的 runtime、outbounds、memory 仍可讀。`max_points` 從最新點往前，依能滿足上限的最小 stride 抽取，再依時間由舊到新回傳。`sampled_every_seconds` 是這個名義 stride，不保證沒有缺口。

原始時間戳記、null 與取樣缺口都保留，不做插值，也不補零。

### 設定來源、驗證與操作

只有從真實 `.dae` 啟動、載入時擷取到的來源集合，才會啟用設定管理。在程式裡建構的 Config，或以 serde 格式載入的設定，都不是無損來源，其設定 capability 不可用。GET 回傳最後已接受的快照，不會臨時重新掃描磁碟。

來源 ID 不含路徑。來源的 `path` 與規則的 `file` 保留正規化後、相對入口目錄的名稱，例如 `config.d/routing.dae`；來源的 `absolute_path` 另外給出正規化絕對路徑。原文 SHA-256、位元組數、載入時間與每個來源的 `writable` 分別提供。來源集合與驗證最多 32 個來源、8 MiB 原始位元組；依賴每載入一次，也各計一份來源數量與位元組預算。

`GET /config` 回傳 `{generation_id,revision,sources,diagnostics,secrets_redacted,x-honk:{store}}`。每個來源含 `id`、`path`、`kind`（`main` 或 `include`）、`content_sha256`、`content`、`bytes`、`line_count`、`writable` 與 `loaded_at`。唯讀來源另含 `read_only_reason`；檔案模式另含 `absolute_path`。`GET /config/sources/{source_id}` 回傳單一來源物件，不含 `writable`、`read_only_reason` 與 `loaded_at`。

geodata 檔案是引擎整體載入的執行時資產，只參與 hash 衝突偵測，不計入前面說的來源預算。HTTP JSON 內容的 64 KiB 上限仍然獨立生效，超限回傳 413。因此 capabilities 中的 `config.max_bytes` 是 61440：從 65536 位元組的內容上限中扣掉 4096 位元組的建立信封，就是單次請求能攜帶的最大替換或新建內容。

`config_validate.max_bytes` 是 8 MiB 預算，因為完整驗證還要算上從磁碟讀到的依賴。`resources.config` 中沒有 `content` 欄位。替換或新建的內容超過 `config.max_bytes` 時，回傳 `413 request_too_large`。

reload 會重新整理之前擷取的依賴指紋；來源與指紋都沒變時，保留原來的設定修訂。

已放行的匿名 loopback 請求與 Bearer 認證請求會讀到同一份設定資料。已接受的內容中會有一般憑證、分享連結與路徑。honk 只遮蔽宣告的原生或 Clash listener secret 值，包括重複的宣告、被覆寫的宣告，以及這些值出現在來源中其他位置的情況。

honk 用解析器給出的範圍來識別憑證值，非憑證文字與行結構保持不變。憑證來源仍然是唯讀的，hash 仍然對應原始位元組。寫入內容中含有被遮蔽的值時，無論原文還是 JSON 轉義寫法，都回傳 `403 permission_denied`。

不足八位元組的值既不遮蔽，也不拒絕寫入，可以寫進一般來源，讀出來是原樣。`secrets_redacted` 是必備欄位，布林值，表示這次有沒有遮蔽 listener secret 值。遮蔽之後的內容不能拿去編輯再回寫。

啟用 `config_write`、並設定了非空 secret 或 `password_auth` 時，已接受且不含憑證的主檔案與所有不含憑證的 include 都可以寫。只有已接受的來源 ID 才能授權替換；新建只接受由 include 模式載入的新 `.dae` 路徑，呼叫方給的路徑不能用來授權寫入任意檔案。generated 與 subscription 來源不可寫。

一般 include 仍然沿用原來的語意：入口相對 glob、排序、無匹配以及重複或越界檢查。API 不允許修改原生設定，也不允許改變或移動 API 憑證。要編輯含憑證的主檔案，先在本地把憑證遷到專門的唯讀 include，然後重啟；這個遷移無法透過 API 完成。

設定寫入被拒絕時，`details.reason` 給出原因，並與 `stage` 等其他 details 欄位合併。details 不是物件時，原值放在 `value` 中。`code`、`message` 與 HTTP 狀態都不變。

每個回應只回報第一個未通過的檢查：

| 原因 | 首個未通過的檢查 |
| --- | --- |
| `writes_disabled` | 未啟用 `config_write`，或既未設定 secret 也未啟用 `password_auth` |
| `configuration_unavailable` | 設定協調器未執行 |
| `listener_secret_source` | 該來源宣告了原生或 Clash listener secret，或寫入後會宣告 |
| `listener_secret_in_content` | 該來源或寫入內容含有 listener secret 值；資料庫模式下也包括來源路徑含有該值 |
| `listener_settings_changed` | 候選設定相對目前執行設定修改了 `experimental.native_api`、`clash_api.secret`，或在資料庫模式下修改了 `global.data_dir` |
| `credential_sources_changed` | 本次寫入，或上次 reload 後的磁碟編輯，改變了宣告 listener secret 的來源；reload honk 後重試 |
| `import_entry_changed` | `-c` 入口不是資料庫目前修訂的入口 |
| `unsafe_path` | 儲存拒絕目標路徑 |

這些原因會出現在這些回應中：來源 PUT、新建、import 與修訂啟用回傳的 `403 permission_denied`；群組 PATCH 以及節點、provider 寫入回傳的 `404 capability_not_supported`；節點、provider 的來源寫入被拒之後回傳的 `503`；儲存拒絕新建來源時回傳的 `400 invalid_request`。資料庫 import 如果在憑證欄位之外還有 listener secret 值，回傳 `422 unsupported_value`，原因為 `listener_secret_in_content`。來源寫入與管理寫入都先檢查 `writes_disabled`，再檢查 `configuration_unavailable`。

候選設定依序檢查：憑證宣告、內容中的憑證值、憑證來源變化、listener 設定變化。其他拒絕不帶 `reason`。帶原因的拒絕會以 INFO 等級寫進請求日誌列，附帶 `reason`，不記錄路徑與內容。

原生 `/logs` 會顯示這一列的 `reason` 與 `status`，其他請求列仍然不輸出。

在 `GET /config` 中，`writable: false` 的來源用 `read_only_reason` 回報第一個未通過的檢查。可寫的來源省略這個欄位。這裡的原因只反映已接受的快照：

| 原因 | 說明 |
| --- | --- |
| `writes_disabled` | 設定寫入已停用，意義同上。 |
| `store_blocked` | 資料庫模式下記錄失敗，在重新啟用目前 head 修訂前拒絕寫入。 |
| `listener_secret_source` | 來源宣告了 listener secret。 |
| `listener_secret_in_content` | 來源包含 listener secret 值。 |

`GET /config/sources/{source_id}` 不回傳 `read_only_reason`、`writable` 與 `loaded_at`。

來源中含 listener secret 值時保持唯讀，honk 照常執行。啟動時以及每次 reload 被接受之後，honk 都會為每個這樣的來源記錄一條 WARN 日誌，內容沒變的 reload 也一樣。宣告憑證的來源、以及停用設定寫入的情況，同樣照此處理。

warning 中有來源 ID 與依清單方式遮蔽的路徑。換成任何來源中都沒有的憑證之後，這個來源就恢復可寫。

驗證請求使用 `Content-Type: application/json`，例如 `{"mode":"syntax","sources":[{"id":"candidate","content":"..."}]}`。`mode` 可以是 `syntax` 或 `full`，每個來源的 `id` 與 `path` 都可以省略。`syntax` 只解析提交的文件；路徑只作來源標籤，不授權檔案存取，也不會去跟隨磁碟上的 include。

省略的 `sources[].id` 依序預設為 `source-1`、`source-2`，以此類推。ID 是 1–128 位元組的 ASCII 字母、數字、`-`、`_` 或 `.`，在請求內唯一，只用於標註診斷。提供的路徑必須非空且唯一。ID 或路徑無效、`sources` 是空陣列時回傳 400；來源超過 32 個回傳 413；`mode` 未知回傳 422。

原生診斷的格式是 `{level,source_id,line,column,span,code,message}`。`level` 為 `error`、`warning` 或 `info`。診斷無法精確定位到來源時，`line` 與依位元組計的 `column` 為 `null`，`span` 也是 `null`。

`full` 模式下，第一份文件對應入口主檔案，額外的路徑必須落在入口根目錄之內。完整離線 admission 會用到 overlay、已放行的本地 include、唯讀訂閱快取，以及實際的本地 geodata/hosts/ECH 依賴。從未抓取過的訂閱依 warning 等級 admission，不會產生快取節點。

已經有相同抓取設定的使用中節點仍然可以 rebase。其他缺少或無效的依賴都算錯誤。`full` 模式下，如果第一份文件的 `path` 不是入口主檔案、不是 `.dae`，或者跑到入口根目錄之外，回傳 `400 invalid_request`。

驗證不連網，不建立目錄，也不改權限，不啟動 worker，不發布 generation。執行完成但無效的 dry-run 回傳 `200` 與 `valid:false`。它代替不了之後真實 reload 時的執行時驗證，也不保證 reload 一定成功。

`full` 驗證先依 include 順序合併，再判定有效設定的語意。沒有進入實際 include 樹的提交文件只做結構檢查，包括 lexer 恢復之後保留的錯誤；它的設定與 warning 不影響有效候選。但它的位元組與來源數量仍然和每次依賴載入共用同一份預算。

PUT 與驗證的請求內容中如果有未知欄位，包括 `secrets_redacted`，回傳 `400 invalid_request`。PUT 的 JSON 內容是 `{"content":"..."}`，`If-Match` 依 RFC 9110 求值。

來源的強 ETag 是加上雙引號的小寫 SHA-256；把讀到的 `content_sha256` 加上雙引號就能用。它比較的是磁碟上目前的原始位元組，不是設定修訂，也不是執行時 generation。清單與多個 header 欄位行依合併處理，只要有一個 strong 標籤匹配，條件就算滿足。

weak 標籤語法合法，但永遠不匹配；`*` 匹配已存在的資源。合法卻不匹配的 opaque 標籤，包括大小寫不同的 hash，回傳 412，而不是格式錯誤。來源 GET 回傳的仍是已接受快照，因此外部編輯之後可能需要本地處理或明確 reload，而不是拿舊快照去覆寫磁碟。

| 寫入條件/結果 | HTTP 語意 |
| --- | --- |
| 缺少 `If-Match`（先於 `Content-Type` 與內容檢查） | `428 precondition_required` |
| 畸形 `If-Match` 語法或非文字值 | `400 invalid_request`；清單、weak、`*` 與多個 header field line 本身合法 |
| 條件不匹配；偵測到目標/依賴變化後重新求值仍不匹配 | `412 stale_revision`，偵測到的外部內容不覆寫 |
| 偵測到目標/依賴變化，但條件仍成立（例如 `*` 或匹配清單） | `409 state_conflict`，不覆寫並行變化 |
| 候選設定或依賴驗證失敗 | `422 unsupported_value`，不寫入磁碟、不 reload |
| 修改目前執行設定中需重啟的項目 | `422 unsupported_value`，不寫入磁碟、不 reload；每個設定一則 `error` 級 `restart-required` 診斷，訊息寫明設定名稱 |
| 未授權的來源、憑證或原生設定修改 | `403 permission_denied` |
| 操作容量或協調佇列繁忙 | `503 temporarily_unavailable` 與 `Retry-After` |

reload 會拒絕那些修改了需重啟設定的候選設定，但已經寫入的檔案不會復原。於是磁碟上的 hash 與已接受的 hash 不再一致，後續寫入都會回傳 412。因此協調器在寫入之前就拒絕這類修改。群組 PATCH、節點與 provider 編輯、資料庫模式的 import 與修訂啟用同樣如此；`full` 驗證會以 warning 回報這些診斷。需重啟的設定請在設定檔中改，然後重啟 honk。

協調器在產生副作用之前先預留操作，把 API 新寫入與 SIGHUP 序列化處理。SIGHUP 也要先入佇列，再去讀取磁碟。

單一來源的覆寫通過完整驗證後，寫入使用目錄檔案描述符，依序執行：

1. 檢查目標為非符號連結的一般檔案。
2. 建立獨佔暫存檔案並保留檔案權限。
3. 對檔案執行 fsync。
4. 複查目標與完整依賴集。
5. 原子重新命名。
6. 對目錄執行 fsync。

外部編輯器不受協調器約束，最後一次檢查與 rename 之間仍然有 race 視窗。UI 正在儲存時，不要同時手動修改同一個檔案。rename 之後如果目錄 fsync 失敗，503 會明確帶上 `written:true,durability_confirmed:false`，且不帶 `Retry-After`：可見內容已經改變，這不表示沒有寫入成功，也不表示已復原。

寫入之後 reload 無法入佇列時，同樣回傳 `written:true`，不帶 `Retry-After`。

`POST /api/v1/config/sources` 用來新建一個原始檔。只有 `config.writable` 為 true 時，capability 中的 `config.create` 才為 true。設定不可用或不可寫時，回應與 PUT 相同。

設定可寫但 `config.create` 為 false 時回傳 `404 capability_not_supported`。請求內容是 `{"path":"config.d/proxies.dae","content":"..."}`。`path` 相對入口目錄，只含一般路徑段，以 `.dae` 結尾，不超過 1024 位元組，不含控制字元。

父目錄必須位於入口根目錄之內；透過符號連結指向根目錄外同樣會被拒絕。不滿足時回傳 `400 invalid_request`。路徑已經在磁碟上存在，或屬於已接受的來源時，回傳 `409 state_conflict`，不覆寫。

候選設定要通過和 PUT 一樣的完整驗證、憑證檢查與需重啟設定檢查，而且新檔案必須被某個 include 模式載入進來。否則回傳 422，並帶上 `source-not-included` 錯誤診斷：歸屬主檔案，位置為 null。檔案先寫入暫存檔，再用不覆寫目標的 rename 寫入，權限沿用入口檔案的 mode。

資料庫模式下改成把新來源記錄成新修訂。reload 失敗時，新建的檔案留在原處，因為刪掉它會和該路徑上的其他編輯器衝突。每個失敗的新建操作都會回報 `written`（檔案建立之後為 `true`）與 `committed`（`false`、`true` 或 `null`）。

大小限制、`Idempotency-Key` 以及 413、415、429、503 回應都與 PUT 相同。

只有耐久寫入完成並進入真實 reload 佇列之後，PUT 才回傳 `202`。明確的 POST reload 進入協調佇列後回傳 `202`。回應含 `operation_id`、`href`、同樣的 `Location` 與 `Retry-After: 1`，不表示設定已經生效。

admission 的結果是 `{operation_id,kind,status,href}`。輪詢 `href` 回傳：

```json
{"operation_id":"operation-id","kind":"reload","status":"queued","created_at":"2026-11-13T00:00:00Z","started_at":null,"finished_at":null,"result":null,"error":null}
```

`status` 為 `queued`、`running`、`succeeded` 或 `failed`；還沒到終態時，回應帶 `Retry-After: 1`。操作結束之前，`result` 與 `error` 都是 `null`。

| `kind` | 成功時的 `result` |
| --- | --- |
| `reload` | `{active_generation_id,datapath_generation_id}`，兩個 ID 均可空 |
| `probe` | 有界探測一節中的探測結果 |
| `provider_refresh` | 下文的 provider 結構 |
| `group_update` | `{group_id,config_revision}` |
| `geodata_update` | 下文的 GeoData 結構 |

操作由常駐程式持有。HTTP 斷線不會取消操作，也不會中斷監督器的狀態協調。

可選的 `Idempotency-Key` 繫結主體、方法、路徑、實例與原始內容。同一個 key、同樣內容的並行請求或重試共用結果，不會重複寫入或 reload。如果遺失第一個 202，還可以用原來的 If-Match 重試。內容不同則回傳 `409 idempotency_conflict`。

`Idempotency-Key` 重複、為空或不是文字時回傳 `400 invalid_request`。

預留與保留的操作合計最多 32 個，終態最多保留 300 秒。儲存滿時，新的 admission 先淘汰最早結束的終態操作，那個 ID 之後回傳 404。操作結束後的 300 秒內，它的 `Idempotency-Key` 仍然重放原來的 `202`，內容不同仍然回傳 `409`。

被淘汰的 key 最多保留 1024 個，上限由 `resources.operations.max_replay_keys` 給出；超出就丟掉最早的一個。只有當全部名額都落在準備中或執行中的操作上時，才回傳 `503 temporarily_unavailable` 與 `Retry-After: 1`。重啟後不保留。

真實結果要透過 GET 操作、`runtime.last_reload` 與 `operation.updated` 去讀，不能把收到 202 當成 succeeded。reload 被拒絕時，舊的已接受快照與 generation 保留，但已經寫入的位元組不復原。提交之後進入 degraded 時，保留新的快照與 generation，並回報 failed，而不是聲稱舊 generation 還在運作。

管理員應該依磁碟內容與操作結果去修，然後再明確 reload。磁碟檔案載入不了時，失敗的操作與 `last_reload` 會回傳 `unsupported_value` 錯誤、`details.diagnostics`（與寫入同樣內容時的回應相同）與 `committed:false`，並標明已接受的來源 ID 與行號。如果全部診斷列超過操作錯誤 details 的 4 KiB 上限，只保留 error 等級的列。

每次失敗的 reload、來源寫入，以及節點或 provider 寫入，都會在 `error.details.committed` 中回報結果（`false`、`true` 或 `null`）。一般 reload 的 details 不帶 `written`，只有寫入類操作才帶。SIGHUP 本身不會建立 API 操作。

只改註解也會更新來源 hash 與設定修訂，但有效設定沒變時不會新增執行時 generation。有效群組成員變化會改變修訂，健康測量變化不會。來源 hash、設定修訂與執行時 generation 是三種不同的並行 token，不能互相替代。

設定 `secret` 或密碼登入保護 listener 時，所有 session 共用一個管理員操作 principal，登出不會刪除保留的操作。操作也用於探測、訂閱重新整理與群組更新。探測與訂閱重新整理不要求來源管理 capability。

原生暫停與恢復仍不可用，回傳 `404 capability_not_supported`。

### 設定資料庫（`--store db`）

`honk-core --store db` 把受管理的 `.dae` 來源以修訂形式存進狀態資料庫 `<data_dir>/state/honk.db`。`data_dir` 取自 `--data-dir`（預設 `/var/lib/honk`），必須與 `global.data_dir` 一致，不會退回工作目錄。`state` 目錄權限 0700，檔案 0600；兩者都屬於常駐程式使用者，且不能是符號連結。

啟動時，或執行 `honk-core admin reset` 時，如果這兩者屬於常駐程式使用者、只是多了群組或其他使用者的讀取與執行權限，honk 會移除這些權限並記錄一條 warning。其他情況一律拒絕，群組或其他使用者可以寫入時也一樣。`config export` 與其他離線讀取遇到 0700 與 0600 以外的權限時一律拒絕，也不改權限。

資料庫使用 WAL 模式，同目錄下的 `honk.db-wal` 與 `honk.db-shm` 權限與主檔案相同。檔案系統不支援 WAL 時，例如不支援共用記憶體，honk 退回回滾日誌 `honk.db-journal` 並記錄一條 warning。設定中只有 `.dae` 來源會進資料庫。

訂閱內容在兩種模式下都儲存在資料庫中。hosts、ECH 與 geodata 仍然在磁碟上，依 `data_dir` 解析。匯入來源樹所在的目錄不授權任何依賴。

資料庫為空時，啟動過程會匯入 `-c`。這要求啟用 `native_api.enabled` 與 `config_write`，並設定憑證。匯入會刪掉 `native_api` 與 `clash_api` 中所有的 `secret:`，確認去掉憑證的來源樹在重新套上憑證後解析出同樣的設定，然後以 principal `startup` 記錄修訂 1。如果憑證值刪掉後還有殘留，例如留在註解或檔名中，匯入就被拒絕。

已經有修訂時，啟動過程載入目前修訂，不讀 `-c`。如果啟動期間另一個實例移動了 `head`，啟動會終止。只有不持實例鎖的 mock 模式實例會造成這種情況。

資料庫模式不提供 Clash API：不管是匯入的來源樹還是目前修訂，只要
`experimental.clash_api.external_controller` 非空，啟動就會被拒絕。資料庫損壞、
`application_id` 不符，或 schema 版本更高時，也拒絕啟動，honk 不會給資料庫改名或
重建。啟動與 API 重新匯入都會恢復剝離掉的憑證，對齊解析器臨時產生的群組與訂閱 ID
以及解析時間戳記，再嚴格比較設定值。節點派生身分、endpoint、群組定義與訂閱抓取設定仍
然必須一致。

listener secret 與修訂分開儲存，從不回傳。寫入不能改 listener secret、`native_api` 設定或 `global.data_dir`，否則回傳 403。含已儲存憑證值的來源也會被拒絕。

回應與 `--without-secrets` 匯出都會遮蔽這兩個已儲存的值。資料庫模式下來源省略 `absolute_path` 欄位，來源路徑只是標籤，不對應任何檔案。`If-Match` 比較的是資料庫中儲存的來源位元組。

寫入先啟用，再記錄。只有啟用提交之後，包括 degraded 與 reconciliation 失敗的提交，才寫入修訂列並移動 `head`。啟用被拒絕時不增加記錄，並回報 `written:false`。

記錄失敗時，操作以錯誤碼 `store_unavailable` 失敗，`details` 為 `{committed:true,written:false,active_generation_id}`。引擎在確認啟用之前就停了，操作錯誤碼是 `activation_unconfirmed`，`details` 為 `{committed:null}`。這兩種情況下，`store.recorded` 都會變成 false，capabilities 回報設定不可寫，匯出檔名不帶修訂，寫入回傳 `503 temporarily_unavailable` 與 `details.stage:"store"`。

啟用 `head` 所在的修訂會重新啟用它，不新增記錄，並解除這個狀態。重啟也會解除；重啟後載入 `head`。最多保留 50 個修訂，依儲存的 JSON 計算共 16 MiB，從最舊的開始清理，目前修訂不刪。

JSON 轉義會讓修訂比原始檔本身更大。單一修訂的 JSON 超過 16 MiB 時拒絕寫入。

新的已接受來源已經發布、但耐久記錄還沒完成時，`store.recorded` 為 false，匯出檔名是 `honk.dae`；`revision` 與 `parent` 仍然描述耐久的 head。如果讀到的舊已接受來源本身沒變，仍可回報為已記錄。協調器要等阻塞的 SQLite promotion 結束，才完成操作、處理下一項修改或確認關閉。

以下路由與欄位是 honk 擴充，依契約的 Engine extensions 規則放在 `x-honk` 下。`GET /config` 增加 `x-honk.store {kind, revision, parent, recorded}`，`kind` 為 `file` 或 `db`。capabilities 增加 `config.x-honk.store`，並在 `resources.x-honk` 中增加 `config_export {available}`、`config_import {available, replace_required}` 與 `config_revisions {available, can_activate, max_revisions}`。

已放行的發現介面在 `links.x-honk` 中給出這三個連結。下列路徑都位於 `/api/v1/x-honk` 下。

- `GET /config/export` 把已接受的來源合併成一份文件回傳，帶 `text/plain; charset=utf-8`、`Content-Disposition: attachment; filename="honk-r<n>.dae"`、以內容為基礎的強 `ETag` 與 `Cache-Control: no-store`。檔案模式下檔名是 `honk.dae`。內容不含 listener secret。有憑證被省略時，第一行是 `# listener secrets omitted`，補回憑證之後才能執行。兩種模式都能用。
- `POST /config/import` 用於資料庫模式，要求可寫。它接受嚴格 JSON `{"replace":bool}`，必須帶 `Idempotency-Key`。它會重新讀取 `-c` 來源樹，透過 reload 操作記錄成 origin 為 `import` 的新修訂。因為啟動過程總會記錄修訂 1，這裡必須提交 `replace:true`，其他請求回傳 `409 state_conflict`。憑證副本在刪除後還有殘留時回傳 `422 unsupported_value`。來源樹必須保持入口路徑、listener secret、`native_api` 設定與 `data_dir` 不變，否則回傳 403。
- `GET /config/revisions` 用於資料庫模式，回傳 `{active, max_revisions, revisions:[{revision, parent, created_at, principal, origin, content_sha256, bytes, sources:[{path, sha256}]}]}`，由新到舊排列，不含內容。`active` 與各列來自同一個資料庫快照。父修訂被留存清理刪掉後，`parent` 為 null。
- `POST /config/revisions/{n}/activate` 用於資料庫模式，要求可寫。它接受空內容或 `{}`，`Idempotency-Key` 可選。它會驗證並啟用修訂 `n`，再記錄成 origin 為 `activate` 的新修訂。`store.recorded` 為 true 時，啟用目前修訂不會產生變更。未知的 `n` 回傳 `404 resource_not_found`。

檔案模式下，import 與修訂路由回傳 `404 capability_not_supported`。

要恢復檔案模式：

1. 執行 `honk-core config export --out /etc/honk/config.dae`。
2. 去掉 `--store db` 後重啟。

之後再用資料庫模式啟動時，從 `head` 繼續。對檔案的改動只能透過 `replace:true` 的匯入進資料庫。

恢復損壞的資料庫：

1. 執行 `honk-core config export --out exported.dae`。匯出只檢查應用 ID 與模式版本，因此仍可能讀取損壞的檔案。
2. 停止 honk。
3. 執行 `mv <data_dir>/state <data_dir>/state.bad`，移走整個目錄，確保 `honk.db-wal` 與主檔案一起移動。
4. 以 `--store db -c exported.dae` 啟動。

### 有界探測

`POST /probes` 要求 JSON，例如 `{"target":{"type":"node","node_id":"<id>"},"kind":"http","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`。

`target`、`kind`、`transport`、`ip_version` 與 `warmth` 都必填。`members` 可以省略，但不能為 `null`；成員 ID 清單不能含空 ID 或重複 ID，節點目標不能帶 `members`。以下是同時使用兩種傳輸的 DNS 探測：

```json
{"target":{"type":"group","group_id":"<id>"},"kind":"dns","transport":["tcp","udp"],"ip_version":"ipv4","warmth":"cold","members":"direct"}
```

| 欄位 | 取值 |
| --- | --- |
| 節點目標 | `{"type":"node","node_id":"<id>"}`；不接受 `members` |
| 群組目標 | `{"type":"group","group_id":"<id>"}` |
| 群組 `members` | `"direct"`（預設）、`"leaves"` 或非空直接成員 ID 清單 |
| `kind` | `tcp_connect`、`http` 為資料探測，僅使用 TCP；`dns` 為 DNS 探測，可使用 TCP、UDP 或兩者。 |
| `transport` | `["tcp"]`、`["udp"]` 或 `["tcp","udp"]`；只有 `dns` 接受 UDP |
| `ip_version` | `ipv4`、`ipv6`、`any` |
| `warmth` | `cold`、`warm` |

honk 不接受呼叫方指定的 URL。探測用途由 `kind` 決定，不用在請求中提交：`tcp_connect` 與 `http` 是資料探測，只用 TCP；`dns` 是 DNS 探測，可以用 TCP、UDP 或兩者。

群組可以用直接成員、葉節點或明確的成員 ID。honk 先固定目前設定、成員與註冊的 generation，再去重執行測量，並保留成員到葉節點的 association。TCP 連線探測測的是節點實際設定的連接埠，不接受呼叫方指定任意連接埠。

HTTP 使用設定中的檢查 URL，不跟隨重新導向。DNS 執行真實的 UDP 交換或帶長度幀的 TCP 交換。探測目標只來自已接受的設定；honk 不對目標或節點伺服器施加位址、連接埠策略。

目標主機名稱依目前 DNS 設定解析；這份設定答不上來時，例如用了 `asis` 路由，就退回 bootstrap DNS。私網、loopback 位址與非預設設定連接埠不需要額外放行。IPv4-mapped IPv6 會正規化成 IPv4；選中的 IP 保持固定，HTTP Host 與 TLS SNI 保留設定中的名稱，不能交給代理重新解析。探測、geodata 與共用下載都使用設定中的目標，不設位址或連接埠白名單。

能夠寫入設定或控制訂閱內容的人，決定這些目標是什麼。provider 內容屬於可信的設定。

對 `direct` 或 `block` 節點做 `tcp_connect`，或對不支援 UDP 的節點做 UDP 探測，會在這項測量開始之前回傳 `422 unsupported_value`。

| 探測預算 | 上限 |
| --- | --- |
| 每項任務的成員 association | 64 |
| 每項任務的結果行 | 256 |
| 每項任務的並行測量 | 10 |
| 使用中任務 | 4 |
| 排隊任務 | 16 |
| 每個目標的任務 | 1 |
| 準備、排隊與測量 | 共用 30 秒期限 |
| 每個資源的每分鐘請求數 | 唯一認證主體與全域各 30 次 |

最終傳輸 owner 的清理即使超期，也要等到結束，因此一個操作的總耗時可能超過 30 秒。限流回傳 `429 rate_limited`；容量不足或 owner 不可用回傳 503，兩者都帶正數的 `Retry-After`。

即使已經有四個使用中任務，也會立刻回傳 202 與一個 `queued` 操作。

202 只表示常駐程式接手了任務。在測量開始前就結束的任務，會以 `probe_cancelled`、`probe_deadline`、`unsupported_value` 或 `engine_unavailable` 失敗。`unsupported_value` 表示本地解析被拒絕，或者節點無法把 UDP 轉發到探測連接埠。斷開 HTTP 連線不會取消任務。

重複使用可選的 `Idempotency-Key` 時，會重放仍然保留的探測 admission 結果。

結果會保留真實的 measurement、位址族、warmth 與時間，以及健康狀態更新有沒有被目前時期接受。過時的 generation、取消或超期不會偽造成 unhealthy，TCP-connect 也不會冒充 HTTP 排名樣本。最終清理失敗時，操作以 `probe_cleanup_failed` 失敗，`result` 保持 null，已完成的測量放在 `error.details` 中。

探測操作成功時的 `result`：

```json
{"target":{"type":"group","group_id":"group-id"},"selection_changed":{"tcp":false,"udp":false},"selection_before":{"tcp":"member-id","udp":null},"selection_after":{"tcp":"member-id","udp":null},"results":[{"member_id":"member-id","resolved_leaf_node_id":"node-id","kind":"dns","purpose":"dns","transport":"udp","ip_version":"ipv4","warmth":"cold","state":"healthy","latency_ms":12.5,"health_updated":true,"error":null,"observed_at":"2026-11-13T00:00:00Z"}]}
```

`latency_ms`、`resolved_leaf_node_id` 與 `error` 可為 `null`。`health_updated` 表示該樣本是否計入健康狀態。

直接成員中的子群組，會透過它選中的一個葉節點來探測。選這個葉節點可能展開後代；除了沒有子群組、也沒設定 `final` 的 Selector，規劃圖超過 256 項就拒絕。目標群組仍然受 64 個成員與 256 列結果限制，更大的群組可以用 `members` 清單分批，每批最多 64 個 ID。`members: "leaves"` 在整組圖超過 256 項時也會被拒絕。

### DNS 查詢、快取與結果歷史

`POST /dns/query` 要求嚴格的 JSON 請求內容，`Content-Type` 必須是 `application/json`；其他媒體型別回傳 415。

請求內容上限 4096 位元組，超出回傳 `413 request_too_large`。

| 欄位 | 位置 | 要求或預設值 |
| --- | --- | --- |
| `domain` | 請求內容 | 必填 |
| `type` | 請求內容 | 可選非空陣列，最多八個不同記錄型別；預設 `["A"]`。超過上限回傳 `413 request_too_large`。 |
| `cache_mode` | 請求內容 | `normal` 為預設值，或 `bypass` |
| `upstream` | 請求內容 | 已設定的上游名稱，包括未被規則引用的上游 |
| `detail` | 查詢字串 | `summary` 為預設值，或 `full` |

支援 A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、SVCB、HTTPS 和 CAA。

型別可以寫成大寫名稱、十進位數字，或 `TYPE` 加數字，所以 `"A"`、`"1"` 與 `"TYPE1"` 等價。型別名稱區分大小寫。型別無效或重複時回傳 400；合法但不在上面十二種之內的型別回傳 422。快取與日誌的 `type` 過濾接受任意合法型別。

所有型別固定同一個 DNS generation，共用十秒 deadline。唯一認證主體與全域各限每分鐘 30 次。

指定 upstream 會替換請求階段的路由選擇，但不改變 hosts 與 strategy 的優先順序，也不改變回應側策略，包括重新查詢。命中本地 hosts 記錄時，仍然回報預設路由，而且沒有 upstream。

`bypass` 不執行以下操作：

- 讀取或寫入正快取、負快取及過期快取。
- 加入會寫入快取的 singleflight。
- 替換快取項目或啟動重新整理。

沒有提供 `cache_mode` 時，保留正常的生產語意。完整詳情會展示經過驗證的答案記錄；各型別的逾時、拒絕或錯誤仍依實際結果回報。

`detail=full` 回應如下；摘要省略 `answers`：

```json
{"domain":"example.com.","cache_mode":"normal","query_time":"2026-11-13T00:00:00Z","results":[{"type":"A","question":{"name":"example.com.","type":"A","class":"IN"},"elapsed_ms":12,"cached":false,"cache_entry_id":null,"upstream":"dns1","route":{"source":"default","rule":null},"status":"NOERROR","answers":[{"name":"example.com.","type":"A","class":"IN","ttl":60,"data":"192.0.2.1"}]}]}
```

`route.source` 為 `default`、`dns.routing` 或 `forced`，`route.rule` 可空。快取結果的 `upstream` 為 `null`。`status` 為回應碼；某個型別失敗時為 `TIMEOUT`、`REFUSED` 或 `ERROR`。

DNS 查詢、快取回應與 DNS 日誌分頁都會遮蔽用於顯示的 listener secret 值，但不改變不透明 ID 或游標繫結。

字面值 `.` 表示 DNS 根，可以用在實際查詢、精確快取清單與依名稱刪除中。一般輸入名稱不區分大小寫，末尾的點可以省略；展示名稱會保留正規化後的末尾點。合法的根域 wire 問題也走一般嚴格 DNS 路徑；非 UTF-8 標籤仍不在這份消費者契約範圍內。

名稱去掉可選的末尾點之後是 1–253 位元組，由 1–63 位元組的標籤組成，標籤只含 ASCII 字母、數字、`-` 或 `_`。即時查詢、快取的 `name` 與路由追蹤的 `domain` 都使用這條規則。

快取 GET 只觀察執行時精確 key 上的正、負記錄（`persistent:false`），不會提升 LRU 優先順序，也不計入命中統計。它支援 `name` 精確名稱、`domain` 子字串、可重複的 `type`、`include_expired=false|true`、`detail`、`limit`（1–1000，預設 100）與 `cursor`。最多保留 8 份繫結過濾器與實例的不可變快照，30 秒，合計 8 MiB；底層記錄被淘汰之後，快照佔用的空間仍計入預算。

`name` 匹配一個精確名稱；`domain` 匹配大小寫不敏感的子字串。分頁結果是 `{observed_at,coverage,entries,total,next_cursor,usage}`，`total` 是匹配的項目數。項目為 `{entry_id,domain,type,class,status,expires_at,stale_until}`，`stale_until` 可空；`detail=full` 時另含 `answers`。

超出這份預算時回傳 `503 snapshot_unavailable`。游標無法識別時回傳 `410 snapshot_expired`；可識別但過濾器或 `limit` 不同的游標回傳 `400 invalid_request`。`entry_id` 標示精確的 incarnation，用舊 ID 刪不掉替代它的記錄。

依 name 刪除可以跨精確 key 的各種變體，並用 type 限定範圍。刪除與 flush 與入庫發布序列化，會等已啟用的持久化確認失效；確認之後，舊的 foreground 或 refresh 不能把已刪的快取復活。flush 不清空 DNS 路由投影。

DNS 查詢、快取與日誌的完整 JSON 回應上限都是 262144 位元組。快取與日誌分頁如果下一筆會超出上限，就提前結束並回傳 `next_cursor`，因此 `limit` 只是上限，不保證筆數。單筆記錄本身就超限時，會獨佔一頁完整回傳，不受這個上限約束。

原始封包最長 65535 位元組，展開後大小有界；拒絕它會讓其後的記錄都讀不出來。查詢回應超限或無法保留快照時回傳 503 與 `Retry-After`，不會裁剪 RRset 去冒充完整答案。

`DELETE /dns/cache/{entry_id}` 不接受請求內容或查詢參數，回傳 `{deleted}`。`DELETE /dns/cache?name=...&type=A` 不接受請求內容，回傳 `{matched,deleted}`，省略 `type` 時選擇該名稱的全部型別。`POST /dns/cache/flush` 接受空請求內容或 JSON `{}`，回傳 `{matched,deleted}`。

名稱、型別與過期篩選在快照的位元組 admission 與複製之前就完成；沒選中的快取記錄不佔本次快照預算。負回應優先順序與過期篩選使用同一個觀測時刻。

每頁還帶 `usage {entries, entry_capacity}`，描述快照那一刻的整個執行時快取，不受過濾器影響。`entry_capacity` 是 `max_cache_size` 限制到 1–100,000 之後的值。兩個值都是十進位字串，在所有分片同時加鎖時讀取。

同一快照的後續頁會重複同樣的值。淘汰依分片處理，也受快取回應位元組數限制，因此某個分片可能已經在淘汰，而合計值看起來還有餘量。`usage.entries` 還會計入 `total` 不包含的過期記錄與非精確 key 記錄。

`record_dns_log` 預設為 `true`，獨立 DNS 日誌需求有效時允許記錄，最多保留 512 筆、8 MiB。明確設成 `record_dns_log: "on"` 之後，即使沒有用戶端也會持續記錄。設定中寫 `false` 就禁止記錄，改了要重啟。

記錄實際停止時會釋放歷史，已有的游標隨之失效。記錄發生在用戶端請求實際完成時：記的是一般 DNS 查詢結果，以及來源已知的用戶端解析結果，包括已知的用戶端 socket、入口，還有能解析出結果的拒絕或錯誤。原生與 Clash 的診斷呼叫、以及背景重新整理產生的重複記錄都排除在外。

只存在記憶體中。完整的原始封包與中繼資料一起計入預算，淘汰時依整筆舊記錄計算。`GET /dns/log` 依最新優先，支援大小寫不敏感的 `name` 子字串、`type`、不帶連接埠的 `src`、`limit`（1–500，預設 100），以及與過濾器繫結的 `cursor`。

`name` 匹配大小寫不敏感的子字串；`src` 是不帶連接埠的 IP 位址。分頁結果是 `{observed_at,total,next_cursor,records}`，`total` 是全部保留記錄數，不是匹配數。記錄含 `id`、`observed_at`、可空的用戶端 `src`（位址加連接埠）、`question`、`status`、`cached`、可空的 `upstream`、`route`、`elapsed_ms` 與 `answers`，結構與 DNS 查詢結果相同。

淘汰或縮容會讓受影響的游標失效；無法識別的游標回傳 `410 snapshot_expired`。可識別但過濾器或 `limit` 不同的游標回傳 `400 invalid_request`。停止記錄不影響正常的 DNS 服務。

### 路由模擬與規則位置

已放行的匿名 loopback 請求與 Bearer 認證請求，在讀取規則與路由模擬上的權限相同。`POST /routing/trace` 接受 `{"input":{"network":"tcp","domain":"example.com","dst_port":443},"resolve":"none"}`。`input` 要求 TCP 或 UDP、非零目標連接埠，以及至少一個 `domain` 或 `dst_ip`。

其他輸入欄位都可選：`dst_ip`、`src_ip`、`src_port`（1–65535）、`pname`、`dscp`（0–63）與 `mark`（32 位元，接受但不參與求值）。未知欄位回傳 400。`resolve` 預設為 `none`，回傳固定 `instance_id` 與 `generation_id` 的 `simulation` 結果。`live` 要求帶 `domain` 且不能帶 `dst_ip`，違反這個結構回傳 400。

結構合法但暫時不支援的 `live` 請求回傳 422。`Content-Type`、JSON 與 schema、`input` 與 `resolve` 的驗證先於限流 admission；被驗證拒絕的請求不佔路由模擬的限流名額。

模擬固定目前已編譯的路由器、設定與 generation：不查 DNS，不探測，不推進群組選擇，也不建立連線。缺少的輸入保留 `indeterminate/missing_inputs`，不能當作歷史 flow 證據，也不代表真的會這樣轉發。上限是 1 個位址、256 個規則或條件步驟、5 秒；唯一認證主體與全域各限每分鐘 30 次。

`GET /rules` 回傳目前完整字典，含 fallback，從不截斷。`max_rules` 取 4096 與目前字典列數中較大的那個；`dns_rules.max_rules` 同樣不小於較長的那個 DNS 清單。fallback 項目的 `expression` 是它的來源語句，例如 `fallback: proxy`。

`GET /rules` 回傳 `{generation_id,rules,fallback}`。規則含 `rule_id`、`index`、`expression`、`outbound`、`must`、可空的 `source` 與 `kind`；`fallback` 為 `{outbound,source}`。

追蹤結果為 `{mode,instance_id,generation_id,observed_at,evaluations,dns}`。每個求值含可空的 `dst_ip`、`decision`、可空的 `outbound`、`missing_inputs` 與 `rules`。規則求值為 `{rule_id,expression,result,missing_inputs,conditions}`，條件為 `{id,expression,result,missing_inputs}`；`result` 為 `matched`、`not_matched`、`indeterminate` 或 `skipped`。

沒有保留來源文字時，用 `fallback: <outbound>`。路由模擬的求值結果也用 `fallback: <outbound>`。兩者在 deadline 內無法固定路由器時，回傳 `503 snapshot_unavailable`，帶 `Retry-After`。

規則 ID 與使用者態擷取證據共用同一個 generation 範圍內的身分。有已接受的解析器來源位置時，給出不透明的 `source_id`、從 1 開始的 `line` 與依位元組計的 `column`。`file` 與該來源相對入口目錄的 `path` 一致；否則 `source` 為 null。

歷史 flow 不會從目前字典重建；核心 final 的來源仍然可能是 unknown。編輯時請用來源 ID 與對應的內容權限，不要從顯示標籤推導檔案系統路徑。

對已接受 `.dae` 設定中的規則，包括含憑證來源的規則，`/rules` 與 `/routing/trace` 的規則 `expression` 保留編寫時的條件值，包括 geosite/geoip 名稱、否定與帶引號引數，同時去掉註解與出站子句。追蹤的逐條件表示式依實際編譯後的順序，以 dae 寫法顯示設定值，不加引號：一個 `domain(...)` 中的一般網域名稱候選與 geosite 會合成一個聯集條件，否定作用於整個聯集。目標 IP 與 geoip 候選同樣共用一個條件。

listener secret 值仍然被遮蔽。一般條件文字不需要寫入權限就能讀到。沒有已接受來源中繼資料的規則，顯示編譯後的條件值，來源保持 null。

編譯後的展示反映的是正規化之後的謂詞，不等於原始寫法，也不展開 geodata。追蹤的展示中繼資料與決策固定在同一已接受 generation 上。磁碟上的編輯只有在 reload 被接受之後，才會更新這兩種回應。

reload 被拒絕時保留舊的表示式。歷史 flow 保留各自 generation 擷取到的有界編譯後值，包括在程式裡建構路由器時的值。

### DNS 路由規則

`GET /dns/rules` 以 `{generation_id, request, response}` 回傳目前 generation 的 `dns { routing { … } }` 規則。這個介面是唯讀的；要改 DNS 規則，和改 `/rules` 一樣，透過來源 PUT 完成。兩個清單都依求值順序排列，末尾恰好一條 `kind: "fallback"`。

每筆記錄含 `rule_id`、從 0 開始的 `index`、`expression`、`action`、`upstream`、`source` 與 `kind`。請求規則的 action 是 `upstream`、`asis`、`reject`；回應規則的是 `accept`、`reject`、`requery`。

action 是 `upstream` 或 `requery` 時，`upstream` 是引擎實際使用的小寫名稱；其他 action 下為 null。`expression` 是編寫時的整條語句，含 action，去掉行尾註解，例如 `qname(suffix: example.com) -> AliDNS` 或 `fallback: googledns`。設定中沒寫 fallback 時，也會列出引擎的預設值：請求側是 `upstream` `default`，回應側是 `accept`。

它的 expression 是 `fallback: <action>`，`source` 為 null。被解析器以 warning 等級忽略的規則不會列出。

`rule_id` 的格式是 `{instance}:{generation}:dns_request:rule:{index}` 或 `{instance}:{generation}:dns_request:fallback`，回應清單把 `dns_request` 換成 `dns_response`。它在兩個清單之間唯一，隨 generation 變化，因此定位一條規則要同時用 `generation_id` 與 `rule_id`。`source` 與 `/rules` 結構相同：不透明的 `source_id`，與該來源相對入口目錄的 `path` 一致的 `file`，以及語句在該來源中起始處從 1 開始的 `line` 與依位元組計的 `column`。

沒有已接受來源中繼資料的規則，`source` 為 null，expression 由解析後的條件產生。兩個清單都完整回傳，包含 fallback。`resources.dns_rules.max_rules` 至少是 4096，也不小於目前較長清單的筆數。

5 秒內無法固定目前設定時回傳 `503 snapshot_unavailable`，帶 `Retry-After`。磁碟上的編輯只有在 reload 被接受之後才會反映到回應中。

### Provider 觀測與重新整理

已放行的匿名 loopback 請求與 Bearer 認證請求會讀到同一份 provider 資料。provider 的 GET 不連網。訂閱項目把真實的 SubscriptionSupervisor 觀測與已接受節點的 `subscription_id` 關聯起來；可以用 `Node.provider_id` 去對應。

分頁為 `{providers,next_cursor}`。provider 含 `id`、`name`、`kind`（`inline` 或 `subscription`）、可空的 `url_redacted`、`updated_at` 與 `expires_at`、`node_count`、`status`（`ok`、`stale` 或 `error`）、`traffic`（`null`，或十進位字串組成的 `{upload_bytes,download_bytes,total_bytes}`）、`last_error`（`null` 或 `{code,message,details}`）與 `download`（下述路由物件或 `null`）。

訂閱物件帶的是設定中的名稱，`url_redacted` 回傳完整 URL；欄位名是為了相容用戶端才保留的。GET 與成功操作的結果使用同一種表示。

`traffic` 與 `expires_at` 來自 provider 的 `subscription-userinfo` 回應 header；沒有這個 header 時為 null。設定名稱如果和舊的 `provider-<id>` 標籤相同，那只是一般名稱，不當 ID 別名。從未載入、正在等待載入，或已停用又沒有快取時，狀態為 `stale`，節點數為零，時間與錯誤都是 null。

只有真的失敗、且沒有可用節點時，狀態才是 `error`；保留了舊節點或快取節點時是 `stale`。訂閱項目還帶 `download`，也就是由 `download_detour` 決定的抓取路由，結構與 geodata 路由相同：`route` 為 `routing`、`direct` 或 `group`，`group_id` 是該群組在 `GET /groups` 中的 ID，其他路由或群組已不存在時為 `null`。inline 項目的 `download` 為 `null`。沒有檔案 provider 這種型別。

抓取失敗時，`last_error.code` 為 `fetch_failed`。訂閱的下載路由暫時沒有可用節點時為 `route_unavailable`，見[訂閱參考](./subscription.md#抓取持久化與恢復)。已分類的 `fetch_failed` 錯誤會用 `details` 給出失敗階段 `stage`，例如 `connection_failed`、`download_timeout`、`tls_failed`、`parse_failed`，以及選中的節點 `node` 和選中該節點的群組 `group_id`。無效 URL、重新導向之類沒分類的失敗回傳 `details: null`。直連下載、選中節點之前就失敗，以及解析失敗到無法保留抓取歸屬時，`node` 為 null；沒有群組歸屬，或對應的群組已經不在目錄中時，`group_id` 為 null。設定驗證拒絕發布時，例如節點與靜態節點重複，`last_error.code` 為 `publication_rejected`，診斷程式碼寫在 `details.diagnostic_code` 中，例如 `duplicate-node-id`。

因發布被拒而失敗的 refresh 操作帶同樣的 `details.diagnostic_code`；抓取方面的 `stage`、`node` 與 `group_id` 只出現在 provider 的 `last_error` 中。清單的 `limit` 預設 100，範圍 1–1000；快照上限是 8 份、30 秒、4 MiB，容量不足時回傳 `503 snapshot_unavailable`，帶 `Retry-After`。游標無法識別時同樣回傳 `410 snapshot_expired`；可識別但過濾器或 `limit` 不同的游標回傳 `400 invalid_request`。

訂閱已啟用、且 supervisor 正在執行時，才能向 refresh endpoint 送出 POST。訂閱已停用，或沒有掛接 supervisor（`can_refresh: false`）時，回傳 `404 capability_not_supported`。同一個 provider 上不同的並行 refresh 回傳 409；保留的冪等重放先於衝突檢查。

`POST /providers/{id}/refresh` 要求空請求內容，可以帶 `Idempotency-Key`，回傳 202 操作回應。

重新整理成功的要求是真實的 revision-fenced 發布被接受；抓取成功或寫了快取都不算成功，HTTP 斷線也不會丟結果。虛擬的 inline provider 不能重新整理，也不能刪除。它關聯的是 `provider_id: inline` 的靜態、非內建節點；內建歸屬保持 null，訂閱 ID 仍是 UUID。

### 原生日誌與執行時設定

`record_logs` 預設為 `true`，獨立 `/logs` SSE 需求有效時允許擷取日誌，最多保留 512 筆、60 秒。日誌 capability 用 `max_buffered_records` 與 `retention_seconds` 宣告這兩個上限，並列出 `filters: [level, target]`。明確把執行時設定改成 `record_logs: "on"` 後，即使沒有用戶端也會持續擷取。設定中寫 `false` 就禁止擷取，改了要重啟。

記錄實際停止時會釋放日誌，續傳游標隨之失效。真實的 `ts`、`level`、`target` 會保留。只有審查過的靜態訊息，以及有界、型別明確的安全欄位可以輸出；其他 `message` 與 `fields` 明確標記為不輸出。honk 不靠正規表示式去猜所有秘密，也不轉發主控台或 Clash 的格式化輸出。

`GET /logs` 以 SSE 向已認證的呼叫方與已放行的匿名 loopback 呼叫方回傳 `stream.ready` 和日誌，可選最低 `level` 與 `target` 字首作為過濾。續傳使用 `Last-Event-ID`，游標繫結串流、實例與過濾器。續傳順序和 `/events` 一樣，是 ready、重放、即時：ready 保留請求中的游標，之後才由重放推進。

`GET /logs` 接受 `level` 與 `target`。`level` 是小寫的 `error`、`warn`、`info`、`debug` 或 `trace`，預設 `trace`；`target` 是 1–256 位元組的模組路徑字首。過濾只是從已擷取的記錄中挑選，不會提高擷取等級。每個 `log` 事件的資料是 `{ts,level,target,message,fields}`，`fields` 可空。不會輸出的訊息顯示為 `[message withheld: not audited for native disclosure]`。

每條串流最多 16 個用戶端，每個用戶端最多排隊 64 個事件，每 15 秒送一次心跳註解。16 個名額用滿後，新連線回傳 `503 temporarily_unavailable`，帶 `Retry-After`。游標過期、屬於別的串流或實例、或過濾器不同時，在 HTTP 200 之前回傳 `409 event_cursor_expired`；佇列已滿或重放記錄遺失時直接斷流。

縮容會讓被淘汰記錄的游標失效。

和 Clash `/logs` 一樣，擷取始終排除 `quinn::endpoint` 目標：它由 endpoint 驅動任務報出的 ERROR，會和 honk 自己回報、帶情境的 carrier 故障重複。

`PATCH /runtime/settings` 使用 JSON 合併語意，只接受 capability 宣告列出的欄位：

完整合併請求範例：`{"log":{"level":"debug","buffered_records":128},"flows":{"retention_seconds":60}}`。

| 欄位 | 允許的值 | 設定值 |
| --- | --- | --- |
| `record_flows`、`record_logs`、`record_dns_log` | `"on"`、`"off"`、`"auto"` | `"auto"` |
| `log.level` | `trace`、`debug`、`info`、`warn`、`error` | 設定的原生日誌擷取等級 |
| `log.buffered_records` | 64–512 | 512 |
| `dns_log.max_records` | 64–512 | 512 |
| `flows.max_flows` | 64–1024 | 1024 |
| `flows.retention_seconds` | 1–300 | 300 |
| `geodata` | 見 [Geodata 來源與自動更新](#geodata-來源與自動更新) | 單獨儲存，不因啟用重設 |

未知欄位、null、空物件與越界值都算結構或邊界錯誤，回傳 `400 invalid_request`。`geodata: null` 是例外，它表示清除已儲存的 geodata 設定。geodata 的憑證 admission 先於結構驗證執行：請求中含 `geodata` 的匿名請求會先拿到 `403 permission_denied`。不在 `resources.runtime_settings.fields` 中的欄位回傳 `422 unsupported_value`，例如設定禁止了對應記錄器時的 `log.*`、`dns_log.*`、`flows.*`，或沒有狀態資料庫與 geodata owner 時的 `geodata`。

GET 與成功的 PATCH 回傳內部一致的記錄器設定快照，含 `source: "config"|"runtime"`。geodata 單獨讀取，可能已經反映了並行更新。設定中的 `log.buffered_records` 與 `dns_log.max_records` 都是 512，`flows.max_flows` 是 1024，`flows.retention_seconds` 是 300。

整個合併結果通過驗證後，記錄器設定由同一個 owner 原子發布，`source` 為 `runtime`。只改 geodata 時，頂層 `source` 保持不變。縮容會淘汰舊記錄，並讓受影響的游標失效。

capability 宣告的是取值範圍，不是目前值：`logs.min_buffered_records`、`dns_log.min_records` 與 `flows.min_flows` 都是 64；`flows` capability 宣告回傳 `max_flows` 與 `retention_seconds` 的上限，即 1024 與 300。修改 `log.level` 會同時替換主控台與日誌檔案的過濾器，包括由 `RUST_LOG` 或 `--debug` 設下的過濾器。Clash `/logs` 仍依各請求的等級過濾。

這些執行時覆寫值不會寫進 `.dae` 或快取資料庫。每次明確的設定啟用被接受時，包括 no-op 或提交後 degraded 的啟用，都會恢復設定中的等級、啟動時的主控台與日誌檔案過濾器、初始留存上限，並把記錄模式重設成 `"auto"`。啟用被拒絕、provider 重新整理或網路重新整理時，執行時設定保留。

`geodata` 單獨儲存，不受啟用影響，見 [Geodata 來源與自動更新](#geodata-來源與自動更新)。

在頂層記錄欄位中，`"on"` 讓已放行的記錄器一直開著，`"off"` 強制關閉。初始的 `"auto"` 讓 flow、日誌、DNS 日誌各自依對應的獨立診斷需求決定。省略的欄位保持不變。

null 會被拒絕。設定中寫了 `false` 就禁止記錄；執行時請求開啟這個記錄器，會讓整次 PATCH 以 `422 unsupported_value` 被拒絕。哪些等級與留存控制可用，由設定權限決定，和記錄器是不是暫時停著無關。

GET 與成功的 PATCH 回應中有唯讀的 `recording`：`flows`、`logs`、`dns_log` 各含 `{allowed, mode, active}`，其中 `mode` 為 `"auto"`、`"on"` 或 `"off"`。`events.active` 表示事件擷取是否開啟；`grace_remaining_seconds` 表示通用連線的寬限期還剩幾秒，不是任何獨立 flow、日誌或 DNS 日誌診斷需求的倒數計時。還有通用串流連線時，這個欄位為零。

讀取設定不會延長任何期限。

### 主檔案項目與 geodata 管理

`POST /api/v1/nodes` 接受 1–8192 個字元的連結。更長的宣告要透過編輯設定來源寫入，例如接近 16 KiB header 上限的 XHTTP `extra`。引擎拒絕的連結回傳 `422 unsupported_value`，`error.message` 是解析器給出的靜態原因，例如 `XHTTP xPaddingBytes must stay within 1-8192`，`details.fields` 為 `["name","link"]`。

回應不會回顯提交的名稱、連結或選項值，也不會寫入任何內容。`POST /api/v1/providers` 用同樣方式回報被拒絕的訂閱項目。其他拒絕仍然使用通用訊息。

`resources.nodes.can_manage` 與 `resources.providers.can_manage` 要求來源協調器正在執行，已接受的主檔案可寫，且不含 API 憑證。建立節點提交 `{"name":"edge","link":"socks5://192.0.2.2:1080"}`。建立 provider 提交 `{"name":"feed","kind":"subscription","url":"https://example.net/sub"}`。

`resources.providers.create_options` 列出省略 provider 欄位時實際生效的預設值：

| 欄位 | 限制 | 內建預設值 |
| --- | --- | --- |
| `update_interval` | 秒，最多一年；`0` 表示僅依請求重新整理 | `86400` |
| `user_agent` | 1–256 個可列印 ASCII 字元 | `honk/<version>` |
| `cache` | 僅在 `global.store_subscribe` 開啟訂閱儲存時可用 | `true` |

如果 `assets.subscription` 設定了對應的預設值，`create_options` 回傳那個值，而不是內建的 fallback 值。

`resources.providers` 還會宣告 `create_unfetched: true`，表示支援先建立、暫不抓取的方式。明確寫了選項的 provider 會寫成 `tag: 'url' { ... }`，`ua`、`interval` 與 `cache` 各佔一行。結構中的長度、匹配模式、型別、interval 或 user-agent 邊界不滿足時，回傳 `400 invalid_request`。

未宣告的選項回傳 `422 unsupported_value`，例如沒有 store 時的 `cache`。嚴格 JSON 與 64 KiB 內容限制不變。這裡沿用引擎解析器、完整離線 admission、相對於 FD 的耐久寫入與實際 reload。

只有啟用與訂閱協調都完成之後，才以 `201` 回傳目前的 Node 或 Provider 與 `Location`。HTTP 斷線不會取消已經入佇列的工作。使用 `--store db` 時，這些操作記錄新修訂，不重寫主檔案。

節點名稱 1–64 字元，連結最多 8192 字元。provider 名稱是 1–64 個 ASCII 字母、數字或 `_.-`，HTTP(S) URL 最多 4096 字元。違反結構定義中的長度、匹配模式、列舉或邊界要求時，回傳 `400 invalid_request`。

重名回傳 409。結構合法但不支援的連結、身分、provider URL scheme 或選項回傳 422。新 provider 即使有舊的快取內容，也從零節點、`stale`、沒有更新時間的狀態開始。

同一個來源定義上的延遲抓取狀態，會在無關編輯與 reload 中保留，直到明確 refresh。修改這份 specification 或重啟之後，恢復一般的訂閱啟動行為。API 不會建立相同抓取設定的別名。

刪除時如果歸屬有歧義，直接拒絕，不會轉移 ID 或節點。

DELETE 不接受請求內容與查詢參數：帶了任意一個就回傳 `400 invalid_request`；內容超限回傳 `413 request_too_large`。兩種都不帶 `Retry-After`。未知 ID 回傳 `{"deleted":0}`，不寫入。成功刪除則在啟用之後回傳 `{"deleted":1}`。

內建節點、訂閱派生節點、非主檔案項目，以及不支援或有歧義的歸屬，都回傳 `404 capability_not_supported`。靜態 include 仍然在 inline 檢視中可見。固定的用戶端契約沒有逐節點的 `writable` 欄位，所以介面上的刪除按鈕仍可能被拒絕。

刪除被某個群組用作 `final` 的節點回傳 `409 state_conflict`，`details.groups` 列出這些群組的 ID。其他仍被引用的項目要先改掉引用，否則寫入前的驗證會失敗。主檔案讀取之後又在磁碟上被改動時，回傳 `409 state_conflict`。

編輯已有項目仍然用來源 PUT；節點與 provider 都沒有 PATCH 介面。

這些同步動作和來源 PUT、群組 PATCH、SIGHUP 共用協調器，會檢查已接受修訂、磁碟位元組與依賴，但攔不住任意的外部編輯器。失敗時的 `details` 含 `stage`、`written`、`durability_confirmed` 與 `committed`；這類同步寫入始終帶 `stage`，`durability_confirmed` 只在 `written` 為 true 時出現。無法確認時為 null，不偽造成 false。

生命週期與執行失敗回傳帶 `Retry-After` 的 503；POST 重名衝突回傳 409；寫入期間磁碟上的來源被改動時回傳 `409 state_conflict`，這類請求沒有前置條件。DELETE 的其他驗證失敗仍然對映成 503。已經耐久寫入、但啟用被拒絕時，回報 `written:true` 與 `committed:false`。

`--store db` 在啟用之前不寫入，被拒絕時回報 `written:false`。提交後 degraded 時回報 `committed:true`，並帶上 `active_generation_id`；無法確認時為 null，不承諾復原。來源 PUT 仍然使用獨立的磁碟 hash If-Match，舊編輯器在管理修改之後會收到衝突。

已放行的匿名 loopback 請求與 Bearer 認證請求會讀到同一份 geodata。geodata 的 GET 依既有的 router-before-config 鎖序讀取流量與 DNS 的保留中繼資料，不掃描磁碟，也不連網。這裡的 hash 與大小屬於已載入的位元組，不是之後在磁碟上做的外部編輯。

`GET /geodata` 回傳 `{observed_at,assets}`。資產為 `{kind,sha256,size_bytes,modified_at,source_redacted}`：`kind` 為 `geosite` 或 `geoip`，`size_bytes` 是十進位字串，`modified_at` 與 `source_redacted` 可空。存在已初始化的 geodata owner 時，每個資產還含 `fetched_url_redacted`、`verified` 與 `download_route`，回應也含下文的更新狀態欄位。

沒有記錄或前後不一致的修改時間為 null。`source_redacted` 保留了欄位名，在 GET 與成功操作的結果中回傳第一個下載 URL：去掉 userinfo、查詢與片段，可能含憑證的路徑段替換成 `[redacted]`，再遮蔽 listener secret。沒有 URL 的資產，或無法安全顯示的 URL，為 null。

沒有用到的資產不會列出。已載入快照互相衝突時回報不可用，不會隨便挑一個。

更新需要 `config_write`、來源寫入權限，且每個已載入資產都要有下載 URL：來自設定檔的 `assets.geodata.geosite`/`assets.geodata.geoip`，或在來源可設定時來自已儲存或內建的 URL，見下節。URL 不作為請求參數。只接受最終直達的 HTTP(S) URL，拒絕 userinfo、片段、redirect 與 content encoding。

HTTPS 會驗證憑證。直連請求只用設定中那個數字位址的 `global.bootstrap_resolver` 解析網域名稱，不會退回系統 DNS。`routing` 依路由規則匹配時，先用這個解析器查網域名稱；沒設定或查詢失敗時，再查 `/etc/hosts` 與系統網域名稱伺服器。

請求使用下一節說的下載路由，預設是 `routing`。一次更新最多兩個資產，各 256 MiB。每個 URL 對應的檔案必須在請求送出後 30 秒內送出回應 header；內容每次停頓不得超過 30 秒，整個下載最長 10 分鐘。

檔案下載完成後，校驗檔案請求另有 10 秒 deadline，涵蓋路由決策、網域名稱解析、隧道與 TLS 在內的整個請求。校驗、磁碟操作與必須完成的等待，都不構成硬性的總時限保證。

要等全部下載完成、解析並編譯出完整候選之後，才會替換任何檔案。新檔案缺少目前設定用到的分類時，更新以 `asset_validation_failed` 失敗，已載入的檔案保持不變。已載入檔案位於 `global.data_dir` 或 `$DAE_LOCATION_ASSET` 時，就地替換。

已載入檔案來自優先順序更低的位置時，例如套件安裝的 `/usr/share/honk`，honk 不會覆寫它，而是改在 `global.data_dir/<file>` 新建檔案；如果這期間該路徑已經出現了檔案，就拒絕替換。此後查詢時會優先使用新檔案。檔案透過不跟隨符號連結的父目錄 FD 與檔案 FD 開啟；別名、位元組、來源或依賴衝突，以及不安全的路徑，都拒絕。

父目錄分量只在安全開啟之後才做身分正規化。各檔案獨立原子替換，並確認耐久，這不是跨多個檔案的原子交易。第一個 rename 之後失敗時，會保留逐資產的 written 與 durability 資訊，不會自動撤回。

實際 reload 在 no-op 與重建兩條路徑上都使用不可變的、已驗證的 geo 快照，之後磁碟上的改動替換不了啟用的位元組。成功結果來自實際發布的 GeoData。被拒絕或降級時仍然失敗，並回報提交資訊。

重試之前，先修掉磁碟上的衝突。快取訂閱仍然參與 admission 的依賴檢查，但它的指紋
標籤指向資料庫列，不是檔案路徑。geodata 更新會在 rename 之前做最後一次重新擷取，
檢查內容有沒有變；只有真實的檔案依賴才會取得 inode guard。

`POST /geodata/update` 不帶內容。同 key 的冪等重放先於互斥檢查；不同的在途請求回傳 409；操作容量滿回傳 503。`202` 只代表常駐程式接手了，不代表檔案或路由已經改變。

下載內容和已載入檔案相同的資產不會寫入。所有資產都相同時，更新直接成功：不啟用，不產生 generation 事件，也不改 `runtime.last_reload`。更新一旦進入啟用階段，之後就會寫 `runtime.last_reload`。

啟用之前失敗時，這個欄位不變。

### Geodata 來源與自動更新

有狀態資料庫、且 geodata owner 已初始化時，`resources.geodata.configurable_sources` 為 true，`runtime_settings.fields` 中會列出 `geodata`。capability 還會回報 `max_urls: 4`、`interval_hours: {min: 6, max: 168, default: 24}` 與 `lifecycle: {file_values: start, overrides_persist: true}`。在 cron 排程下，`interval_hours` 讀出來就是這個預設值。`lifecycle` 說明設定檔的值只在啟動時讀取，而 API 覆寫在重啟後仍然保留。不管有沒有狀態資料庫，`checksum` 都是 `sha256sum`。啟用原生 API 時，honk 總會嘗試開啟 `<data_dir>/state/honk.db`。

資料庫模式、啟用了 `password_auth`、資料庫裡是外來的 application ID 或更新的 schema、或者資料庫被另一個 honk 實例佔用時，開啟失敗會中止啟動。其他開啟失敗時，honk 可能以無持久化的模式繼續執行。開啟成功時，設定會存在其中一張嚴格表 `geodata_settings` 中，重啟與啟用之後都保留。

如果這張表打不開，listener 仍會啟動，記錄一條 warning，不宣告 geodata capability。沒有狀態資料庫或 geodata owner 時，只用設定檔中的 URL，以下這些欄位都不會出現。

這種情況下，`GET /runtime/settings` 中會含 `geodata`：`source`、`geosite.urls`、`geoip.urls`、`auto_update`（`enabled`、`interval_hours`、`cron`）、`download`（`route`、`group_id`）與 `verify_checksum`。只有已儲存的設定生效。啟動時，honk 會把 `assets.geodata` 中設定的下載 URL、出口、`auto_update`、`cron` 或 `checksum` 寫進已儲存的設定，覆寫透過 API 改過的值。

如果設定檔沒有給某個資產設定 URL，之前由設定檔寫入的清單會被刪掉，改用內建 URL；透過 API 改過的清單則保留。更新排程與 `verify_checksum` 同理：設定檔不再設定時，之前由設定檔寫入的值會被刪掉，恢復預設值；API 改過的值保留。設定檔中的下載 URL、出口、更新排程與校驗開關，都由啟動階段持有。

reload 如果改變這些生效值，會因為需要重啟而被拒絕；因此其他啟用不會動到已儲存的設定，透過 API 改過的 URL 會保留到下次啟動。

| `source` | 說明 |
| --- | --- |
| `config` | 已儲存的清單全部來自設定檔。 |
| `override` | 至少一個已儲存清單來自 API URL 修改。 |
| `default` | 沒有已儲存清單。使用內建 MetaCubeX `meta-rules-dat` 發行檔案，先嘗試 raw.githubusercontent.com，再嘗試 fastly.jsdelivr.net。 |

`download.route` 決定每個 geodata 請求的出口，校驗檔案請求也算。`routing` 是預設值，和使用者流量一樣遵循路由規則。`group` 始終走 `group_id` 指定的那個群組，這個 ID 就是 `GET /groups` 回傳的 ID。

`direct` 用 bootstrap 解析器解析主機，並以 bypass mark 直連。走規則或群組的請求，和外部 UI 下載共用路由決策與隧道。路由不可用時，這個 URL 會依連線錯誤失敗：

| `last_error.code` | 條件 |
| --- | --- |
| `group_unavailable` | 群組不存在或沒有可選成員 |
| `route_blocked` | 路由規則選擇 `block` |
| `connection_failed` | 隧道無法建立 |

之後 honk 會改試下一個 URL，不會退回直連。啟動後不久，如果路由或規則選中的群組還沒有可達節點，更新也依連線錯誤處理。經節點下載時，網域名稱由節點出口解析。

啟動時，`assets.geodata.route` 優先於 `assets.route`，生效的出口會寫進已儲存的設定，覆寫 API 改過的值。設定檔沒有設定出口時，保留透過 API 改過的出口；否則遵循路由規則，並刪掉之前由設定檔寫入的出口。

出口不影響 `source`。見 [Assets 參考](./assets.md)。

`PATCH /runtime/settings` 會合併並儲存 `geodata`，不觸發下載。`urls` 清單含 1–4 個互不相同的 HTTP(S) URL，每個最長 4096 位元組，不含 userinfo 或片段，依 fallback 順序整體替換原清單。修改一個資產時只存這個資產的清單，`source` 不管原來是什麼都會變成 `override`，另一個資產仍然取設定檔或內建 URL。

`auto_update` 單獨儲存。帶 `interval_hours`（6–168）就切換成間隔排程，帶 `cron` 就切換成 cron 排程；同一個請求裡兩個都帶回傳 400，只帶 `enabled` 時保留目前排程。cron 排程讀出來是 `interval_hours: 24`，`cron` 為表示式；間隔排程的 `cron` 是 null。`assets.geodata.auto_update` 與 `cron` 會在啟動時寫進這裡，見 [Assets 參考](./assets.md)。`download` 也單獨儲存。`group` 路由必須帶 `group_id`，其他路由不能帶。

以下 `PATCH /runtime/settings` 請求內容分別只替換 geosite URL 清單，以及啟用經群組下載的 cron 排程：

```json
{"geodata":{"geosite":{"urls":["https://example.net/geosite.dat"]}}}
```

```json
{"geodata":{"auto_update":{"enabled":true,"cron":"0 3 * * *"},"download":{"route":"group","group_id":"<id-from-GET-groups>"}}}
```

cron 語法與日曆解析不依賴時區。geodata owner 啟動與 PATCH 還會拒絕一種明確的 cron：在實際本地時區中沒有未來的觸發時間，即使 `enabled: false` 也拒絕。保留的排程要到啟用時才做這個檢查：不可用的排程仍然可以透過 PATCH 停用或修正，有效的檔案覆寫值也能在啟動時修正舊的已儲存排程。不可用的排程不會被換成預設值。

ID 不對應目前任何群組時回傳 `409 state_conflict`。已儲存的群組被後續啟用刪掉後，`group_id` 讀出來是 null，下載以 `group_unavailable` 失敗，直到改動路由為止。`verify_checksum` 單獨儲存，`assets.geodata.checksum` 在啟動時寫進它。

`"geodata": null` 刪除已儲存的設定。設定檔中的值會在下次啟動時重新寫入。頂層 `source` 不受影響。

`geodata` 和其他欄位在同一個請求中一起驗證，任何一部分驗證失敗，全部都不改。匿名
loopback 主體不能修改 `geodata`，會收到 `403 permission_denied`。所有已放行的呼
叫方都能讀到原始 URL，只有 listener secret 被遮蔽。如果 geodata 已經儲存，而關閉
過程讓記錄器設定無法生效，PATCH 回傳 `503 temporarily_unavailable`，並帶
`details.geodata_stored: true`；已儲存的 geodata 不會復原。

更新會依序嘗試資產的各個 URL；遇到連線錯誤、非 200 狀態、逾時或校驗失敗，就改試下一個。校驗檔案的 URL 是在原 URL 路徑末尾加上 `.sha256sum`，查詢部分保留。回傳 200 時，它的第一個欄位必須等於檔案的 SHA-256。

回傳 404 視為沒有發布校驗檔案，檔案依未校驗處理。其他狀態或失敗，都會讓這個 URL 失敗。某個資產的所有 URL 都失敗時，失敗詳情描述最後嘗試的那個 URL，給出 `stage` 與失敗的資產 `asset`（`geosite` 或 `geoip`）。

如果這個 URL 是因為伺服器回應而失敗，還會給出該回應的 `http_status`，也就是檔案回傳非 200，或校驗檔案回傳非 200 且非 404 的那個狀態。`asset: geoip, stage: checksum_unavailable, http_status: 403` 表示伺服器拒絕的是 `.sha256sum`，不是檔案本身。設定檔、已儲存與內建的 geodata URL，包括校驗檔案請求，都不設位址或連接埠白名單。

`verify_checksum` 預設為 `true`。設成 `false` 後，手動與自動更新都不再請求 `.sha256sum`，下載的檔案一律依未校驗處理：`verified` 為 `false`，`sha256` 照常回報。這個設定用於那些缺少校驗檔案時會回傳非 404 狀態、或回傳非校驗內容頁面的鏡像站。

以 `checksum_unavailable` 或 `checksum_mismatch` 失敗時，日誌中的 warning 會指出這個設定。校驗不會被自動關掉。

geodata owner 存在時，`GET /geodata` 還會報告下面這些欄位：

| 範圍 | 欄位 | 說明 |
| --- | --- | --- |
| 每個資產 | `fetched_url_redacted` | 已載入檔案的下載 URL，顯示方式與 `source_redacted` 相同 |
| 每個資產 | `verified` | 下載是否經過校驗 |
| 每個資產 | `download_route.route` | 該次下載使用的路由設定 |
| 每個資產 | `download_route.group_id` | 請求經過的群組，包括規則選中的群組；否則為 null |
| 頂層 | `last_checked_at`、`last_updated_at`、`next_check_at`、`last_error` | 更新狀態與排程 |
| 頂層 | `required_codes` | 目前設定為每個已載入資產引用的分類，依順序排列 |

`last_error.code` 表示失敗階段，例如 `http_status_rejected`、`checksum_mismatch` 或 `asset_validation_failed`。

`last_checked_at`、`last_updated_at`、`last_error` 與連續失敗次數都存在狀態資料庫的嚴格表 `geodata_status` 中。每次啟動會依這些狀態重新計算 `next_check_at`，並重新抽一次隨機延遲；這個欄位本身不儲存。

每個資產的欄位只存在記憶體中。重啟後、下一次嘗試之前，這些欄位為 null，`verified` 為 false。

自動更新預設開啟，每天本地時間 03:00（`0 3 * * *`）。把 `auto_update.enabled` 設成 `false` 就關掉。cron 排程在上次記錄的檢查之後、表示式依系統本地時區給出的第一個時間執行；間隔排程則在上次檢查之後過了一個間隔時執行，這種排程可能由 API 設定，也可能是沿用 cron 排程出現之前存下的記錄。啟動後從上次記錄的檢查時間繼續計時。

不存在的本地時間會跳過；重複的時間只在第一次出現時觸發。如果之後的時區變化讓排程變得不可用，honk 在進入該狀態時發出一條 warning，不再安排未來的排程下載。失敗退避仍然單獨生效，因此 `next_check_at` 仍可能表示重試時間。`last_error` 繼續描述最後一次實際的更新嘗試。

符合以下任一條件時，第一次檢查在啟動後五分鐘再加隨機延遲執行：

- 上次檢查距今已超過等待時間，或此後已經錯過 cron 表示式給出的時間。
- 上次檢查時間晚於目前時間，也就是時鐘曾經超前。
- 沒有上次檢查記錄。

因此重啟不會立刻觸發下載；重啟間隔比更新排程還短的主機，也仍會更新。`POST /geodata/update` 可以立即更新。

自動更新使用同一個 `geodata_update` 操作。自動更新執行期間，手動更新回傳 `409 state_conflict`。

自動更新到期時如果已經有更新在執行，下次時間由那次更新的結果決定。每次排程檢查都加 0–60 分鐘的隨機延遲。連續失敗後先等 1 小時，之後每次失敗加倍，但不會晚於下一次排程檢查；失敗次數在重啟後保留。

成功後恢復正常排程。

### 內嵌 doona 來源

預設關閉的 `native-ui` 隱含啟用 `native-api`。建置時內嵌以下兩個版本：

| 版本 | 資產絕對目錄 |
| --- | --- |
| 標準版 doona | `HONK_DOONA_DIR` |
| doona lite | `${HONK_DOONA_DIR}-lite`，忽略 `HONK_DOONA_DIR` 的末尾斜槓 |

兩個目錄都必須含 `index.html`。只需設定 `HONK_DOONA_DIR` 這一個環境變數。

| `.github/ci/pins.env` 中的固定項 | 值 |
| --- | --- |
| doona 版本 | `0.1.0-rc.5` |
| 提交 | `6102778700c6cd15908cf2a76be7121d0355da21` |
| 壓縮檔檢查碼 | `DOONA_SHA256`、`DOONA_LITE_SHA256` |

在倉庫根目錄執行 `export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`。指令碼依序執行：

1. 從固定發行版本下載兩種壓縮檔。
2. 分別核對壓縮檔的檢查碼。
3. 檢查各包中的 `THIRD-PARTY-NOTICES.txt` 及其 `NOTICE` 引用的全部 `LICENSES/` 檔案。
4. 刪除字型，將標準版解壓到指定目錄，將 lite 解壓到其 `-lite` 同級目錄。
5. 只輸出標準版目錄。

未設定該變數時，`just lint` 與 `just test-ci` 自動執行指令碼。

完整發行產物包含內嵌 UI，精簡的 `-clash-api` 與 `-native-api` 產物不包含。二進位檔中內嵌兩個版本各自的宣告；每個完整發行壓縮檔也會在 `doona/` 與 `doona-lite/` 目錄中附帶這些檔案。lite 版使用系統字型。

內嵌產物不含 Noto Sans TC 與 SC 字型。doona 的 CSS 用 `font-display: optional` 宣告這些字型，因此字型請求回傳 404 時，瀏覽器會使用系統字型。

需要 Noto Sans 時，可以從以下兩種方式中選一種：

- 從 [doona 發行頁](https://github.com/Zakkaus/doona/releases)下載 `doona-<version>.tar.gz` 與 `doona-fonts-<version>.tar.gz`，解壓到同一目錄，並讓 `ui` 指向該目錄。
- 安裝 `doona` 與 `doona-fonts` 套件，並設定 `ui: /usr/share/doona`。

兩個版本共用的 GPL-3.0-only 原始碼，是 doona 標籤 [`v0.1.0-rc.5`](https://github.com/Zakkaus/doona/tree/v0.1.0-rc.5)。發行流程會把 `doona-source-0.1.0-rc.5.tar.gz` 附加到正式標籤發行與滾動 Debug 發行上。這個包由 `ci/fetch-doona.sh --source` 產生：先確認標籤仍指向固定的提交，再執行 `git archive --format=tar --prefix=doona/ v0.1.0-rc.5 | gzip -n`，使用 GNU gzip。

再散布 `native-ui` 二進位檔時，要保留宣告，並依 GPL-3.0 第 6 條允許的方式提供對應的原始碼。

重現時，把原始碼包解壓到獨立目錄，使用符合 `^22.13.0 || ^24.0.0 || >=26.0.0` 的 Node 與 `pnpm@11.15.1`。在解壓後的原始碼目錄中依序執行：

1. `pnpm install --frozen-lockfile`。
2. `pnpm build`。
3. `pnpm -C apps/lite build`。
4. `SOURCE_DATE_EPOCH=1793194168 pnpm package`。

這個時間戳記是固定上游提交的時間。原始碼包中沒有 Git 歷史。需要安裝 brotli，`PATH` 中必須是 GNU tar 與 GNU gzip；已驗證的是 tar 1.35 與 gzip 1.15。

換成別的 gzip 實作，即使壓縮的是同樣的 tar 位元組，也可能得到不同的包摘要。Cargo 建置只內嵌 `HONK_DOONA_DIR` 與它 `-lite` 同級目錄中的檔案，既不建置也不下載前端。這份原始碼的檢查器是 `tools/conformance.mjs`。

即時 walk 是唯讀的，會跳過控制、診斷與缺少已觀測 ID 的資源。基礎契約與管理契約要分別核對，瀏覽器操作另外驗收。模式檢查通過，不等於完整的 UI、核心或部署矩陣都通過了。

### 連線關閉、模式與資料面生命週期

單項 DELETE 的 `204` 表示已經確認對應的 owner 完成關閉，而不只是刪掉了連線追蹤記錄：

| owner | 完成條件 |
| --- | --- |
| 精確 TCP UUID | 轉發任務結束 |
| 精確 UDP token/generation/source view | 完成退役、後端確認，以及已通過 admission 的傳送與回覆排空 |

共享 XUDP 只關閉目前檢視，不關閉其他檢視共用的 carrier，也不重放封包。

同一個 owner 還在連線追蹤記錄中時，並行或重複的關閉會共用同一個真實完成訊號，也就是 `Pending`，並繼承成功或 `Failed` 的結果。處於 `Closing` 或 `Failed` 狀態的 owner 不會被回報成 `Gone` 或 404。ID 不存在，或擷取的 owner 已被別的 incarnation 替換時，仍然回傳 `Gone` 或 404；不可關閉的非使用者態 owner 回傳 409；無法確認退役回傳 503。

批次關閉只擷取一次匹配集合，支援 `type=tcp|udp|all` 與不帶連接埠的 `src`。既沒限制網路也沒限制來源時，必須帶 `all=true`；只寫 `type=all` 不算過濾。匹配超過 1000 筆時先回傳 413，一條連線都不關。

成功時回傳實際的 `closed/skipped`。關閉選定集合之後新出現的連線不受影響。批次關閉中只要有一項退役無法確認，就等所有選定的連線處理完，再回傳 503，`error.details` 帶上 `closed/skipped` 計數；這些連線不會復原。

DELETE 請求內容必須為空。重複 `Idempotency-Key` 仍檢查目前連線狀態，不重放舊結果。

原生 `x-honk` 擴充中的 `runtime_mode` 暫時不可用：它固定的 PUT 契約沒有宣告生命週期衝突，也沒宣告 owner 或後端不可用時該回傳什麼錯誤；capability 也不區分讀寫。GET、HEAD、PUT 都回傳 `404 capability_not_supported`，不宣告接受任何 mode。內部共用的 `DatapathFlagsHandle` 與 Clash 控制仍然保留。

它不是 `dial_mode`，不覆寫 must/block 的終態，也不合成閘道器規則。只有在原生 API 未啟用時，才會快取模式。原生 API 啟用後，兩種 API 共用同一套臨時模式契約：不恢復，也不寫模式快取；啟動與成功且明確的設定啟用（包括 no-op）會把它重設成 `Rule`，provider 重新整理與網路重新整理則保留。

Global 繫結的是穩定身分：目標消失後，新流量依 fail-closed 處理，也就是拒絕轉發，不會退回一般路由，也不會改投同名的替代者。原生 API 未啟用時，保留原來的 Clash 快取行為。

明確的設定啟用時，設定提交與模式重設是兩個獨立的結果。路由與設定已經提交、但後端寫入模式失敗時，記錄器設定已經恢復成設定值，模式及其來源還保留著之前的值。控制面關閉 admission，回報 `committed-degraded`，操作失敗。

此時既不能聲稱 Rule 已生效，也不能聲稱設定已復原。實際狀態透過 Clash `/configs` 與操作結果檢查；`/configs` 只在啟用 Clash API 時可用。

正常的 no-op 接受也會觸發重設，provider 與網路更新則不觸發。

`GET /datapath` 與執行時中的資料面摘要都使用後端的程式、掛接、路由與 admission 觀測，不依設定的介面去猜。Mock 回報 `disabled` 與 `none`。真實觀測是 `partial`，沒有驗證過的事實保留未知值或 `null`，路由 generation 的身分獨立於執行時 generation。已知對映容量不代表知道佔用量。hook 只是掛上了，不代表 admission 已經開啟，也不宣告 `full_transparency`。

`GET /datapath` 回傳 `{observed_at,kind,state,visibility,ebpf,errors}`。`kind` 不是 `ebpf` 時 `ebpf` 為 `null`。`detail=full` 增加 `ebpf.attachments` 與 `ebpf.maps`，預設的 `summary` 省略二者。

| 欄位 | 取值 |
| --- | --- |
| `kind` | `ebpf`、`mock`、`unknown` |
| `state` | `active`、`degraded`、`detached`、`disabled`、`unknown` |
| `visibility` | `ebpf` 為 `partial`，其他為 `none` |
| `ebpf` | `backend: "real"`、`programs`、`hooks`、`routing`、`health`、可空的 `last_error`、`checked_at` |
| `ebpf.programs` | `loaded`、`not_loaded`、`error`、`unknown` |
| `ebpf.hooks` | `attached`、`detached`、`partially_attached`、`unknown` |
| `ebpf.routing` | `state`（`published`、`not_published`、`error`、`unknown`）、形如 `<instance>:datapath:<n>` 的可空 `generation_id`、為 `null` 的 `epoch` |
| `ebpf.health` | `healthy`、`degraded`、`unknown` |
| `ebpf.attachments[]` | `name`、`kind: "interface"`、`interface`、`direction`（`ingress` 或 `egress`）、`state`（`attached`、`detached`、`error`、`unknown`） |
| `ebpf.maps` | `state`（`partial`、`error`、`unknown`）與 `conn_state`：`null` 或 `{occupancy,capacity,occupancy_known}` |

`errors[]` 為 `{code,message}`，`code` 取 `program_observation_failed`、`hook_observation_incomplete`、`routing_observation_failed`、`admission_observation_failed`、`map_observation_failed` 或 `observation_limit_reached`。

關閉時間沒有硬上限。abort async 的外層不會取消已經開始執行的 blocking 工作。StateTick 維護的 owner 超過名義停止期限後，honk 會記錄一條 warning，然後繼續等真實的 SQLite 工作結束。

憑證的 KDF 與資料庫工作、以及已經開始的系統解析與 NSS，同樣會等到真實結束。可選的[業務連線寬限等待](./global.md#關閉)不允許在清理階段超期時丟掉 owner，來聲稱關閉成功。

原生 HTTP 自己另有五秒的 graceful drain；上面這些阻塞等待結束之前，總退出時間還可能被拉長。見[終止所有權](../design/control-plane.md#終止所有權)。

## 啟用與認證

只有 `experimental.clash_api.external_controller` 非空，且二進位檔包含預設啟用的 `clash-api` feature 時，API 服務才會啟動。控制器位址必須是 `127.0.0.1:9090` 或 `[::1]:9090` 這樣的數字 socket 位址，不能寫 DNS 主機名稱。寫成 `:port` 會繫結到 `0.0.0.0:port`。

無效位址只會寫入日誌，不會停止引擎。

當 `experimental.clash_api.secret` 非空時，API 請求必須攜帶：

```http
Authorization: Bearer <secret>
```

WebSocket 升級也可以改用 `?token=<percent-encoded-secret>`。honk 會先對 token 做百分號解碼，再精確比較。查詢參數中的 token 認證只適用於 WebSocket 升級；一般 HTTP 請求要使用 Bearer header。

header 必須精確是 `Bearer ` 加憑證，大小寫一致，中間只有一個空格。WebSocket 升級帶了非空 `token` 時只檢查 `token`，不檢查 header，因此 `token` 寫錯時，即使 header 是對的也會失敗。失敗回傳 `401 {"message":"Unauthorized"}`。

`secret` 為空時關閉認證。`/ui` 靜態目錄不經過 API 認證層。

API 自身不提供 TLS。請把它繫結到 localhost，或在前方放一個 TLS 反向代理；如果有不可信的用戶端能存取 listener，必須設定足夠強的 `secret`。

Clash listener 允許任意 CORS 來源，沒有原生 API 那樣的 Host 與 Origin 檢查。

隨附的 `config.dae` 繫結的是 `127.0.0.1:9090`。如果控制器位址不是 loopback、`secret` 又為空，啟動會發出一條 warning，但仍然允許監聽；這時不管有沒有設防火牆，通配位址與已分配的介面位址都適用。

## endpoint 表

下表與 `crates/honk-core/src/clash_api.rs` 中的 router 一致。

| 方法 | 路徑 | 用途 |
| --- | --- | --- |
| GET | `/` | 回傳 Clash hello 文件；啟用外部 UI 託管時，將非 JSON 用戶端重新導向到 `/ui/`。 |
| GET | `/version` | 回傳 `honk <build-version>`（包含發行標籤，與 CLI 共用建置版本）及 Clash premium/meta capability 旗標。 |
| GET | `/configs` | 回傳目前模式、已實作的 Clash 相容設定快照，以及 `honk-diagnostics` 下目前設定的安全診斷。 |
| PUT | `/configs` | 相容性 no-op；接受請求並回傳 `204 No Content`。 |
| PATCH | `/configs` | 將 `mode` 設為 `Rule`、`Global` 或 `Direct`；匹配不區分大小寫。 |
| GET | `/proxies` | 回傳所有節點與群組，以及合成的 `GLOBAL` Selector。 |
| GET | `/proxies/{name}` | 回傳一個節點、群組或 `GLOBAL` Selector。 |
| PUT | `/proxies/{name}` | 用 `{"name":"member"}` 選擇 Selector 群組的直接成員；也可修改合成的 `GLOBAL` Selector。包括 Score 在內的自動群組會拒絕寫入。 |
| GET | `/proxies/{name}/delay` | 使用呼叫方的 `?url=`，對節點或群組執行按需代理延遲測試。已預熱的傳輸會重用；每個尚未預熱的可重用 session 或 QUIC 用戶端都會先在臨時執行時中預熱，再開始計時。 |
| GET | `/group/{name}/delay` | 使用呼叫方的 `?url=` 測試全部群組成員，最多並行 `URLTEST_MAX_CONCURRENT`（10）次代理撥號，並以相同計時語意回傳成功成員的延遲。 |
| GET | `/rules` | 每條路由回傳一列。簡單 matcher 使用原生 Clash rule type；組合、取反與 `must` 規則使用 `complex`，並保留完整 dae 語句。 |
| GET | `/connections` | 回傳連線快照；WebSocket 升級後改為推送快照。 |
| DELETE | `/connections` | 關閉所有已追蹤連線。 |
| DELETE | `/connections/{id}` | 關閉一個已追蹤連線。 |
| GET | `/traffic` | 透過 WebSocket 或分塊 JSON 列推送每秒流量。 |
| GET | `/memory` | 透過 WebSocket 或分塊 JSON 列推送行程 RSS。 |
| GET | `/stats` | 回傳下文所述的使用者態出站、ready 池、熱資源、Score 選路原因與 UDP 快照。 |
| GET | `/logs` | 透過 WebSocket 或分塊 JSON 列推送 tracing 事件；所有訂閱者共用一個 256 槽位的廣播佇列，`?level=` 預設為 `info`。 |
| GET | `/dns/query` | 經 honk DNS 解析 `?name=` 並回傳 DoH 風格 JSON；`?type=` 預設為 `A`。 |
| POST | `/cache/fakeip/flush` | 相容性 no-op，回傳 204；沒有持久化 FakeIP 對映可清除。 |
| POST | `/cache/dns/flush` | 清除存活 DNS 快取及其持久化 DNS 狀態。 |
| GET | `/providers/proxies` | 將非空群組暴露為 Clash proxy provider。每個 provider 是一個代理群組，不是訂閱；訂閱狀態見 [Provider 觀測與重新整理](#provider-觀測與重新整理)。 |
| GET | `/providers/rules` | 回傳目前空樁文件 `{"providers":[]}`。 |
| GET | `/ui`, `/ui/*` | 將 `/ui` 重新導向到 `/ui/`，並提供已設定的外部 UI 目錄。 |

一般 HTTP GET 下，`/traffic`、`/memory` 與 `/logs` 每列送一個 JSON 文件。`/logs` 只在有訂閱者時才開啟動態的 `tracing` 事件過濾；沒有訂閱者時，Clash 日誌層不格式化事件。每個訂閱者的等級過濾發生在共用佇列之後。

訂閱者落後時會跳過被覆寫的事件，且不會收到事件遺失標記。

`GET /` 回傳 `{"hello":"clash"}`；啟用外部 UI 且 `Accept` 不含 `application/json` 時，回傳指向 `/ui/` 的 302。`/ui` 以 301 重新導向。`GET /version` 回傳：

```json
{"version":"honk <build-version>","premium":true,"meta":true}
```

`GET /configs` 還回傳固定的相容欄位，它們不設定任何功能：`mode-list: ["Rule","Global","Direct"]`、值為 0 的 `port`、`socks-port` 與 `mixed-port`、為 `false` 的 `allow-lan` 與 `ipv6`、`bind-address: "*"`、設定的 `log-level`，以及 `tun: {"enable":false}`。

`GET /proxies` 回傳 `{"proxies":{"<name>":<document>}}`；`GET /proxies/{name}` 回傳單一文件。節點文件含 `name`、`type`、`udp: true` 與 `history`。群組文件含 `name`、`type`、成員名稱清單 `all`、TCP 選擇 `now` 與 `history`；Score 另含 `scoreVerification`。`GLOBAL` 含 `type: "selector"`、`all` 與 `now`，沒有 `history`。

節點 `type` 為 `Shadowsocks`、`Trojan`、`Vmess`、`Vless`、`Socks5`、`Hysteria2`、`Tuic`、`Juicity`、`AnyTLS`、`Direct` 或 `Reject`，其中 `Reject` 對應 `block`。群組 `type` 為 `selector`、`url_test`、`load_balance` 或 `fallback`；Score 回報為 `url_test`。`history` 項目為 `{time,delay}`，取最近一次真實 TCP IPv4 測量。

`GET /rules` 回傳 `{"rules":[{"type","payload","proxy"}]}`，由設定的路由規則產生，不含原生規則 ID，也沒有 fallback 列。

`GET /connections` 回傳 `{downloadTotal,uploadTotal,connections,memory}`。兩個總量是目前各列之和，`memory` 是行程 RSS 位元組數。每列為 `{id,metadata,upload,download,start,chains,rule,rulePayload}`。`metadata` 含 `network`、`type`、字串形式的 `sourceIP`、`destinationIP`、`sourcePort` 與 `destinationPort`、`host`、`dnsMode: "normal"`、`process` 與 `processPath`；未知值為 `""`。

WebSocket 連線上，`?interval=` 設定推送間隔，單位毫秒，預設 1000。它會向上取整到 100、200、500、1000、2000、5000、10000、30000 或 60000，最大 60000。

`DELETE /connections/{id}` 在連線已關閉或 ID 未知時回傳 204，無法關閉時回傳 409，關閉失敗時回傳 503。`DELETE /connections` 回傳 204，任一關閉失敗時回傳 503。兩者都沒有回應內容。

`/traffic` 幀為 `{"up":<bytes>,"down":<bytes>}`，即上一幀以來的位元組數。`/memory` 幀為 `{"inuse":<rss-bytes>,"oslimit":0}`；無法讀取 RSS 時 `inuse` 為 0。

`/logs?level=` 接受 `trace`、`debug`、`info`、`warn`、`warning` 或 `error`，不區分大小寫；其他值回傳 `400 {"message":"invalid log level"}`。幀為 `{"type":"<level>","payload":"<text>"}`。

`GET /dns/query` 接受 `name` 與 `type`。`type` 可以是 `A`、`NS`、`CNAME`、`SOA`、`PTR`、`MX`、`TXT`、`AAAA`、`SRV`、`SVCB`、`HTTPS`、`CAA` 這些名稱，不區分大小寫，也可以是數字。缺少名稱或型別無效時回傳 400。回應是數字型別的 DoH JSON：

```json
{"Status":0,"Question":[{"name":"example.com","type":1}],"Answer":[{"name":"example.com.","type":1,"TTL":60,"data":"192.0.2.1"}]}
```

解析失敗時仍回傳 200，`Status` 為 2，`Answer` 為空。

`GET /providers/proxies` 回傳 `{"providers":{"<group>":{"name","type":"Proxy","vehicleType":"Compatible","updatedAt":null,"proxies":[...]}}}`，每個代理為節點文件。

### `/configs` 中的診斷資訊

`GET /configs` 保留現有的 Clash 欄位，另外新增 `honk-diagnostics`。設定項與診斷資訊來自同一份已提交的設定快照。啟動時只發布通過 admission 的檔案診斷與訂閱診斷。reload 失敗或訂閱重新整理被拒絕時，目前診斷清單保持不變；介面不快取最近一次失敗的嘗試。

有效設定沒變的成功 reload，可以替換診斷資訊而不遞增 `generation`。訂閱重新整理通過授權與 admission 檢查之後，只替換這個訂閱的診斷，即使節點沒變也一樣；靜態檔案與其他訂閱的診斷保持不變。

函式庫呼叫方要傳給 `ControlPlane::reload_runtime_config(config, diagnostics)` 一個 `DiagnosticBuckets`，分別儲存靜態設定與訂閱內容的診斷。程式裡建構、沒有診斷的輸入用 `DiagnosticBuckets::default()`。`merge_subscription_nodes(provider, nodes, diagnostics)` 接收這個訂閱的診斷向量，也支援已通過 admission 但沒有 worker 宣告的訂閱。

完整設定替換會移入候選設定的全部診斷來源資訊；訂閱替換只影響對應的訂閱。SIGHUP 只保留重建候選設定時實際沿用的那些訂閱內容的診斷。自動產生的拓撲與 ECS 更新保留原輸入的來源。

所有修改都沿用設定寫鎖的發布屏障：先拿設定鎖，再拿診斷鎖。

完整替換的酬載中，provider bucket 必須使用唯一的 UUID。出現重複 UUID 時，整個 reload 會在發布前被拒絕，即使有效設定沒變也一樣；目前設定與診斷都保持不變。

| 欄位 | 說明 |
| --- | --- |
| `honk-diagnostics.generation` | 目前設定的 `generation`；啟動時為 `0`。 |
| `honk-diagnostics.sources` | 保留的診斷所引用的來源及這些來源的祖先，僅包含中繼資料。 |
| `sources[].id` | 本次快照內的不透明數字來源識別碼，供 `diagnostics[].source` 引用。 |
| `sources[].ordinal` | 來源在單次解析嘗試的來源表中的原始序號，從 `0` 開始。 |
| `sources[].parent` | 父來源的 `id`；根來源為 `null`。 |
| `honk-diagnostics.diagnostics` | 目前設定與已通過 admission 的訂閱保留的安全診斷。 |
| `diagnostics[].code` | 穩定的診斷程式碼。 |
| `diagnostics[].severity` | 小寫嚴重等級：`info`、`warning` 或 `error`。 |
| `diagnostics[].source` | 對應的 `sources[].id`。 |
| `diagnostics[].span` | 從 `0` 開始的位元組範圍 `{start, end}`，不含 `end`；未知時為 `null`。 |
| `diagnostics[].line` | 原始文字中的行號；未知時為 `null`。 |
| `diagnostics[].byte_column` | 依位元組計數的欄號；未知時為 `null`。 |
| `diagnostics[].setting` | 含原始項目序號的固定設定欄位路徑，不含使用者提供的名稱。 |
| `diagnostics[].value` | 安全值表示；私有值經過遮蔽。 |
| `diagnostics[].message` | 靜態診斷訊息。 |
| `diagnostics[].entry_index` | 原始項目序號；未知時為 `null`。 |
| `diagnostics[].related_indices` | 相關原始項目的序號。 |
| `diagnostics[].terminal` | 該診斷是否表示本次嘗試的終止錯誤。 |

設定的 `generation` 與目前 DNS 執行時一致。來源識別碼只在本次快照內有效，不是檔案
系統識別碼。來源的排列順序是：先靜態檔案，再依設定中的訂閱宣告順序，最後依保留
bucket 的順序列出已通過 admission 的非 worker 訂閱；各來源表內部保留原始順序。只
列出診斷引用到的來源及其祖先，不匯出檔案路徑、原始輸入、憑證、訂閱名稱或訂閱 ID。

### 延遲測量

兩個介面使用上表所列的 URL 參數與並行上限。

兩個延遲介面都接受以毫秒計的 `timeout`；省略或為 0 時為 15000。範例：`GET /proxies/edge/delay?url=https%3A%2F%2Fexample.com%2Fgenerate_204&timeout=5000`。

延遲測試使用正規的 HTTP 檢查目標解碼器。HEAD 保留原始路徑與查詢字串，點段與只有查詢字串的 `/?query` 也算在內；authority 會去掉憑證與預設連接埠；片段不會送出。它和週期健康檢查共用 HTTP 實作，回報第二輪請求的熱路徑 RTT，不含代理撥號、目標 TLS 與第一輪請求。HTTPS 會驗證憑證，協商 HTTP/2 或 HTTP/1.1，並停用伺服器 push。

兩輪最終回應的解碼狀態都必須是有效的 200–499。第二輪傳輸失敗或逾時時，可以退回已經驗證過的第一輪樣本。HTTP/1 的部分回應即使逾時也不退回；正常的 HTTP/2 GOAWAY 則可以退回。

每輪 HTTP/1 的臨時回應 header 與最終回應 header 累計上限是 16 KiB，HTTP/2 的回應 header 清單上限也是 16 KiB。session 預熱、撥號、目標 TLS、HTTP/2 啟動與每輪請求各自使用階段預算。針對冷的可重用 generation 的探測，使用帶 guard 的臨時執行時，結束後關閉。

HTTP/2 驅動任務在完成或取消後釋放，因此群組掃描不會為每個已測試節點留下新的常駐可重用執行時。

測量成功會更新節點的延遲歷史。單一節點失敗回傳 `503`；群組測量會省略失敗的成員；任意手動測試目標的失敗，都不會增加真實撥號失敗的連續計數。

`/proxies/{name}/delay` 回傳 `{"delay":12}`；`/group/{name}/delay` 回傳 `{"<member>":12,...}`。延遲以毫秒計，上限 65535。對 URLTest 群組，兩個介面都可能依新測量切換其選擇。

按需的 delay exchange 會保留 Alive/API 的延遲歷史，但不回報業務結果，也不填充設定中 Score 的比較 cohort。實際的 server 或 session 前置準備可以回報聚合的預熱建立情況；honk 不會把呼叫方的 URL 虛構成預熱自身的目標，也不提供晉升證明。

兩個延遲介面都會一直持有已接納的任務，直到測量清理結束，即使 HTTP 用戶端已經斷開。owner 接納失敗時回傳 `503`，這個回應會區分容量耗盡、檢查已停止與 worker 失敗。

QUIC 探測逾時，或等待正常關閉，都屬於測量結果，不代表健康檢查 owner 失敗。有限的對端通知寬限期結束之後，先停止並等 Quinn 驅動任務結束，再停止並等 packet-adapter worker 結束。

真正的受管 worker 失敗，仍然會關閉健康檢查的接納。

### Score 代理群組表示

設定成 `policy: score` 的群組始終可用，為了相容 Clash 表示成 `type: "url_test"`。它的 `all` 清單和其他群組一樣保留直接成員標籤；`now` 回報目前聚合的 TCP 勝者，不會暴露某個精確目標的私有選擇。Score 始終是自動的，`PUT /proxies/{name}` 會被拒絕，無法固定成員。

評分 cell 與只由 scorer 持有的目標資料不會加進 proxy 文件。`/stats.score` 只包含下文那些安全的聚合計數。`/connections` 只保留原有的目標中繼資料。

## 模式與 Selector 修改

`PATCH /configs` 不看 `Content-Type`，直接依 JSON 解析請求內容，只處理字串 `mode`。沒有該欄位時回傳 204，不做修改。JSON 無效或模式未知時回傳 400，模式切換失敗時回傳 500 或 503。例如：

```json
{"mode":"Global"}
```

模式更新走 `DatapathFlagsHandle`。它是 shared mode 與 `DATAPATH_FLAGS_MAP` 唯一的序列化 writer，因此模式修改會和 reload 的 NFQUEUE fence、reopen、disable 操作原子地組合，不會重新發布過期的就緒狀態 bit。

由規則派生的 feature bit 屬於不可變的路由 policy descriptor。原生 API 未啟用時，啟用快取資料庫會儲存正規化的模式。原生 API 啟用後，兩種 API 共用一種臨時模式：不恢復，不持久化，並在明確的設定啟用之後重設成 Rule。

`PUT /proxies/{name}` 不要求特定的 `Content-Type`。對已設定的 Selector，目標必須是直接成員的標籤；只能透過巢狀群組到達的葉節點不是直接成員。

寫入會同時原子地設定 TCP 與 UDP，Clash 的 `now` 只顯示 TCP。原生 API 可以分別設定兩種網路。有效變更透過共用的 `control/reload` owner 發布；狀態快取可用時，預設分別持久化網路選擇。

只有明確設定 `experimental.cache_file.enabled: false` 才會關閉；省略這個設定仍然保留持久化。`interrupt_connections` 會依建立時擷取的群組路徑與發生變化的網路，關閉對應的精確 TCP/UDP owner，並等待確認，不再只是刪掉 tracker。選擇沒有變化時不會觸發中斷。

URLTest、LoadBalance、Fallback 和 Score 都拒絕手動選擇。

`GLOBAL` 是合成的 Selector，但它的 `all` 中每個成員都是具體的已設定群組或節點，也都有對應的頂層 proxy 文件。`PUT /proxies/GLOBAL` 只接受這些名稱，並透過同一個 `DatapathFlagsHandle` 更新。原生 API 未啟用時，快取資料庫以 `GLOBAL` 為 key 儲存選擇；空值、已移除、未知與舊的虛擬選擇都會退回第一個具體成員。

原生 API 啟用時，保留共用的穩定目標身分，不持久化；目標消失時，不會自動改投同名物件或其他成員。

## 外部 UI hosting

設定 `experimental.clash_api.external_ui` 可以提供一個靜態控制面板目錄。目錄缺少或為空時，honk 會在背景下載 ZIP；啟動不會等它，檔案可用之前靜態路由回傳 `404`。`assets.ui.url` 會替換內建的 zashboard URL，`HONK_UI_DOWNLOAD_URL` 則保持最高的覆寫優先順序。

每次下載請求連同重新導向在內只接受 HTTP(S)，最多跟隨五次重新導向，下載的 ZIP 內容上限 128 MiB。允許從 HTTPS 降級到 HTTP，也允許 URL 直接寫 IP 位址；每一跳都遵循路由或 `assets.ui.route`、`assets.route` 中生效的出口。

`assets.ui.route` 優先於 `assets.route`，對初始請求與每次重新導向都適用。`direct` 走直連的 HTTP 用戶端，群組名稱則強制經過選中的出站葉節點。沒有設定出口時，每個 URL 都遵循 honk 目前的流量路由決策：`direct` 走直連用戶端，`block` 中止下載，代理結果則經過選中的出站葉節點。

凡是直連或經代理、且實際經過 Score 群組的 HTTP 請求，都會向路徑上經過的 Score 群組回報真實的 host 或 IP、連接埠、建立、首次回應、位元組與終態。其他路徑不會建立評分 reporter 或 cell。建立的記錄點在連線與 TLS 準備完成之後、送出 HTTP 請求之前。

首次回應仍然由實際回應觸發。共用 HTTP 錯誤會保留原始的 typed cause：目標故障歸因於目標，typed carrier 故障即使在建立之後也仍然歸因於 node。下載或解壓失敗只寫日誌，不會停掉引擎。

## `GET /stats`

`GET /stats` 是使用者態快照，而不是 eBPF `OUTBOUND_STATS` map，也不暴露該 map 的封包計數器。固定 DNS、TCP、UDP 與 NFQUEUE 模式不建立動態的逐節點標籤。

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  dns: {
    socketAdmission: { refused, timeouts },
    proxyAdmission: { timeouts },
    pressure: { retiredUdpPools, retiredTransports }
  },
  quic: {
    activeConnections, srttUs, cwndBytes, flowReceivedBytes, flowSentBytes,
    receiveWindowBytes, receiveWindowAvailableBytes, streamReceiveWindowBytes,
    sendWindowBytes, sendWindowAvailableBytes, lossRatePpm, sentPackets,
    ackFrames, lostPackets,
    sentPlpmtudProbes, lostPlpmtudProbes, currentMtu, blackHoles,
    congestionEvents, txBytes, rxBytes, txDatagrams, rxDatagrams, txIos, rxIos,
    transportTxWouldBlock, transportTxDrops, transportRxDrops, sessionRxDrops,
    sendTimeouts, pathStalls
  },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R, verification: { tcp: V, udp: V }, budget: { tcp: B, udp: B } }],
    businessStarts,
    cache: {
      exactCells, aggregateCells, exactEvictions, aggregateEvictions,
      comparisonCells, comparisonLogicalBytes, comparisonLogicalCapacity,
      comparisonEvictions, comparisonExpired, comparisonRejected
    }
  },
  udp: {
    endpoint: { hits, misses },
    latency: {
      route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
    },
    capacity: { rejected },
    slowPermit: { accepted, rejected, closed },
    queue: { accepted, full, flowFull, globalPayloadFull, closed },
    firstSend: { failures },
    stagger: { attempts, winners, cancellations },
    warm: { attempts, successes, failures },
    nfqueue: {
      received, activeFlows, kernelQueueDepth, kernelStatsAvailable,
      kernelStatsReadErrors, kernelDropped, kernelUserDropped, heldPackets,
      heldPeak, socketReceiveBufferBytes, actorQueueFull, correlatorFull,
      actorQueueDepth, actorQueuedBytes, actorOldestAgeNanos, directAccepted,
      proxyCopied, proxyDropped, block, cancel, drop, tokenMismatch,
      tokenExhaustion, tokenRollovers, verdictErrors, receiptToVerdict: H
    }
  }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
R = {
  coldExplore, periodicExplore, reliabilityWinner, performanceWinner,
  incumbentHeld, insufficientEvidenceHeld, directionalTradeoffHeld, incumbentIneligible,
  freshFailureBypass, deadFiltered, ordinarySwitch, switchFlap,
  failStreakExcluded, exploreBackedOff, carrierPressure, carrierRttPressure,
  carrierLossPressure, carrierValidation
} // every R value is a u64 count
V = { provisionalSelections, usableSelections, validationSelections }
B = { businessStarts, sources: { cold, periodic, recovery }, trialStarts,
      reserved, spent, budgetBlocked, inFlightBlocked, refunded, expired,
      coldAllowance, coldAvailable, earnedAvailable, earningPeriod, scopes,
      trialSuccess, trialFailure, trialCancelled, trialSetupHistogram,
      trialSetupMillis, trialElapsedMillis }
```

### DNS 欄位

全部 `dns` 欄位都是行程生命週期 `u64` 事件計數器，由使用中與退役 generation 共用，reload 不會歸零。各欄位獨立取樣，單次快照不保證跨計數器一致。這些總數由 Clash `/stats` 暴露，原生 DNS 診斷或歷史 API 不提供。

| 欄位 | 說明 |
| --- | --- |
| `socketAdmission.refused` | Endpoint 網路 bootstrap 需要兩個額度，而整個 DNS socket 分割區不足兩個時被拒絕的次數。 |
| `socketAdmission.timeouts` | 因 admission 期限耗盡而回傳的必要實體 socket admission 呼叫。 |
| `proxyAdmission.timeouts` | 因 admission 期限耗盡而回傳的必要代理 stream 或非原始 packet 準備 admission 呼叫。 |
| `pressure.retiredUdpPools` | 因壓力而選中退役的空閒 UDP socket pool，每個被摘除的 pool 只計一次。 |
| `pressure.retiredTransports` | 首次因壓力而選中退役的空閒 TCP/TLS/H2/QUIC transport pool；恢復已保留的 teardown 不重複計數。 |

`socketAdmission.refused` 與 `socketAdmission.timeouts` 互不重疊。初次競爭、可選 UDP shard 擴充失敗與呼叫方取消，都不算 admission 失敗。計數在 admission 處累加，不依 singleflight follower 或用戶端回應重複累加。壓力計數表示被選中的資源，不是查詢數、遺失封包數，也不是已經釋放的描述符數；一個 transport pool 可能持有多個 socket。DNS admission 失敗可能表現為 `SERVFAIL`，和 singleflight 的 `REFUSED` 各自獨立。既有的節流失敗日誌保持不變。

### TCP 欄位

| 欄位 | 說明 |
| --- | --- |
| `activeFlows` | 目前持有 TCP admission permit 的透明 TCP flow。 |
| `limit` | 目前行程級 TCP flow admission 上限；從描述符推導出的下限開始，並隨閒置描述符餘量動態擴縮。 |
| `capacity.rejected` | 因 TCP 預算已滿而等待 permit 的 accept-loop 單調計數；已接受 socket 保留在核心 backlog 中，不會被丟棄。 |

### QUIC 欄位

| QUIC 欄位 | 說明 |
| --- | --- |
| `srttUs`、`cwndBytes`、`currentMtu` | 使用中連線的平均值；沒有使用中連線時為零 |
| `receiveWindowBytes`、`receiveWindowAvailableBytes`、`streamReceiveWindowBytes` | 使用中連線的平均值；沒有使用中連線時為零 |
| `sendWindowBytes`、`sendWindowAvailableBytes` | 使用中連線的平均值；沒有使用中連線時為零 |
| `flowReceivedBytes` | 已交付給應用程式的 flow 位元組數 |
| `flowSentBytes` | 已被對端確認的 flow 位元組數 |

位元組計數包含已完成的池化連線。封包、UDP 位元組、I/O、遺失封包、黑洞與壅塞計數同樣包含這些連線。

池中的 TUIC、Juicity 與 Hysteria2 連線每秒取樣一次流量控制狀態。

| 視窗增長依據 | 效果 |
| --- | --- |
| 收發方向的十秒有效吞吐量 EWMA，RTT 至少 80 ms，且連續三個樣本確認高 BDP | 將使用中連線的接收或傳送下限提高到約 `2 x BDP`。 |
| 對端的 `DATA_BLOCKED` 或 `STREAM_DATA_BLOCKED` | 直接表明已通告視窗受限。繞過 RTT 門檻，將連線或 flow 的接收下限加倍。 |
| 連線額度仍受限時的零進展樣本 | 保留但不增加連線級連續樣本計數。 |

視窗正在限制流量時，有效吞吐量的估計會偏低，不能拿來作為升檔依據。每個下限獨立執行五分鐘的調整冷卻。自動提高的上限是 32 MiB，但不會降低更大的明確設定。

honk 不會因為應用需求低就縮小已經學到的視窗，也不會在使用中連線上切換壅塞控制。

| 計數器 | 說明 |
| --- | --- |
| `ackFrames` | 收到的 ACK 幀，表示路徑進展；重複幀可能重複計數。 |
| `lossRatePpm` | 排除 PLPMTUD 探測的遺失封包率；分母為 `sentPackets - sentPlpmtudProbes` |
| `lostPackets` | 排除 PLPMTUD 探測的遺失封包數 |
| `sentPlpmtudProbes`、`lostPlpmtudProbes` | 獨立的 PLPMTUD 探測計數 |
| `txIos`、`rxIos` | 反映批處理效率的 I/O 次數 |
| `transportTxWouldBlock` | 64 包 adapter 佇列已滿的次數；Quinn 會重試 |
| `transportTxDrops` | 代理傳輸回報壅塞或逾時後主動丟棄的封包數 |
| `transportRxDrops` | adapter 接收佇列已滿的次數 |
| `sessionRxDrops` | TUIC/Hysteria2 的 256 包 session 佇列已滿的次數 |
| `sendTimeouts` | 啟用指標的連線上，仍計入目前 no-ACK 等待、但傳送期限已到的 UDP 傳送次數 |
| `pathStalls` | 路徑監視器在完整 no-ACK 寬限期後退役的共享 QUIC 連線數 |

`sendTimeouts` 是壅塞診斷，不是全部逾時、節點故障或恢復次數。`pathStalls` 不是遺失封包數、受影響 flow 數或恢復次數。兩者都是行程生命週期內的累計值。

### Score 選路原因欄位

`score.groups` 是已認證 `/stats` 回應中額外的一部分。目前沒有任何群組使用 `policy: score` 時，它是 `[]`。否則它包含每個目前的 Score 群組，包括沒解析出葉節點的群組，依 `name` 的字典序排列。

每個群組的 `tcp` 與 `udp` 物件始終存在，每個物件也始終包含全部 `R` 欄位。沒有網路活動時這些值是零，欄位從不省略。

每個 `R` 值是飽和的 `u64` 計數，不是延遲、吞吐量或健康測量。一次已授權的多候選 Score Apply 記錄一個最終原因：

| 最終原因 | 說明 |
| --- | --- |
| `coldExplore`、`periodicExplore` | 驗證 |
| `incumbentIneligible` | 離開已不滿足普通資格的當前成員 |
| `freshFailureBypass` | 合格的當前成員存在尚未恢復的業務失敗。 |
| `insufficientEvidenceHeld` | 沒有挑戰者獲得晉升，且普通效用排名的勝者缺少合格的共同性能比較。 |
| `directionalTradeoffHeld` | 沒有挑戰者獲得晉升。某個比較在一個已知方向提升至少 10%，在另一個方向退化超過 10%。 |
| `incumbentHeld` | 比較優勢未超過保持門檻。 |
| `reliabilityWinner`、`performanceWinner` | 其他情況下，保留依替代候選資格分類的意義。 |

`performanceWinner` 本身不證明效能提升或發生切換。`insufficientEvidenceHeld` 不表示可靠性歷史缺少。

| 附加計數器 | 說明 |
| --- | --- |
| `ordinarySwitch` | 實際提交的普通 A→B 選擇 |
| `switchFlap` | 同一目標八次普通選擇內返回前一勝者的次數 |
| `deadFiltered`、`failStreakExcluded`、`exploreBackedOff` | 每次排名中受影響的候選數 |

首次選擇、試用及缺少先前歷史時不增加切換計數。Peek、API 讀取、單例旁路與最後嘗試不增加原因計數。巢狀群組排名與實際出站連線並非一一對應。

對 UDP 來說，`deadFiltered` 還會統計因協定或設定不具備 UDP capability 而被排除的候選。它不是新發生故障的節點數，也不是業務嘗試數；這類排除不會增加 Score 失敗，也不會增加探索退避。

`carrierPressure` 統計被已有的群組或網路聚合 cell 接收的新鮮 carrier 位址族事件，不是封包數，也不是失敗連線數。重複的心跳讀取不會增加它。`carrierValidation` 統計的是一種週期驗證選擇：普通贏家身上有比上次驗證更新的 carrier 提示。

這是可重疊的診斷計數，不是新的互斥原因，也不證明只有這個提示導致了選擇。提示不會改變業務可靠性、資格或健康。該欄位在 API 讀取時是唯讀的。

carrier 觀測由控制心跳接入，和選路呼叫相互獨立。

`carrierRttPressure` 與 `carrierLossPressure` 保留被接收事件的原因。兩種條件同時滿足時，兩個原因計數都加一，但 `carrierPressure` 只加一次。這些可重疊的計數不會標示具體的 carrier 或傳輸協定，不是應用遺失封包率，也不會增加失敗次數。

重複或過期的提示都不會增加它們。TCP 的 loss pressure 表示重傳壓力，不代表已經確認有應用封包遺失。

計數在行程啟動時從零開始，只在行程記憶體中累積。只要群組名稱還在已提交的設定裡，成功的 reload 就會保留它們，包括零葉節點以及臨時的 Score→非 Score→Score 轉換。非 Score 群組不會出現在這個回應中。

已經提交的刪除會清除這個名稱的計數，之後重新建立同名群組從零開始。受 generation fence 約束的已淘汰 manager 在被替換之後不能再改計數，即使同名群組隨後又被建立。快照在 JSON 序列化之前複製，讀取不會改變選路狀態。

`/stats.score` 只公開群組名稱、固定的 TCP/UDP 原因、驗證與預算欄位、根業務計數，以及有界的證據快取總量。它不含節點身分、目標 domain/IP/port、原始 cell、cadence key、權限依據或憑證。

`/proxies` 中既有公開成員名稱與 `/connections` 中目標中繼資料保持不變。

### Score 驗證資訊

`/proxies` 與 `/proxies/{name}` 中的 Score 群組會增加 `scoreVerification`。它固定的目標是 `responseQualityWithAvailability`，範圍是 `aggregate`，並不保證每一個精確目的地。`tcp` 與 `udp` 中分別包含：

| 欄位 | 說明 |
| --- | --- |
| `selected` | 本次唯讀判定對應的既有公開成員標籤；沒有普通合格候選時為 null。存在時 TCP `now` 使用同一次判定的選擇。 |
| `state` | `provisional` 或 `observedUsable`。後者要求同一個連續 cohort 中，四個不同的定向 Traffic reporter 在 setup 或 TX 之後收到了 RX，而且最近一次合格 RX 距今不到 60 秒。失敗、reload 或 60 秒間隔都會重設 cohort；clone 與重複的回包不能增加信用。這個狀態不授予冷啟動資格。真正失敗之後的 cohort 可以獨立地用同樣四份信用取得作用域恢復。聚合可用並不代表每個精確目標都合格。 |
| `challengers` | `selected` 與已評估挑戰者之間新鮮的成對回應比較，見下文。 |
| `nextAction` | `nextBusinessFlow` 表示要靠未來的真實業務來補充證據、普通資格或恢復，不是已經預留或已經派發的 I/O；要同時看 `waitReason`。`backoff` 表示保留失敗隔離。`none` 表示沒有可以執行的待補工作。缺少傳輸證據不會建立工作；方向的有效吞吐量要等真實負載。 |
| `question` | `none`、`availability`、`response`、`qualification` 或 `recovery`，表示下一個還沒解決的證據問題。沒有剩餘動作時是 `none`。退避時保留被阻塞候選的問題，不會退回到已解決現任的問題。 |
| `waitReason` | 工作等待的原因。取值和聚合作用域的規則見下表。等待不代表工作一定會成功。 |
| `coverage` | `scope` 為 `all` 或 `bounded`。`candidates` 統計目前可見的候選全體；`evaluated` 是這個檢視與共用服務池的交集；`unevaluated` 是兩者之差。勝者不額外佔位。父群組入口和目標共用這個池，TCP 與 UDP 分開。池外成員不接受普通或可選策略的工作；這些數量不是所有既有連線涉及的節點總數。`pending` 統計還有未決問題的已評估成員，包括已有比較、但仍需資格或恢復工作的成員。 |
| `network`、`targetFamily`、`healthFamily`、`targetSpecific` | 傳輸與適用範圍；此聚合介面沒有精確目標，不匯出 domain/IP/port 或原始節點 ID。 |


| `waitReason` | 說明 |
| --- | --- |
| `none` | 沒有等待 |
| `budget` | 額度不可用；或者已有可用選擇時，試用因反覆失敗而暫停 |
| `comparableTraffic` | 等待未來出現可比較的業務 |
| `inFlight` | 已有的同目標工作夠了，或達到了獨立的每節點四項工作上限 |
| `backoff` | 失敗隔離 |

聚合讀取會檢查已保留的 IPv4/IPv6 作用域，不會建立新作用域：

- 兩者都因預算阻塞：回傳 `budget`。
- 任一作用域可用，或尚未建立：仍然可以等未來的可比較流量。
- 其他情況：保留在途等待。

唯讀與 Peek 使用已提交的參與者，不重新排名。Apply 會初始化並重新整理參與者。初始化之前，唯讀查詢使用臨時的有界投影。

見[評估集生命週期](../design/groups.md#有條件的驗證結論)。

`challengers` 列出所選成員目前原始比較對中、具有新鮮合格回應指標的項目；這些比較對就是普通晉升讀取的同一批。沒有該指標的成員不會出現，全都沒有時是空清單。每項含 `name`、`basis`、`relation`、`reporters` 與 `validForMs`。`name` 是公開成員標籤，僅作顯示，巢狀路徑下可能重名；`basis` 為 `targetResponse`、`commonTargets` 或 `configuredProbe`；`relation` 為 `selectedFaster`、`equivalent` 或 `challengerFaster`。

`equivalent` 對實際回應值使用含邊界的對稱區間 `high - low <= 0.1 × low`，零與亞毫秒值也算在內。`reporters` 取雙方已保留的不同 reporter 支援量中較小的那個：四個區塊各保留最多四個 ID，跨區塊去重後聯集最多十六個，不是所有已觀測 reporter 的精確總數。`validForMs` 是這個回應指標還剩多久有效。

業務區塊是 15 秒，在區塊起點之後 60 秒到期。設定探測依生產者週期 `I` 使用 `max(15s, 2I)` 的區塊；有效期同時受兩個條件限制：最早支援的區塊的四區塊保留期限，以及較弱一側最近支援再加上 `max(60s, 2I)`。失敗、reload、incarnation 的邊界不變。

`commonTargets` 最多用八個正規、等權、回應合格的共同目標，不是無關的聚合均值。建立與預熱都不算比較證據。

這裡的關係只描述測得的回應時間：它不是晉升決定，不是可靠性或頻寬結論，不是誤判機率，也不保證最優，更不能證明所選成員比清單之外的成員更好。普通切換仍然使用自己依賴完成數的門檻，以及可靠性、可用性與方向保護。查詢不會派發驗證，也不改變計數。

`/stats.score.groups[].verification.tcp` 與 `.udp` 中增加了飽和計數 `provisionalSelections`、`usableSelections` 與 `validationSelections`，只在授權 Apply 時推進。

### Score 工作預算與觀測成本

`/stats.score.businessStarts` 對巢狀群組去重，統計唯一的原始 Score 業務開始數。`/stats.score.groups[].budget.tcp` 與 `.udp` 聚合的是保留的目標位址族作用域。不要把巢狀群組的總量相加當作唯一業務數。

原始業務被選為試用時仍然計數；延續嘗試即使換了網路或目標位址族，也不會累積另一份原始額度。節點專屬工作在代理 DNS 與實體撥號的 admission 等待之前就開始，和 reporter 的實體、邏輯 I/O 邊界無關。DNS 查詢生命週期的 admission，是在這之前同步檢查池是否開放，不是實體撥號的 admission 等待。

預算計數器反映的是已經記錄的帳本值。唯讀等待與冷啟動判定還會考慮過期未開始預留中可退回的額度，但不更新 `refunded`、`expired` 或其他計數器。

| 欄位 | 說明 |
| --- | --- |
| `businessStarts` | 保留作用域中原始業務開始數之和。 |
| `scopes` | 保留的作用域數量。 |
| `earningPeriod` | 各作用域中最快的目前累積週期 `q`，通常是 16。如果群組最近每秒至少兩條業務，且作用域的試用大多成功，就是 8。還沒有作用域時為 0。這個值不能當合併作用域預算公式的分母。每個作用域建立時固定一份冷啟動額度 `B`，之後每次原始業務開始，依當時的 `q` 累積 `1/q`。各作用域的 `spent + reserved` 不超過 `B` 加上已累積額度的整數部分。 |
| `sources.cold`、`sources.periodic`、`sources.recovery` | 依來源區分的已開始工作：冷額度試用、已賺額度試用、不增加可選額度的延續嘗試。`recovery` 包含 TCP 替代、DNS 改路與 UDP 轉 TCP，以及 UI 與訂閱重新導向，不限於出錯後的重試；它既不是可選試用，也不是新的原始業務。一般的非試用沒有來源桶。 |
| `trialStarts`、`spent`、`reserved` | 已開始的可選試用數、累計已支出的 token，以及尚未開始的 token 預留。開始只支出一次，開始之後取消不退回額度。 |
| `coldAllowance`、`coldAvailable`、`earnedAvailable` | 固定初始額度與目前可用額度的合計。每個作用域最多保留八個未花費的已賺 token。時間流逝、讀取、目標變動與證據過期都不會賺額度；保留的作用域在 reload 或成員變化之後不重設。 |
| `budgetBlocked`、`inFlightBlocked`、`refunded`、`expired` | 四個都是計數。前兩個是預留被拒絕的次數，其中 `budgetBlocked` 也計入作用域因試用反覆失敗而暫停時被拒絕的候選。`refunded` 是最後引用釋放或未開始失效時退回的額度數，`expired` 是在途追蹤項目過期的數量。只有未開始的預留能退回額度；追蹤過期不會退回已經開始工作的支出。 |
| `trialSuccess`、`trialFailure`、`trialCancelled` | 已開始的可選試用的 exactly-once 終態。拒絕、關閉與中性取消都歸入 `trialCancelled`。`trialFailure` 是實際觀測到的失敗，不是相對於未觀測的替代路徑、因為選擇試用而額外造成的失敗。 |
| `trialSetupHistogram`、`trialSetupMillis`、`trialElapsedMillis` | 八個固定 log2 毫秒建立桶（槽位 0 包含 0–1 ms，末槽包含 128 ms 及以上）、已觀測建立時長之和，以及開始至終態時長之和。它們是實際試用成本，不是因果上的額外延遲或開銷。 |

`/stats.score.cache.comparisonCells` 上限是 512。`comparisonLogicalBytes` 計入比較儲存、vector 容量與所持 key 的容量。`comparisonLogicalCapacity` 是依實作結構大小算出的最壞分配界限，不超過 1 MiB。

這兩個值都不是實測的行程 RSS，也不是全部 Score 狀態的大小，都不含分配器開銷與行程中的其他分配。`comparisonEvictions`、`comparisonExpired`、`comparisonRejected` 統計儲存移除與 admission 事件。唯讀存取可以先讓支援失效，要等實際移除之後才增加計數。

既有的精確和聚合 LRU 欄位不變。

### 出站與 ready pool 欄位

| 欄位 | 說明 |
| --- | --- |
| `outbounds[].name` | 出站名稱。 |
| `outbounds[].totalConns` | 經該出站啟動的連線數。 |
| `outbounds[].activeConns` | 目前經該出站開啟的連線數。 |
| `outbounds[].upload` | 使用者態中從用戶端到 proxy 的位元組數。 |
| `outbounds[].download` | 使用者態中從 proxy 到用戶端的位元組數。 |
| `outbounds[].errors` | 歸因於該出站的連線嘗試失敗數。 |
| `pool.readyHits` | ready 裸連線池命中數。 |
| `pool.readyMisses` | ready 裸連線池未命中數。 |
| `pool.entries` | 目前 ready 裸連線項目數。 |

### Histogram 格式

每個 `H` 都是 `{count, sumNanos, buckets}`。`count` 是觀測數，`sumNanos` 是以奈秒計的總和。`buckets` 是包含 64 個非累積計數的陣列：槽位 $n$ 涵蓋 $2^n$ 到 $2^{n+1}-1$ ns，槽位 0 還包含零，最後一個槽位在 `u64::MAX` 飽和。

### UDP 欄位

| 欄位 | 說明 |
| --- | --- |
| `endpoint.hits` | 已建立 UDP endpoint fast 路徑處理的封包數。 |
| `endpoint.misses` | 冷啟動 flow 的 endpoint lookup miss 數。 |
| `latency.route` | 冷啟動 route selection 延遲。 |
| `latency.dial` | 冷啟動 UDP dial attempt 延遲。 |
| `latency.replyReady` | endpoint 驅動任務 commit 前同步準備 reply socket 的延遲。 |
| `latency.firstSend` | 首次傳送嘗試延遲。 |
| `latency.firstReply` | 第一個回應成功重新注入用戶端之前的時間。 |
| `capacity.rejected` | 精確 endpoint capacity reservation 被拒次數。 |
| `slowPermit.accepted` | 進入使用中 UDP slow 路徑的 admission 數。 |
| `slowPermit.rejected` | 因 shared connection semaphore 已滿而拒絕的 slow-path admission 數。 |
| `slowPermit.closed` | generation draining 期間拒絕的 slow-path admission 數。 |
| `queue.accepted` | 進入有界 endpoint-driver 佇列的封包數。 |
| `queue.full` | retained 佇列的 drop-newest 事件總數。 |
| `queue.flowFull` | 單一 flow packet 槽位上限導致的 drop-newest 數。 |
| `queue.globalPayloadFull` | 全域 retained 酬載 byte 上限導致的 drop-newest 數。 |
| `queue.closed` | 對正在關閉或已關閉 endpoint 驅動任務發起的佇列嘗試數。 |
| `firstSend.failures` | 首次傳送錯誤或逾時數；兩者都依 ambiguous send 處理。 |
| `stagger.attempts` | 已啟動的冷啟動 URLTest speculative preparation 嘗試數。 |
| `stagger.winners` | 首個滿足條件且成功的 staggered preparation 數。 |
| `stagger.cancellations` | 其他 candidate 獲勝後取消的已啟動 speculative preparation 數。 |
| `warm.attempts` | 已啟動的 generation-owned UDP 預熱 dispatch 數。 |
| `warm.successes` | 回傳 `Ready` 的預熱 dispatch 數。 |
| `warm.failures` | generation 仍存活時的真實預熱 failure 數。`NotApplicable` 保持中性。 |

`queue` 衡量 endpoint-driver 佇列；它不同於衡量 UDP slow 路徑 admission 的 `slowPermit`。

### NFQUEUE 欄位

| 欄位 | 說明 |
| --- | --- |
| `received` | NFQUEUE listener 投遞的封包數。 |
| `activeFlows` | 目前由 pending-verdict correlator 持有的 flow cell 數。 |
| `kernelQueueDepth` | 目前使用中 kernel 佇列實例中的排隊封包數。 |
| `kernelStatsAvailable` | 最近一次 kernel 佇列 statistics 讀取是否成功。 |
| `kernelStatsReadErrors` | 累計 kernel 佇列 statistics 讀取失敗數。 |
| `kernelDropped` | 因 kernel NFQUEUE 達到佇列上限而丟棄的封包數；跨佇列 hard rebind 累加為行程生命週期計數器。 |
| `kernelUserDropped` | kernel 向使用者態投遞 NFQUEUE message 時丟棄的封包數；跨佇列 hard rebind 累加為行程生命週期計數器。 |
| `heldPackets` | 目前已投遞但 verdict guard 仍被持有的封包數。 |
| `heldPeak` | 佇列 service 回報的同時持有 verdict guard 峰值。 |
| `socketReceiveBufferBytes` | netlink socket 的有效接收緩衝區大小。 |
| `actorQueueFull` | 因有界 ingest 執行單元佇列已滿而失敗時拒絕轉發丟棄的封包數。 |
| `correlatorFull` | 達到任一 correlator 硬上限時丟棄的封包數：4,096 個 flow cell 或每 flow 64 個 retained verdict。 |
| `actorQueueDepth` | 目前 ingest 執行單元佇列項目數。 |
| `actorQueuedBytes` | 目前 ingest 執行單元佇列保留的酬載位元組數。 |
| `actorOldestAgeNanos` | 目前最舊 ingest 執行單元項目的年齡，單位為奈秒。 |
| `directAccepted` | direct 決策成功執行 marked `NF_ACCEPT` verdict 的次數。 |
| `proxyCopied` | 酬載所有權轉交給正規 UDP 初始化器的次數。 |
| `proxyDropped` | proxy 決策成功對原始封包執行 `NF_DROP` verdict 的次數。 |
| `block` | policy block 成功執行 drop verdict 的次數。 |
| `cancel` | cancellation 成功執行 drop verdict 的次數。 |
| `drop` | 其他成功執行的失敗時拒絕轉發 drop verdict 數。 |
| `tokenMismatch` | 過期或不匹配的 decision token/flow identity 事件數。 |
| `tokenExhaustion` | 觀測到持久化 decision-token allocator 耗盡的次數。 |
| `tokenRollovers` | token 耗盡後成功完成 generation rotation 的次數。 |
| `verdictErrors` | `NF_ACCEPT` 或 `NF_DROP` 操作失敗數。 |
| `receiptToVerdict` | 從 listener 收包到成功 terminal verdict 的 histogram；它不是 kernel 佇列 residence time。 |

獨立的一秒取樣器讀取自己的 kernel 佇列，不依賴封包 dispatch。讀取失敗之後，之前的 `kernelQueueDepth`、`kernelDropped` 與 `kernelUserDropped` 仍然可見，而本地的 held-packet 與 receive-buffer 瞬時值會繼續重新整理。

### 熱資源欄位

| 欄位 | 說明 |
| --- | --- |
| `warm.nodes.preconnect` | 歸因於啟動時裸 TCP 預連線的熱節點。 |
| `warm.nodes.health` | 健康狀態 probing 期間觀測到的熱節點。 |
| `warm.nodes.udp` | 歸因於 UDP 預熱 coordinator 的熱節點。 |
| `warm.nodes.selector` | 作為已設定 Selector 葉節點而保留的熱節點。 |
| `warm.nodes.traffic` | 沒有顯式 attribution mark、因而歸因於 traffic 的熱節點。 |
| `warm.sessions.anytls` | 保留的 AnyTLS 池 session 數。 |
| `warm.sessions.vless` | 保留的 VLESS 池 session 數。 |
| `warm.sessions.tuic` | 已佔用的 TUIC 用戶端槽位數。 |
| `warm.sessions.juicity` | 已佔用的 Juicity 用戶端槽位數。 |
| `warm.sessions.hysteria2` | 已佔用的 Hysteria2 用戶端槽位數。 |

一個節點可以同時計入多個明確原因。瞬時值跟隨目前執行時 generation；已排乾資源會從下一次快照中消失。

## Related docs

- [Experimental 設定](./experimental.md)
- [NFQUEUE 設計](../design/nfqueue.md)
- [控制面設計](../design/control-plane.md)
