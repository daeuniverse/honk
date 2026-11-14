# 訂閱參考

`subscription {}` 設定遠端節點清單。

```dae
subscription {
    primary: 'https://example.com/sub'
    'https://example.com/no_tag_link'
    detailed: 'https://example.org/sub' {
        ua: 'honk/1.0'
        interval: 6h
        cache: false
        route: direct
    }
}
```

## 欄位

要為單一訂閱設定選項時，在帶引號的 URL 後面追加一個區塊，每行一個 key。四個選項都可省略。省略的選項先取 `assets.subscription` 裡對應的預設值（`route` 取 `assets.route`），再取內建預設值。見 [Assets 設定參考](./assets.md)。

| Key | 預設值 | 意義 |
| --- | --- | --- |
| `ua` | `honk/<version>` | 覆寫請求的 `User-Agent`；見 [`ua`](#ua)。 |
| `interval` | `86400s` | 設定定期重新整理間隔；見 [`interval`](#interval)。 |
| `cache` | `true` | 把該訂閱的正文儲存在訂閱儲存中；見 [`cache`](#cache)。 |
| `route` | `routing` | 選擇抓取出口；見 [`route`](#route)。 |

### `ua`

把該值當作請求的 `User-Agent` 傳送。預設是 `honk/<version>`。

`ua: ''` 把繼承來的 `assets.subscription.ua` 重設為 `honk/<version>`，不會刪掉 `User-Agent` header。值不是合法的 HTTP header 值時，抓取失敗。

### `interval`

設定重新整理間隔。預設是 `86400s`；`0` 關閉定期重新整理和失敗重試。

取整數秒，可以省略單位，也可以帶小寫的 `s`、`m` 或 `h` 字尾。`ms` 表示毫秒，向上取整到秒。`d`、`1h30m` 這類組合值，以及 `0.5s` 這類小數都無效。

值無效時產生 warning，並把 `interval` 設為 `0`；honk 不會改用繼承來的值。

### `cache`

啟用 `global.store_subscribe` 時，把該訂閱抓取到的正文儲存在訂閱儲存中，供離線啟動恢復使用。預設是 `true`。

`cache` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不區分大小寫。

`false` 既不儲存也不恢復正文，維護任務會刪掉此前儲存的正文。值無效時產生 warning，並把 `cache` 設為 `true`。

修改 `global.store_subscribe` 需要重啟；SIGHUP 會拒絕這項修改。

### `route`

選擇抓取該訂閱 URL 的出口。預設是 `routing`。

| 出口 | 行為 |
| --- | --- |
| 空值或 `routing` | 每個 URL 都按流量路由規則處理，重新導向也不例外。規則可以選擇節點、群組、`direct` 或 `block`。 |
| 群組名 | 強制經過該群組。 |
| `direct` | 使用引導解析器和 bypass mark 直連主機，不經過路由。沿用原來的直連傳輸。 |

`route` 為空時，所有建置都跟隨路由。honk 在驗證時拒絕未知群組。如果這條出口要在首次啟動時就能用，見[首次啟動時訂閱 URL 被阻斷](#首次啟動時訂閱-url-被阻斷)。

## 條目語法

URL 寫在條目行上。兩種舊寫法仍可解析，且不產生 warning：

| 寫法 | 範例 |
| --- | --- |
| 帶引號的 URL 後追加 `(UA)` | `compatible: 'https://example.net/sub'(honk/1.0 like)` |
| URL 寫在區塊內 | `detailed: { url: '…' ua: '…' }` |

只有把 URL 寫在區塊裡的寫法接受 `download_detour`，作為 `route` 的別名。兩個都設定會產生 `conflicting-subscription-route` 錯誤。URL 寫在條目行上時，`download_detour` 是未知 key，會觸發 warning 並被忽略。下文的字尾規則和緊貼註釋規則只適用於 `(UA)` 寫法。

標籤可以省略。標籤和 URL 都能用成對的單引號或雙引號。

| 條目形式 | 標籤解析規則 |
| --- | --- |
| 裸條目 | 第一個 `:` 之前的文字是標籤，除非這個冒號屬於 `://`。URL 裡後面的冒號不再拆出標籤。 |
| 帶引號的標籤後接 `:` | 明確標籤。 |
| 沒有明確標籤的帶引號 URL | 去掉外層引號後，按首個冒號規則處理。`'paid:https://example.com/sub'` 的標籤是 `paid`；`'https://example.com/sub'` 沒有標籤。 |

整體加引號的 `'paid:https://example.com/sub'` 會產生 `legacy-embedded-tag` warning，應改寫成 `paid: 'https://example.com/sub'`。

`(UA)` 字尾要求 URL 帶引號，避免和裸 URL 裡的括號混淆。兩種形式都保留 `sub_type: simple`，自動識別下文支援的正文格式。

解析器先處理連結字尾，再正規化引號裡的標籤。
`'paid:https://example.com/sub'(agent)` 和 `'paid:https://example.com/sub'#note`
都保留標籤 `paid`。診斷裡的條目序號按來源順序計算，區塊形式和行內宣告一樣，被略過的
條目也佔一個序號。

條目以引號開頭時，只有緊接結束引號後的冒號才算明確標籤，中間可以有空白。未加引號
的 User-Agent，或緊貼連結的註釋字尾裡的冒號，都仍算字尾資料：
`'https://example.com/sub'(agent:1)` 依然是不帶標籤的條目。

不帶標籤的條目用 URL 的主機名當名稱，`'https://example.com/sub'` 的名稱就是 `example.com`。解析不出主機名時，名稱留空，設定驗證會拒絕該條目。驗證不要求名稱唯一：明確標籤 `example.com` 和同一主機上不帶標籤的 URL 都匹配 `subtag(example.com)`，這個篩選條件會選中兩個訂閱的節點。按主機名產生名稱只在 dae 裡適用；JSON、YAML 和 TOML 仍要求提供 `name`。

不帶標籤且不含 `://` 的文字，honk 會直接忽略。帶明確標籤的條目仍要過設定驗證：名稱必須非空，URL 必須用 HTTP(S)。`file://`、`http-file://` 和 `https-file://` 仍不受支援。

在條目行裡，成對引號之外的 `#` 只要位於語句開頭，或者緊跟 ASCII 空格、Tab 字元，就開始註釋。裸 URL 裡緊貼前文的 `#` 仍是資料，前一個字元是括號也一樣，例如 `https://example.com/sub?filter=(hk)#token`。User-Agent 裡如果有前面帶空格的 `#`，要給 UA 加引號，寫成 `'https://example.com/sub'('agent # build')`，否則註釋會把這段字尾截斷。

URL 帶引號時，緊貼結束引號或完整 `(UA)` 字尾的 `#` 會被當作註釋接受，並在該位元組處產生 `legacy-glued-hash` warning，提示在註釋前加空白。`'http://q'#c` 和 `'http://q'(ua)#c` 都保留 URL `http://q`，只有後者設定 UA `ua`。成對引號裡的括號不計入巢狀深度。字尾內部緊貼前文的 `#` 仍是 UA 資料，例如 `(Mozilla/5.0 (X11; (Linux)#build))` 裡的 `#`。其他尾隨文字會讓 honk 略過該條目，並產生 `trailing-entry-text` 或 `legacy-ua-boundary` 診斷，例如 `(ua)(x)` 或 `(agent) junk`。

這種緊貼尾部的相容截斷發生在區塊結構識別之後，不算詞法註釋。`sub: 'http://q'(ua)# }` 裡獨立的 `}` 仍會關閉訂閱區塊，後面的條目就會落到區塊外。應寫成 `(ua) # }`，讓大括號變成註釋資料。

引號錯誤和區塊結構規則見[方言參考](./dialect.md)。

## 內部模型

| 欄位 | 型別 | 預設值 | 可在 dae 中設定 | 意義 |
| --- | --- | --- | --- | --- |
| `id` | UUID | 隨機 UUID | 否 | 執行時訂閱身分。SIGHUP 時，如果抓取身分與已有訂閱匹配，就保留這個值；抓取身分由 URL、設定的 `ua` 和 header 組成。結構化設定 `id` 時，值不能為 nil，並且要在所有條目中唯一。 |
| `name` | string | `""` | 是，作為標籤；省略時取 URL 主機名 | 顯示標籤，也是代理群組 `subtag(...)` 過濾條件和 DNS `subtag(...)` 規則用的值。 |
| `url` | string | `""` | 是 | HTTP(S) 抓取 URL。 |
| `sub_type` | enum | `simple` | 否 | 正文解析器：`simple`、`clash`、`sip008` 或 `custom`。 |
| `update_interval` | u64 | `86400` | 是，對應 `interval` | 定期重新整理間隔，單位為秒；`0` 停用定期重新整理。 |
| `user_agent` | string 或 null | null | 是，對應 `ua` | 可選的 `User-Agent` 覆寫值；為 null 或空時傳送 `honk/<version>`。 |
| `headers` | `{key,value}[]` | `[]` | 否 | 按順序傳送的額外請求 header；同名 header 逐條傳送。header 名稱或值無效時，抓取失敗。 |
| `download_detour` | string | `""` | 是，對應 `route` | 抓取的出口；見 [`route`](#route)。 |
| `enabled` | bool | `true` | 否 | 停用的訂閱不恢復、不抓取、不重新整理。 |
| `cache` | bool | `true` | 是，對應 `cache` | 正文快取，供離線啟動恢復；見 [`cache`](#cache)。 |
| `last_updated` | datetime 或 null | null | 否 | 模型中繼資料；目前 core 執行時不會更新該欄位。 |
| `node_count` | u32 | `0` | 否 | 模型中繼資料；目前 core 執行時不會更新該欄位。 |
| `created_at` | datetime | 構造時間 | 否 | 模型構造時間。 |

正文解析器按下面的規則選擇：

| `sub_type` | 解析行為 |
| --- | --- |
| `simple` | 自動識別分享連結清單、Clash YAML/JSON、SIP008、sing-box JSON/YAML 和受支援的用戶端記錄。 |
| `clash` | 帶頂層 `proxies` 序列的 YAML 或 JSON。 |
| `sip008` | SIP008 `servers` 物件或裸伺服器陣列；不是分享連結清單。 |
| `custom` | 與 `simple` 使用相同的格式識別。 |

`honk-tool sub` 對下載的正文和本地檔案使用同一個解析器。

## 抓取、持久化與恢復

`global.store_subscribe` 預設是 `true`。啟用後，執行時開啟私有訂閱儲存，並立即抓取每個已啟用的訂閱。請求預設用 `honk/<version>`，可以用 `user_agent` 覆寫。`update_interval` 非零時，執行時安排後續重新整理。

| 屬性 | 目前行為 |
| --- | --- |
| 位置 | 狀態資料庫 `<data_dir>/state/honk.db` 裡的 `subscription_body` 表。檔案權限 0600，目錄 0700，見 [API 參考](./api.md#設定資料庫--store-db)。`data_dir` 預設是 `/var/lib/honk`。 |
| Key | 對帶長度邊界的 URL、設定裡的 user agent 覆寫值，以及有序的 header key/value 對計算 SHA-256，再用 URL-safe Base64 編碼並加上 `.sub`。user agent 覆寫值未設定或為空時，按空值參與計算。版本化的預設請求 UA 不參與計算，所以預設訂閱升級後仍能沿用已存正文。請求身分不會以明文暴露。 |
| 寫入邊界 | HTTP 請求成功且正文通過匯入驗證後，honk 在一個交易裡儲存完整的原始回應，被拒絕的條目也算在內。 |
| 容量限制 | 單一正文最多 8 MiB，全部正文合計最多 32 MiB。寫入會讓總量超過 32 MiB 時，honk 先刪除已停用訂閱的正文；仍然超出就拒絕寫入，保留原正文，並在本次抓取中報告 `subscription-store-write-failed`。訂閱連續兩次維護都沒啟用時，honk 刪掉它的正文；維護每 60 秒一次。啟動時 `store_subscribe: false`，但因 `cache_file`、`password_auth` 或 `--store db` 仍開啟了狀態資料庫時，honk 會清空該表。 |
| 從 `.sub` 升級 | 取得實例鎖後，honk 匯入符合條件的舊正文，步驟見下文。 |
| 重新導向 | 最多 5 跳。從 `https` 重新導向到其他 scheme，本次抓取失敗。重新導向到 loopback、私有、連結本機或未指定的字面位址，也同樣失敗，除非設定的 URL 自己就用了該位址。解析到這類位址的主機名不在檢查範圍內。 |
| 正文大小 | 最多 8 MiB，在讀取過程中判定，不等整個正文緩衝完。 |

啟動時，honk 取得實例鎖，然後按下面的步驟匯入舊 `.sub` 儲存：

1. 依次檢查 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub`，選第一個私有舊儲存。
2. 複製已啟用訂閱的正文；狀態資料庫裡已有的正文優先。
3. 刪掉已複製的 `*.sub`，以及該目錄裡所有 `.*.tmp` 檔案。目錄空了就一併刪掉，其他舊位置不動。

無法讀取、超過 8 MiB，或會讓總量超過 32 MiB 的正文留在原處，honk 記一條 warning。已停用訂閱的正文也保留。以後啟動時啟用該訂閱，honk 可以直接匯入正文，不用抓取。

匯入前舊行程已經退出，所以它最後寫入的正文和其他正文一樣會被複製。此後舊版本再啟動時，只能找到保留下來的正文，其餘訂閱會重新抓取。

訂閱正文及其產生的節點都屬於執行時狀態，不會寫回 dae 設定。

除非條目的 [`route`](#route) 或 `assets.route` 另有指定，訂閱抓取預設走路由，和 honk 發起的其他下載一樣。

經路由的請求與 Geo 資料、外部 UI 下載共用路由決策和隧道，並保留同樣的 `User-Agent`、header 和下載限制：

| 限制 | 行為 |
| --- | --- |
| 逾時與正文大小 | 30 秒；最多 8 MiB。 |
| 重新導向狀態碼 | 僅跟隨 301、302、303、307、308，最多 5 次。 |
| 重新導向目標 | 不允許從 HTTPS 轉到 HTTP，也不允許從公網位址轉到私有字面位址。前一張表的重新導向限制同樣適用。 |
| URL userinfo | URL 中的 userinfo 以基本認證傳送。 |
| 協定、主機或埠變化 | 協定、主機或埠一變，honk 就去掉 `Authorization`、`Cookie`、`Cookie2`、`WWW-Authenticate`、`Proxy-Authorization` 和設定的 `Host`。 |
| Referer | Referer 設為上一跳 URL，並去掉 userinfo 和 fragment。 |

未啟用 `native-api` 的建置使用相同的訂閱抓取路由規則。

訂閱可能經由它自己提供的節點抓取，例如規則把訂閱 URL 發往一個只含該訂閱節點的群組。全新安裝時這些節點還不存在。honk 不會退回直連：所選路由沒有可用節點時，抓取失敗，錯誤訊息給出訂閱名和出站，說明這條路由暫時承載不了這次下載，並建議為該訂閱設定 `route: direct`。原生 API 的 provider 狀態裡 `last_error.code` 是 `route_unavailable`。這期間，從已存正文恢復的節點照常生效。

啟動時先恢復節點，再重新整理訂閱：

1. 連網重新整理前先解析已存正文。有效正文會立刻提供活動節點；缺失、無效或空的正文，honk 直接忽略。
2. 沒能有效恢復的 `direct` 訂閱，共用五秒的首次抓取等待，直到抓取完成或等待期滿。有效恢復的訂閱不參與等待，但仍會在背景重新整理。
3. 啟動階段的訂閱處理完成後，路由就緒，再抓取經路由的訂閱。

之後通過驗證的重新整理替換 SQLite 裡的正文行，不再寫舊儲存檔案。

恢復或首次抓取的正文裡，如果某個節點 ID 已被內嵌節點佔用，啟動設定會排除該訂閱，而不是讓啟動失敗；執行時釋出也會拒絕這種衝突。如果節點 ID 已經由其他訂閱釋出，honk 會從本訂閱裡去掉這個節點並記一條 warning，其餘節點照常釋出，該節點仍歸先發布的訂閱。正文仍然可以替換該訂閱自己的節點。

原生 API 的 provider 會把 `last_error.code` 報為 `publication_rejected`，把 `last_error.details.diagnostic_code` 報為 `duplicate-node-id`。釋出這樣被拒絕後，已恢復的正文仍算已恢復：該訂閱不參與首次抓取等待，背景重新整理照常執行，並重複這項檢查。

SIGHUP 時，抓取身分相同的訂閱保留執行時 ID；抓取身分由 URL、設定的 `ua` 和 header 組成。reload 沿用仍處於啟用狀態的訂閱的活動節點，提交重建後的設定，然後立刻開始背景重新整理。即使某個訂閱沒有存活節點，reload 也不會讀已存正文；只有啟動時才從儲存恢復正文。

抓取失敗時，honk 會保留可用的執行時狀態：

- HTTP 錯誤、UTF-8 編碼錯誤、解析錯誤，或者沒有可用節點，都不會發布替換節點，也不會寫入儲存，所以活動節點和上一次有效正文都還在。通過驗證的正文按原始位元組儲存，不修復編碼。
- 抓取失敗後，honk 先等待 30 秒和 `interval` 中較小的那個，之後每次翻倍，上限是 10 分鐘和 `interval` 中較小的那個；`interval: 0` 關閉自動重試。釋出成功或被拒絕都會結束已有的退避，恢復正常重新整理間隔。
- 解析成功後，持久化寫入失敗算非致命錯誤。新解析出的節點仍會返回，供釋出使用；原子寫入不會留下不完整的正文。下次啟動時，可以從磁碟恢復任何一份完整有效的正文。
- 不支援或格式錯誤的節點逐個略過。共用節點建構器給出的 warning 帶從 1 開始的條目索引和固定的拒絕原因。流傳輸正規化錯誤還會帶上標準欄位，例如 `proxies[1].xhttp` 或 `outbounds[1].ws_headers`，不暴露提交的 header 名稱、值或憑據。只有剩餘可用節點為零時，整個正文才算失敗；空結果絕不會清空上一 generation 的節點。

上一次有效正文指通過目前匯入規則驗證的正文，不是最後一次成功釋出的執行時設定。部分條目無效、但還剩一個可用節點的正文，可以替換儲存；全部條目無效的不行。恢復正文時，honk 按目前規則重新解析，所以舊版本儲存的正文可能被拒絕。寫入成功後，如果節點集合驗證或釋出失敗，活動設定不變，但磁碟上可能已經存了新正文。磁碟和活動設定不在同一個交易裡。

## 首次啟動時訂閱 URL 被阻斷

訂閱 URL 被阻斷，或它的網域被 DNS 汙染時，可以先新增一個可達的靜態代理節點，再把
訂閱的 `route` 指向只含這個節點的群組。該群組在首次啟動時就能用，不依賴任何訂閱提供
的節點。範例裡的 SOCKS5 位址要換成能存取 provider 的代理位址，訂閱 URL 換成實際
位址。

```dae
node {
    bootstrap: 'socks5://192.168.1.2:1080'
}

group {
    Bootstrap {
        filter: name(bootstrap)
    }
}

subscription {
    provider: 'https://example.com/sub' {
        route: Bootstrap
    }
}
```

## 訂閱正文格式

所有被接受的節點都會獲得訂閱 ID。派生出的節點 ID 重複時，保留第一個可用條目；被拒絕的條目不佔身分。後續重複條目的診斷會同時記下兩個原始索引。陣列索引從 1 開始，在正規化前確定；URI 和記錄索引用實體行號，空行和註釋也算在內。解碼後的 Base64 帶一個指向原始正文的子來源，不虛構編碼位元組偏移。匯入完整用戶端設定時只取節點，其中的 DNS、路由、群組和遠端訂閱設定都不匯入。

正規化後的條目逐個進入 admission 流程，不保留一個和正文條目數一樣大的中間結果清單。每份正文最多保留 128 條非終止診斷；超出時追加一條 `subscription-diagnostics-truncated` 摘要，記下省略了多少條。導致正文失敗的終止錯誤單獨保留。呼叫方原有的診斷不變，也不佔這個限額。結構化匯入、URI 匯入、記錄匯入都用同一限額，Base64 解碼和持久化正文恢復也不例外；達到限額不會中斷有效節點的 admission，也不改變重複節點保留第一個可用條目的規則。

`simple` 和 `custom` 先嘗試標準或 URL-safe 的 Base64 解碼，所以 Base64 編碼能承載任何可識別的格式，不限於分享連結清單。`clash` 和 `sip008` 要求正文不編碼。

| 診斷程式碼 | 結果 |
| --- | --- |
| `malformed-subscription-entry` | 略過欄位無效或語法錯誤的條目。 |
| `unsupported-subscription-entry` | 略過依賴不支援的協定或 feature 的條目。 |
| `duplicate-subscription-entry` | 略過節點身分重複的後續條目。 |
| `subscription-profile-entry` | 忽略設定檔中的非代理內容。 |
| `invalid-subscription-encoding` | 拒絕不是 UTF-8 的正文，包括 Base64 解碼後的內容。 |
| `invalid-subscription-body` | 拒絕無法解析的結構化正文。 |
| `empty-subscription-body` | 拒絕沒有可用節點的正文。 |

Clash、SIP008 和 sing-box 的憑據純量保留字串的原始位元組，原生有限數則轉成來源格式的標準十進位文字。缺失或 null 表示未提供。布林值、清單、對映和非有限數會讓條目被拒絕。有效的別名掩蓋不了已提供的無效憑據。數字 UUID 仍然過不了 UUID 驗證；空密碼仍要滿足對應協定的要求。

### 分享連結清單

正文可以是純文字，也可以用標準或 URL-safe Base64 編碼；填充可以省略，編碼區塊之間允許 ASCII 空白。原始正文和解碼後的正文都能以 UTF-8 BOM 開頭。每行一個分享連結：

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

空行、註釋和 Shadowrocket 的 `REMARKS=`、`STATUS=` 中繼資料行，honk 會忽略，也不產生節點 warning。其餘每行交給 `Node::from_share_link` 解析；不支援或格式錯誤的行會略過並記 warning。honk 不執行代理外掛，所以帶非空外掛值的分享連結也略過。正文裡沒有一個受支援的節點 URI 時，包括只有中繼資料的正文，honk 拒絕整個正文。標準的分享連結欄位和協定見[節點參考](./nodes.md)。

### Clash YAML 與 JSON

完整設定或 provider 正文必須包含頂層 `proxies` 序列。缺少受支援的 `type`、伺服器位址、有效非零埠或必需憑據的條目，honk 會略過。埠可以是整數，也可以是數字字串。JSON 用原生解碼，支援顯示名稱裡的 UTF-16 代理對跳脫。

可接受的 `type` 有 `socks5`、`ss`/`shadowsocks`、`trojan`、`vmess`、`vless`、`hysteria2`/`hysteria`、`tuic`、`juicity` 和 `anytls`。無關的用戶端中繼資料，honk 會忽略；不支援的傳輸方式、代理外掛，以及相互矛盾的安全設定，也不會被悄悄替換。

#### 通用代理欄位

| Clash 欄位 | 內部欄位 | 規則 |
| --- | --- | --- |
| `name` | `name` | 預設為 `<type>-<server>:<port>`。 |
| `server`, `port` | `host`, `port`, `address` | 必需的位址和非零 `u16` 埠；接受數字形式的埠字串。 |
| `username` | `username` | 可選 string。 |
| `password` | `password` | 可選 string；VLESS 按下文列出的優先順序取值。 |
| `cipher` | `encryption` | 可選加密演算法；VLESS 的欄位優先順序見下文。 |
| `plugin`, `plugin-opts`, `plugin_opts` | — | 不支援。任一欄位非空時，honk 在釋出節點前略過該條目，對映型別的 options 也拒絕。 |
| `network` | `transport` 或封包網路 capability | Trojan/VMess/VLESS 用流傳輸，可取 `tcp`、`ws`、`grpc`、`xhttp`；AnyTLS 用封包網路 capability。 |
| `tls` | `tls` | 可選 bool。Trojan、AnyTLS、Hysteria2、TUIC 和 Juicity 預設啟用 TLS，明確關閉會被拒絕。 |
| `servername`、`server-name`、`sni` | `sni` | 空值或純空白名稱視為未指定；非空別名必須逐位元組一致。 |
| `skip-cert-verify`、`skip_cert_verify`、`insecure` | `skip_cert_verify` | 須使用原生布林值；已提供的別名必須一致。 |
| `fingerprint`、`pin-sha256`、`pin_sha256` | `tls_pin_sha256` | 葉憑證 SHA-256 固定值，十六進位，忽略冒號和空白；它取代 PKI 與主機名稱驗證。所有 TLS 協定都會匯入 Clash 的 `fingerprint`，不帶 TLS 的協定則略過該條目。已提供的別名必須一致。 |
| `alpn` | `tls_alpn` | raw TCP TLS 的有序字串清單或逗號分隔字串；XHTTP 只接受 H2，省略時正規化為 `["h2"]`。QUIC 保留下文的協定專屬規則。 |
| `disable-sni`, `disable_sni` | — | `true` 時略過該條目；`false` 可以接受。 |

#### 協定專屬選項

支援的拼寫別名會在派生節點身分前正規化。

| 協定 | 匯入的選項 |
| --- | --- |
| Hysteria2 | `password`/`auth`，以及 `obfs: salamander` 與 `obfs-password`。支援上傳/下載頻寬、`ports`/`mport` 跳躍埠範圍、`hop-interval`/`mhop`、接收視窗、MTU 與 MTU 探索設定。 |
| TUIC | UUID/密碼、擁塞控制、ALPN、接收視窗、MTU。 |
| AnyTLS | `idle-session-check-interval`、`idle-session-timeout`、`min-idle-session`。 |

明確關閉的 feature block 按停用處理，honk 不會把它當成已啟用的不支援的 feature。原生支援 UDP 的協定接受 `udp: true`；VMess 沒有 UDP 路徑，honk 忽略這個宣告，節點仍按 TCP 匯入。節點模型保留不了明確 UDP 限制時，honk 拒絕匯入。

TUIC 允許省略密碼或使用空密碼。Hysteria2 和 Juicity 接受與執行時固定選擇一致的 `h3` ALPN。

Juicity 的流接收視窗和連線接收視窗初始都是 8 MiB，自適應流控可以分別把它們調高到最多 32 MiB。匯入時的初始視窗欄位接受缺失、`0` 或 `8388608`，其他覆寫值拒絕。

AnyTLS 按 `anytls-network`、適用的 `network`、`udp` 的順序，一次性解析封包 capability 宣告。空字串或 null 不提供網路宣告。網路字串用逗號分隔 `tcp` 和 `udp`。別名按是否允許 UDP 比較，所以 `udp` 與 `tcp,udp` 一致，`tcp` 與 `udp: true` 衝突。即使已有有效別名，`quic` 這類未知值仍會讓條目被拒絕。等價的宣告保留第一個明確網路欄位的寫法；只給布林值時，才產生 `tcp` 或 `tcp,udp`。

以下 TCP TLS ALPN 規則適用於結構化訂閱匯入和扁平欄位 `tls_alpn`。分享連結的 ALPN 相容行為不變。

| 輸入或限制 | 行為 |
| --- | --- |
| 清單成員 | 原樣保留位元組和順序。每個名稱佔 1–255 個 UTF-8 位元組。 |
| 帶長度字首的完整清單 | 最多 65,533 位元組。完整 ClientHello 還受 TLS 庫的大小限制。 |
| 匯入的 `alpn` 缺失、為 null 或為空 | 保留原有 TLS 設定方案預設值及節點 ID。 |
| 扁平 `tls_alpn` | 接受省略或字串陣列，不接受 null。 |
| 非空覆寫值 | 參與節點身分派生。與關閉 TLS、REALITY、WebSocket 或 gRPC 組合時，honk 會拒絕，不會直接忽略。 |
| Chrome ALPS | 僅在實際 ALPN 清單包含 `h2` 時傳送。 |

XHTTP 不受裸 TCP ALPN 規則限制：它始終使用 H2，包括 REALITY 和明確明文 H2。Mihomo 接受 `network: xhttp` 或輸入別名 `splithttp`。

| `xhttp-opts` 欄位 | 匯入行為 |
| --- | --- |
| `path`、`host`、`mode`、`headers`、`x-padding-bytes`、`no-grpc-header`、`sc-max-each-post-bytes`、`sc-min-posts-interval-ms` | 接受。 |
| `no-sse-header`、`sc-max-buffered-posts`、`sc-stream-up-server-secs` | 僅伺服器端使用，檢查型別後丟棄。 |
| `reuse-settings`、`xmux` | 按 Xray 語義遵循 URI `xmux` 規則。Mihomo 則只要存在 `reuse-settings` 就啟用自己的重用管理器。 |
| `download-settings` | 須為 Xray StreamConfig 對映，見下文。 |

`download-settings` 接受面板匯出的 Xray 結構。欄位有 `address`、`port`、`network`、`security`、`alpn`、`tlsSettings`、`xhttpSettings`。還可以包含扁平的 `x-padding-bytes`、只在上傳端使用的 `no-grpc-header`/`sc-*` key，以及預設值的 `reuse-settings`/`xmux`。它的語義與 URI 的 `downloadSettings` 相同，所以同一訂閱用兩種方式匯出會得到相同的節點 ID。

Mihomo 自身有繼承語義的 key，honk 會拒絕，例如 `server`、`servername`、`tls`、`skip-cert-verify`。這一點和 mihomo 有意不同：mihomo 忽略 Xray 結構的 key，把 GET 發往上傳伺服器。標準的預設值、範圍和 header 限制見 [XHTTP 節點參考](./nodes.md#h2-上的-xhttp)。

其他不支援的參數，包括放在別的欄位位置和填充混淆設定，只要出現就會讓條目被拒絕，值為 null、空值或 false 也一樣。其他有效節點照常保留。解析 URI 或 VMess extra JSON 時，honk 在建構對映前就拒絕重複成員。

#### VLESS transport 與 REALITY

VLESS 欄位會在派生節點身分前應用：

| Clash 輸入 | 對映 |
| --- | --- |
| `uuid`, then `password` | 憑據；`uuid` 優先，`password` 作為回退。 |
| `encryption`, then `cipher` | VLESS Encryption；`encryption` 優先。 |
| `flow` | 空值或純空白視為未指定；否則必須為 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。 |
| `network` | 流傳輸；packet permission 仍由獨立的 `udp` 宣告控制。 |
| `reality-opts.public-key` | 啟用 REALITY TLS carrier；必須是非空 string。 |
| `reality-opts.short-id` | 可選 REALITY short ID。 |
| `reality-opts.spider-x` | REALITY spider path；缺失或為空時使用 `/`。 |
| `ws-opts.path` | WebSocket path；回退到扁平別名 `ws-path`。 |
| `ws-opts.headers.Host` | WebSocket Host header。key 匹配不區分大小寫，第一個非空白值優先；字串保留原始位元組，有限數字轉成文字。無效或空白的 Host 值，honk 忽略。取值依次回退到 scalar `ws-headers`、`ws-host`，只有前面都沒有可用值時才看下一項。 |
| `ws-opts.headers.<name>` | 附加的 WebSocket 升級 header，所有支援 WebSocket 的代理共用；以小寫名稱匯入，例如 `User-Agent`。null 值忽略，非 scalar 值會讓條目被丟棄；保留的握手 header 會按[節點欄位約定](./nodes.md#欄位)拒絕該條目。 |
| `grpc-opts.grpc-service-name` | gRPC service name；回退到 `grpc-service`。 |
| `client-fingerprint` | 有意不匯入。TLS 指紋由行程級 `global.tls_implementation` 與 `global.utls_imitate` 選擇。 |

巢狀的 WS/gRPC 值優先於對應的扁平別名。啟用的 `reality-opts` 必須是對映，並且含非空 `public-key`；無效的啟用宣告絕不會降級成普通 TLS。空 block 或明確停用的 feature block，honk 直接忽略。匯入的 REALITY 和標準分享連結行為一致：只用 TLS 1.3，key share 先 hybrid 後 classic，單個 ClientHello 且 fail-closed；見[節點參考](./nodes.md#vless-udp-and-multiplexing)。

#### VLESS UDP 與多路複用

匯入的預設值取決於來源格式，而且並不都等於 honk 標準的 `packetEncoding=auto` 預設值。

| Clash 表示 | Packet 回退 | Multiplex | UDP permission |
| --- | --- | --- | --- |
| 沒有封包宣告且沒有啟用的封裝 | `auto` | off | 關閉 |
| 只有空/null 封包編碼 | `auto` | off | 關閉 |
| `packet-encoding: none`/`legacy`，或 `xudp: false` | 原生 | off | 除非 `udp: false`，否則開啟 |
| `packet-encoding: xudp`，或 `xudp: true` | Single XUDP | off | 除非 `udp: false`，否則開啟 |
| 未宣告其他封包設定時的 `udp: true` | Single XUDP | off | 開啟 |
| `udp-over-tcp: true`，或 version 為 `0`/`2` 的啟用 object | UoT v2 | off | 除非 `udp: false`，否則開啟 |
| 啟用 `smux`/`multiplex`，並指定 `protocol: h2mux` 或明確 `padding` | auto，被封裝接管時不生效 | H2MUX | 除非 `udp: false`，否則開啟 |
| `mux: { enabled: true, ... }` | `auto`，除非明確封包編碼還能通過 protocol 回退或 `skip` 生效 | Xray Mux.Cool | 除非 `udp: false`，否則開啟 |

啟用 H2MUX 時，必須設定 `protocol: h2mux` 或明確的 `padding`。`padding` 預設是 `false`，設為 `true` 選擇帶填充的 H2MUX。`only-tcp: true`、啟用的 Brutal，以及非零的 `max-connections`、`min-streams` 或 `max-streams`，都會讓條目被拒絕。啟用的 H2MUX 與 Xray mux、UoT 互斥，啟用的 UoT 也與 Xray mux 互斥。明確 XUDP 與 H2MUX 或 UoT 衝突。封裝接管後，原生或 auto 宣告不生效。

啟用的 Clash `mux` 區塊只把 `enabled`、有符號 `i16` 的 `concurrency` 和 `xudpConcurrency`，以及 `xudpProxyUDP443` 當作有效設定。未生效的額外設定直接忽略。

| 並行值 | TCP `concurrency` | `xudpConcurrency` |
| --- | --- | --- |
| 負值 | 關閉 TCP 多路複用。 | 使用封包回退路徑。 |
| 零 | 每條 TCP carrier 允許同時承載 8 個邏輯 child。 | 共用已啟用的 TCP 池和它的逐連線並行值。TCP 多路複用關閉時，走封包回退路徑。 |
| 正值 | 設定每條 carrier 的邏輯 child 並行上限，最多 128。 | 建立獨立 UDP 池，按該值設定每條 carrier 的邏輯 child 並行上限，最多 128。 |

並行值不表示實體 carrier 數量。UDP/443 策略預設是 `allow`，也接受 `skip` 或 `reject`。優先順序見[節點參考](./nodes.md#vless-udp-and-multiplexing)。

`udp: false` 單獨關閉封包撥號，仍然符合條件的裸 TCP 路徑不受影響。遇到下面這些情況，honk 也會拒絕該 VLESS Clash 條目：別名衝突、重複的 XUDP 表示、啟用的 packet-address 模式、不支援的封包編碼、不支援的 UoT version，以及啟用的 Xray mux 裡無效或不支援的設定。

標準 VLESS 分享連結用精確的 `packetEncoding=auto|none|xudp|uot-v2`、`mux=off|h2mux|xray` 和 `udp=0|1` 查詢參數。已移除的 `vless_mode` 查詢參數，以及 `smux`、`udp-over-tcp`、`packet-encoding` 這類含義不明確的第三方拼寫，honk 一律拒絕，不猜測語義。

### SIP008 與 sing-box JSON 或 YAML

SIP008 和 sing-box 正文可以是 JSON，也可以是等價的 YAML。SIP008 的 `{"servers":[...]}` 封裝和裸伺服器陣列會匯入 Shadowsocks 的 `server`、`server_port`、`method`、`password` 和 `remarks`。封裝裡的 `version` 必須是整數 `1` 或 `2`。空的外掛欄位不會導致拒絕；有效的外掛設定仍不受支援。

sing-box 設定從 `outbounds` 匯入受支援的條目：

- 代理節點：Shadowsocks、SOCKS5、VMess、VLESS、Trojan、Hysteria2、TUIC、Juicity、AnyTLS。
- 結構性條目，不屬於代理節點：`selector`、`urltest`、`direct`、`block`、`dns`。

TLS/SNI、REALITY、WebSocket/gRPC 升級 header、VLESS 封包選項，以及受支援的協定調優，都會經過共用的節點建構器正規化。`Host` 以外的升級 header 同樣包括在內。

沒設定 `tls` 或 `tls.enabled` 時，sing-box 的 TLS 處於關閉狀態，所以沒有 `tls.enabled: true` 的 Trojan、Hysteria2、TUIC、Juicity 和 AnyTLS 條目，honk 會略過。

| 來源特有情況 | 匯入行為 |
| --- | --- |
| WebSocket `transport.headers` | `Host` 保留為獨立的 string 欄位，重複的 Host 別名會被拒絕。其他 string 值原樣保留，空字串也算；null 忽略，其他型別會讓條目被拒絕。名稱和值遵循[節點 header 約定](./nodes.md#欄位)。 |
| VLESS 未啟用 H2MUX/UoT 封裝，且沒有明確 `packet_encoding` 選擇其他路徑 | 使用 Single XUDP 並允許 UDP。這是 sing-box 匯入的預設值，不是 Auto 的全域意義。 |
| gRPC 服務名為空或省略 | 保留 sing-box 的空服務名，不使用 honk 的 `GunService` 預設值。 |
| Hysteria2 提供 `server_ports`，未提供 `server_port` | 以第一個跳躍埠作為名義 endpoint。 |
| 節點級 uTLS 指紋提示 | 不覆寫 honk 的行程級 TLS 選擇。 |

不支援的鏈式代理、wire feature 或認證要求，honk 會報錯，不會直接忽略。

在 sing-box 輸入裡，`network` 表示封包網路 capability，不是流傳輸型別；流傳輸方式由 `transport.type` 選擇。`h2` 這類不支援的名稱，honk 會拒絕，不會把它當成裸 TCP。

官方 sing-box 沒有原生 XHTTP 傳輸。匯入器明確拒絕 `transport.type: xhttp` 和 `splithttp`，也不會把舊的 `http`、H2、QUIC 或第三方 fork 解釋成 XHTTP。Client-record 裡的 XHTTP 傳輸同樣不受支援。

在支援封包限制的 sing-box 對映裡，`network: udp` 和 `network: tcp,udp` 允許 UDP，`network: tcp` 關閉 UDP。這些值不會反過來禁止 TCP。`network` 和 VLESS 回退編碼、H2MUX/UoT carrier 的選擇互不影響。

明確寫出的 sing-box 原生 VLESS UDP，即 `packet_encoding: ""`，對映為原生路徑。啟用 H2MUX 或 UoT v2 後，封包路徑由封裝承載，即使來源同時明確指定了 `packet_encoding` 也一樣，包括 `"xudp"`。停用封裝不會關掉 sing-box 的 Single-XUDP 預設值。sing-box 多路複用匯入仍只支援 H2MUX，不會合成 Xray Mux.Cool 控制項。

### Surge、Surfboard、Loon 與 Quantumult X

匯入器接受 Surge/Surfboard/Loon 的具名逗號分隔記錄，也接受 Quantumult X 的 `protocol=endpoint,...,tag=name` 記錄。完整設定用 `[Proxy]` 或 `[server_local]`；其他設定段 honk 忽略。帶引號的名稱和密碼可以包含逗號、等號、跳脫引號，以及有意保留的首尾空格。

明確憑據和加密方法別名在轉換前必須一致。具名記錄只有在對應的具名值缺失時，才使用位置參數；有效的明確值不會因為位置參數不同而衝突。Quantumult X 不用位置參數回退。明確空憑據也參與別名比較，不會觸發回退。

允許為空的可選記錄憑據會逐位元組保留空字串和帶引號的空白，包括 SOCKS 使用者名稱和密碼、Hysteria2 認證值、TUIC 密碼。明確空值仍優先於位置參數；要求非空憑據的協定仍然拒絕空值。

honk 在賦值前比較記錄裡的 `transport`/`network` 流傳輸宣告；重複 key 也比。空字串和 `tcp` 都表示裸 TCP。宣告衝突或含不支援的傳輸方式時，honk 拒絕該條目。

AnyTLS 記錄裡的 `network` 表示封包 capability，不是流傳輸方式。honk 在選擇前驗證所有重複的 `network`、`udp` 和 `udp-relay` 值。等價宣告保留第一個明確網路值的寫法；只要有一個值無效或衝突，honk 就拒絕該記錄。

VLESS 記錄的 `packet-encoding`/`packet_encoding`/`packetencoding` 值為 `none` 或空時，選擇原生 UDP；值為 `xudp` 時選擇 Single XUDP。重複別名的值必須一致，明確空賦值也算。`udp`/`udp-relay` 單獨控制 packet permission。既沒有封包編碼也沒有 `udp: true` 時，記錄保持 UDP 關閉；只有 `udp: true` 時選擇 Single XUDP。記錄格式裡有效的 `mux` 和 UoT 宣告仍不受支援，honk 不會重新解釋它們。

受支援的記錄把憑據、TLS/SNI、WebSocket/gRPC、REALITY 和已實作的協定選項對映到同一個節點模型。Quantumult X 的 `obfs=wss` 會把 `obfs-host` 同時用作 WebSocket Host 和預設 TLS SNI；明確 TLS 主機名優先。SSR、不支援的外掛、混淆和傳輸方式，honk 直接略過，不會當成別的協定匯入。

Surge 的 `server-cert-fingerprint-sha256` 對映到 honk 的葉憑證 pin，兩者都替代標準 X.509 驗證。`server-cert-verify-name`、用戶端憑證、`sni=off` 和 Shadow TLS 在 honk 裡表達不出來，honk 會拒絕，不會直接忽略，見 [Surge TLS 參考](https://manual.nssurge.com/policies/tls.html)。

honk 在賦值前比較記錄裡的 `skip-cert-verify`、`allow-insecure`、`insecure`，以及取反後的 `tls-verification`。`tls-verification=false,insecure=true` 算一致；`tls-verification=true,insecure=true` 時，honk 拒絕該條目。記錄文字只接受不區分大小寫的 `true/yes/1/on` 和 `false/no/0/off`；空字串和 `t/y/f/n` 仍是無效值。憑證固定規則的限制不變。

Quantumult X 裡有效的 `tls-cert-sha256` / `tls-pubkey-sha256` 固定憑證設定，honk 會拒絕：honk 的葉憑證 pin 替代 PKI，不能替換一個尚未確認等價的外部驗證約定。明確設定 `tls-verification=false` 時，QX 會忽略這兩類 pin，匯入後保留這種停用驗證的行為。有效的 QX REALITY 會按[官方設定](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)忽略自訂的 `tls-alpn` 和 session-ticket 設定；普通 TLS 沒有這個例外。舊 VMess `aead=false`、啟用的 Shadowsocks UoT/SSR、不支援的 TLS ALPN，以及停用 TLS session 重用，honk 都會拒絕，不會直接忽略。

## 離線解析與探測

`honk-tool sub` 接受需要抓取的訂閱 URL，也接受任一種受支援正文格式的本機檔案。本機檔案不會觸發訂閱下載，可以離線解析；之後命令仍會執行設定的連通性和延遲探測：

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

傳入 `-` 時，從標準輸入讀一個 HTTP(S) 訂閱 URL，不讀訂閱正文。探測參數和輸出見 [CLI 參考](./cli.md)。

## 相關文件

- [節點參考](./nodes.md)
- [群組參考](./groups.md)
- [CLI 參考](./cli.md)
