# Assets 設定參考

`assets {}` 設定 geodata、外部 Clash 面板和訂閱的下載預設值，也設定 geodata 的自動更新排程和檢查碼開關。

```dae
assets {
    route: routing
    geodata {
        geosite: 'https://example.org/geosite.dat'
        geoip: 'https://example.org/geoip.dat'
        route: direct
        auto_update: true
        cron: '0 3 * * *'
        checksum: true
    }
    ui {
        url: 'https://example.org/dashboard.zip'
    }
    subscription {
        ua: 'clash.meta'
        interval: 6h
        cache: true
    }
}
```

## 欄位

| Key | 預設值 | 意義 |
| --- | --- | --- |
| `route` | 省略，`routing` | 設定檔裡各項下載的預設出口。見 [`route`](#route)。 |
| `geodata.geosite` | 省略，有狀態資料庫時用內建 URL | 已載入的 geosite 資產的 HTTP(S) 來源。見 [`geodata.geosite`](#geodatageosite)。 |
| `geodata.geoip` | 省略，有狀態資料庫時用內建 URL | 已載入的 geoip 資產的 HTTP(S) 來源。見 [`geodata.geoip`](#geodatageoip)。 |
| `geodata.route` | 省略，`assets.route` | Geodata 下載及檢查碼請求的出口。見 [`geodata.route`](#geodataroute)。 |
| `geodata.auto_update` | 省略，`true` | 更新路由或 DNS 已載入的 geodata 檔案。見 [`geodata.auto_update`](#geodataauto_update)。 |
| `geodata.cron` | 省略，`0 3 * * *` | 自動更新在系統本地時區的執行時間。見 [`geodata.cron`](#geodatacron)。 |
| `geodata.checksum` | 省略，`true` | 依與檔案一同釋出的 `.sha256sum` 核對每個下載檔案。見 [`geodata.checksum`](#geodatachecksum)。 |
| `ui.url` | 省略，`https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip` | 外部 dashboard ZIP 來源。見 [`ui.url`](#uiurl)。 |
| `ui.route` | 省略，`assets.route` | 外部 UI ZIP 下載的出口。見 [`ui.route`](#uiroute)。 |
| `subscription.ua` | 省略，`honk/<version>` | 訂閱條目的預設請求 User-Agent。 |
| `subscription.interval` | 省略，`86400s` | 預設定期重新整理間隔。見 [`subscription.interval`](#subscriptioninterval)。 |
| `subscription.cache` | 省略，`true` | 條目正文的預設快取開關。見 [`subscription.cache`](#subscriptioncache)。 |

### route

設定檔裡各項下載的預設出口：geodata、外部 dashboard 和訂閱。

- `routing` 依流量路由規則決定。
- `direct` 直接連線。
- 代理群組名稱會強制經由該群組。

未知的群組會在設定驗證時被拒絕。設定檔沒有指定出口時，先前透過 API 儲存的 geodata 出口繼續生效。

```dae
assets {
    route: Proxy
}
```

### geodata.geosite

已載入的 geosite 資產的 HTTP(S) 來源。URL 依照 [Geodata URL 規則](#geodata-url-規則)。

沒有狀態資料庫時，必須設定 URL 才能更新。有狀態資料庫時，該資產預設使用[內建 URL](#geodata-url-規則)。

```dae
assets {
    geodata {
        geosite: 'https://example.org/geosite.dat'
    }
}
```

### geodata.geoip

已載入的 geoip 資產的 HTTP(S) 來源。限制與預設值和 [`geodata.geosite`](#geodatageosite) 相同。

```dae
assets {
    geodata {
        geoip: 'https://example.org/geoip.dat'
    }
}
```

### geodata.route

Geodata 下載及檢查碼請求的出口。

```dae
assets {
    geodata {
        route: direct
    }
}
```

### geodata.auto_update

自動更新路由或 DNS 已載入的 geodata 檔案。從未載入的檔案不會下載。

只有在啟用原生 API 且有狀態資料庫時才會執行，見[Geodata 來源與自動更新](./api.md#geodata-來源與自動更新)。

```dae
assets {
    geodata {
        auto_update: true
    }
}
```

### geodata.cron

自動更新的時間。它是五個欄位的 cron 運算式，依序是分、時、日、月、星期。更新依系統本地時區計算，另加最多一小時的隨機延遲。

不存在的本地時間會略過。重複出現的本地時間只在第一次出現時觸發。

各欄位接受數字、`*`、清單 `a,b`、範圍 `a-b` 和步長 `*/n` 或 `a-b/n`。星期欄位的 0 與 7 都代表星期日；日與星期兩個欄位都不以 `*` 開頭時，任一欄位符合就觸發。

解析不依賴時區。解析器拒絕名稱、`@daily` 等巨集、秒欄位、每天觸發超過四次的運算式，以及不符合任何日曆日期的運算式。

步長只能接在 `*` 或範圍之後，範圍也不能繞回：`0 */6 * * *` 有效，`0 3/2 * * *` 和 `23-2` 無效。

```dae
assets {
    geodata {
        cron: '0 3 * * *'
    }
}
```

### geodata.checksum

honk 會請求與每個檔案一同釋出的 `.sha256sum`。伺服器傳回 404 時不核對，直接使用該檔案。

核對檔案的第一個欄位與檔案的 SHA-256 不符，或發生其他失敗時，honk 會拒絕這個 URL 並改試下一個。設為 `false` 時不送出該請求，檔案未經核對就直接使用。

```dae
assets {
    geodata {
        checksum: true
    }
}
```

### ui.url

外部 dashboard ZIP 來源。`HONK_UI_DOWNLOAD_URL` 優先。

只有在設定的外部 UI 目錄不存在或為空時才會下載。

```dae
assets {
    ui {
        url: 'https://example.org/dashboard.zip'
    }
}
```

### ui.route

外部 UI ZIP 下載的出口。也接受節點 tag。

### subscription.ua

訂閱條目的預設請求 User-Agent。

### subscription.interval

預設定期重新整理間隔。`0` 關閉定期重新整理。

語法與條目的 [`interval`](./subscription.md) 相同。

### subscription.cache

條目正文的預設快取開關，仍受 `global.store_subscribe` 限制。

## Geodata URL 規則

Geodata URL 必須是 HTTP(S)，不能帶 userinfo 和 fragment，長度最多 4096 位元組。可以帶查詢字串。

有狀態資料庫時，各資產會依序嘗試下列 URL：

| 資產 | URL |
| --- | --- |
| `geosite` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat`，然後 `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat` |
| `geoip` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat`，然後 `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat` |

在設定檔中設定的 URL 會取代該資產的清單，不會附加成映像。

## 已儲存設定

有狀態資料庫時，honk 會在啟動時把設定中的 geodata URL、出口、更新排程與檢查碼開關寫入已儲存設定。此後 API 的修改會覆蓋這些值，直到下次啟動。

`auto_update` 和 `cron` 合起來是一個更新排程：只設定其中一項時，另一項取預設值。兩項都不再設定時，如果先前的排程是由設定檔寫入的，就還原成預設排程。移除 `checksum` 時也一樣，前提是先前的值來自設定檔。設定檔沒有指定替代值時，API 寫入的設定繼續保留。

## 優先順序

條目裡的設定優先於 `assets.subscription` 和 `assets.route`。`geodata.route` 與 `ui.route` 又優先於 `assets.route`。兩處都沒設定時才用內建預設值。

條目語法見[訂閱參考](./subscription.md)，已儲存的 geodata 設定見 [API 參考](./api.md#geodata-來源與自動更新)。

`geodata.route` 或 `ui.route` 為空時會繼承 `assets.route`。若要讓 geodata 依路由規則處理、其他下載經由某個群組，需明確設定 `routing`：

```dae
assets {
    route: Proxy
    geodata {
        route: routing
    }
}
```

## 重啟與 reload

修改任何 `assets.geodata` 設定，或修改解析後的 UI 下載 URL 或出口，都需要重啟。SIGHUP 會拒絕這類修改。訂閱預設值會跟著使用它們的訂閱一起 reload。

## 時區與排程驗證

啟動時，geodata owner 會拒絕在實際本地時區裡永遠不會觸發的明確 cron，即使 `auto_update: false` 也一樣。保留下來的排程只在啟用時做這項檢查；設定檔裡的有效覆蓋值可以修正舊的已儲存排程。不可用的排程不會被取代成預設值。

如何停用或修復保留的排程，以及之後時區變化怎麼處理，見 [API 參考](./api.md#geodata-來源與自動更新)。

在 Linux 上，honk 鎖定的 chrono 0.4.45 會讀取 `TZ`。空值表示 UTC，`CST-8` 這類 POSIX 字串不需要 tzdata，IANA 時區名則需要可讀的 zoneinfo 檔案。沒有設定 `TZ` 時讀取 `/etc/localtime`。如果這一步失敗，再試 `iana-time-zone` 找到的系統時區名及其 zoneinfo 檔案，最後回退到 UTC。OpenWrt 沒有可用的 zoneinfo 檔案時，要把 `/etc/TZ` 的內容當成 `TZ` 傳給 honk；儲存庫的 `docker-compose.yml` 會掛載主機的 `/etc/localtime`。日誌時間戳記使用同一個時區。

## 無效值

`geodata.auto_update`、`geodata.cron` 或 `geodata.checksum` 的值無法解析時，honk 會發出 warning 並忽略該值，效果等同沒寫。

`geodata.auto_update` 和 `geodata.checksum` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不區分大小寫。

`subscription.interval` 的值無效時產生 warning 並變為 `0`；`subscription.cache` 的值無效時產生 warning 並變為 `true`。

## 舊 experimental 別名

下列 `experimental` 欄位仍會當成別名讀取。每出現一次，都會在該行產生一條 `legacy-assets-key` warning。

| 舊設定項 | 新設定項 |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

舊設定項的值非空，又同時設定對應的 `assets` 設定時，會報 `conflicting-assets-setting`；舊值為空不算衝突。`assets` 子區塊沒有對應的出口時，舊出口設定仍可覆蓋 `assets.route`。

## 非 dae 格式

只有 `.dae` 設定會解析 `assets`。JSON、YAML 和 TOML 設定儲存的是已解析的下載欄位。

使用這些格式時，`assets` 只記錄預設值，不會再次套用；請直接設定 `experimental` 下載欄位和各訂閱自己的欄位。

`assets.geodata.auto_update`、`cron` 和 `checksum` 沒有對應的 `experimental` 欄位，任何格式都從 `assets` 讀取。
