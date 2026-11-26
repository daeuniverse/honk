# 用戶端 DNS TCP syslog 稽核

`dns-syslog` 是選用的 feature，可以和原有的 eBPF/API 編譯選項組合，建置時明確開啟：

```sh
cargo build --release -p honk-core --features dns-syslog
```

這個 feature 預設關閉，`native-api` 和 `native-ui` 都不會自動帶上它。如果二進位檔
沒編入這個 feature，又開啟了 DNS 稽核，啟動會報錯；稽核入口是空實作，不建立佇列，
也不建立傳送任務。釋出版的 feature 清單保持不變，要用 DNS 稽核，得換成明確啟用
該 feature 的建置。

在 `global` 設定 TCP syslog 接收端：

```dae
global {
    syslog_addr: '192.0.2.10:514'
    syslog_dns_enabled: true
    syslog_cee_enabled: true
    syslog_hostname: 'router01'
    syslog_app_name: 'honk'
}
```

IPv6 寫成 `[2001:db8::10]:514`。稽核預設關閉，位址預設為空；啟用時必須指定一個數字
單播 IP 和非零埠。位址、傳送開關、CEE 模式，以及 hostname/app_name 的修改，都
需要重啟。

`syslog_hostname` 預設為空。為空時，啟動會讀取 `/proc/sys/kernel/hostname`，去掉結
尾的一個 LF 再驗證；讀取失敗或值不合法就回退成 `-`。這是執行 honk 的裝置名稱，不是
用戶端名稱。明確設定的 hostname 必須是 1–255 位元組、不含空格的可列印 ASCII。
`syslog_app_name` 預設是 `honk`，要求 1–48 個同樣型別的位元組。明確寫出的空白、控
制字元和 Unicode 會被拒絕，不做 trim。傳送端身分只寫進 RFC5424 訊息標頭；JSON 正
文不再帶 `hostname` 和 `app_name`，免得接收端解析後出現重複欄位。

## 擷取與事件格式

DNS 控制器和獨立 `dns.bind` 的 UDP/TCP 入口，會擷取實際用戶端、前端開始處理的時
間，以及最終產生的應答。每個請求或 TCP 訊框產生一個邏輯事件，涵蓋快取命中、負應答、
可解析的拒絕和失敗。上游重試不增加事件；用戶端重送則分別記錄。應答產生前被取消時，
記為 `result: "cancelled"`、`rcode: null`。無法投影的查詢計數後略過。起始時間取
稽核入口開始處理的時間，不是核心收到封包的時間。

稽核和 `native-api`、UI、`record_dns_log`、512 筆歷史記錄、日誌等級都無關。診斷
呼叫、背景重新整理和引擎內部解析不記錄。只有原樣 direct/group TCP/UDP 中繼、沒有經過
DNS 控制器的 53 埠流量不在涵蓋範圍內，原有路由策略也不變。

輸出用固定的 RFC5424 標頭：PRI134（local0/info）、UTC 時間、設定的身分、MSGID
`dns.query`，後面跟著完整的緊湊 JSON 事件。`syslog_cee_enabled` 預設 false，以相容於
普通的 JSON 接收端；像上例那樣設為 true 時，會在訊息前加 `@cee: ` 字首，供支援
CEE 的接收端解析：

```text
<134>1 2026-11-02T12:00:00.010000Z router01 honk - dns.query - @cee: {JSON正文}
```

```json
{
  "schema_version": 1,
  "event": "dns.query",
  "message": "DNS 192.168.1.100 example.com. A IN: NOERROR answers=1",
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
  "answers_omitted": null,
  "answer_ips": ["203.0.113.20"],
  "answer_cnames": [],
  "answer_types": ["A"]
}
```

`duration_ms` 是數值型的處理耗時，單位為毫秒，精確到微秒。單調時鐘從稽核
admission 開始計時，在最終回應準備完成或請求取消時停止，排除回應的稽核資料複製、向
用戶端傳送回應及背景日誌排隊。UTC 時間欄位仍使用系統時鐘，不用兩個時間戳記相減計時。
`upstream` 取最終結果的上游設定名稱；正常快取和過期快取的回應統一寫 `"cache"`。
本地答案、拒絕、取消等沒有上游後設資料的結果寫 null。不輸出最初上游或重查詢歷史。

`transport` 描述用戶端與 honk 之間的 DNS 傳輸方式；稽核輸出本身一律使用 TCP。完整
答案保留名稱、型別、類別、TTL 和內容，未知型別用 RFC3597 文字。honk 產生依首次出現
順序去重的陣列：`answer_ips` 取出 A/AAAA data，`answer_cnames` 取出 CNAME 目標，
`answer_types` 取出全部型別，沒有符合的項目時輸出空陣列。不刪除或改寫原始答案。應答
驗證只檢查記錄邊界，不檢查每筆記錄的內容；已經傳送給用戶端的應答仍可能無法渲染。此
時事件保留其他欄位，`answers` 為 null、陣列為空，`answers_omitted` 為 `"invalid"`
（投影超過事件上限時為 `"budget"`）；其他情況 `answers_omitted` 為 null。TC 描述實
際的用戶端應答，可能受用戶端 UDP 大小限制。擷取發生在應答傳送前，不證明用戶端已收
到。行程 UUID 重啟後改變，序號用來識別產生的事件，不為 admission 失敗編號，也不證
明無遺失。

## 訊框與批次

訊框化使用 [RFC6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587)：先寫
完整 RFC5424 訊息的十進位位元組數，再寫一個 ASCII 空格，然後是訊息內容。長度包含訊
息標頭、CEE 字首和 JSON，不包含長度字首本身；依 UTF-8 位元組計數，不依字元，也不新
增換行或 NUL。一批裡拼接多條各自訊框化的事件：

```text
<長度1> <訊息頭和JSON1><長度2> <訊息頭和JSON2>
```

接收端必須支援長度字首，不能直接把 HTTP JSON Lines 介面拿來用。不傳送 UDP，也不
做應用層分段；超過 8192 位元組的事件，只要在 4 MiB 上限內，仍是一整個訊框。重複的欄
位名、展開的名稱、搜尋陣列、長 TXT，以及二進位或未知的記錄，都會讓體積變大。

每個目標有一個非同步任務，需要時建立並重複使用一條 TCP 連線。批次目標是 128 KiB，或
者從第一條備妥的訊息起滿 1 秒就送出；後來到達的訊息不會重設這個期限。單條訊息超
過批次目標時，單獨完整傳送。完整的 RFC5424 訊息上限是 4 MiB：分配答案之前先檢查有
限的投影預算，序列化本身也有上限。超過投影預算的答案依上文省略；仍然超過訊息上限
的事件會整筆丟棄並計數，不會靜默截斷答案。這些是起始參數，不是吞吐量保證。

## admission 與故障

DNS 路徑只提交不可變的封包，不等待網路。正在擷取或等待處理的事件最多 1,024 個；
原始請求和應答、複製的上游名稱，加上條目核算，一共限制在 8 MiB。應答位元組的
admission 不等待，失敗時丟棄整個事件，不會誤記成取消。佇列滿時丟棄新事件並計數，
不拖慢 DNS。關閉這個 feature 後不複製封包，也不啟動任務。

8 MiB 是原始資料的 admission 限制，不是總記憶體。背景還會另外持有：有界的投影和
JSON、訊框化用的複製、通常不超過 128 KiB 的批次或一筆不超過 4 MiB 的事件，以及送出
時最多一筆備妥的下一個訊框。大批次佔用的容量用完就釋放。

連線 socket 之前，先設定實際的 `global.so_mark_from_dae`，並開啟 TCP_NODELAY。接
收端的網域名稱不解析，流量也不走代理；mark 設定失敗時不允許退回無標記。連線和批次
寫入的逾時都是 3 秒。連線失敗時保留有界批次、停止消費佇列，然後以 250 ms 到 30 秒
的指數退避重連。斷線期間保證不了 1 秒內送出；只有整批寫入成功才重設退避，連線成功
本身不重設。

寫入出錯或逾時的時候，批次可能已經送出一部分，所以會丟棄這個不確定的批次、關閉
連線，不重放。後續排隊的事件改用下一條連線。不承諾恰好一次，也不承諾應用層確認或
接收端已經持久化。寫入成功只算 submitted，不等於確認入庫。

關閉會立即取消連線、寫入和退避，關閉 admission，並丟棄待傳送的內容。1 秒是等待或
終止任務的上限，不是最後一次送出的寬限期。owner Drop 會終止任務；reload 不會重複
建立傳送器。關閉時會報告丟棄、無效、提交的事件，以及連線和寫入的失敗。接收端開始
故障時記一筆帶錯誤的 WARN，之後批次寫入成功時記 INFO，中間的重試記 DEBUG；佇列上
限導致的丟棄最多每 10 秒 WARN 一次，無法編碼的事件記 DEBUG。本機不寫入磁碟，留存、
輪替和搜尋都由遠端負責。

## 顯示訊息

完整 JSON 事件裡有一個非空的 `message` 摘要，寫明正規化後的用戶端 IP、查詢問題、
應答狀態，或者 `cancelled`，以及答案數量。既有的結構化欄位和完整答案繼續用於稽核
查詢；摘要也計入整筆訊息的位元組上限。

開啟 `syslog_cee_enabled: true` 後，VictoriaLogs 的 syslog 接收器展開 CEE JSON
時會把 `message` 對映到 `_msg`，日誌清單顯示的就是這個欄位。缺少該欄位的舊事件可
能顯示預設的缺少訊息預留位置，其他欄位仍會儲存。參見 [VictoriaLogs
syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
及[訊息欄位](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field)。

## 固定格式與設定變更

訊息標頭的佈局和 JSON 欄位結構是固定的，見上文。不提供訊息模板、JSON 模板、標籤、格
式版本或 CEF 模式。序列化在背景的傳送任務裡做；一般設定 reload 既不改變事件格式，
也不重啟 TCP 傳送器。上面那五項設定即使在稽核關閉時改動，也仍然需要重啟。

### 從較早的 fork 版本遷移

原本從 JSON 正文讀 `hostname` 或 `app_name` 的接收端，應改成讀取解析後的 RFC5424
標頭對應欄位。既有的歷史日誌不受影響。

`syslog_dns_template` 和 `syslog_dns_json` 已經移除。dae 設定和結構化設定只要出
現舊 key 就拒絕，空字串、false 和 null 也不能保留。如果要保持上一版固定的 CEE 輸
出，請明確設定 `syslog_cee_enabled: true`；否則預設傳送一般 JSON。開啟稽核之前，還
要確認二進位檔已經編入 `dns-syslog` feature。
