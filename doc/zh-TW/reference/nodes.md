# 節點與分享連結

`node { ... }` 從分享連結宣告可撥號的出站，並為每個節點分配穩定的執行時身分。

## 範例

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

## 欄位

Node 模型包含下列欄位。分享連結會從協議方案、userinfo、位址部分、片段和查詢參數填入供使用者設定的欄位；其餘欄位由結構化 loader、匯入或執行時填入。這些欄位都不是 dae `node {}` 裡的獨立 key；節點寫成連結和標籤，見 [`node {}` 宣告](#node--宣告)。

扁平結構化輸入必須包含 `name`、`protocol`、`address` 和 `port`，即使已設定 `host`。表中的預設值是模型預設值。

| Key | 型別 | 預設值 | 意義 |
| --- | --- | --- | --- |
| `id` | UUID | 派生 | 穩定內容身分；執行時不允許 nil。見[節點身分](#節點身分)。 |
| `name` | string | `""` | dae 標籤、解碼後的片段、`remark` 查詢參數、VMess `ps` 或不含憑據的 `{scheme}-{host}` 回退名稱。 |
| `protocol` | enum | `ss` | 從分享連結協議方案派生。 |
| `address` | string | `""` | 從連結解析的 `host:port`；它不補充缺失的埠。 |
| `host` | string | `""` | 明確伺服器端主機；否則 `Node::host()` 從 `address` 派生。 |
| `port` | u16 | `0` | 伺服器端埠；URL 形連結省略埠時使用 `443`，v2rayN VMess 酬載則必須帶有效埠。 |
| `username` / `password` | string? | `null` | 協議憑據；扁平 VMess 和 VLESS 從 `password` 讀取使用者 UUID。 |
| `encryption` | string? | `null` | SS/VMess 加密方式或 VLESS Encryption 客戶端字串；Shadowsocks 省略時在撥號階段回退到 `aes-128-gcm`。見 [Encryption](#encryption)。 |
| `packet_encoding` | `VlessUdpEncoding` | VLESS 為 `auto` | VLESS 回退編碼：`auto`、`native`、`xudp` 或 `uot-v2`；標準 URI 的 `packetEncoding=none` 對映為 `native`。 |
| `multiplex` | `VlessMultiplex` | VLESS 為 `{"protocol":"off"}` | VLESS carrier 選擇：`off`、`h2` 或 `xray`；形態見 [VLESS UDP 與多路複用](#vless-udp-and-multiplexing)。 |
| `plugin` / `plugin_opts` | string? | `null` | SIP002 外掛後設資料；代理外掛不受支援，訂閱匯入會拒絕非空值。 |
| `transport` | string | `"tcp"` | 流傳輸：空值或 `tcp`、`ws`、`grpc`，或輸入 `splithttp` 正規化成的 `xhttp`；見[流傳輸](#流傳輸)。 |
| `tls` | bool | `false` | 流 TLS 旗標；Trojan 與 AnyTLS 連結會開啟它，標準 VLESS 連結保留歷史上預設開啟的行為。 |
| `sni` | string? | `null` | TLS 伺服器端名稱；非空的 `sni` 與 `peer` 必須一致，未被傳輸層使用的 `host` 作為回退值。 |
| `tls_alpn` | string[] | `[]` | AnyTLS 與 TCP 傳輸的 Trojan/VMess/VLESS 使用的裸 TCP TLS ALPN 名稱。見 [`tls_alpn`](#tls_alpn)。 |
| `skip_cert_verify` | bool | `false` | 由 `allowInsecure`、`allow_insecure` 和 `insecure` 宣告得出的憑證驗證旁路。見 [`skip_cert_verify`](#skip_cert_verify)。 |
| `ech_enabled` | bool | `false` | 存在靜態 ECH 設定，或 `ech=1`/`true`。 |
| `ech_config` | string? | `null` | 來自 `ech_config` 或 `echconfig` 的 Base64 ECHConfigList。 |
| `ech_config_path` | string? | `null` | 結構化 loader 中指向 base64 ECHConfigList 的路徑；不是分享連結查詢參數。 |
| `reality_public_key` | string? | `null` | 來自 `pbk` 的 REALITY X25519 public key。 |
| `reality_short_id` | string? | `null` | 來自 `sid` 的 REALITY short ID。 |
| `reality_spider_x` | string? | `null` | 儲存的 `spx`；REALITY 連結預設設為 `/`。 |
| `flow` | string? | `null` | VLESS `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`；Shadowrocket `xtls=2` 選擇基礎 flow。 |
| `network` | string? | `null` | 受支援協議的封包 capability；與 VMess JSON `net` 等流傳輸欄位獨立。 |
| `ws_path` / `ws_host` | string? | `null` | WebSocket `path` 與 Host header。 |
| `ws_headers` | object | `{}`；輸出時省略空 map | 附加的 WebSocket 升級 header。見 [`ws_headers`](#ws_headers)。 |
| `grpc_service` | string? | `null` | gRPC `serviceName` 或 `service_name`。 |
| `xhttp` | object? | 省略 | 扁平結構化輸入與輸出中的標準 XHTTP 參數。見 [`xhttp`](#xhttp)。 |
| `hy2_auth` / `hy2_obfs` | string? | `null` | Hysteria2 認證與 salamander 密碼。 |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | `null` | Hysteria2 brutal 傳送端與接收端頻寬提示。 |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | `null` | Hysteria2 `mport` 埠清單與 `mhop` 跳躍秒數。見 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。 |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | `null` | Hysteria2 QUIC 接收視窗。見 [`hy2_init_stream_recv_window` / `hy2_init_conn_recv_window`](#hy2_init_stream_recv_window--hy2_init_conn_recv_window)。 |
| `hy2_disable_mtu_discovery` | bool? | `null` | Hysteria2 `disablePathMTUDiscovery`。 |
| `quic_mtu` | u16? | `null` | 來自 `mtu` 的 QUIC UDP 酬載大小。見 [`quic_mtu`](#quic_mtu)。 |
| `tls_pin_sha256` | string? | `null` | 來自 `pinSHA256` 或 `pin_sha256` 的葉憑證 SHA-256 pin。見 [`tls_pin_sha256`](#tls_pin_sha256)。 |
| `tuic_uuid` / `tuic_password` | string? | `null` | TUIC 憑據；扁平欄位須與 `username` / `password` 一致。 |
| `tuic_congestion` / `tuic_alpn` | string? | `null` | TUIC `congestion_control` 與逗號分隔的 `alpn`；見 [TUIC 與 Juicity](#tuic-與-juicity)。 |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | `null` | TUIC QUIC 接收視窗；有效預設值為 8 MiB / 8 MiB，conn 視窗自動增長至最多 32 MiB。 |
| `juicity_uuid` / `juicity_password` | string? | `null` | Juicity 憑據；扁平欄位須與 `username` / `password` 一致。 |
| `anytls_password` | string? | `null` | 從連結 userinfo 複製的 AnyTLS secret。 |
| `anytls_min_idle_session` | usize? | `null` | 來自 `min_idle_session` 的空閒 session 目標下限；有效預設值 `0`，受八條 session 的池上限約束。 |
| `anytls_idle_session_check_interval` | u64? | `null` | 解析後的 `idle_session_check_interval` 秒數；目前執行時 janitor 週期仍固定為 30 秒。 |
| `anytls_idle_session_timeout` | u64? | `null` | 來自 `idle_session_timeout` 的空閒驅逐；有效預設值 30 秒。 |
| `mark` | u32? | `null` | 結構化模型中的出站 `SO_MARK`；不是 dae 分享連結查詢參數。 |
| `tags` | string[] | `[]` | 分類後設資料；不是 dae 分享連結查詢參數。 |
| `subscription_id` / `group_id` | UUID? | `null` | 匯入與執行時歸屬後設資料。 |
| `created_at` / `updated_at` | datetime | 目前時間 | 執行時後設資料。 |

節點自身驗證要求非空名稱、有效主機和明確非零 `port`。`address` 不會補充缺失的埠；僅提供 IPv6 位址時須明確設定 `host`。只有身分與注入規則完全一致的 `direct`/`block` 內建節點可省略 endpoint。

URL userinfo 中，Trojan、AnyTLS、VLESS 和 VMess 取 `user:pass` 的密碼部分，沒有冒號時取整個 userinfo。Hysteria2 保留完整的 `user:pass`，TUIC 和 Juicity 讀取 `uuid:password`，SOCKS5 分別保留兩部分。憑據會做百分號解碼，結果必須是有效 UTF-8。secret 中的字面 `:` 或 `@` 須寫成 `%3A` 或 `%40`。

### `tls_alpn`

設定裸 TCP TLS ALPN 清單，用於 AnyTLS 以及 TCP 傳輸上的 Trojan、VMess、VLESS。每個名稱須為 1–255 位元組；預設 `[]`。

XHTTP 將省略或 `h2` 正規化為 `["h2"]`，包括 REALITY 和明確明文 H2。

其他協議、關閉 TLS 的上下文、REALITY、WS/gRPC 或 QUIC override 帶有非空值時，honk 拒絕該節點。TUIC 保留自己的 `tuic_alpn`。

只有結構化輸入與匯入會設定該清單；XHTTP 以外，分享連結的 `alpn` 僅為相容而接受，不會儲存。

### `skip_cert_verify`

略過憑證驗證。取值來自相互一致的 `allowInsecure`、`allow_insecure` 和 `insecure` 宣告；預設 `false`。

分享連結的布林值忽略首尾空白和 ASCII 大小寫：

| 值 | 憑證驗證 |
| --- | --- |
| `true`、`yes`、`1`、`on` | 關閉 |
| `false`、`f`、`no`、`n`、`0`、`off`、`t`、`y` | 開啟 |
| 空文字、未知文字或別名衝突 | 拒絕連結 |

**安全行為變更：** `yes` 和 `on` 以前保持驗證開啟，現在會關閉驗證並產生 warning。升級前應檢查這些連結，改用明確的 `true` 或 `false`。結構化布林值仍須使用原生布林型別，不轉換字串或數字。

### `ws_headers`

以 string map 形式新增 WebSocket 升級 header。名稱正規化為小寫；等值別名合併，衝突別名拒絕。最多 64 項，名稱與值合計 16 KiB；控制位元組拒絕。預設 `{}`，空 map 在輸出時省略。

honk 拒絕以下保留名稱：`host`、`connection`、`upgrade`、`sec-websocket-key`、`sec-websocket-version`、`sec-websocket-extensions`、`sec-websocket-accept`、`sec-websocket-protocol`、`content-length`、`transfer-encoding`。

honk 拒絕非 WebSocket 流傳輸上的非空 map。沒有流傳輸的協議會丟棄該欄位。`null` 無效。

只有訂閱與結構化輸入能提供 header；任何分享連結方言都不攜帶它們。

### `xhttp`

在扁平結構化輸入與輸出中儲存標準 XHTTP 參數。`{}` 選擇預設值；`null` 會被拒絕。

其他傳輸攜帶該物件時，honk 拒絕該節點。

參數名、範圍與正規化見 [H2 上的 XHTTP](#h2-上的-xhttp)。

### `hy2_port_hopping` / `hy2_hop_interval`

選擇 Hysteria2 埠跳躍：`mport` 埠清單與以秒為單位的 `mhop` 跳躍間隔。

`mport` 接受逗號分隔的埠和包含兩端的範圍，例如 `443,5000-5010`；空段略過。重複埠或重疊範圍會在撥號前拒絕該節點，包括 `443,443`；單埠集合仍然有效。官方客戶端把跳躍埠寫進位址部分（`:443,5000-6000`），效果與 `mport` 相同；兩者同時指定會被拒絕，非法的內嵌清單在解析期報錯。位址中的埠清單仍拒絕空項。

`mhop` 只接受無字尾的無號整數秒：寫 `30`，不能寫 `30s`。`500ms` 和 `1s` 會被忽略，並產生不含原值的 warning。預設值為 `30`；設定值會被限制在上游規定的最小值 `5`。

有效設定保留原寫法。

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?mport=20000-30000&mhop=30#hy2'
}
```

### `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window`

以位元組為單位覆蓋 Hysteria2 的兩個 QUIC 接收視窗。每個值為無號整數。有效預設值為 8 MiB / 8 MiB，應用讀取足夠快時 conn 視窗自動增長到最多 32 MiB。

conn 視窗同時是每連線記憶體預算，因此慢消費者最多緩衝約 3 倍該值。

分享連結裡格式錯誤或超出範圍的值會被忽略，不會使連結被拒絕。

### `quic_mtu`

用 `mtu` 設定 QUIC UDP 酬載大小。取 1200 到 65527 之間的整數。通告的接收大小預設為 `1252`，範圍相同。

傳送 MTU 從 1200 開始，透過路徑 MTU 探索而成長。明確 `mtu` 同時設定初始傳送 MTU 和探索上限。

大於 1252 時在常規 socket 上啟用 GSO，但不包括 Hysteria2 混淆和跳埠 socket。`HONK_QUIC_GSO=0` 強制關閉 GSO。

分享連結裡格式錯誤或超出範圍的 `mtu` 會被忽略，不會使連結被拒絕。

```dae
node {
    quic_mtu: 'tuic://00000000-0000-4000-8000-000000000001:secret@edge.example:443?mtu=1300#quic-mtu'
}
```

### `tls_pin_sha256`

固定葉憑證：符合後，在任何 TLS 或 QUIC 協議上代替憑證鏈與主機名稱驗證。取 64 個十六進位字元，忽略冒號和空白。

連結來源為 `pinSHA256`，缺失時取 `pin_sha256`。預設 `null`。

honk 會拒絕空值或格式錯誤的 pin，不回退到 PKI。

```dae
node {
    hy2_pin: 'hysteria2://secret@example.com:443?pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#hy2-pin'
}
```

### 結構化 loader 相容性

TOML、YAML 與 JSON 繼續使用舊的扁平節點 key。載入時只讀取所選 `protocol` 的欄位。其他協議遺留的非預設欄位會被移除，但不會拒絕節點；一條 warning 列出所有移除的欄位名。例如，`ss` 節點上的 `tls: true` 會被忽略並產生 warning，不會開啟 TLS。

VMess 和 VLESS 從 `password` 讀取使用者 UUID；`id` 是節點身分，不是憑據。

對 Trojan、VLESS、Hysteria2 和 AnyTLS，`username` 不是憑據別名。缺少該協議實際使用的憑據欄位時，單獨提供的 `username` 會被移除，並觸發一條針對性 warning；舊版行為和 ID 保持不變。

所選協議使用的值仍會正常解析與驗證。honk 自身的輸出仍可安全地再次匯入。啟用 `store_subscribe` 時，原始訂閱正文只在解析成功後持久化；被拒絕的重新整理不會覆蓋上一份有效正文。

VLESS 扁平輸入已刪除 `vless_mode`，改用 `network` 表示封包權限、`packet_encoding` 表示回退、`multiplex` 表示 carrier 選擇。只要原始輸入中出現該欄位，節點就會被拒絕，包括值為 `null` 或任一舊版已知拼寫。唯一保留的 `vless_mode: "legacy"` 是非 VLESS 扁平格式序列化時使用的相容佔位欄位。它不設定 VLESS，非 VLESS 行為與身分保持不變。

扁平憑據別名在移除不相容欄位前比較：

| 協議 | 必須一致的別名 |
| --- | --- |
| Hysteria2 | `hy2_auth` / `password` |
| TUIC | `tuic_uuid` / `username`；`tuic_password` / `password` |
| Juicity | `juicity_uuid` / `username`；`juicity_password` / `password` |
| AnyTLS | `password` / `anytls_password` |

缺失或 null 表示未提供。已提供的字串須逐位元組一致，空字串和首尾空格也參與比較。空憑據仍須滿足對應協議的要求。扁平憑據欄位仍須使用字串；數字轉換僅適用於訂閱匯入。

新增 `tls_alpn` 欄位不沿用舊欄位剝離規則；見 [`tls_alpn`](#tls_alpn)。

VMess 加密方式接受 `auto` 和 `aes-128-gcm`，忽略大小寫並儲存為小寫；空的可選宣告使用預設值。所有加密方式來源必須在賦值前比較一致，包括：JSON 裡的 `scy` 和 `security`；編碼分享連結裡的 `encryption`、`scy`，以及表示加密方式的 `security`；訂閱支援的加密方式別名。值不受支援或彼此衝突時，節點被拒絕。編碼分享連結中的 `security=none` 和 `security=tls` 仍控制 TLS，不表示加密方式。記錄格式的位置參數仍是低優先順序備用值。

TUIC 分享連結和訂閱的轉發模式只接受未指定、空值或 `native`。即使存在有效別名，不支援的 `udp-relay-mode`/`udp_relay_mode` 仍會使條目被拒絕。

| Hysteria2 來源 | 混淆規則 |
| --- | --- |
| 分享連結 | 只接受小寫的 `obfs=salamander`。未指定或空值關閉混淆；未知名稱（包括 `SALAMANDER`）會被拒絕。缺失或空密碼關閉 Salamander。重複密碼宣告與 `obfs-password`/`obfs_password` 須一致。 |
| Clash | 接受不區分大小寫的 Salamander，要求非空白密碼。 |
| sing-box | 要求小寫型別；拒絕已設定有效欄位但缺少型別或密碼的混淆物件。 |

時長轉換會拒絕負數、非有限值和超出範圍的值，不再截斷為零或上限。結構化訂閱的秒數欄位先把整數毫秒向上取整，`500ms` 和 `1000ms` 都變成 `1`，零仍為零，然後再比較別名。Hy2 分享連結的 `mhop` 遵循 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。AnyTLS 分享連結保留自己的秒數解析規則；dae 毫秒欄位仍只接受裸數值、ms 或 s，不足一毫秒的部分截去。

sing-box 的 `hop_interval`、`idle_session_timeout` 和 `idle_session_check_interval` 保留原生數字零，缺失或 null 仍表示未提供。Hysteria2 記錄會將每個 `mhop`、`hop-interval` 和 `hop_interval` 值轉換為秒後比較；即使存在有效別名，衝突或無效值仍會使記錄被拒絕。

出站建構函式對直接構造的節點使用同一個檢查函式。

普通分享連結、VMess JSON、獨立扁平 Node 反序列化和訂閱匯入都在構造完成時驗證節點。

- 使用 UUID 的協議要求有效 UUID。不支援的加密方式、傳輸型別、封包 capability、flow、ALPN 上下文或埠跳躍集合，會在派生身分前被拒絕。
- 未啟用 VLESS Encryption 時，Vision 要求 TLS 或 REALITY。直接構造的節點也不能帶空 SNI、flow 或 network，這些值本應由介面卡正規化掉。
- 訂閱格式特有的非空密碼要求仍由對應介面卡執行。SOCKS 可選認證及 handler 支援的空憑據仍然有效。
- 無效 dae 節點行和訂閱條目仍依原策略略過，有效條目保留。
- 僅解析 Config 片段的 API 仍不執行整份設定 admission，但片段內的無效節點現在會在構造時被拒絕。
- 獨立反序列化保留傳入的 ID；執行時身分 admission 是另一項檢查。

直接呼叫 `Node::validate()` 與介面卡完成構造時使用相同的固定去識別化錯誤。驗證錯誤不包含傳入的節點名稱或憑據值。

詳細的 Config 載入介面以及設定／登錄檔 admission 會保留節點驗證給出的欄位和原因，並補上從 1 開始的原始節點序號，不再用籠統的無效節點錯誤代替。憑據衝突會指向標準別名欄位，不輸出任何一個值。獨立的 `NodeSeed` 和 Node 反序列化仍傳回去識別化的通用 serde 錯誤。

VMess JSON 使用 `net: "ws"` 時，缺失或為空的 `host` 會讓 WebSocket 握手使用節點伺服器主機；提供非空 `host` 時仍以它為明確覆蓋值。

## `node {}` 宣告

每個非註釋行是一個分享連結。標籤與連結都可加引號或裸寫。兩種寫法都見[範例](#範例)。

配對引號之外，如果 `#` 位於語句開頭，或緊跟 ASCII 空格、製表符，就表示註釋開始。

| `#` 的位置 | 處理結果 | 範例 |
| --- | --- | --- |
| 裸連結的空白之後 | 開始註釋 | `ss://…#hk1 # note` 保留名稱 `hk1`。 |
| 緊接裸連結中的文字 | 保留為連結資料 | `ss://…#hk2#note` 保留 `hk2#note`。 |
| 緊接連結的結束引號 | 依相容規則開始註釋，並在該位元組處產生 `legacy-glued-hash` warning | `'ss://…#hk1'#note` 保留 `hk1`。 |

註釋前應留空白。結束引號後出現其他文字時，honk 略過該條目，並產生 `trailing-entry-text` 診斷。引號錯誤與塊結構規則見[方言參考](./dialect.md)。

解析器同時接受帶標籤和不帶標籤的條目。非空 dae 標籤就是節點名稱；沒有標籤時，URL 連結依次取非空的解碼後片段、非空的 `remark` 查詢值、`{scheme}-{host}`。

VMess JSON 的 `ps` 備註缺失或為空時，節點先以 `vmess-{host}` 通過驗證；非空 dae 標籤隨後替換該名稱。

確定標籤與連結的結束引號位置時，反斜槓轉義下一個字元；解析後的文字保留原始轉義序列。

解析器依以下規則處理無效條目：

| 輸入 | 處理結果 |
| --- | --- |
| 協議已識別但格式錯誤的連結 | 丟棄條目並產生 warning。已知無效欄位保留具體的安全原因和模式路徑；未知解析失敗使用 `invalid-node-entry`。 |
| 未知協議或已刪除的 VLESS `vless_mode` | 拒絕設定。 |
| 獨立的 `mux:` 或 `mux=` 行 | 拒絕設定。VLESS 封包與 carrier 選項須使用連結中的精確查詢參數 `packetEncoding=`、`mux=` 和 `udp=`。 |

診斷會保留原始節點條目的序號和來源位置，但不含原始連結、值或節點名稱。傳回資料的介面只把診斷交給呼叫方，不寫日誌；普通介面只報告一次。

被接受的連結只會產生 `legacy-*` 程式碼的 warning；節點條目上出現其他 warning，就說明解析器已丟棄該條目。客戶端可以用 `syntax` 模式驗證單條 `node { name: 'link' }` 宣告，只看診斷程式碼就能區分被略過和被接受的連結。

舊版 `ss://base64(method:password@host:port)` 格式把解碼後的憑據當作字面值，不再做 URL 解碼：`%20` 保持為 `%20`，`?`、`/`、`#`、`:` 和 `@` 仍是密碼字元。憑據與 endpoint 由最後一個 `@` 分隔，userinfo 本身也可以是 `base64(method:password)`。解碼後的酬載缺少 `@`，或憑據拆不出方法和密碼時，解析失敗。URL userinfo 格式仍會對憑據做百分號解碼。endpoint、路徑、查詢參數和片段繼續依 URL 處理，查詢參數包括 `/?plugin=...`。

## 節點身分

`Node::derive_id()` 是唯一的身分派生路徑。它對以下材料計算 UUID v5：

```text
protocol|host|port|credential-fingerprint|dial-shape
```

憑據指紋遵循各 handler 的欄位優先順序。撥號形態包含：

- `sni`、傳輸方式和 WebSocket/gRPC 形態；
- Hysteria2 混淆、REALITY 參數和 `flow`；
- 有效的 VLESS TLS 安全設定、UDP 權限、回退編碼和多路複用路徑。

明文 VLESS 與 TLS 使用不同身分。REALITY key 選擇認證傳輸，不受冗餘 TLS 旗標影響。

| 結構化 `tls_alpn` | 身分派生方式 |
| --- | --- |
| 非空 | 以基礎 ID 為名稱空間、JSON 元組 `["tls-alpn", <ordered list>]` 為名稱派生子 UUID v5。這將 ALPN 與任意憑據文字分離。 |
| 空值 | 保留基礎 ID。 |

調校參數與顯示後設資料不參與派生；例外是改變實體路徑的 VLESS 多路複用上限。

XHTTP 身分還包含有效的 TLS/明文安全設定，以及全部已接受的標準 XHTTP 參數，包括 header、填充和 POST 間隔。輸入別名、header 名稱大小寫與等價範圍表示會在派生前正規化。新增 XHTTP 不改變已有 TCP/WS/gRPC 身分材料。

WebSocket 的非空標準 header map 也參與身分派生。header 名稱大小寫、插入順序與等值別名不改變身分，值不同則改變身分；省略或空 map 保留原有身分。

拼接前，每個原始憑據欄位、撥號形態欄位和有效的 `host` 值都會將 `\` 轉義為 `\\`，將 `|` 轉義為 `\|`。拼接後的指紋不再轉義。通過 `Config::validate` 的節點，不同身分欄位必然產生不同的 hash 輸入。完整設定驗證拒絕的節點不受此保證，即使 `Node::from_share_link` 能為其派生 ID。

**破壞性升級：** 所有成功重新派生身分的 VLESS 節點都會獲得新 ID，包括從未填寫 `vless_mode`、關閉 UDP 或設定 ALPN 的節點。以 ID 為 key 的健康、預熱及 session 狀態會重新建立。同一次遷移裡，其他協議只在一種情況下改變 ID：上文用 `|` 拼接的身分欄位中含有 `|` 或 `\`。ALPN 使用獨立的 JSON 子 UUID 步驟，因此只有 ALPN 含這兩個字元時，不會觸發該變化。

**逐包帶位址的 UDP 訊框化：** 有效 UDP 路徑在 53、443 或 54 埠使用 UoT v2 或 H2MUX 的 VLESS 節點會再次獲得新 ID。這包括 `packetEncoding=uot-v2`、`mux=h2mux`，以及回退到這兩條路徑的池，因為這些路徑現在逐包攜帶位址。

Auto、native、XUDP、Mux.Cool 與關閉 UDP 的節點 ID 不變。直接選擇節點的 Selector 以節點 ID 為 key，ID 改變時該選擇遺失。結構化 JSON/YAML/TOML 設定若在代理群組的 `nodes` 中引用舊 ID，載入時會關聯到新 ID。

不要為了遷移 ID 而刪除快取。持久化已啟用且可讀時：

| 狀態 | 節點 ID 變化的影響 |
| --- | --- |
| 直接選擇節點的 Selector 固定選擇 | 以節點 ID 為 key，因此遺失。 |
| 選擇子群組的 Selector 固定選擇 | 以群組名為 key，因此保留。 |
| 有效且不超過 24 小時的 TCP-v4 延遲樣本 | 啟動時依節點名稱關聯到新 ID。樣本只用於排名，不恢復存活狀態。改名或重複名稱不能保證恢復同一個葉節點。 |

就緒流原本就隨所屬 generation 退役。`name`/`subtag` 篩選語義不變。

只要可撥號 endpoint 和撥號形態不變，身分在改名、reload 和訂閱重新整理後都保持穩定。設定與執行時組裝會拒絕重複的派生 ID。`Node::default()` 的 ID 為 nil；構造路徑會派生 ID，出站執行時登錄檔會拒絕任何傳入的 nil ID。

## 協議

| 協議 | 別名 | TCP | UDP | 說明 |
| --- | --- | --- | --- | --- |
| `ss` | `shadowsocks`，僅限 Clash 與 sing-box `type` | 是 | 是 | AEAD 與 Shadowsocks 2022 |
| `trojan` | — | 是 | 是* | TLS；TCP/WS/gRPC/XHTTP 傳輸 |
| `vmess` | — | 是 | 否 | AEAD；TCP/WS/gRPC/XHTTP 與 REALITY；handler 需要 `rprx` |
| `vless` | — | 是 | 可設定* | 原生 UDP、UoT v2、H2MUX、XUDP、Mux.Cool、Encryption、REALITY 與 Vision；handler 需要 `rprx` |
| `socks5` | — | 是 | 是 | CONNECT 與 UDP ASSOCIATE |
| `hysteria2` | — | 是 | 是 | QUIC/H3、salamander、brutal/BBR 與埠跳躍 |
| `tuic` | — | 是 | 是 | QUIC 上的 TUIC v5 |
| `juicity` | — | 是 | 是 | QUIC 上的 Juicity |
| `anytls` | — | 是 | 是* | 多路複用 TLS session 與 UoT v2 |
| `direct` | — | 是 | 是 | 保留的內建直連出站；沒有分享連結協議方案 |
| `block` | — | 否 | 否 | 保留的內建拒絕出站；沒有分享連結協議方案 |

`network` 可獨立於流傳輸方式關閉 Trojan、AnyTLS 和 VLESS 的封包撥號。VMess UDP 尚未實作。

| 協議 | UDP 行為 |
| --- | --- |
| AnyTLS | 拒絕超過 16 KiB 的酬載，與 anytls-go 0.0.13 的中繼緩衝區一致。非連線模式 UoT v2 逐封包攜帶目的地和伺服器端的真實源位址。一條流服務一個客戶端源的全部目的地；未經請求的回覆也保留真實源位址。 |
| Trojan | 每個客戶端源使用一條 associate 流承載全部目的地，傳回每個回覆的真實源位址。配合伺服器端可獲得 EIM/EIF 行為。各目的地共享隊頭阻塞，且流故障會影響全部目的地。 |

SOCKS5 UDP ASSOCIATE 為每個客戶端源保持一條控制 TCP 連線和一個中繼 socket，該源的所有目的地共用它，並傳回每個應答標頭中的真實遠端對端。從未聯絡過的對端能否到達客戶端取決於伺服器：Dante 預設的 `udp.connectdst: yes` 僅在只使用過單一目的地期間才會連線其出站 socket。

以下支援 UDP 的代理協議實作 UDP 全錐形：一個客戶端源的全部目的地共用一個 association，每個回覆都帶上真實的遠端位址。

- Hysteria2、TUIC、Juicity、SOCKS5，以及 AEAD 與 2022 兩種 Shadowsocks；
- Trojan、AnyTLS；
- VLESS XUDP/Mux.Cool、UoT v2、H2MUX。

VLESS 原生 UDP 是例外，其流只指定一個目標。這包括明確 `native`，以及未啟用 Vision 時 UDP/53 和 UDP/443 上的 `auto`。

來自此前未聯絡過的對端的回覆，會保留該對端的源位址。這實作了 RFC 5780 全錐形的客戶端部分。伺服器端還須為每個 association 使用一個未連線 socket，並轉發任意對端的回覆。honk 無法繞過伺服器端過濾；`direct` 流量遵循主機自身的 NAT。限制如下：

- 依網域名稱撥號的流會為每個原始目的地各保留一條 association，回覆也投影回該目的地，因此得不到與 endpoint 無關的對映。
- 一個源的各目的地只在同一節點上共用 association。群組可能把新目的地或 Score 試探流送到另一節點，那裡有自己的對映。
- 協議回退路徑不由 H2MUX 或 Xray UDP 池承載。未啟用 Vision 的節點裡，`packetEncoding=auto` 在 53 和 443 埠使用已連線的原生 UDP。這類流只指定一個目標，所以這兩個埠無法實作全錐形。Vision 節點和其他埠使用 Single XUDP。設定 `packetEncoding=xudp`，可以在原本走原生路徑的地方明確啟用 Single XUDP。
- Single XUDP 未設為預設值，原因是測得的效能成本。在 loopback 環境中對 sing-box 1.12.4 使用不限速的 1200 位元組封包時，吞吐約為原生路徑的一半。每 MB 客戶端 CPU 消耗是原生路徑的 1.9–3.3 倍，p99.9 尾延遲也更高。中位數與冷啟動延遲沒有可測量差異。XUDP 還會拒絕超過 7,526 位元組的封包。
- 當 VLESS 源在不同埠上選了不同路徑時，即使在同一節點上，也會依所選路徑各有一條 association。例如 Xray UDP 池加上 UDP/443 的 `skip`，443 就走協議回退，而不是池。
- Trojan、Juicity 和 AnyTLS 把一個源的全部目的地放在一條可靠流上。某個目的地停滯會拖慢同流的其他目的地，寫失敗會終止所有目的地。封包 carrier 沒有這個問題，例如 Hysteria2、TUIC、Shadowsocks 和 SOCKS5。
- 53 埠的流不會在資料路徑裡釋出客戶端回覆的 framing，因此針對 53 埠流的主動回覆要靠主機轉發。
- 所有客戶端源共用一個行程級的外來回覆 socket 池，每個對端位址一個 socket。上限依 endpoint 容量算，每個 endpoint 對應七個 socket。達到上限後，新的外來對端會淘汰最久未使用的 socket。清理任務會關閉超過一個 NAT 逾時時間未使用的 socket。
- 一個源最近關閉的 64 個目的地，其回覆會被丟棄，honk 不會把它們當作外來回覆投遞。連線關閉和不可用節點清理都算在內。重新繫結會把目的地移出清單；第 65 次關閉會移除最早的記錄。空閒逾時和傳輸錯誤不加入記錄，因此只要源仍存在，這些對端仍可傳送外來回覆。仍繫結的流不受影響。
- VMess 沒有 UDP 後端。

在支援 `network` 的協議中，扁平結構化輸入接受逗號分隔的 `tcp`/`udp`，忽略各項首尾空白和 ASCII 大小寫。`tcp` 關閉 UDP；`udp` 與 `tcp,udp` 都允許 UDP。空文字或純空白正規化為未指定，保留協議的預設 capability。`quic` 等未知值，或非空清單中的空項，會使節點被拒絕。該欄位只控制 UDP admission；`udp` 不會額外禁止 TCP。

未啟用 Cargo feature `rprx` 時，VMess 與 VLESS 節點仍能解析，但不會註冊 handler，撥號以 `No handler for protocol` 失敗；未啟用該 feature 的正常建置不會分配 VLESS 池或 carrier 訊號量。`honk-core` 與 `honk-tool` 預設啟用 `rprx`。

`honk-core` 在啟動和 reload 時注入具有固定保留 ID 的 `direct` 與 `block`。使用者節點不得使用這些名稱或協議。群組不會自動從節點池納入它們；只有精確符合名稱的 `filter: name(direct)` 或 `name(block)` 才會選中，見[群組參考](./groups.md#過濾解析)。

## 協議參數

### Shadowsocks 2022

傳統 AEAD 方法 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` 及其別名 `chacha20-poly1305` 使用普通密碼。方法名稱不區分大小寫；其他方法會在構造 handler 時失敗。Shadowsocks 2022 方法使用標準 Base64 PSK：

| 方法 | Base64 解碼後的 PSK 長度 |
| --- | --- |
| `2022-blake3-aes-128-gcm` | 16 位元組 |
| `2022-blake3-aes-256-gcm` | 32 位元組 |
| `2022-blake3-chacha20-poly1305` | 32 位元組 |

key 長度錯誤或不是 base64 時，handler 構造失敗。

AES 2022 方法接受在 `password` 中用冒號分隔的 PSK 鏈，從第一個身分 key 排到使用者 key。每個 key 解碼後的長度都須符合該方法。`2022-blake3-chacha20-poly1305` 只接受一個 PSK；使用 key 鏈會報 `Shadowsocks 2022 EIH support only available in AES ciphers`。

UDP 重放保護為目前 session 和前一個伺服器端 session 分別保留一個視窗。前一個 session 連續 60 秒沒有活動後，才接受第三個 session。只有在認證和回應標頭驗證成功後，honk 才修改接收 session 狀態；無效封包不能重設重放歷史。

Shadowsocks UDP（傳統 AEAD 與 2022）為每個客戶端源的所有目的地只保留一個面向伺服器端的 socket；2022 在這些目的地之間共用一個 session ID、一個遞增的包計數器和一組重放視窗。

回覆會帶回伺服器端回報的真實遠端位址，因此只要伺服器端轉發，從未聯絡過的主機也能到達客戶端；宣告為非撥號網域名稱的回覆會被丟棄。

與撥號目標不同的名稱從不逐封包傳送。真實伺服器端，例如 sing-box 1.12.4，會依第一個目的地固定 outbound 形態；之後出現不同名稱就會終止 association，因此這類名稱以數值目標發出。

### 流傳輸

支援流傳輸的分享連結透過 `type=` 或其別名 `network=` 選擇傳輸方式：

| 值 | 傳輸方式 | 欄位對映 |
| --- | --- | --- |
| 空文字或 `tcp` | 裸 TCP | — |
| `ws` | WebSocket | `path` → `ws_path`；`host` → `ws_host`；升級 header 沒有分享連結欄位 |
| `grpc` | gRPC | `serviceName` 或 `service_name` → `grpc_service` |
| `xhttp` 或輸入別名 `splithttp` | XHTTP | 見下文的 H2 相容範圍。 |

`type`、`network` 與相容的 `obfs` 傳輸選擇宣告必須一致，重複的選擇參數也須一致。`h2`、`kcp` 等不支援的名稱在解析時被拒絕。`sni` 獨立生效。除 XHTTP 外，分享連結的 `alpn` 仍只為相容而接受，不會儲存。

XHTTP 以外，重複的查詢 key 取最後一個值，`serviceName`、`pinSHA256` 和 `ech_config` 分別優先於 `service_name`、`pin_sha256` 和 `echconfig`。TLS、SNI、憑證驗證與 VMess 加密方式的宣告仍須一致。編碼位址形式的 VMess 拒絕值不同的重複 key。XHTTP 要求重複的 `host`、`path`、`mode`、`alpn` 和 `extra` 一致。

WebSocket 路徑和 gRPC 服務名稱裡無法直接放進 URI 的字元會做百分號編碼，例如空格和非 ASCII 文字。已有的 `%XX` 轉義和查詢分隔符保持不變；查詢值裡的空格和非 ASCII 文字也會編碼，例如 `?tag=a b` 變成 `?tag=a%20b`。XHTTP 沿用下文的轉義規則。

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess 接受 v2rayN Base64 JSON（`net`、`host`、`path`、`sni`），也接受 Shadowrocket 的 `vmess://base64(auto:UUID@host:port)?...` 位址部分形式。後者對映 `tls`、`peer`/`sni`、`obfs=websocket|grpc`、`obfsParam`、`path` 和 `remark`；接受 standard / URL-safe Base64，有無填充均可。編碼位址部分的 VMess 要求 AEAD 認證及 `auto`/`aes-128-gcm`；不支援的加密方式和 REALITY 參數會被拒絕，不會靜默替換。

編碼位址可以省略 `auto:`，規則與 [Shadowrocket VLESS](#shadowrocket-vless) 相同。`alterId` 只能省略或為 `0`。

v2rayN JSON 形式要求 `add`、UUID 格式的 `id`，以及 1 到 65535 之間的 `port`，埠可寫成數字或數字字串。只有 `"tls":"tls"` 開啟 TLS。`aid` 會被忽略；認證始終使用 AEAD。

```json
{"add":"edge.example","port":443,"id":"00000000-0000-4000-8000-000000000001","ps":"vmess-tls","tls":"tls"}
```

用 Base64 編碼整個物件，接在 `vmess://` 之後。Base64 後再接 `?query` 或 `#fragment` 會使連結無效；節點名稱用 `ps` 或 dae 標籤指定。

VMess JSON 的 `net` 和 Shadowrocket 傳輸參數只選擇流傳輸方式，不再寫入封包網路 capability 欄位。未指定封包限制時，對有 UDP 後端的協議保留原有預設 UDP capability，VMess 沒有 UDP 後端。已有的有效空傳輸欄位也保留原始寫法。非 XHTTP 傳輸仍沿用舊行為，忽略無關的匯出欄位 `mode`、`extra`；這些欄位不會選擇 XHTTP。傳輸宣告明確衝突時仍會拒絕節點。

VLESS 支援 TCP+REALITY+Vision、TCP+REALITY、TCP+WS、TCP+WS+TLS、TCP+gRPC 與下述 H2 XHTTP 設定方案。未加密 Vision 的 direct-copy 要求使用 TLS 1.3 或 REALITY 的裸 TCP，不能使用 WS/gRPC/XHTTP；加密 Vision 遵循下文的組合規則。

Vision 新增上行填充並移除下行填充。上行 Direct 要求在第一個完整的應用資料記錄前已觀察到符合條件的 TLS 1.3 ServerHello；出現早期資料，或檢查預算耗盡時仍未決定，都會改用 End 結束填充並保留外層傳輸。兩個方向各自獨立切換。參見 [Vision 支援邊界](../design/outbound.md)。

#### H2 上的 XHTTP

Trojan、VMess 與 VLESS 共用該出站傳輸。VMess 仍僅支援 TCP。本實作只支援 H2 上的 XHTTP，不提供完整的 Xray 或 mihomo 設定相容性。

| 安全模式 | H2 要求 |
| --- | --- |
| 普通 TLS | 必須協商 `h2`。 |
| 認證後的 REALITY | 依傳輸約定選擇 H2，即使伺服器端未傳回 ALPN。 |
| 明確明文 | 對端必須支援 H2。 |

不提供 H1/H3 回退。

```dae
node {
    xhttp: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&type=xhttp&mode=stream-up&path=%2Fxhttp%2F&sni=edge.example&alpn=h2#xhttp'
}
```

`mode` 預設為 `auto`；空字串也表示 `auto`：

| 模式 | 請求形式 |
| --- | --- |
| `auto` | 普通 TLS 或明文選擇 `packet-up`，REALITY 選擇 `stream-one`。 |
| `packet-up` | 有序的有限長度 POST 正文，以及同一 session 的 GET。 |
| `stream-up` | 獨立的流式 POST 和 GET。 |
| `stream-one` | 單一雙向 POST。 |

VMess JSON 在 `net=xhttp|splithttp` 時也接受 v2rayN 的 `type` 作為模式欄位。明確 `mode` 與 `type` 必須一致。JSON 的 `fp`、`insecure` 和 `allowInsecure` 與舊有 VMess 傳輸一樣，接受但忽略。憑證驗證保持開啟。

URI、VMess JSON 和 Mihomo 匯入會去除 ALPN 字串及清單成員的首尾空白，再忽略空值。未指定時選擇 `h2`。即使 header 偽裝為 gRPC/SSE，正文仍是原始代理位元組。

| XHTTP 請求欄位 | 正規化與驗證 |
| --- | --- |
| `path` | 預設為 `/`。在查詢部分之前補齊首尾斜槓，不清理點路徑段或百分號轉義。 |
| HTTP `host` | 獨立於撥號位址和 SNI。須為 `cdn.example:8443` 這樣的 authority，不含 scheme、路徑、userinfo 或空白。為空或未指定時依次回退到 SNI、伺服器主機名稱。 |
| 路徑部分 | 解碼後的字面值。傳送時依 Xray 規則將字面 `%` 轉為 `%25`，並對空格、`<`、`>` 和 UTF-8 位元組做百分號編碼。 |
| 查詢部分 | 原樣傳送，依原始 HTTP URI 語法驗證。字面空格須先做百分號編碼。 |
| 路徑與查詢整體 | 最多 16 KiB。任何位置的控制位元組、DEL 和 `#` 均被拒絕。 |

URI 分享連結參數只解碼一次，因此 `path=%2Fxhttp%2F` 傳送 `/xhttp/`；Mihomo 路徑使用 YAML 字串字面值。

直接構造節點時，必須先呼叫 `normalize_stream_transport()`，再派生 ID。不可變 admission 會拒絕非標準 XHTTP 名稱、選項和 ALPN。

URI `extra` 接受百分號編碼的 JSON 物件，可含 `host`、`path`、`mode`，其意義、正規化和驗證與頂層欄位相同，且只支援下表列出的選項。Extra 中的請求欄位只填入缺失的頂層欄位；明確頂層欄位即使為空也優先。重複的 URI extra 僅在有效標準選項一致時合併。

VMess JSON 的 `extra` 可以是物件，也可以是內容為同一 JSON 的字串。URI 中的 `extra` 是經過百分號編碼的物件。下面的物件設定一個 header、一個填充範圍和獨立的下載 endpoint：

```json
{
  "headers": {"X-Client": "honk"},
  "xPaddingBytes": "100-200",
  "downloadSettings": {
    "address": "download.example",
    "port": 443,
    "network": "xhttp",
    "security": "tls",
    "tlsSettings": {"serverName": "download.example", "alpn": ["h2"]},
    "xhttpSettings": {"path": "/download/", "host": "cdn.example"}
  }
}
```

壓縮並百分號編碼後，得到以下連結：

```dae
node {
    xhttp_split: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&type=xhttp&extra=%7B%22headers%22%3A%7B%22X-Client%22%3A%22honk%22%7D%2C%22xPaddingBytes%22%3A%22100-200%22%2C%22downloadSettings%22%3A%7B%22address%22%3A%22download.example%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%2C%22security%22%3A%22tls%22%2C%22tlsSettings%22%3A%7B%22serverName%22%3A%22download.example%22%2C%22alpn%22%3A%5B%22h2%22%5D%7D%2C%22xhttpSettings%22%3A%7B%22path%22%3A%22%2Fdownload%2F%22%2C%22host%22%3A%22cdn.example%22%7D%7D%7D#xhttp-split'
}
```

| Xray extra key | flat `xhttp` 欄位 | 預設值 | 支援邊界 |
| --- | --- | --- | --- |
| `headers` | `headers` | `{}` | 最多 64 項，名稱和值總共不超過 16 KiB |
| `xPaddingBytes` | `x_padding_bytes`；別名 `x-padding-bytes` | `100-1000` | 1–8192 位元組 |
| `noGRPCHeader` | `no_grpc_header`；別名 `no-grpc-header` | `false` | 布林值 |
| `scMaxEachPostBytes` | `sc_max_each_post_bytes`；別名 `sc-max-each-post-bytes` | `1000000` | 1–16777216 位元組 |
| `scMinPostsIntervalMs` | `sc_min_posts_interval_ms`；別名 `sc-min-posts-interval-ms` | `30` | 0–60000 ms；零關閉最小間隔 |

kebab-case 別名只適用於扁平 `xhttp` 物件。

範圍接受無號整數、`"30"` 這樣的數字字串、`min-max` 字串或 `{"min":N,"max":N}`。空字串會還原成上表中的預設值。header 名稱正規化為小寫，等價別名合併；衝突別名、控制字元，以及傳輸層管理的 header，例如 `host`、`content-type`、`content-length`、`referer`、hop-by-hop header 和 trailers，都會被拒絕。URI/VMess extra JSON 在轉為 map 前拒絕重複成員。Padding 始終啟用。這些範圍是本地安全上限，不保證每個對端或 CDN 都接受。

未設定 `User-Agent` 時，XHTTP 請求使用 Xray 預設的 Chrome `fetch()` header：

| header | 行為 |
| --- | --- |
| Windows Chrome `User-Agent` 與 `Sec-CH-UA` 品牌 | 主版本遵循 [Xray 的估算](https://github.com/XTLS/Xray-core/blob/836a6fed385b902e437dde43ee9adc82d23a5303/common/utils/browser.go#L26-L34)，隨機延遲在每個行程內只抽取一次。 |
| `Sec-CH-UA-Mobile`、`Sec-CH-UA-Platform`、`DNT`、`Accept-Language`、`Sec-Fetch-Mode: cors`、`Sec-Fetch-Dest: empty`、`Sec-Fetch-Site: same-origin` | 與 Xray 一樣，覆蓋已設定的同名值。 |
| `Accept`、`Priority`、`Cache-Control`、`Pragma` | 僅在未設定時補充。 |

CDN 的機器人過濾規則可能拒絕不含這些 header 的 XHTTP 請求。設定 `User-Agent` 後，不再新增這組預設 header，而是原樣傳送設定值。Xray 的 `chrome`、`firefox`、`edge`、`golang` 關鍵字不會被解釋。這些 header 只在執行時新增，不改變節點身分。

存在 `extra` 時，頂層 `host`、`path` 和 `mode` 仍優先。

| 相容輸入 | 處理方式 |
| --- | --- |
| URI `fp` | 接受但忽略；指紋由全域 TLS 模式控制。 |
| 值為 `none` 或空值的 `headerType` / `quicSecurity`；空 `serviceName` | 接受但忽略，因為 XHTTP 自行管理 HTTP 訊框。 |
| `headers` 查詢參數 | 僅接受只有 `Referer` 成員的 JSON 物件，隨後丟棄。Xray 的填充會覆蓋該 header，因此不會傳送。 |
| `allowInsecure`、`allow_insecure`、`insecure` | 保留共用 TLS 語義；別名必須一致。 |
| Extra 中的 `noSSEHeader`、`scMaxBufferedPosts`、`scStreamUpServerSecs` | 僅作用於 Xray 伺服器端；檢查型別後丟棄。 |
| `xmux` | 僅在全為零或恰好等於 Xray 的預設 XMUX 填充值時接受並丟棄：`maxConcurrency` 為 1、`hMaxRequestTimes` 為 600–900、`hMaxReusableSecs` 為 1800–3000，其餘為 0。其他值拒絕。 |

未知或不支援的參數會使整個節點被拒絕，即使值為 null 或空值也不例外。這包括其他 session、序號或酬載位置、自訂上傳方法和填充混淆設定。Mihomo 訂閱使用對應的 `xhttp-opts` 欄位。官方 sing-box 和客戶端記錄格式仍不支援 XHTTP 傳輸。

Extra 中的 `downloadSettings` 是 Xray StreamConfig，用於把 GET 發往獨立 endpoint。下載端不繼承上傳端的任何設定，包括 header。因此，即使上傳端設定了 `User-Agent`，下載 GET 仍攜帶預設的 Chrome `fetch()` header。

| 下載設定 | 要求或對映 |
| --- | --- |
| 必需欄位 | `address`、`port`、`network: xhttp`、`security: tls`。 |
| `address` | 去除首尾空白並轉為小寫。必須是主機名稱或 IPv4 字面量，因為撥號時依文字與埠拼接。 |
| `tlsSettings.serverName`、`xhttpSettings.path`、`xhttpSettings.host` | 對映到 `xhttp.download.server_name`、`path`、`host`。扁平 `xhttp.download` 物件還包含 `address`、`port` 和預設值為 `100-1000` 的 `x_padding_bytes`。 |
| 頂層或 `tlsSettings` 的 ALPN | 只能預設或為 `h2`。 |
| `tlsSettings.fingerprint`、`xhttpSettings.mode` | 檢查後忽略。 |
| 值為 null 的已知成員 | 視為預設。 |
| HTTP 主機名稱 | 依次回退到下載端的伺服器名稱、位址。 |

下載端始終驗證 TLS。上傳端的憑證固定、不安全驗證、ECH 和 REALITY 設定不作用於下載端。`allowInsecure: true`、REALITY、`sockopt`、下載端 `headers` 或 `extra`，以及其他任何成員都會使節點被拒絕。下載設定也不能與 `stream-one` 模式或 REALITY 上傳端組合。

每個對端各有獨立的 carrier 池。因此，Trojan 或 VMess 節點最多可持有四條不佔 VLESS 行程 permit 的可重複使用 carrier。延遲探測與 `honk-tool sub` 的位址族列只反映上傳 endpoint。

XHTTP 禁止 TCP Mux.Cool，但保留 UDP-only XUDP carrier。已有 VLESS UDP 權限、封包編碼與 UDP/443 策略不變。Packet-up 的協議裡沒有表示上傳 EOF 的標記：shutdown 會重新整理已經接受的上傳位元組，並保留 GET 等待應用的最終回覆；只有關閉邏輯流才結束該請求。


### Shadowrocket VLESS

統一解析器接受 `vless://base64(auto:UUID@host:port)?...`，以及省略 `auto:` 的編碼位址部分。支援 standard / URL-safe Base64，有無填充均可；IPv6 endpoint 必須使用方括號。編碼內容必須包含有效 UUID 和明確非零埠。格式錯誤的編碼位址部分會被拒絕，不再誤當作主機名稱或顯示名稱。

查詢參數對映遵循 [Shadowrocket 匯出器](https://github.com/cedar2025/Xboard/blob/master/app/Protocols/Shadowrocket.php)：

| 輸入 | 意義 |
| --- | --- |
| `tls=0` / `tls=1` | 關閉 / 開啟 TLS。編碼連結沒有安全選項時預設明文；標準 `UUID@host:port` 連結保留預設開啟 TLS 的行為。 |
| 未指定 `security` 時的 `pbk`、`sid`、`spx` | 選擇 REALITY，必須提供非空 `pbk`。仍支援明確 `security=reality`。 |
| `xtls=0` / `xtls=2` | 無 flow / `xtls-rprx-vision`。拒絕已淘汰的 XTLS Direct（`xtls=1`）及未知值。 |
| `remark` | 沒有非空片段時當成顯示名稱；當成查詢參數值時只解碼一次。 |
| `peer` | 明確 SNI 別名；非空的 `sni` 與 `peer` 必須一致。空值或純空白名稱視為未指定。 |
| `obfs=websocket`、`obfsParam`、`path` | WebSocket 傳輸、Host header 回退值和路徑。 |
| `obfs=grpc`、`path` | gRPC 傳輸和 service name 回退值。 |

TLS/REALITY、flow 或傳輸宣告相互衝突時會拒絕連結，不會靜默降級。VLESS 的 `obfs` 僅接受空值/`none`、`websocket` 或 `grpc`，不會把不支援的傳輸方式當作 TCP。`host` 和 `serviceName`/`service_name` 保留原有回退順序。明確 SNI 別名在賦值前依原始位元組比較：相同值合併，不同值報錯，不轉換大小寫。空值或純空白的 SNI 和 flow 在派生節點 ID 前正規化為未指定；非空 flow 必須為 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。

Clash 匯入會比較 `servername`、`server-name` 和 `sni`；記錄格式還會比較 `tls-name` 和 `tls-host`，並保留較低優先順序的 `obfs_sni` 回退值，包括 Quantumult X 的 WSS Host。記錄中的 `off` 仍為無效值。分享連結和 VMess JSON 的 WebSocket `host` 僅用作 Host header；非 WebSocket 傳輸則當成較低優先順序的 SNI 回退值。TLS 使用方最終仍可回退到節點主機名稱。

### Hysteria2

解析器同時接受 `hysteria2://` 和 `hy2://`。完整的百分號解碼後 userinfo 是認證字串：字面 `user:password` 保留兩部分及冒號，與百分號編碼的 `user%3Apassword` 等價。

| 連結輸入 | 節點欄位 / 行為 |
| --- | --- |
| userinfo secret | `hy2_auth`；保留完整 `user:password`，而不是隻取 password |
| `obfs=salamander&obfs-password=...` | 小寫 `salamander` 配合非空密碼設定 `hy2_obfs`。混淆名稱缺失或為空，或密碼缺失或為空時關閉混淆。未知混淆名稱使連結被拒絕。 |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`；以 Mbps 為單位的整數，不帶單位。上傳值為正時啟用 Brutal，否則使用 BBR；下載值依 bytes/s 通告。 |
| `mport` / `mhop` | `hy2_port_hopping` / `hy2_hop_interval`；見 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。 |
| `pinSHA256` | `tls_pin_sha256`，替代 PKI/主機名稱驗證 |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC 接收視窗覆蓋值，單位為位元組 |
| `disablePathMTUDiscovery` | 值為 `1`/`true` 時關閉 QUIC PMTU 發現 |
| `mtu` | 共用 QUIC UDP-payload 上限；只接受 1200–65527 |
| `sni` / `peer`、insecure 別名、ECH 參數 | 共用 TLS 行為；非空的明確 SNI 別名必須一致 |

`mport` 接受逗號分隔的埠和包含兩端的範圍，例如 `443,5000-5010`；空段會被略過。格式錯誤或超出範圍的 `upmbps`、`downmbps`、接收視窗和 `mtu` 會被忽略，不會使連結被拒絕。TUIC 的接收視窗和 `mtu` 依同樣方式解析。

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### TUIC 與 Juicity

| 協議 | 連結輸入 | 節點欄位 / 行為 |
| --- | --- | --- |
| TUIC | `uuid:password` userinfo | 通用 `username` / `password`；供 `tuic_uuid` / `tuic_password` 的 handler 回退使用 |
| TUIC | `congestion_control` | `cubic`、`new_reno` 或 `bbr`；`bbr` 即 quinn 原有的 BBR 或 BBRv3，由 `HONK_QUIC_BBR` 選擇。省略時為 `cubic`；未知值產生 warning 並回退到 cubic |
| TUIC | `alpn` | 逗號分隔的 ALPN 覆蓋值；分享連結預設 `tuic`；原始 Clash/Mihomo 匯入使用下述來源預設值 |
| TUIC | `initStreamReceiveWindow` / `initConnReceiveWindow` | 接收視窗覆蓋值 |
| Juicity | `uuid:password` userinfo | 通用 `username` / `password`；供 `juicity_uuid` / `juicity_password` 的 handler 回退使用 |
| Juicity | 協議預設值 | ALPN `h3`、BBR，以及 8 MiB / 8 MiB 的初始接收視窗（共享自適應流控可使其增長） |
| Juicity | UDP | 每個客戶端源一條 QUIC bi 流承載所有目的地；回覆傳回真實的遠端對端，取決於伺服器端自身的 UDP socket 與出口策略 |
| 兩者 | `mtu`、`sni`、insecure 別名、pin、ECH | 共用 QUIC/TLS 參數 |

```dae
node {
    tuic: 'tuic://00000000-0000-4000-8000-000000000001:secret@edge.example:443?congestion_control=bbr&alpn=h3#tuic'
    juicity: 'juicity://00000000-0000-4000-8000-000000000001:secret@edge.example:443?sni=edge.example#juicity'
}
```

`HONK_QUIC_BBR` 選擇 `congestion_control=bbr` 使用的 BBR 版本，見[環境變數](cli.md#環境變數)。

原始 Clash/Mihomo `proxies` 條目中的 TUIC `alpn` 缺失或為 null 時，會補為 `h3`。明確非空清單保留順序；明確空清單或空白字串繼續使用 honk 既有的 `tuic` 回退，並不表示不傳送 ALPN。該來源預設值不適用於原生分享連結、扁平節點、sing-box `outbounds` 或文字記錄格式。

**升級注意：** 依賴此前 `tuic` 回退的匯入節點須明確設定 `alpn: [tuic]` 才能保留舊行為。協議專用 ALPN 不改變節點 UUID，但有效設定變化會為新請求重建執行時；已有流繼續遵循正常的 generation 退休機制。

### AnyTLS

| 連結輸入 | 節點欄位 / 行為 |
| --- | --- |
| userinfo secret | `password` 與 `anytls_password` |
| `min_idle_session` | `anytls_min_idle_session`；0–65535 的整數，預設 0，作為請求的待機下限，受八條 session 的池上限約束。無效值會被忽略。 |
| `idle_session_check_interval` | 以秒儲存的時長；目前不生效，因為清理週期固定為 30 秒 |
| `idle_session_timeout` | 以秒儲存的時長；預設 30 秒 |

時長為整數秒，可不帶字尾，也可帶 `s`、`m` 或 `h` 字尾。`ms` 值向上取整為秒，因此 `500ms` 為 1 秒。無效值會被忽略，保留預設值。

```dae
node {
    anytls: 'anytls://secret@edge.example:443?sni=edge.example&min_idle_session=1&idle_session_timeout=1m#anytls'
}
```

## VLESS

<a id="vless-udp-and-multiplexing"></a>

### UDP 與多路複用

VLESS 有三個獨立選擇。`udp=0|1` 控制是否允許封包撥號，`packetEncoding=auto|none|xudp|uot-v2` 選擇回退封包協議，`mux=off|h2mux|xray` 選擇 TCP/UDP carrier 路徑。這些選擇不會協商。

| 標準 URI 查詢參數 | 預設值 | 接受值與作用 |
| --- | --- | --- |
| `udp` | 允許 | `1`/`true` 允許封包撥號；`0`/`false` 關閉 UDP 而不關閉 TCP。文字布林值不區分 ASCII 大小寫；重複宣告必須一致。 |
| `packetEncoding` | `auto` | `auto`、`none`（原生 VLESS command-UDP）、`xudp`（Single XUDP）或 `uot-v2`。mux 不接管 UDP 路徑時使用該回退值。 |
| `mux` | `off` | `off`、`h2mux` 或 `xray`。 |
| `padding` | `false` | 只接受精確的 `true` 或 `false`，僅對 `mux=h2mux` 有效；選擇 sing-mux v1 填充。與 `udp` 不同，`1`、`TRUE` 等其他寫法會被拒絕。 |
| `concurrency` | `0` | 僅對 `mux=xray` 有效的有符號 `i16`：負值關閉 TCP mux；零允許每條 TCP carrier 同時承載 8 個邏輯 child；正值設定每條 carrier 的並行上限，最多 128。它不設定實體 carrier 數量。 |
| `xudpConcurrency` | `0` | 僅對 `mux=xray` 有效的有符號 `i16`：負值使用協議回退；零在 TCP mux 啟用時共享 TCP 池及其 carrier 並行，否則使用協議回退；正值建立獨立 UDP 池，每條 carrier 的邏輯 child 並行使用該值，最多 128。 |
| `xudpProxyUDP443` | `allow` | 僅對 `mux=xray` 有效的 `reject`、`skip` 或 `allow`；UDP/443 的精確優先順序見下文。 |

`packetEncoding`、`mux` 與每個 mux 控制項最多出現一次。重複的 `udp` 宣告僅在所有值一致時接受。

| `mux` 值 | TCP 與 UDP 路徑 |
| --- | --- |
| `off` | 保留普通 VLESS TCP，UDP 使用 `packetEncoding`。UoT v2 為每個客戶端源建立一條非連線模式流，承載全部目的地並傳回每個回覆的真實源位址。 |
| `h2mux` | 邏輯 TCP 與 sing-mux PacketAddr UDP 共用節點所屬的 HTTP/2 carrier 池。UDP 每個客戶端源使用一條流，逐封包攜帶位址。`padding=true` 選擇現有的填充 H2MUX 線協議格式。 |
| `xray` | 兩個並行設定所啟用的連線池分別使用 Xray Mux.Cool。TCP 與 UDP 池化相互獨立。 |

H2MUX 接管兩類路徑，因此回退編碼不會替換其 UDP 路徑。H2MUX 保留現有池策略，不採用 Mux.Cool 在每條 carrier 分配 128 個邏輯 child 後更換連線的行為。

以下是標準範例（使用合成 UUID）：

```dae
node {
    auto: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=off&udp=1#auto'
    h2_padded: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=h2mux&padding=true&udp=1#h2-padded'
    xray_shared: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=xray&concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip&udp=1#xray-shared'
    vision_udp_pool: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&flow=xtls-rprx-vision&packetEncoding=auto&mux=xray&concurrency=-1&xudpConcurrency=8&xudpProxyUDP443=skip&udp=1#vision-udp-pool'
}
```

結構化 TOML/YAML/JSON 使用以下獨立欄位：

| 欄位 | 意義 |
| --- | --- |
| `network` | 封包權限：`tcp` 關閉 UDP；省略、`udp` 或 `tcp,udp` 允許 UDP。 |
| `packet_encoding` | 回退編碼：`auto`、`native`、`xudp`、`uot-v2`。 |
| `multiplex` | 帶型別標記的 carrier 選擇，具體結構如下。 |

| 多路複用協議 | 結構化形式 |
| --- | --- |
| 關閉 | `{"protocol":"off"}` |
| H2 | `{"protocol":"h2","padding":true\|false}` |
| Xray | `{"protocol":"xray","tcp":N\|null,"udp":"protocol"\|"shared-tcp"\|{"separate":N},"udp443":"reject"\|"skip"\|"allow"}` |

省略的成員預設為 `padding: false`、`tcp: null`、`udp: "protocol"` 和 `udp443: "allow"`。因此結構化的 `{"protocol":"xray"}` 不啟用任何多路複用池；URI `mux=xray` 則預設使用並行為 8 的 TCP 池，UDP 共享該池。

`tcp` 和每個 `separate` 值都是正數，表示每條 carrier 的邏輯 child 並行上限，最多 128。省略 `tcp` 或設為 null 會關閉 TCP 多路複用池。

`udp: "shared-tcp"` 要求非 null 的 `tcp` 並行值。超出 `1..=128` 的值，或沒有 TCP 池的共享 UDP 池，都會使節點被拒絕，即使設定了 `network: "tcp"` 也一樣；這些無效值不會被截斷或正規化成關閉的池。這與上文有符號 URI 控制項不同，也與對應的 Clash 控制項不同：它們會把大於 128 的正值截斷為 128。

#### 從 `vless_mode` 遷移

**破壞性設定變更：** `vless_mode` 已刪除，不是相容別名。升級前應遷移靜態連結與 provider 內容。靜態 `node {}` 中出現該欄位會拒絕候選設定；訂閱只丟棄對應條目，保留其他有效節點。如果訂閱快取全部使用舊模式，離線狀態下無法恢復節點。離線升級前應確保本地已有遷移後的正文，並且不要刪除仍可用的 Selector 或延遲狀態。單一 provider 恢復失敗本身不導致啟動退出，但最終組裝的設定仍須通過驗證。

每種舊模式都有保留原有 capability 的替代組合：

| 已移除的 `vless_mode` | `packetEncoding` | `mux` | `udp` | 額外查詢參數 |
| --- | --- | --- | --- | --- |
| `auto` | `auto` | `off` | `1` | — |
| `native` | `none` | `off` | `1` | — |
| `legacy` | `auto` | `off` | `0` | 保留僅 TCP 行為；不保留舊身分。 |
| `uot-v2` | `uot-v2` | `off` | `1` | — |
| `h2mux` | `auto` | `h2mux` | `1` | `padding=false` |
| `h2mux-padded` | `auto` | `h2mux` | `1` | `padding=true` |
| `xudp` | `xudp` | `off` | `1` | — |
| `mux-cool` | `auto` | `xray` | `1` | `concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip` |

最後一行保留 TCP/UDP 可用性；`skip` 的 UDP/443 目標使用協議回退，而不是 pooled XUDP。現在預設允許 UDP/443，包括 Vision；需要封鎖 QUIC 時使用路由規則。本次升級中所有接納的 VLESS 節點都使用新的身分派生規則，見[節點身分](#節點身分)。

舊版 `vless_mode` URI 語法會被拒絕。解析器也拒絕 `smux`、`multiplex`、`udp-over-tcp`、`packet-encoding`、`packet_encoding`、`packet-addr`、`xudp`、`only-tcp`、Brutal 控制項與 H2 流數量調校等意義不明確的第三方 URI 拼寫；只有上表中的精確標準參數會設定這些選擇。

非 VLESS 連結把 `packetEncoding=none` 當作不生效的相容值接受。其他 `packetEncoding` 值或 `vless_mode` key 會使連結被拒絕。

#### 目標選擇與組合

未啟用 Vision 時，`packetEncoding=auto` 對目標埠 53、443 使用原生 VLESS UDP，其他埠使用 Single XUDP。啟用 Vision 時，獲准目標使用 Single XUDP。原生 UDP 傳送範圍為 1–8190 位元組，Single XUDP 為 1–7526 位元組；空封包或超長封包只會拒絕該封包本身，收到的零長度 frame 仍算一個封包。

預設允許 UDP/443，包括基礎 `xtls-rprx-vision`。需要封鎖時，在更寬泛的符合規則之前設定 `l4proto(udp) && dport(443) -> block`。

| `mux=xray` 的 UDP/443 策略 | 結果 |
| --- | --- |
| `reject` | 即使兩個多路複用池均關閉，仍拒絕 UDP/443。 |
| `skip` | 選擇 `packetEncoding`。 |
| `allow`（預設） | 使用設定的 UDP 池；沒有池時使用協議回退。 |

`xtls-rprx-vision-udp443` 正規化為基礎 Vision，不再改變權限或身分；線上附加欄位仍為基礎 flow。策略和容量拒絕會終止本次嘗試，且不影響健康狀態或 Score。它們不會觸發其他節點或 `direct` 回退，也不會自動重放封包。

Vision 始終要求 direct TCP 路徑：`mux=off`，或 `mux=xray` 且關閉 TCP mux。所有 H2MUX TCP 組合都無效，包括使用 Encryption 時。

Vision 可以使用僅 UDP 的 Xray 池；`concurrency=-1` 時，用正數 `xudpConcurrency` 建立該池。

未加密 Vision 還要求使用協商 TLS 1.3 或 REALITY 的裸 TCP。加密 Vision 可以保留已選 outer 流傳輸與 random-XOR 處理，但仍不能啟用 TCP mux、H2MUX UDP、原生 UDP 或 UoT v2；XUDP/Xray UDP 或關閉 UDP 均有效。

VLESS carrier slot 和 UDP endpoint slot 都出自行程級的檔案描述符預算。carrier slot 先劃分，所以可重複使用的 carrier 容量和 endpoint 數量會互相排擠。容量耗盡會當成本機容量問題回報，不算遠端協議失敗。honk 還依照自己的可重複使用 source/session 所有權，以及依目的地路由的語義，限定 XUDP Global ID 的 scope。它既不是 Xray 只認來源的身分，也不承諾無衝突的 NAT 身分。標準的生命週期與 scope 定義見[源/session 所有權與容量](../design/outbound.md#sourcesession-ownership-and-capacity)。

### Encryption

`encryption` 省略、為空或為 `none` 時不啟用 VLESS Encryption。其他值必須以 `mlkem768x25519plus.` 開頭；字串其餘部分由 handler 驗證。

`encryption=` 接受的基本客戶端字串形式為：

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<base64url-key>
```

key 為 Base64url，有無填充均可，解碼後是 32 位元組 X25519 key 或 1184 位元組 ML-KEM-768 key。鏈式 key 當成後續的點分隔段，不是冒號清單。

第一個 key 前可以加 `probability-min-max` 填充段，例如 `mlkem768x25519plus.native.1rtt.100-35-35.<key1>.<key2>`。從零計數，偶數段設定以位元組為單位的長度，奇數段設定以毫秒為單位的間隔。第一段的機率須為 100、最小長度至少 35 位元組，所有長度段最大值之和不得超過 65553 位元組。

`0rtt` 使用快取票據，冷啟動時走 1-RTT 路徑。VLESS Encryption 位於選定的 outer TCP/TLS/REALITY/WS/gRPC 傳輸內層。它支援原生或 XUDP 回退以及 Xray UDP 池，但不支援 H2MUX TCP/UDP 或 UoT v2。Encryption 與 Vision 可以在上述 direct-TCP-path 規則下組合。

### REALITY 與 Vision

在 VLESS 與 Trojan URL 連結中，`security=reality` 開啟 TLS 並對映 REALITY 查詢參數欄位，不再靜默回退到普通 PKI TLS。其他分享連結協議方案拒絕 REALITY 意圖；結構化 VMess REALITY 仍受支援。僅 VLESS 使用 `flow` 選擇 Vision。

| Query | 意義 |
| --- | --- |
| `security=reality` | 選擇 REALITY 並開啟 TLS。選擇了 REALITY 卻沒有 `pbk` 的節點會在驗證時被拒絕，而不是降級成普通 TLS。 |
| `pbk` | Base64url 編碼的 32 位元組 X25519 伺服器端 public key；無效輸入 fail-closed。 |
| `sid` | 偶數長度十六進位 short ID，最多 8 位元組；允許為空。 |
| `spx` | 儲存 spider path；選擇 REALITY 時預設為 `/`。 |
| `flow=xtls-rprx-vision` | 依上述 UDP/443 規則啟用 Vision。 |
| `flow=xtls-rprx-vision-udp443` | 正規化為 `xtls-rprx-vision`；預設已經允許 UDP/443。 |
| `fp` | 接受但忽略；ClientHello 指紋由全域 TLS 模式控制。 |

VLESS 依以下規則選擇 TLS：

| 輸入 | TLS 行為 |
| --- | --- |
| 明確 `security=none` | 關閉 TLS，覆蓋歷史預設值。 |
| 其他明確 `security=` 值 | 開啟 TLS。 |
| 無 `security`，有明確 `tls=0\|1` | 使用明確 TLS 選擇。 |
| 普通 VLESS 連結未提供兩者 | 預設開啟 TLS。 |
| Base64 編碼位址的 Shadowrocket 連結未提供兩者 | 預設關閉 TLS，除非 REALITY 欄位將其開啟。 |

標準 VMess 連結改用其 v2rayN JSON `tls` 欄位。

重複的 `security` 與已識別的 `tls` 宣告必須一致，包括別名之間的 TLS 開關。後值不能覆蓋前面的衝突宣告。VLESS 與編碼 VMess 只接受 `tls=0|1`；其他協議方案保留對未識別 `tls` 文字的處理。Trojan 與 AnyTLS 拒絕明確明文宣告，而不是靜默保留強制 TLS。

REALITY 僅使用 TLS 1.3，首次嘗試依次通告 hybrid `X25519MLKEM768` 與預設 classic `X25519` share。僅當握手完成後收到非 ed25519 葉憑證，才向同一對端新建一次僅使用 X25519 的連線；新連線仍須通過設定的 REALITY key/HMAC 認證，之後才能傳送代理資料。

兩次嘗試共享 `3 × connect_timeout` 的 setup deadline，不增加設定項。這個觸發結果沒有經過認證，不是伺服器端版本檢測。ed25519 HMAC 錯誤、TLS/IO 錯誤和 HRR 仍然是最終失敗。每條連線只 seal 一次 ClientHello，不復用 key/nonce。參見[相容與認證邊界](../design/outbound.md)。

裸 TCP 池只接納握手前保持靜默的 socket。任何排隊的伺服器端位元組，包括致命 TLS 警報，都會讓該裸連線在接納或取出時被拒絕；沒有 SNI/警報特例，也不會重試握手。已經完成協議準備的就緒流即使緩衝了有效應用資料，也不會因此被拒絕。

REALITY 不使用 CA 驗證或 `skip_cert_verify`。目標 TLS 記錄的緩衝限制取決於伺服器端版本。文件中的 sing-box 1.12 / MetaCubeX-uTLS 1.8.0 對端使用 8192 位元組緩衝區，包含訊框開銷，這不是 honk 統一的憑證上限。參見[伺服器端版本約束](../design/outbound.md)。REALITY 設定方案還會加入 ed25519；被忽略的 `fp` 和全域 Chrome-oriented 模式都不承諾精確的瀏覽器身分。

## TLS 指紋與 ECH

全域 `tls_implementation` 同時作用於代理 TCP TLS 與 QUIC：

| 取值 | 行為 |
| --- | --- |
| `tls` | 原生 BoringSSL ClientHello |
| `utls` | Chrome 形 ClientHello，包含 GREASE、擴充套件亂序、Chrome 演算法/曲線、憑證壓縮、ALPS 與 ECH GREASE |

依節點的 ECH 控制項為：

| 輸入 | 行為 |
| --- | --- |
| `ech_config=<base64>` / `echconfig=<base64>` | 靜態 ECHConfigList；隱含 `ech_enabled` 且優先 |
| `ech_config_path` | 結構化 loader 檔案路徑；兩者同時存在時 `ech_config` 優先 |
| `ech=1` / `ech=true` | 沒有靜態設定時開啟 DNS HTTPS-RR 發現 |

`ech_config` 和 `ech_config_path` 檔案的內容是 Base64 文字，標準或 URL-safe 均可，填充可選；檔案不能是二進位 ECHConfigList。讀取或解碼失敗會使節點被拒絕，不會回退到發現。

靜態設定會提供真實 ECH；ECH 被拒絕時，握手 fail-closed。發現是盡力而為且 fail-open：找不到 ECHConfigList 時，握手不帶真實 ECH 繼續，`utls` 仍傳送 ECH GREASE。發現走 bootstrap resolver，未設定時使用系統第一個 nameserver，並依網域名稱快取結果。同一組控制項也適用於 QUIC 協議。

## 分享連結 scheme

XHTTP 以外，未知查詢 key 會被忽略，因此拼錯 key 名不會報錯。XHTTP 連結拒絕未知 key，VLESS 拒絕上文列出的第三方寫法。

| Scheme | 格式與對映 |
| --- | --- |
| `ss://` | SIP002 Base64 userinfo 或完整位址，或明文 `ss://method:password@host:port` |
| `vmess://` | 寬鬆 Base64 v2rayN JSON 或編碼位址形式，見流傳輸一節 |
| `vless://` | URL userinfo UUID，加流傳輸、TLS/REALITY、flow、Encryption 與上文標準 UDP/mux 查詢參數 |
| `trojan://` | URL userinfo secret，加傳輸與 TLS 查詢參數 |
| `anytls://` | URL userinfo secret，加 TLS 與池查詢參數 |
| `hysteria2://` | 上述 Hysteria2 查詢參數對映；也接受 `hysteria://` |
| `tuic://` | 上述 TUIC userinfo 與 QUIC 調校 |
| `juicity://` | Juicity userinfo 與共用 QUIC/TLS 查詢參數 |
| `socks5://` | SOCKS5 userinfo；也接受 `socks4://` 和 `socks4a://`，但仍使用 SOCKS5 協議，因此不能連線僅支援 SOCKS4 的伺服器端 |

明文 `method:password` userinfo 中的方法本身可以是 Base64，例如 `ss://YWVzLTEyOC1nY20=:password@host:port`。無法得到方法和密碼的 userinfo 會整體當成密碼，方法回退到 `aes-128-gcm`。

honk 不執行 Shadowsocks 外掛。`plugin=name;options`、`plugin-opts` 和 `plugin_opts` 只當成後設資料保留；其他 scheme 出現這些 key 會被拒絕。

SOCKS5 只在連結同時帶有使用者名稱和密碼時提供使用者名稱/密碼認證，兩者各不得超過 255 位元組。

寫成 `a -> b` 的鏈只解析 `a`。節點名稱來自 dae 標籤、`#fragment`、`remark`、VMess `ps` 或 `{scheme}-{host}`，從不使用原始 URI 或 userinfo，因此名稱不會洩露憑據。

## 相關文件

- [訂閱參考](./subscription.md)
- [群組參考](./groups.md)
- [出站設計](../design/outbound.md)
