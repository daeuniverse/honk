# 全域設定參考

`global { ... }` 定義程序級設定。

## 範例

```dae
global {
    tproxy_port: 12345
    log_level: info
    log_file: 'honk.log'
    data_dir: '/var/lib/honk'
    store_subscribe: true
    nfqueue_enable: true

    lan_interface: br0
    wan_interface: auto

    tcp_check_url: 'https://www.gstatic.com/generate_204'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms

    dial_mode: domain++
    bootstrap_resolver: '223.5.5.5:53'

    preconnect_node_count: 'auto'
    udp_warm_node_count: 0
    max_concurrent_dials: 64
}
```

## 欄位

下表列出 `global` 的欄位及其執行期效果。部分 key 只為相容既有的 dae 設定而接受：解析器會把它們存入 `GlobalConfig`，但 honk 目前不讀取；每個這樣的欄位都會在含義欄或所連結的小節裡註明。

所有欄位都可省略，省略時使用表中的預設值。啟用 DNS 稽核時，`syslog_addr` 必填。

以下欄位需重啟才能改動：`tproxy_port`、`tproxy_port_protect`、`pprof_port`、`so_mark_from_dae`、`log_level`、`log_file`（解析後的實際目標變化時）、`syslog_addr`、`syslog_dns_enabled`、`syslog_cee_enabled`、`syslog_hostname`、`syslog_app_name`、`lan_interface`、`wan_interface`、`auto_config_kernel_parameter`、`nfqueue_enable`（啟動時確實降級的情況除外）、`data_dir`、`store_subscribe`，以及 [reload 健康檢查與 TLS 模式](#reload-健康檢查與-tls-模式) 列出的健康檢查輸入。reload 若改動健康檢查輸入會被拒絕，目前生效的設定保持不變。

Key 欄以破折號開頭的五列，是 dae 語法無法設定的內部欄位。

| Key | 內部欄位 | 預設值 | 含義 |
| --- | -------- | ------ | ---- |
| `tproxy_port` | `tproxy_port` | `12345` | TCP/UDP 透明代理連接埠；見 [`tproxy_port`](#tproxy_port)。 |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | 用於避免透明代理連接埠被再次攔截的相容開關；目前的 honk 不讀取它。 |
| `pprof_port` | `pprof_port` | `0` | pprof HTTP 連接埠相容欄位；見 [`pprof_port`](#pprof_port)。 |
| `so_mark_from_dae` | `so_mark_from_dae` | `0`（實際 `0x100`） | honk 主動建立的 socket 使用的程序級 `SO_MARK`，資料路徑也用它做精確的旁路比對；見 [socket mark](#socket-mark)。 |
| `log_level` | `log_level` | `"info"` | 啟動日誌過濾器，語法同 `RUST_LOG`；見 [`log_level`](#log_level)。 |
| `log_file` | `log_file` | `""` | 以附加方式寫入的日誌路徑；見 [`log_file`](#log_file)。 |
| `syslog_addr` | `syslog_addr` | `""` | TCP syslog 接收端；見 [`syslog_addr`](#syslog_addr)。 |
| `syslog_dns_enabled` | `syslog_dns_enabled` | `false` | 透過 RFC 5424 syslog 傳送客戶端 DNS 稽核；見 [`syslog_dns_enabled`](#syslog_dns_enabled)。 |
| `syslog_cee_enabled` | `syslog_cee_enabled` | `false` | 為 JSON 正文加上 `@cee: ` 字首，供支援 CEE 的接收端使用；見 [`syslog_cee_enabled`](#syslog_cee_enabled)。 |
| `syslog_hostname` | `syslog_hostname` | `""` | RFC 5424 header 中的傳送端主機名稱；見 [`syslog_hostname`](#syslog_hostname)。 |
| `syslog_app_name` | `syslog_app_name` | `"honk"` | RFC 5424 header 中的應用程式名稱：1–48 位元組、不含空格的可列印 ASCII。 |
| `disable_waiting_network` | `disable_waiting_network` | `false` | 相容 key；目前的啟動路徑不讀取它。尚未解析的 `auto` 網卡本來就會保持待定，不會阻塞啟動。 |
| `shutdown_wait_connections` | `shutdown_wait_connections` | `false` | 退出時給業務連線的寬限等待；見[關閉](#關閉)。 |
| `lan_interface` | `lan_interface` | `[]` | 逗號分隔的 LAN 網卡，其 hook 會攔截轉發流量；見[網卡語義](#網卡語義)。 |
| `wan_interface` | `wan_interface` | `[]` | 逗號分隔的 WAN 網卡，其 hook 會攔截本機發起的 TCP/UDP；見[網卡語義](#網卡語義)。 |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | sysctl 自動設定的相容開關；見 [`auto_config_kernel_parameter`](#auto_config_kernel_parameter)。 |
| `nfqueue_enable` | `nfqueue_enable` | `true` | 把有歧義的 LAN 轉發 UDP 留在 NFQUEUE；見 [`nfqueue_enable`](#nfqueue_enable)。 |
| `data_dir` | `data_dir` | `"/var/lib/honk"` | 生成狀態和相對執行期資源的根目錄；見[資料目錄與資源路徑](#資料目錄與資源路徑)。 |
| `store_subscribe` | `store_subscribe` | `true` | 將每個訂閱最近一次有效的正文持久化到 `data_dir/state/honk.db`，僅供啟動恢復；reload 沿用作用中的節點，不讀取已儲存的正文。 |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | TCP/HTTP 健康檢查 URL；見 [`tcp_check_url`](#tcp_check_url)。 |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | URL 健康檢查使用的 HTTP 方法，例如 `HEAD` 或 `GET`。空值按 `HEAD` 處理；無效的方法會讓每次 HTTP 探測都因請求無效而失敗。 |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | UDP 健康檢查的 DNS 目標；見 [`udp_check_dns`](#udp_check_dns)。 |
| `check_interval` | `check_interval_secs` | `30s` | 全域健康檢查間隔，單位是整秒；見 [`check_interval`](#check_interval)。 |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | URLTest 切換成員前要求的延遲改善量；見 [`check_tolerance`](#check_tolerance)。 |
| `dial_mode` | `dial_mode` | `"domain"` | 目的網域探索和路由模式；見 [`dial_mode`](#dial_mode)。 |
| `allow_insecure` | `allow_insecure` | `false` | 全域 TLS 驗證備援的相容欄位；見 [`allow_insecure`](#allow_insecure)。 |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | 嗅探逾時的相容欄位；見 [`sniffing_timeout`](#sniffing_timeout)。 |
| `tls_implementation` | `tls_implementation` | `"tls"` | 寫 `utls`（不區分大小寫）會啟用 honk 的 Chrome 風格 ClientHello 模擬，不保證精確的瀏覽器身分。其他任何值，包括空值和拼寫錯誤，都會選擇一般 BoringSSL 客戶端設定，不報錯也不產生 warning。 |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | 相容指紋請求；見 [`utls_imitate`](#utls_imitate)。 |
| `tls_fragment` | `tls_fragment` | `false` | TLS ClientHello 分片相容開關；目前的 TLS connector 不讀取它。 |
| `tls_fragment_length` | `tls_fragment_length` | `""` | 分片長度範圍的相容欄位；目前的 TLS connector 不讀取它。 |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | 分片間隔範圍的相容欄位；目前的 TLS connector 不讀取它。 |
| `mptcp` | `mptcp` | `false` | MPTCP 相容開關；目前的撥號路徑不讀取它。 |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | 節點主機名稱和控制面撥號使用的帶 mark UDP/TCP resolver；見 [`bootstrap_resolver`](#bootstrap_resolver)。 |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | 備援 resolver 相容值；目前的 honk 不讀取它。 |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | 傳送頻寬提示的相容值，例如 `'200 mbps'`；目前的 honk 不讀取它。 |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | 接收頻寬提示的相容值；目前的 honk 不讀取它。 |
| `preconnect_node_count` | `preconnect_node_count` | `"auto"` | 啟動時預熱裸 TCP 的節點數；見 [`preconnect_node_count`](#preconnect_node_count)。 |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | 每個代理群組的 UDP 預熱候選數；見 [`udp_warm_node_count`](#udp_warm_node_count)。 |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | 每個 generation 的代理連線和握手上限；見 [`max_concurrent_dials`](#max_concurrent_dials)。 |
| —（dae 語法中不可設定） | `tproxy_mark` | `0x08000000` | 使用者空間策略路由與編譯後的 eBPF 資料路徑共用的固定 fwmark。 |
| —（dae 語法中不可設定） | `udphop_interval_secs` | `30s` | 舊的全域 UDP hop 間隔。目前的撥號器不讀取它；協定專屬的連接埠跳躍使用節點欄位。 |
| —（dae 語法中不可設定） | `connect_timeout_ms` | `3000ms` | 代理連線、協定準備、預連線、健康檢查和控制面撥號使用的階段逾時。透明 TCP 候選 race 與 UDP transport preparation 還共用絕對總預算 `max(10s, 4 × connect_timeout)`；不新增設定 key。 |
| —（dae 語法中不可設定） | `dns_resolve_timeout_ms` | `2000ms` | 控制面 DNS 解析逾時，包括撥號前必須轉換為 IP 的目標。 |
| —（dae 語法中不可設定） | `relay_idle_timeout_secs` | `300s` | 舊中繼閒置逾時；目前的中繼路徑不讀取它。 |

### tproxy_port

把 TCP/UDP 透明代理連接埠寫入使用者空間 listener 和 eBPF 資料路徑。

取值為十進位連接埠號。其他文字（包括十六進位）會產生 `legacy-config-warning`，並退回 `12345`。

### pprof_port

pprof HTTP 連接埠相容欄位；`0` 表示關閉。honk 目前不啟動 pprof 服務，也不讀取該欄位。

不是十進位連接埠號的值會產生 warning，並退回 `0`。

### log_level

啟動時的日誌過濾器，語法同 `RUST_LOG`，例如 `info` 或 `'info,honk_core=debug'`。值為空白時按 `info` 處理。

優先順序從高到低是有效的 `RUST_LOG`、`--debug`、該值。

`info` 涵蓋執行狀態：啟動、reload、健康檢查和訂閱。逐條連線的分流記錄（`TCP connection`、`UDP connection`、eBPF 卸載）位於 `debug` 等級，以免路由器的 syslog 被逐連線日誌佔滿。

透過 SIGHUP 修改不會生效，必須重啟。原生 API 的 `log.level` PATCH 會替換該過濾器，直到下次啟用。

要核對分流結果，就用 `debug` 執行，或從 API 讀取 `/logs?level=debug`。

### log_file

以附加方式寫入的日誌路徑。空值或只有空白的值會關閉檔案輸出，主控台日誌仍然啟用。

相對路徑在 `data_dir` 下解析；見[資料目錄與資源路徑](#資料目錄與資源路徑)。

只有在解析後的實際目標改變時，SIGHUP 才需要重啟。`--log-file` 優先於此設定值。

### syslog_addr

TCP syslog 接收端：數字 IP 加連接埠，例如 `192.0.2.10:514` 或 `[2001:db8::10]:514`。

啟用 DNS 稽核時必填。此時必須是單播 IP 加非零連接埠，否則以 `invalid-config-value` 驗證失敗。

### syslog_dns_enabled

需要 `dns-syslog` Cargo feature。啟用後，honk 傳送客戶端 DNS 結果：訊息依 RFC 5424 固定，正文為 JSON，經一條 TCP 長連線傳輸，並以 RFC 6587 的長度字首劃分訊框。

稽核獨立於原生 API 歷史記錄和日誌等級。傳送分批進行且有上限，重連會退避；沒有應用層確認，也不會寫入磁碟。

見 [DNS 稽核](../design/dns-syslog.md)。

### syslog_cee_enabled

為固定 JSON 正文加上 `@cee: ` 字首，用於支援 CEE 的接收端，例如 VictoriaLogs。一般 JSON 請保持 `false`。

該欄位不會啟用稽核，也不會編譯 `dns-syslog` feature。

### syslog_hostname

設定 RFC 5424 header 中的傳送端主機名稱。空值會在啟動時讀取一次系統主機名稱，失敗時退回 `-`。

明確指定的值必須是 1–255 位元組、不含空格的可列印 ASCII，關閉 DNS 稽核時也一樣要驗證。

### auto_config_kernel_parameter

自動設定 sysctl 的相容開關。執行期不再依該欄位分支；真實資料路徑一律執行固定的 best-effort sysctl 設定。

該設定會把 `net.ipv6.conf.all.forwarding` 固定為 1，因此會為每個 WAN 根介面寫入 `net.ipv6.conf.<wan>.accept_ra=2`，包括同時作為 LAN 的介面。介面出現在網卡拓撲中時就會立即寫入，無論是啟動時已存在或之後才出現；寫入不等待該介面的 hook，也不要求連結 UP。這樣一來，SLAAC/RA 學到的 IPv6 預設路由不會因為 forwarding 被固定而過期消失。

該設定還會為第一個已解析、存在且未被拒絕的 LAN 名稱寫入 `net.ipv4.conf.<lan>.rp_filter=0`，依設定原樣寫入，不做正規化。

每個值約一秒後會再寫一次：新裝置加入時，udev 的 `systemd-sysctl` 會在首次寫入後立即還原發行版預設值。此後 honk 不再改動，直到該裝置被重建。

使用 systemd-networkd 的主機，建議在 WAN 的 `.network` 檔案中明確設定 `IPv6AcceptRA=yes`。

### nfqueue_enable

把有歧義的 LAN 轉發 UDP 原始封包留在 NFQUEUE，直到使用者空間做出最終決策。此功能需要真實 eBPF 後端。

單一執行個體交接後，固定佇列不可用，或資料路徑 admission 之前佇列、規則、健康檢查失敗時，honk 會記一條 warning，並在本程序內關閉該功能，不改寫設定。安裝階段會回收保留的 nftables table。

持久化 token generation 恢復失敗，以及 [admission 後的失敗](../design/nfqueue.md#啟用與範圍)，仍然是 fatal。

`experimental.udp_nfqueue.enabled` 已棄用，改用 `nfqueue_enable`。舊寫法仍被接受，並產生遷移 warning；兩者同時存在時以 `nfqueue_enable` 為準。

只有確實發生過降級時，寫入和 reload 才能繼續請求 `nfqueue_enable: true`，而 NFQUEUE 的生效值保持關閉。省略該 key、採用預設值 `true`，也算這種請求。降級分兩種：啟動早期的降級（mock、不帶 `ebpf` feature，或固定佇列的前置檢查失敗），以及資料路徑 admission 之前較晚發生的佇列、規則或健康檢查降級。請求的來源文字保持原樣，生效值在本程序的整個生命週期內都是 `false`。honk 不會自動重試啟用，只有重啟才會重試。沒有發生降級時，開關的變更仍需重啟。[通用 reload 流程](../design/control-plane.md#reload-與執行時-generation) 會在指紋/no-op 檢查之前正規化生效設定；原生 API 的寫入前檢查與完整驗證使用同一套重啟策略。

`nfqueue_enable` 同時控制 [LAN UDP/53 分片交付](../design/nfqueue.md#lan-dns-分片)：DNS 控制器和 raw group 處理的分片都要求 NFQUEUE 處於 ready，否則直接丟棄，不能繞過 DNS 策略。原生 `direct(must)` 和未分片的 DNS 不變。

### tcp_check_url

設定以逗號分隔的 TCP/HTTP 健康檢查 URL。健康檢查迴圈只使用第一個值；首項缺失或為空時，退回一般的 TCP 檢查。

只支援 `http://`、`https://` 和不帶 scheme 的 URL。其他 scheme 或連接埠 `0` 仍能載入，但每次 HTTP 探測都會因為請求無效而失敗。

URI 解析會分別處理 userinfo、帶方括號的 IPv6、連接埠、路徑、查詢和片段。userinfo 不會變成 authorization header。請求會保留路徑和查詢，不傳送片段；沒有斜線的查詢以 `/?query` 傳送。

明確指定 HTTP/HTTPS 的目標預設使用 80/443 連接埠。不帶 scheme 的健康檢查目標使用 HTTP/80；URLTest 的不帶 scheme 目標使用 HTTPS/443，並對解碼後的路徑和查詢字串送出 HEAD。

第一個 URL 同時也是 Score 的 QUIC 探測目標；見 [reload 健康檢查與 TLS 模式](#reload-健康檢查與-tls-模式)。

```dae
global {
    tcp_check_url: 'https://www.gstatic.com/generate_204'
}
```

### udp_check_dns

設定以逗號分隔的 UDP 健康檢查 DNS 目標。裸 IPv4/IPv6、`[IPv6]` 和網域預設使用連接埠 `53`；明確指定的連接埠必須是 `1..65535` 內的整數。

括號或連接埠格式錯誤時，驗證失敗並產生含位置的診斷。

優先選擇第一個 IP 常值，沒有就解析第一個網域。解析結果與 Score 共用同一個解碼後的主機和連接埠；網域解析完成後仍保留網域身分。

```dae
global {
    udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
}
```

### check_interval

設定全域健康檢查間隔，單位是整秒。取整數，可以不加字尾，也可以加 `s`、`m`、`h`；`ms` 值會向上取整到秒（`500ms` 變成 `1s`），`1.5s` 無效。

該值必須為正。解析失敗的值會變成零，並在驗證時被拒絕。

UDP 預熱協調器也使用這個間隔，但實際下限為 10 秒。

```dae
global {
    check_interval: 30s
}
```

### check_tolerance

設定 URLTest 切換所選成員前要求的延遲改善量，單位為整毫秒。接受裸毫秒數、帶 `ms` 的整數或帶 `s` 的值，包括零。

不足一毫秒的部分會被截去，因此 `0.0005s` 變成 `0ms`，`0.5ms` 無效。其他寫法會保留預設值 `50ms` 並記錄 warning。

```dae
global {
    check_tolerance: 50ms
}
```

### dial_mode

選擇目的網域探索和路由模式：`ip`、`domain`、`domain+` 或 `domain++`。拼寫不區分大小寫。

未知名稱會以 `invalid-config-value` 拒絕驗證。各模式見[撥號模式](#撥號模式)。

```dae
global {
    dial_mode: domain++
}
```

### allow_insecure

全域 TLS 驗證備援的相容欄位。目前的 TLS connector 不讀取該欄位。

跳過證書驗證需在節點分享連結中按節點設定。

### sniffing_timeout

嗅探逾時的相容欄位；目前的控制面不使用它。解析規則和無效值的處理方式同 [`check_tolerance`](#check_tolerance)；無效值會保留預設的 `30ms` 並記錄 warning。

### utls_imitate

相容指紋請求。`utls` 模式只使用一個 Chrome 風格設定，因此此值不會切換設定。

非空且不以小寫 `chrome` 開頭的值，會在啟動時記錄 warning。

### bootstrap_resolver

設定用來解析節點主機名稱和控制面撥號目標的帶 mark UDP/TCP resolver。取值是數字 IP 加連接埠：`223.5.5.5:53`、`udp://223.5.5.5:53`、`tcp://223.5.5.5:53` 或 `[2001:4860:4860::8888]:53`。

只有 `tcp://` 會選擇 TCP，其他 scheme（例如 `tls://`）都按明文 UDP 處理。寫成主機名稱或缺少連接埠時，resolver 不會生效，也不會報錯。

bootstrap 為空或查詢失敗時，honk 先查 `/etc/hosts`，再向 `/etc/resolv.conf` 裡第一個數字 nameserver 送出帶 mark 的 DNS；它不呼叫 libc NSS，也不附加搜尋字尾。

去掉 scheme 後的同一位址，還會用作週期性 `direct` 健康檢查的目標；無效時退回 `223.5.5.5:53`。

DNS [`subtag()` 規則](./dns.md#節點伺服器域名)可以改為接管某個訂閱的節點主機名稱。

```dae
global {
    bootstrap_resolver: '223.5.5.5:53'
}
```

### preconnect_node_count

啟動時執行一輪裸 TCP 預熱，只執行一次。`"auto"` 最多選擇八個合格節點，同時進行四次嘗試；明確指定 `N` 時最多選擇 `N` 個，同時最多 `min(N, 8)` 個。各群組目前的選擇優先，之後再依節點設定順序補充。`0` 關閉這一輪預熱。

可接受的取值見[預熱與撥號預算](#預熱與撥號預算)。

### udp_warm_node_count

啟用獨立的 UDP 預熱協調器，並設定每個代理群組的 UDP 預熱候選數。`0` 關閉。

正值 `N` 表示每個群組、每個 IP family 最多挑選 `min(N, 3)` 個可重複使用的 UDP 葉節點，去除重複後全域最多保留 `4 × N` 個。最多同時進行四次嘗試。

第一輪預熱立即開始。之後每批完成後再等 `max(check_interval, 10s)`；群組的選擇改變時，會提前開始。

### max_concurrent_dials

請求每個 generation 的實體代理連線和協定握手上限。執行期資源預算可能進一步收緊。

實際值至少為一，最多為 `1024`；更大的設定值會被接受，但會收緊到上限。重疊的 reload generation 還會共用一個由檔案描述元推匯出的上限。

Ready pool 命中、已熱 transport 上的邏輯流以及 `direct`/`block` 不佔 permit。

## 列表取值

預設值欄中的 `[]` 表示空列表。dae 沒有列表常值，`lan_interface: []` 會建立名為 `[]` 的網卡；清空網卡列表請寫 `lan_interface: ''` 或 `wan_interface: ''`。`tcp_check_url: ''` 保留一個空項，從而關閉 HTTP 探測。

`tcp_check_url` 和 `udp_check_dns` 的列表項應逐項加上引號，或完全不加引號。整串加引號，例如 `'dns.google:53,8.8.8.8'`，仍然可用，但會產生 `legacy-quoted-list` warning。

## 已移除的鍵

`syslog_dns_template` 和 `syslog_dns_json` 已移除，因為 DNS syslog 使用固定的 JSON schema。無論取值為何，出現任一 key 都會以 `removed-config-setting` 拒絕設定；請刪除該 key。

## HTTP 健康檢查請求

HTTP 健康檢查和 URLTest 請求的 `Host` 只含主機與連接埠，不含憑證。IPv6 會保留方括號，非預設連接埠不會省略。建立連線和處理 TLS 伺服器名稱時，使用的是不帶方括號的主機。

請求路徑和查詢字串會保留設定中的原始點路徑段和百分號編碼。建構請求之前，honk 會拒絕 authority 含多餘斜線、包含反斜線或內嵌 ASCII 空白／控制字元的 URL。被拒絕的 URL 不會出現在健康檢查的 warning 中。

HTTP 探測會把 `200–499` 的任何最終狀態碼視為成功，因此重新導向或 `404` 也算通過。回應 header 超過 16 KiB 或不完整時，探測失敗。

## 關閉

`shutdown_wait_connections: true` 讓 honk 在退出時給已接受的連線最多五秒自然結束，然後關閉並 join 剩餘連線。這段寬限只在關閉過程正常、資料路徑健康，且存在作用中的 runtime epoch 時生效。其他情況會跳過等待，不分長短連線。

關閉時使用最近接受的設定；reload 被拒絕時保留舊值。這個開關不影響 reload 退役、DNS/狀態持久化、NFQUEUE/eBPF 清理，也不影響原生 API 獨立的[五秒 HTTP 寬限期](./api.md#原生-api)。

這不是優雅重啟，也不是總退出時間的限制：[已持有的清理和阻塞工作](../design/control-plane.md#終止所有權)仍須完成。

## socket mark

`so_mark_from_dae: 0` 或省略該項時，保留歷史上的實際 mark `0x100`。非零值會取代 `0x100`，不會和它按位元 OR。honk 會在 connect/send 之前原樣套用這個 mark，作用於代理 carrier、bootstrap/DNS、健康檢查、訂閱和 UI 下載。資料路徑依設定值做精確的旁路比對；只帶有 `0x100` 這一個位元並不能免於攔截。透明 listener socket 使用同一個 mark 供核心辨識；accept 得到的 TCP 客戶端 socket 會清除這個 mark。獨立的 `dns.bind` 入口仍是普通的無 mark 本機服務。

dae 全域純量沿用 honk 既有的十六進位優先規則：`10` 和 `0x10` 都表示 16。格式錯誤或溢位的文字會產生診斷，並退回原始值 `0`，實際生效的是 `0x100`，建議明確寫出 `0x`。這與[直連規則 mark](./routing.md#策略路由-mark) 不同：後者沒有字首時按十進位解析，錯誤值直接拒絕設定。

全域與規則 mark 的驗證都會拒絕保留位 `0xc0000000`；全域 mark 還會拒絕 TPROXY 位 `0x08000000`，daens 會把該位路由到自己的 listener，因此全域 mark 保留的是 `0xc8000000`。

這個值在啟動網路 I/O 之前確定，作用於整個程序；修改需要重啟，不能透過 SIGHUP 切換。非零的直連規則 mark 會取代該直連流的全域策略路由有效位，代理 carrier 和 bootstrap 仍使用全域值。直連流還會攜帶內部分類中繼資料；請使用 [路由參考](./routing.md#策略路由-mark) 中帶遮罩的 IPv4/IPv6 `ip rule` 範例。honk 不負責安裝使用者的 WAN 策略路由表、路由、來源位址規則或 NAT 設定。

## reload 健康檢查與 TLS 模式

以下參數在啟動時確定。reload 若改變生效值會被拒絕，目前的設定與已安裝的探測器保持不變：

- `check_interval`。
- 第一個 `tcp_check_url`，包括其備援位址、路徑和查詢字串。首項缺失或為空都會關閉 HTTP 探測；後續項不參與比較。
- HTTP 探測啟用時的 `tcp_check_http_method`。空值與 `HEAD` 等價。
- `udp_check_dns` 選中的目標。處理時會先去除首尾空白、忽略空項，優先取列表裡第一個 IP 常值，沒有就取第一個網域，兩者都沒有時使用 `8.8.8.8:53`。reload 檢查只比較設定中的位址或網域及其連接埠，不解析 DNS。網域比較不區分大小寫，並忽略一個結尾句點，因此 `dns.example:53` 和 `DNS.EXAMPLE.:53` 是同一目標。未選中項的變化仍可 reload。
- `tls_implementation` 在原生 TLS 與 uTLS 之間的切換。比較 `utls` 時不區分大小寫。

dae 設定中的 `check_tolerance` 仍可透過 reload 更新 URLTest 群組的容差。群組層級的檢查 URL 和直接連線探測仍沿現有路徑動態更新。reload `utls_imitate` 只會儲存相容設定值，不會改變指紋。

Score 群組還會對第一個 `tcp_check_url` 發起 QUIC 握手探測。該 URL 必須以小寫 `https://` 開頭，否則此探測會關閉，Score 只使用其他探測，並由 `quic_probe` 降級項報告。QUIC 目標只在啟動時建立，因此 reload 新增第一個 Score 群組時，會報告原因 `restart_required`，直到下次重啟。

UDP DNS 目標在啟動時按健康檢查逾時嘗試初始化。本機拒絕或初始化逾時會讓設定目標保持待定，留給後續健康檢查週期重試；honk 不會替換預設目標，也不會降低節點健康狀態，獨立的 QUIC 檢查仍可繼續。首次成功解析出的位址隨後保持固定。延後的解析和 DNS 交換共用同一次探測的絕對期限；一般解析失敗仍保留既有的預裝置援。

## 流量入口與攔截

honk 透過所設定網卡上的 eBPF TC hook 接收流量，不提供供客戶端連線的代理連接埠。

- `lan_interface` 上的 hook 會攔截 LAN 客戶端經本機轉發的流量，例如把本機設為閘道器的客戶端。
- `wan_interface` 上的 hook 會攔截本機發起的 TCP/UDP。
- 需要使用者空間處理的流量由資料路徑經 `dae0` 送進 `daens` 命名空間，再由 `sk_lookup` 交給 `tproxy_port` 上的透明代理 TCP 或 UDP listener。有歧義的 LAN 轉發 UDP 則由 NFQUEUE 暫存（`nfqueue_enable`）。
- 攔截需要真實 eBPF 後端；mock 後端不攔截任何流量。

honk 沒有 TUN 入站，也沒有 `mixed-port`、`redir-port` 或 HTTP/SOCKS 入站。Clash API 的 `GET /configs` 會把 `port`、`socks-port` 和 `mixed-port` 報告為 `0`，並把 `tun.enable` 報告為 `false`。除了透明代理 listener，honk 只會監聽選用的 [`dns.bind`](./dns.md#獨立-listenerbind) 位址，以及 [`experimental`](./experimental.md) 中設定的 API listener。流量經過各個 hook 的過程見[封包路徑](../design/overview.md#封包路徑)。

## 網卡語義

`lan_interface` 為空時，honk 不安裝 LAN TC hook，也絕不會用 `lo` 替代。僅有 WAN 的閘道器因此只使用 `wan_interface`；經過這些 WAN hook 的本機 TCP/UDP 流量仍會被代理，但不會額外安裝 LAN 攔截。

多個網卡使用 `lan_interface: 'eth0', 'eth1'`；`wan_interface` 也採用相同語法。將整個逗號分隔列表放在一組引號內，例如 `lan_interface: 'eth0,eth1'`，會建立一個網卡名稱，而不是兩個。

在乙太網路父裝置上，VID 非零的 VLAN 標籤訊框屬於 VLAN 裝置。要管理該子網路，請列出 `eth1.20`；VLAN-aware bridge 則列出 `br0.N`。VLAN-aware bridge 拓撲尚未經過真實流量驗證。參見[介面 hook 集合](../design/datapath.md#介面-hook-集合)。

`auto` 在所有使用處都會去除首尾空白，且不區分 ASCII 大小寫，所以 `AUTO`、` auto ` 和只剩空白的項目都算 `auto`。`.dae` 的列表解析器會丟棄真正為空的項，因此空列表仍表示沒有介面。`auto` 會解析為擁有最低 metric IPv4 預設路由的網卡。沒有這條路由時，該項目會保持待定，絕不退回 `lo`，直到預設路由出現。同一列表裡明確命名的網卡照常運作。只有存在 `auto` 項時才會讀取路由表；路由表讀不出來是錯誤，不能當作沒有預設路由：啟動時會失敗，執行期間失敗則保持現有繫結不變。

網卡存在即繫結，不要求 `IFF_UP`。角色按網卡區分，見[介面 hook 集合](../design/datapath.md#介面-hook-集合)，因此 LAN/WAN 共用的網卡不會改變其他 LAN 網卡的 hook。bond、bridge 或其他 master 的成員會透過該 master 繫結，但 `vrf` 和 `openvswitch` 的成員則保持自身。LAN bridge 還會以 LAN 角色繫結它的連接埠；bond 的 hook 只掛在邏輯 master 上，不會掛到成員。

每個已設定的項目都是 lazy 繫結，不會導致啟動失敗。網卡尚不存在、沒有預設路由的 `auto` 項目，或被拒絕的連結型別，都不會繫結任何 hook，其流量在繫結之前不會被攔截。TCX link 建立、更新或驗證失敗時，項目可能只繫結了部分 hook，此時有效的 hook 仍可能攔截流量。項目完全沒繫結 hook，或只繫結了部分 hook，都會由 `interface_binding` [降級](./api.md#原生-api)報告；`lifecycle.state` 仍是 `running`，監控時必須讀取這條降級。比對只看核心的主名稱，altname 視為不存在。裝置出現時會繫結，消失時會釋放 hook，以新網卡 index 重建的裝置會重新繫結。屬於尚不存在網卡的 `dns.bind` 位址不算網卡項目：繫結它仍會導致啟動失敗，錯誤為 `EADDRNOTAVAIL`。

連結型別決定程式族：

| 連結型別（`ifi_type`） | 訊框格式 |
| --- | --- |
| 乙太網路：eth、bond/team（其第一個連接埠為乙太網路時）、bridge、vlan、macvlan/macvtap、ipvlan、veth、netkit、vxlan、geneve、gretap、tap、dummy、macsec | `_l2` |
| `ARPHRD_NONE`（wireguard、tun、`collect_md` GRE、無 MAC 模式的 geneve/VXLAN-GPE）、PPP、RAWIP、IPIP、IP6TNL、SIT | `_l3` |
| GRE / IP6GRE | 僅當置位 `IFF_POINTOPOINT` 且未置位 `IFF_BROADCAST` 時為 `_l3`；否則拒絕 |
| `lo`、`vcan`、InfiniBand、802.15.4、nlmon 及其他所有型別 | 拒絕 |

這張表描述的是分類器，不是經過驗證的裝置支援矩陣。IPv4 GRE 和 `collect_md` GRE 的核心測試只檢查旗標與 TCX hook，不驗證隧道負載轉發。本次變更沒有驗證真實的 IP6GRE、IPIP、SIT、IP6TNL、PPP、RAWIP、tun 和 wireguard 裝置。GRE 以及這些 L3/NONE 程式族也都缺少端對端流量覆蓋。

如果核心回報網路 header 位於訊框起點後 14 位元組，且第 12–13 位元組與封包協定一致，`_l3` 程式就會按乙太網路 header 解析，而不是按裸 IP 解析。先設成乙太網路、再改為 RAWIP 的裝置就會這樣。線性頭超過 65550 位元組的訊框仍按裸 IP 解析。L3 bond 上經 AF_PACKET raw socket 發出的裸 IP，如果來源位址位元組恰好等於 EtherType，會被誤當作乙太網路解析；這類傳送方需要 `CAP_NET_RAW`，而該權限本身就能設定 honk 的 bypass mark。核心測試涵蓋了改型別為 RAWIP 的 TAP，不包括真實的行動網路模組。

IP6GRE 如果只有單播 remote、沒有明確的 local 位址，可能不帶 `IFF_POINTOPOINT`；即使它的封包本來可以按裸 IP 處理，也會被拒絕。既有 IP6GRE 不支援用 `ip link change` 原地修改：核心可能改掉點對點旗標，卻不清理 `header_ops`，於是隧道 header 仍在時，分類器會選擇 `_l3`。請刪除並重建裝置，不要原地修改。IP6GRE 的建立和流量都還沒有驗證。

被拒絕的項目不會繫結任何 hook，並會按每個 episode 記錄一次錯誤日誌，寫明網卡和原因。原因包括：連結型別不受支援；不支援的 bond/bridge 巢狀，或自身即是 master；`vrf` 裝置，此時應設定它的成員，VRF 成員會繫結自身；`dae0` 或 `dae0peer`。降級會以原因 `unsupported_type` 報告。即使被拒絕的是第一個已解析的 LAN 或 WAN 項目，也不會導致啟動失敗，或阻止其他項目繫結。型別不受支援的 bridge 連接埠會被默默跳過。bond 或 team master 的型別取自它目前的第一個連接埠，因此 InfiniBand bond 會被拒絕。L3S 模式的 ipvlan 和 `reorder_hdr off` 的 VLAN 裝置屬於不受支援的組合。

`IfaceWatcher` 訂閱連結、位址和 IPv4/IPv6 路由事件，每 60 秒協調一次。如果無法訂閱或無法註冊輪詢，它仍每 60 秒協調一次，但沒有事件通知，並報告 `iface_watch` 降級。它會隨網卡和預設路由的變化建立、更新或釋放所需的 LAN/WAN hook。拓撲變化仍用於 ECS 重新整理，並立即喚醒受健康狀態控制的出站探測；不過 honk 不再生成閘道器位址的 `direct(must)` 規則，也沒有隱藏的核心位址白名單。網卡列表設定本身的變更仍需重啟；閘道器管理存取請用[明確使用者路由](./routing.md#顯式本地路由)。啟動順序和會導致啟動失敗的條件見[介面協調](../design/datapath.md#介面協調)。

真實 LAN 繫結還會執行提示性的[自保覆蓋檢查](./routing.md#顯式本地路由)。無法確認時只會記錄 warning，不拒絕啟動或 reload，也不插入路由規則。

## 撥號模式

| 模式 | 嗅探 | 網域驗證 | 路由與撥號行為 |
| ---- | ---- | -------- | -------------- |
| `ip` | 否 | 不適用 | 保留原始目的 IP；不嗅探，也不重新執行路由。 |
| `domain` | 是 | 嗅探到的名稱必須通過與目的 IP 的 reality check。 | 驗證通過後可按網域重新執行路由；沒有網域規則命中時，仍由一般 IP/連接埠規則決定。代理出站可按已驗證的網域撥號。 |
| `domain+` | 是 | 否 | 保留初始 IP 規則決策，但允許代理出站使用嗅探到的網域作為目標。 |
| `domain++` | 是 | 否 | 根據嗅探到的 SNI/Host 重新計算非保留決策，再使用所得的代理網域目標。 |

直連、阻擋、`must` 及其他保留 handoff 保持最終決策，並保留原始 IP 目標。

## 資料目錄與資源路徑

`data_dir` 預設為 `/var/lib/honk`，必須是非空絕對路徑，並在程序內只設定一次。啟動時 honk 會遞迴建立目錄，再用一個私有隨機檔案做 create-new/remove 探測。候選目錄不可用時，只有通過同一探測的程序工作目錄能作為備援；兩者都不可用時，啟動失敗並報告兩項原因。使用 `--store db` 或啟用原生 API 密碼登入時，啟動過程不允許這種備援。舊根目錄是 `/var/share/honk`，也稱 `LEGACY_DATA_DIR`，用於讓既有資源繼續可用。舊快取和訂閱匯入會把符合條件的狀態複製到 `state/honk.db`。即使使用自訂的 `data_dir`，也遵循相同的備援順序。絕對的子路徑保持原樣。

`geoip.dat` 和 `geosite.dat` 嚴格使用以下順序中第一個已存在的普通檔案：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`，也就是 `LEGACY_DATA_DIR`
4. 程序工作目錄中的 `./<name>`
5. `/usr/local/share/honk/<name>`，然後 `/usr/share/honk/<name>`
6. `/usr/local/share/dae/<name>`、`/usr/share/dae/<name>`，然後 `/etc/dae/<name>`

其他相對執行期路徑會按下表保留舊安裝。除日誌外，每次查詢會先檢查實際生效資料目錄中已有的副本，再檢查 `/var/share/honk` 中已有的副本，最後檢查各呼叫端既有的舊候選路徑。都不存在時，傳回 `data_dir` 下的路徑供建立使用；絕對路徑保持原樣。

| 路徑 | 解析與舊路徑退回 |
| ---- | ---------------- |
| 節點 `ech_config_path` | 依序優先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目錄相對路徑。都不存在時解析為 `<data_dir>/<path>`，讓讀取錯誤指出預期位置。 |
| `global.log_file` | 相對路徑一律透過只供建立使用的路徑 helper 解析為 `<data_dir>/<path>`，啟動時建立父目錄；它不會讀取或遷移 `/var/share/honk` 裡已有的日誌。絕對路徑保持原樣。在 Linux 上，新日誌檔案使用 mode `0600`；符號連結和非普通檔案會被拒絕，既有普通檔案的權限保持不變。honk 以附加方式寫入，檔案達到 10 MiB 時輪轉：目前檔案改名為 `<name>.1`，覆蓋舊副本，然後按相同檢查開啟新檔案，因此日誌最多佔用 20 MiB。重啟交接期間兩個執行個體共用該檔案時，只有檔案仍在原路徑上的執行個體會執行改名，另一個執行個體直接切換到新檔案，所以不會互相覆蓋輪轉副本。輪轉失敗時，例如新檔案打不開，honk 不再嘗試輪轉，繼續寫目前檔案直到 20 MiB，之後丟棄日誌行，並在 stderr 輸出一次 warning，直到重啟。主控台和檔案裡的時間戳記都是主機的本地時間，帶 UTC 偏移，例如 `2026-09-12T02:30:15.123456+10:00`。 |
| `experimental.cache_file.path` | 不再決定儲存位置，狀態儲存在 `<data_dir>/state/honk.db`。首次啟動時會依原有的解析順序讀取一次，用於匯入舊的 `cache.db`。見[升級說明](./experimental.md#從-cachedb-升級)。 |
| `experimental.clash_api.external_ui` | 依序優先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目錄相對目錄。都不存在時，dashboard 下載會使用 `<data_dir>/<path>`。 |
| 訂閱儲存 | 正文儲存在 `<data_dir>/state/honk.db` 中。每次啟動時，honk 會依序在 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub` 中尋找第一個私有的舊儲存，匯入已啟用訂閱的正文，然後刪除已複製的檔案。見[訂閱參考](./subscription.md#抓取持久化與恢復)。 |

## 預熱與撥號預算

`preconnect_node_count`、`udp_warm_node_count` 和 `max_concurrent_dials` 取非負整數，例如 `4`；`preconnect_node_count` 還接受不區分大小寫的 `auto`。其他值會以 `invalid-config-value` 拒絕設定。這三個欄位與代理群組的互動見[群組設計](../design/groups.md)。

## 相關文件

- [設定指南](../configuration.md)
- [節點參考](./nodes.md)
- [群組參考](./groups.md)
- [群組設計](../design/groups.md)
