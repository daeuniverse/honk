# 命令列參考

`honk-core` 提供引擎命令列介面，`honk-tool` 提供診斷工具。

## `honk-core`

`honk-core` 載入設定、初始化控制面，然後選擇真實 eBPF 後端或 mock 後端。

### 呼叫格式

```text
honk-core [OPTIONS] [COMMAND]
```

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `-c`, `--config PATH` | 省略，`/etc/honk/config.dae` | 設定入口檔案。見 [`--config`](#--config)。 |
| `--log-file PATH` | 省略，未設定 | 覆寫本次引擎程序的 `global.log_file`。見 [`--log-file`](#--log-file)。 |
| `-b`, `--bpf-object PATH` | 省略，內嵌物件檔 | 替換 `ebpf` 建置內嵌的物件檔；只有真實後端讀取它。 |
| `--bpf-pin-root PATH` | 省略，`/sys/fs/bpf` | eBPF map 的 pin 根目錄，傳給真實後端。 |
| `--disable-timestamp` | 省略，關 | 主控台日誌行不再帶時間戳記。見 [`--disable-timestamp`](#--disable-timestamp)。 |
| `-d`, `--debug` | 省略，關 | `RUST_LOG` 沒提供有效過濾器時，用 `debug` 作預設主控台過濾器。 |
| `--mock-ebpf` | 省略，關 | 用 `MockEbpfBackend`，不載入核心 eBPF。見 [`--mock-ebpf`](#--mock-ebpf)。 |
| `--store file\|db` | 省略，`file` | 從 `<data-dir>/state/honk.db` 裡的修訂版本載入設定。見 [`--store`](#--store)。 |
| `--data-dir PATH` | 省略，`/var/lib/honk` | 資料目錄，狀態資料庫在它下面的 `state/honk.db`。見 [`--data-dir`](#--data-dir)。 |

兩個二進位檔都提供 `-h`/`--help` 和 `-v`/`--version`。

### --config

```text
honk-core --config /etc/honk/config.dae
```

設定入口檔案。

用 `--store db` 時，只在資料庫為空或由 API 匯入設定時讀取。檔案模式下，`mode`、`proxy` 和 `delay` 也讀這個路徑。

`reload` 忽略此項，只向執行中的執行個體送出訊號；執行中的執行個體按啟動時用的路徑執行 reload。

### --log-file

```text
honk-core --log-file honk.log
```

只覆寫本次引擎程序的 `global.log_file`，不改設定檔。相對路徑在 `global.data_dir` 下解析。

主控台日誌照常啟用。

設定之後，SIGHUP 會忽略被覆寫的設定值變更，除非實際生效的目標改變。

### --disable-timestamp

```text
honk-core --disable-timestamp
```

主控台日誌行不再帶時間戳記。systemd 這類自帶時間戳記的日誌系統適用。

`--log-file` 或 `global.log_file` 指定的檔案仍然帶時間戳記。

### --mock-ebpf

```text
honk-core --mock-ebpf
```

使用 `MockEbpfBackend`，不載入核心 eBPF。

設定要求 `global.nfqueue_enable: true` 時，honk 會記一條 warning，然後只在本程序關閉 NFQUEUE 暫存。

### --store

```text
honk-core --store db --data-dir /var/lib/honk
```

`db` 從 `<data-dir>/state/honk.db` 裡的修訂版本載入設定，資料庫為空時匯入 `-c`。建置時需要包含 `native-api`。見[設定資料庫](./api.md#設定資料庫--store-db)。

### --data-dir

```text
honk-core --store db --data-dir /var/lib/honk
```

資料目錄，狀態資料庫在它下面的 `state/honk.db`。`--store db`、`config export` 和 `admin reset` 會用到。

用 `--store db` 時必須和 `global.data_dir` 相同；檔案模式啟動忽略此選項。

### 日誌等級優先順序

有效的 `RUST_LOG` 會優先於其他日誌等級設定。執行檔會先選出 debug 或設定中的預設值，再呼叫 `EnvFilter::try_from_default_env()`。

原始碼註解所寫的預期順序是 `--debug` → `RUST_LOG` → `global.log_level` → `info`；目前的優先順序是：

| 目前優先順序 | 來源 | 行為 |
| --- | --- | --- |
| 1 | `RUST_LOG` | 有效的 tracing 過濾條件會蓋過所有預設值，包括 `--debug`。 |
| 2 | `--debug` | `RUST_LOG` 不存在或無效時使用 `debug`。 |
| 3 | `global.log_level` | 未指定 `--debug` 且沒有有效 `RUST_LOG` 時使用。 |
| 4 | `info` | `global.log_level` 為空時使用。 |

`log_level` 見[全域設定參考](./global.md)。

各等級的含義固定，因此預設的 `info` 保持低頻：

| 等級 | 含義 |
| --- | --- |
| `error` | 設定要求的功能在人工介入前無法恢復：啟用已提交但 degraded、程序停止、子系統永久停止，或內部不變量被破壞。 |
| `warn` | 降級但仍在執行。honk 會在進入這種狀態時記錄一次：改走備援路徑、資源達到上限、節點或代理群組不可用、新設定被拒而舊設定繼續運作。每次 DNS 查詢都會重複發生的失敗，例如 SERVFAIL 和 singleflight 飽和，最多每 10 秒記一次 warning。 |
| `info` | 啟動、停止、啟用、維運操作，以及從 warning 狀態恢復。 |
| `debug` | 單一連線、請求和 DNS 查詢的結果，包括單次撥號和轉發失敗，以及週期性維護結果。原生流也記錄同樣的逐流結果。 |

### 子命令

| Key | 含義 |
| --- | --- |
| `reload` | 向持有引擎鎖的程序送出 `SIGHUP`。見 [`reload`](#reload)。 |
| `mode` | 把引數字串寫進結構化格式檔案的 `experimental.clash_api.default_mode`。見 [`mode`](#mode)。 |
| `proxy` | 列印按請求做出的群組和節點選擇。見 [`proxy`](#proxy)。 |
| `config export` | 把設定資料庫目前的修訂版本寫成一份 `.dae` 檔案。見 [`config export`](#config-export)。 |
| `admin reset` | 從狀態資料庫刪除密碼模式管理員。見 [`admin reset`](#admin-reset)。 |
| `delay` | 測量到節點的直連 TCP 耗時。見 [`delay`](#delay)。 |

用 `--store db` 時，`proxy` 和 `delay` 讀目前修訂版本，建置時需要包含 `native-api`；`mode` 會拒絕執行。

#### reload

```text
honk-core reload
```

從已加鎖的 `/run/honk-core.lock` 讀取 PID，送出 `SIGHUP`。

只報告訊號已成功送達；執行中的程序隨後記錄 `applied` 或 `rejected`。mock 執行個體不持有這把鎖。

真實資料面程序在整個生命週期裡持有這把鎖，`reload` 會先確認檔案仍被鎖定，再信任裡面的 PID。`kill(2)` 成功送達，並不表示候選設定通過了驗證，也不表示需重啟欄位檢查過。

#### mode

```text
honk-core mode <rule|global|direct>
```

載入 `--config`，把引數字串寫進 `experimental.clash_api.default_mode`，並在重寫結構化格式檔案之前完成驗證。

`.dae` 檔案會被拒絕並保持原樣，因為 writer 保留不了 dae 語法、註解和 include；這類原始檔請直接編輯，或者改用 `.toml`、`.yaml`、`.json`。

該命令只改檔案，不聯絡執行中的引擎，也不改 dial mode。它接受的字串和正常的 dial mode 值 `ip`、`domain`、`domain+`、`domain++` 不同。

#### proxy

```text
honk-core proxy <group> <node>
```

檢查群組名稱和節點名稱都存在，然後列印按請求做出的選擇；不檢查節點是否屬於該群組。

不寫任何內容，也不聯絡執行中的引擎。

#### config export

```text
honk-core config export --out PATH [--without-secrets]
```

建置時需要包含 `native-api`。把設定資料庫目前的修訂版本寫成一份 `.dae` 檔案；沒給 `--without-secrets` 時，把 listener secret 補回去。

不論常駐程式是否正在執行，都會透過一個以讀寫方式開啟的 query-only 連線讀取資料庫。關閉這個連線不會執行檢查點，也不會刪除 `honk.db-wal`；除了 SQLite 可能建立的 `-shm` 索引，唯一可能的寫入是回滾崩潰遺留的日誌。

檔案寫完後才會發布。以 0600 權限新建 `PATH`，已存在的檔案會被拒絕。

#### admin reset

```text
honk-core admin reset
```

從 `--data-dir` 下的狀態資料庫刪除密碼模式管理員，下次啟動時重新開放 setup。

任何 honk-core 開啟該狀態資料庫時都會拒絕執行，mock 模式也一樣。

#### delay

```text
honk-core delay <node> [-u|--url HOST:PORT]
```

解析位址後直連 TCP，列印耗時毫秒數，含解析時間。沒給 `--url` 時用節點伺服器位址。

解析出的多個位址會並行競速，同時最多兩個，間隔 250 ms，每次嘗試的逾時為五秒。

這條路徑不經過代理，不是 HTTP URLTest，也不聯絡執行中的引擎。

### 重啟要求

[編譯路由發布計數器](../design/routing.md#同步槽與原子發布)用盡後需要重啟；它和一般 SIGHUP 及 DNS 執行期的 reload 分開計數。

## 環境變數

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `RUST_LOG` | 省略，`honk-tool` 用 `warn` | 兩個二進位檔的 tracing 過濾條件。見[日誌等級優先順序](#日誌等級優先順序)。 |
| `NO_COLOR` | 省略，未設定 | `honk-core` 主控台：非空值關閉 ANSI 顏色。否則只在 stdout 是終端機時啟用顏色。 |
| `HONK_UI_DOWNLOAD_URL` | 省略，未設定 | 優先順序最高的 dashboard ZIP URL，覆寫 `assets.ui.url`。見 [`HONK_UI_DOWNLOAD_URL`](#honk_ui_download_url)。 |
| `HONK_POOL_DISABLE` | 省略，未設定 | 繞過 Ready 流和裸 TCP 兩類池。見 [`HONK_POOL_DISABLE`](#honk_pool_disable)。 |
| `HONK_QUIC_GSO` | 省略，未設定 | 強制開啟或關閉 QUIC 出站的 UDP GSO。見 [`HONK_QUIC_GSO`](#honk_quic_gso)。 |
| `HONK_QUIC_BBR` | 省略，`v3` | 選擇 `congestion_control: bbr` 背後的 BBR 實作。見 [`HONK_QUIC_BBR`](#honk_quic_bbr)。 |
| `TOKIO_WORKER_THREADS` | 省略，核心數 | `honk-core` 的 Tokio worker 數量。見 [`TOKIO_WORKER_THREADS`](#tokio_worker_threads)。 |
| `HONK_VMLINUX_BTF` | 省略，`/sys/kernel/btf/vmlinux`，其次 `/usr/lib/debug/boot/vmlinux` | 覆寫程序名路由和原生 UDP 接收追蹤共用的原始核心 BTF。見 [`HONK_VMLINUX_BTF`](#honk_vmlinux_btf)。 |
| `DAE_LOCATION_ASSET` | 省略，未設定 | `honk-core` 和 `honk-tool` 最先檢查其中 `geoip.dat` 和 `geosite.dat` 的目錄。 |

### HONK_UI_DOWNLOAD_URL

```text
HONK_UI_DOWNLOAD_URL=https://example.org/dashboard.zip honk-core
```

`honk-core` 啟用 `clash-api` 時，這個變數給出優先順序最高的 dashboard ZIP URL。設定的外部 UI 目錄需要下載時，它會覆寫 `assets.ui.url`。

### HONK_POOL_DISABLE

```text
HONK_POOL_DISABLE=1 honk-core
```

繞過 Ready 流和裸 TCP 兩類池，每次都重新撥號。

該值第一次使用後快取。`1` 和不區分大小寫的 `true` 都表示啟用。

### HONK_QUIC_GSO

```text
HONK_QUIC_GSO=1 honk-core
```

`1` 或不區分大小寫的 `true` 強制開啟 UDP GSO；其他任何值都強制關閉，空值也一樣。該值第一次使用後快取。

未覆寫時，GSO 在保守的 1252 位元組 MTU 下保持關閉。明確設定更大的 `mtu` 時，honk 會自動開啟 GSO，並把批次限制在最多 16 個 segment。

### HONK_QUIC_BBR

```text
HONK_QUIC_BBR=v1 honk-core
```

選擇 `bbr` 擁塞控制背後的實作，適用於 TUIC 的 `congestion_control: bbr`、Juicity，以及沒有設定上傳速率的 Hysteria2。

`v3` 是 BBRv3。`v1` 是 quinn 原有的 BBR，不會對封包遺失做出反應；在高頻寬延遲乘積路徑上，quinn-proto 0.11.16 及以上的接收端可能以 `too many gaps in stream buffer` 中止它的上傳。

預設 `v3`；其他值會觸發 warning，並保持預設。

### TOKIO_WORKER_THREADS

```text
TOKIO_WORKER_THREADS=4 honk-core
```

Tokio 的 worker 數量。`honk-core` 使用預設的多執行緒執行期，預設數量等於核心數。

值必須是正整數：`0` 或非數字會讓 Tokio 在啟動時 panic。

每個 worker 持有獨立的分配器堆，在多核閘道器上把值調小可以降低 RSS。實驗室測量用 4 核主機、120 條連線和 DNS：16 個 worker 約 85 MiB，8 個約 66 MiB，4 個約 60 MiB。CPU 差異在雜訊範圍內。

中繼路徑執行在這些 worker 上，應按流量設定。

### HONK_VMLINUX_BTF

```text
HONK_VMLINUX_BTF=/path/to/vmlinux.btf honk-core
```

覆寫程序名路由和原生 UDP 接收追蹤共用的原始核心 BTF。檔案必須匹配執行中的核心。

明確指定的檔案不可讀或無效時，honk 會拒絕啟動真實後端，不會自行改用其他檔案。TCP 歸屬證明不讀取核心結構，也不依賴它。

### UDP NFQUEUE

UDP NFQUEUE 沒有環境變數開關，由 `global.nfqueue_enable` 控制，預設開啟；設為 `false` 即可關閉。見[全域設定參考](./global.md)和 [NFQUEUE 設計](../design/nfqueue.md)。

## eBPF 與執行期路徑

| Key | 含義 |
| --- | --- |
| eBPF 物件檔 | 真實後端載入的物件檔。見 [eBPF 物件檔](#ebpf-物件檔)。 |
| 核心 BTF | 路由和接收追蹤使用的核心型別資訊。見 [核心 BTF](#核心-btf)。 |
| Bypass mark | 撥號、探測、DNS 和下載使用的精確 socket mark。見 [Bypass mark](#bypass-mark)。 |
| TPROXY mark | `TPROXY_MARK = 0x08000000`；`global.tproxy_mark` 必須等於該值。 |
| Geo 資源 | `geoip.dat` 和 `geosite.dat` 的搜尋順序。見 [Geo 資源](#geo-資源)。 |

### eBPF 物件檔

啟用 `ebpf` feature 時，`build.rs` 透過 `include_bytes!` 內嵌物件檔。`--bpf-object` 會在執行期替換這些位元組。

honk 在 probe/loading 之前就拒絕物件宣告的 `ByName` pinning：要用未 pin 的 map 重新建置，把 pin 路徑交給 core 管理。沒有啟用 `ebpf` 的建置使用 mock 後端。

### 核心 BTF

未覆寫時，honk 讀 `/sys/kernel/btf/vmlinux`；不可讀時再讀 `/usr/lib/debug/boot/vmlinux`，也就是 OpenWrt 的 `vmlinux-btf` 套件。只接受原始 BTF；如果只有 ELF 格式的 debug vmlinux，先擷取它的 `.BTF` 段，再用該變數指向擷取結果。

選定的 BTF 統一提供核心欄位偏移、Aya loader 的目標 BTF 和接收追蹤的函式簽章。BTF 缺失或無效時，honk 拒絕啟動。核心 argv 擷取不可用時，仍可退回執行緒的 `comm`。

原生 UDP 接收追蹤還需要核心自帶的 BTF 和 ftrace，缺了就降級執行；外部檔案替代不了它們。

### Bypass mark

`global.so_mark_from_dae` 設定撥號、探測、DNS 和下載使用的精確 socket mark。零值表示用預設的 `0x100`。

修改需要重啟，見 [socket mark](./global.md#socket-mark)。

### Geo 資源

honk 依序檢查 `DAE_LOCATION_ASSET`、`global.data_dir`、舊根目錄 `/var/share/honk`、工作目錄、`/usr/local/share/honk`、`/usr/share/honk`、`/usr/local/share/dae`、`/usr/share/dae`、`/etc/dae`；每個候選都必須是普通檔案。

見[全域設定參考](./global.md)。

## `honk-tool`

`honk-tool` 負責訂閱探測、已固定 map 檢查、引擎健康檢查和離線 Geo 資源搜尋，不載入也不掛接 eBPF 程式。

### 建置與部署

一般開發建置：

```bash
cargo build --release -p honk-tool
```

部署到閘道器時，使用倉庫的 Zig 包裝器建置靜態 musl 目標，再複製單一二進位檔：

```bash
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl=$PWD/ci/zigcc \
CXX_x86_64_unknown_linux_musl=$PWD/ci/zigcxx \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$PWD/ci/zigcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$(ci/zig-bindgen-env x86_64-linux-musl)" \
cargo build --release -p honk-tool --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/honk-tool root@GATEWAY:/tmp/
```

目前的 `just build-musl` 和 `just deploy-vyos` 只建置和部署 `honk-core`，不含 `honk-tool`。以 GNU 連結器建置的二進位檔，可能無法在純 musl 閘道器上執行。

### 命令族

| Key | 含義 |
| --- | --- |
| `sub` | 拉取或解析節點，並探測 TCP 位址族、URLTest 和受支援的 UDP 路徑。 |
| `bpf` | 讀取並解碼執行中引擎已經 pin 的 map。 |
| `diagnose` | 執行唯讀的引擎、網路設施、map 和 API 健康檢查。 |
| `geosite` | 列出、檢查和反向搜尋 `geosite.dat`。 |
| `geoip` | 列出、檢查和最長字首搜尋 `geoip.dat`。 |

二進位檔提供 `-h`/`--help` 和 `-v`/`--version`。每個命令族和操作也都有說明資訊。

### `sub`

```text
honk-tool sub <url|file|-> [--target HOST:PORT] [--url TEST_URL]
              [--udp-check HOST[:PORT]]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--tls-implementation tls|utls] [--utls-imitate PROFILE]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `<url\|file\|->` | 必填 | HTTP(S) 訂閱 URL、既有的本機訂閱檔案，或 `-`。`-` 從 stdin 讀取恰好一個 HTTP(S) 訂閱 URL，不會讀取訂閱正文。 |
| `--target HOST:PORT` | 省略，`cp.cloudflare.com:443` | 探測目標的主機和連接埠。見 [`--target`](#--target)。 |
| `--udp-check HOST[:PORT]` | 省略，`dns.google:53`、`8.8.8.8`、`2001:4860:4860::8888` | UDP DNS 檢查目標。見 [`--udp-check`](#--udp-check)。 |
| `--url TEST_URL` | 省略，`https://www.gstatic.com/generate_204` | 經代理的 URLTest 目標。 |
| `--timeout SECS` | 省略，`5` | 每項探測的逾時。`0` 表示零逾時，不表示不限時。 |
| `--concurrency N` | 省略，`10` | 並行節點探測任務的上限。`0` 不執行任何探測，只輸出空摘要，不表示不限並行數。 |
| `--limit N` | 省略，`0` | 僅探測前 `N` 個節點；`0` 表示全部。 |
| `--ua UA` | 省略，未設定 | 遠端訂閱拉取使用的 `User-Agent`。 |
| `--tls-implementation tls\|utls` | 省略，`tls` | 探測使用的程序級 TLS ClientHello 實作。 |
| `--utls-imitate PROFILE` | 省略，`chrome_auto` | `utls` 使用的指紋設定方案；目前的驗證器只接受以 `chrome` 開頭的名稱。 |
| `--v4-target IP:PORT` | 省略，`1.1.1.1:443` | v4 探測連線的數字 IPv4 位址，不檢查位址族。 |
| `--v6-target [IP]:PORT` | 省略，`[2606:4700:4700::1111]:443` | v6 探測連線的數字 IPv6 位址，不檢查位址族。 |

#### --target

```text
honk-tool sub nodes.txt --target one.one.one.one:443 \
  --v4-target 1.0.0.1:443 --v6-target '[2606:4700:4700::1001]:443'
```

其中的主機用於位址族探測的 HTTPS 請求 URL、TLS SNI 和 Host header。主機和連接埠用於 QUIC 探測。

位址族探測仍然連線 `--v4-target` 和 `--v6-target`，所以改目標時這兩項也要改。UDP DNS 探測目標由 `--udp-check` 單獨指定。

#### --udp-check

```text
honk-tool sub nodes.txt --udp-check 'dns.google:53,8.8.8.8'
```

UDP DNS 檢查目標，預設取自 `honk-config` 裡的引擎列表。可以重複指定，也可以用逗號分隔。

`honk-tool` 使用列表中第一個 IP 或 socket 位址常值。沒有常值時，它會解析第一項，且只用於支援 UDP DNS 探測的節點。省略連接埠時用 `53`。

#### 訂閱源格式

遠端訂閱和本機檔案共用引擎的自動格式辨識：

- 編碼後的分享連結，或原始分享連結。
- Clash YAML/JSON、SIP008 和 sing-box JSON。
- 受支援的 Surge/Surfboard/Loon/Quantumult X 記錄。

`honk-tool` 跳過不支援的節點，不列印原始輸入。使用 `-` 可以避免把含憑證的 provider URL 放進 argv 和程序列表。

#### 退出狀態

訂閱載入成功後，即使探測全部失敗或節點全部被跳過，退出狀態仍是 `0`。探測任務崩潰時會列印 `probe task failed`，退出狀態同樣是 `0`。指令碼要靠摘要行判斷連通性。

#### 輸出

對每個節點，命令報告：

- 伺服器位址族。
- 完整的代理 IPv4/IPv6 交換。
- 經代理的 URLTest 延遲。
- 經封包 handler 的 DNS 查詢。
- 經該 handler 的真實 QUIC 握手。

VLESS 行使用下面的去識別化格式，不含 endpoint、UUID、REALITY key、SNI 或 URL 查詢參數：

```text
vless/{plain|tls|reality}/{tcp|ws|grpc|xhttp}[/vision]/tcp={plain|h2mux|mux-cool}/{udp-fallback=auto|native|xudp|uot-v2|udp=disabled}[/padding=true|false][/mux=TCP:UDP:POLICY]
```

| VLESS 輸出欄位 | 含義 |
| --- | --- |
| `tcp=` | 有效 TCP 路徑。 |
| `udp-fallback=` | 正規化後的退回值，即使 H2MUX 或 Xray 多工已經接管目標 UDP 路徑。 |
| `udp=disabled` | 禁止封包撥號。 |
| `padding=` | 僅在 H2MUX 中出現。 |
| Xray 多工 `TCP` | 每條 TCP carrier 的有效邏輯 child 並行數；`0` 表示關閉。 |
| Xray 多工 `UDP` | `protocol`、`shared`，或獨立 UDP 池中每條 carrier 的邏輯 child 並行數。 |
| Xray 多工 `POLICY` | UDP/443 策略：`reject`、`skip` 或 `allow`。 |

輸出格式範例：

- `vless/tls/tcp/tcp=plain/udp-fallback=native`
- `vless/reality/grpc/tcp=h2mux/udp-fallback=auto/padding=true`
- `vless/tls/tcp/vision/tcp=plain/udp-fallback=auto/mux=0:8:allow`

`xhttp` 表示 H2 XHTTP 傳輸；這一行不暴露 path、HTTP host、自訂 header 或填充內容。模式和受支援的參數見[節點參考](./nodes.md#h2-上的-xhttp)。

#### 探測資格

| 探測資格狀態碼 | 網路操作 |
| --- | --- |
| `supported` | 可執行探測。 |
| `invalid-uuid`、`invalid-reality`、`invalid-config` | 條目仍然顯示，但不執行網路操作。 |
| `unsupported-transport`、`unsupported-flow`、`vision-without-tls`、`vision-non-tcp` | 條目仍然顯示，但不執行網路操作。 |

Vision 的 TCP 路徑要求符合條件的直接 carrier；只有 UDP 的 Xray 多工仍然有效。VLESS Encryption 可以和 Vision 組合。未加密的 Vision 還要求裸 TCP 使用 TLS 1.3 或 REALITY。

`n/a` 表示探測不適用，例如封包撥號已關閉，或者 UDP/443 策略拒絕該目標。本機 carrier 容量拒絕發生在嘗試之後，屬於 terminal failure，會顯示成 `FAIL(...)` 而不是 `n/a`，也不影響遠端 endpoint 的健康狀態。

共用的全域檔案描述元預算能容納的實體 VLESS carrier，可能少於各節點 mux 上限之和。

#### 時限

UDP DNS 的目標解析、封包傳輸建立、傳送和接收共用同一個 `--timeout` 預算。解析失敗或逾時只會反映在 DNS 欄，TCP、URLTest 和 QUIC 探測照常繼續。不支援 UDP 的節點會跳過這項解析；主機名稱解析失敗時，也不會改用另一個目標。

| 探測欄 | 時限 |
| --- | --- |
| 每個非 QUIC 欄 | 各自以 `--timeout` 加一秒為上限。 |
| QUIC | 額外留兩秒等清理完成。清理耗時不計入延遲樣本。 |

URLTest 和位址族探測的撥號、目標 TLS、每次交換各有獨立的 `--timeout`。所以較慢的冷啟動 carrier 建立時，可能達到欄時限。這一欄會報告 `timeout`；UDP 策略拒絕目標時報告 `n/a`。其他欄保留各自的結果。

#### DNS 目標解析

UDP DNS 的主機名稱目標使用共用的非同步解析器，不做阻塞的 NSS 查詢。它會讀 `/etc/resolv.conf` 裡第一個數字形式的 nameserver，UDP 連接埠 `53`，`/etc/hosts` 存在時也載入它。這條路徑不用 NSS 外掛，也不用解析器搜尋字尾。

解析器不可用時，DNS 欄會報告 `resolve`，不會退回公用解析器；常值目標不需要解析器。

#### 重複使用與身分

VLESS carrier 和 session 會依執行期與正規化後的線路協定形態重複使用。因此改動標準的 UDP/多工查詢參數，可能改變節點身分和連線池的重複使用。

共用的實體 carrier 容量屬於全域。XUDP 的 8 位元組 Global ID 會依 honk 的執行期、客戶端、路徑和目的地來源身分劃定作用域，不是程序層級、無碰撞的 NAT key。

見[節點參考](./nodes.md#vless-udp-and-multiplexing)和標準的 [VLESS 出站設計](../design/outbound.md#sourcesession-ownership-and-capacity)。

#### 失敗碼

探測失敗碼有 `resolve`、`timeout`、`exchange`、`handler` 和 `admission`。

探測結果行絕不輸出憑證、endpoint 詳細資訊、SNI、REALITY key、URL 查詢參數資料和原始錯誤。唯一的例外在 stderr：探測執行期清理失敗時會列印 `probe runtime cleanup failed: <error>`，並附上原始錯誤。

### `bpf`

```text
honk-tool bpf show <conn-state|redirect-track|domain-routing|routing-handoff>
                   [--ip IP] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
```

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `show <map>` | 必填 | 解碼一個受支援的 pin map。 |
| `show --ip IP` | 省略，未設定 | 按來源或目的 IP 過濾 tuple map；對 `domain-routing` 按精確 IP key 過濾。 |
| `show --limit N` | 省略，`50` | 最多列印的條目數；`0` 表示全部。 |
| `show --pin-root PATH` | 省略，`/sys/fs/bpf` | 所選 map 的 pin 根目錄。 |
| `stats --pin-root PATH` | 省略，`/sys/fs/bpf` | 統計 map 的 pin 根目錄。 |

| Key | 解碼內容 |
| --- | --- |
| `conn-state` | Tuple、出站、mark、must 標記、狀態、最近出現的時間戳記和追蹤 ID。 |
| `redirect-track` | 回包改寫的來源/目的位址、出站、WAN 方向、介面和最近出現的時間戳記。 |
| `domain-routing` | 從 DNS 或嗅探結果學到的 IP，以及作用中 policy 的網域謂詞位元圖索引；已知但全零的條目仍會顯示。 |
| `routing-handoff` | Tuple、待處理的 eBPF 到控制面路由結果、最近出現的時間戳記、路由 generation 和追蹤 ID。 |

#### 快照讀取

`conn-state`、`redirect-track` 和 `routing-handoff` 透過帶 `BPF_F_LOCK` 的 `BPF_MAP_LOOKUP_BATCH` 讀取。核心不支援時會報錯 `safe external map snapshot requires BPF_MAP_LOOKUP_BATCH ...`，不會退回不加鎖的讀取。

命令透過原始 `bpf(2)` 讀取 pin，不載入程式，也不掛接 hook；通常需要 root 或合適的 BPF capability。

`routing-handoff` 在讀取前檢查 [handoff ABI](../design/datapath.md#map-清單)。工具、引擎和物件檔要一起升級。

#### 統計

`stats` 為下面這些計數器逐行輸出標準標籤和計數，還會列印 `CONN_STATE_OCCUPANCY` 插入/刪除水位計，以及非零的每個出站封包/位元組計數。

`BPF_STATS_MAP` 必須有九個槽。工具和引擎版本不匹配時，會以 `unexpected map layout for BPF_STATS_MAP: expected max_entries=9 found 7` 失敗，舊版工具則反過來，這樣就不會錯誤標註計數器。工具、引擎和物件檔要一起升級。

`stats` 要求 `/sys/devices/system/cpu/possible` 可讀，而且是核心實際匯出的檔案。每個 CPU 緩衝區依這個遮罩裡的 CPU 數量分配，不用 present 或 online 的 CPU 數量。

`CONN_STATE_OCCUPANCY` 和 `OUTBOUND_STATS` 必須是每 CPU 陣列，key 都是 4 位元組，值分別是 8 位元組和 32 位元組。CPU 列表不可讀、格式無效，或者 map 中繼資料不相容時，命令會在每 CPU 查詢之前就報錯，不會退回去猜 CPU 數量。

| Key | 標準標籤 | 計數物件 |
| --- | --- | --- |
| `0` | `udp_conn_overflow` | 沒有既有 tuple 時，UDP conn-state 插入失敗。 |
| `1` | `tcp_conn_overflow` | TCP conn-state 插入失敗。 |
| `2` | `redirect_track_insert_failure` | Redirect-track 發布失敗：map 插入失敗，或準備 scratch 不可用。 |
| `3` | `routing_handoff_insert_failure` | Routing-handoff 發布失敗：map 插入失敗，或準備 scratch 不可用。 |
| `4` | `socket_identity_capture_failure` | socket 程序身分擷取或儲存失敗。 |
| `5` | `tcp_child_proof_storage_failure` | 已接受 TCP child 的歸屬證明儲存失敗。 |
| `6` | `tcp_publisher_claim_failure` | TCP SYN 發布的排他宣告插入失敗，不含普通的同 tuple 衝突，也就是 `EEXIST`。 |
| `7` | `new_flow_rate_limited` | 因單一來源、每 CPU 的新流限制而被丟棄的 LAN 流嘗試。 |
| `8` | `udp_reverse_learning_suspended` | conn 壓力下，conn-state 查詢未命中後被跳過的反向 UDP 學習嘗試。 |

### `diagnose`

```text
honk-tool diagnose [--api URL] [--secret TOKEN] [--pin-root PATH] [--tproxy-mark VALUE]
```

| Key | 預設值 | 含義 |
| --- | --- | --- |
| `--api URL` | 省略，`http://127.0.0.1:9090` | Clash API 基礎 URL。見 [`--api`](#--api)。 |
| `--secret TOKEN` | 省略，設定了就用 `HONK_API_SECRET` | Clash API 的 Bearer token。命令列引數優先於環境變數。 |
| `--pin-root PATH` | 省略，`/sys/fs/bpf` | 檢查 pin map 是否存在、讀取統計時用的根目錄。 |
| `--tproxy-mark VALUE` | 省略，`134217728`（`0x08000000`） | `daens` 策略規則裡預期的 fwmark，以十進位 32 位整數給出，不接受十六進位。 |

#### --api

```text
honk-tool diagnose --api http://127.0.0.1:9090
```

明文 HTTP Clash API 基礎 URL。必須寫連接埠，例如 `http://panel.example:80`；不支援 HTTPS。

空值跳過 API 檢查。

API 檢查沒有逾時，對端沒有回應時會讓命令一直等待。需要的話用 `timeout(1)` 包一層，或者傳 `--api ''` 跳過。

#### 檢查項

`diagnose` 會呼叫 `ip`；執行不了 `ip` 就以非零狀態退出，後面的檢查不再執行，也不輸出摘要。

該命令為唯讀，檢查以下項目：

- 名為 `honk-core`、`honk` 或 `dae` 的引擎程序；
- `/var/run/netns/daens` 和 `/sys/class/net/dae0`；
- `daens` 內的 fwmark 規則；
- 必需的已固定 map，以及可讀取的佔用/溢位統計；
- `<api>/version` 的成功 HTTP 回應。

#### 結果

| 結果 | 輸出 |
| --- | --- |
| API 傳回 2xx | `[ok]`，後接回應正文。 |
| API 傳回非 2xx | `[FAIL]`，後接狀態文字。 |
| 全部檢查通過 | 標準輸出以 `diagnose: all checks passed` 結束，退出狀態為 `0`。 |
| 存在失敗檢查 | 標準輸出以 `diagnose: N issue(s) found` 結束，退出狀態為 `1`，錯誤資訊包含問題數量。 |

統計檢查和 `bpf stats` 對 possible CPU 檔案和 pin map 佈局的要求相同。準備失敗時，命令會列印 `[FAIL] map stats read`，計入問題數量，並以非零狀態退出。

### `geosite` 與 `geoip`

```text
honk-tool geosite [--file PATH] list [FILTER]
honk-tool geosite [--file PATH] show <category> [--attr ATTR]
honk-tool geosite [--file PATH] find <domain>
honk-tool geoip [--file PATH] list [FILTER]
honk-tool geoip [--file PATH] show <code>
honk-tool geoip [--file PATH] lookup <ip>
```

| Key | 行為 |
| --- | --- |
| `geosite list [FILTER]` | 列出類目 code 和條目數；過濾條件為選用，是不區分大小寫的子字串。 |
| `geosite show <category> [--attr ATTR]` | 列印一個類目的條目。`--attr` 按不區分大小寫匹配，保留含該屬性 key 的條目，和路由裡 `category@attr` 謂詞一致。 |
| `geosite find <domain>` | 按類目列印匹配該網域的 full、suffix、keyword 和 regex 條目。 |
| `geoip list [FILTER]` | 列出 code 和 CIDR 數；過濾條件為選用，是不區分大小寫的子字串。 |
| `geoip show <code>` | 列印一個 code 裡的全部 CIDR。 |
| `geoip lookup <ip>` | 傳回最長匹配字首上並列的全部 code/CIDR。 |
| `--file PATH` | 為對應 `.dat` 檔案提供命令族層級的覆寫路徑。 |

`show` 指定的類目或 code 不存在時，命令以非零狀態退出。`list`、`find` 或 `lookup` 沒有匹配時不輸出內容，退出狀態為 `0`。

未指定 `--file` 時，工具會依下列順序選出第一個既有的普通檔案：

1. `$DAE_LOCATION_ASSET/<name>.dat`
2. `/var/lib/honk/<name>.dat`
3. `/var/share/honk/<name>.dat`，舊根目錄
4. `./<name>.dat`
5. `/usr/local/share/honk/<name>.dat`
6. `/usr/share/honk/<name>.dat`
7. `/usr/local/share/dae/<name>.dat`
8. `/usr/share/dae/<name>.dat`
9. `/etc/dae/<name>.dat`

和 `honk-core` 不同，這個工具不載入設定，所以不知道自訂的 `global.data_dir`。每筆記錄輸出一行。下游管道關閉不會導致 panic。

| 命令 | 行格式 |
| --- | --- |
| `geosite list` | `CATEGORY ENTRY_COUNT` |
| `geosite show`、`geosite find` | `CATEGORY KIND VALUE [@ATTR ...]`，`KIND` 為 `domain`、`full`、`keyword` 或 `regexp` |
| `geoip list` | `CODE CIDR_COUNT` |
| `geoip show`、`geoip lookup` | `CODE CIDR` |

## 版本與相容性

CLI 和 Clash API 共用建置時決定的版本號。發布建置使用 GitHub 標籤名稱。本機 Git 建置使用 `git describe --tags --always --match 'v*'`，結果是標籤，或最近標籤加上提交距離和 hash。沒有可用的 Git 中繼資料時，使用 Cargo 套件版本。執行期不依賴 Git。

`honk-tool` 報告的建置版本和 `honk-core` 相同。honk-core、`honk-tool` 和 BPF 物件檔的版本要匹配；honk 會按[資料路徑 ABI 契約](../design/datapath.md#map-清單)拒絕不相容的物件檔和 pinned handoff 佈局。

## 相關文件

- [全域設定參考](./global.md)
- [Experimental 設定參考](./experimental.md)
- [Clash API 參考](./api.md)
