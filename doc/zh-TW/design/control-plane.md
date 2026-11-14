# 使用者態控制面

`honk-core` 使用者態引擎連接核心資料路徑與出站堆疊。

## 範圍

控制面負責透明代理入口、核心交接、使用者態路由、嗅探、出站選擇、中繼、資源 admission 和執行時發布。核心如何把流量交給使用者態，見[資料路徑設計](./datapath.md)。代理群組策略和健康狀態如何驅動選擇，見[代理群組設計](./groups.md)；DNS 執行時行為見 [DNS 設計](./dns.md)。

主要實作位於 `crates/honk-core/src/control/`。控制面讀取 `EbpfBackend` 狀態，並把 TCP 流或 `PacketTransport` UDP 契約交給 `honk-outbound`。

模組分工：

- `src/control/`：
    - `mod.rs` — `ControlPlane` 的[啟動與關閉](#啟動與關閉)。
    - `connection/` — 標準的[流初始化器](#嗅探與流初始化)。
    - `nfqueue/` — `PendingUdpVerdicts` correlator；[NFQUEUE 暫存協議](./nfqueue.md)。
    - `sockets.rs` — [透明代理入口](#透明代理入口)、anyfrom 回覆；`udp_ingress.rs` 負責 `udp_fast_path`。
    - `dns_control.rs` — `DnsController`；[查詢 admission 與投影](./dns.md#解析管線)。
    - `dns_listener.rs` — `DnsListener`；[獨立入口生命週期](./dns.md#入口路徑)。
    - `reload/` — `apply_runtime_config`；[執行時發布](#reload-與執行時-generation)。
    - `routing_matcher.rs` — [原子路由發布](./routing.md#同步槽與原子發布)與[核心規則 lowering](./routing.md#受限原生後端)。
    - `quic.rs`、`packet_sniffer.rs`、`tcp_sniff.rs` — 分別負責 QUIC 解密/重組、逐流嗅探 session 與 TCP 負快取。
    - `udp_endpoint/mod.rs` — `UdpEndpointPool`；[endpoint 事務](#udp-endpoint-管線)。
    - `probers.rs` — `ProxyUdpProber`；`probers/http.rs` — `ProxyHttpProber`；[健康探測](./groups.md#健康狀態與探測)。
    - `janitor.rs` — `BpfJanitor` 的排程與壓力策略；`janitor/sweep.rs` 持有 [map 維護](./datapath.md#使用者態維護與計數)的有界掃描與 fenced retirement；`janitor/health.rs` 持有 map 壓力與 BPF 失敗計數 warning。
    - `retirement_worker.rs` — joined TCP/UDP/hint 退役所有權；`drain.rs` 持有 `DrainTracker` 與[已接受流的排空](#reload-與執行時-generation)。

## 啟動與關閉

- `src/lib.rs` — `run()`、`Cli`/`ClashCommand`、資源限制、後端選擇，以及固定佇列的啟動前置檢查，見[設定指南](../configuration.md)。真實執行個體持有 `/run/honk-core.lock`，並把自己發布成 `reload` 用的 PID。`src/daens.rs` 負責 FD 持有的 `daens`/`dae0` 初始化和有作用域的命名空間切換；`src/sysctl.rs` 負責寫 sysctl 並驗證加固結果。載入或沿用持久化的 allocator pin，然後在資料路徑 admission 之前啟動 NFQUEUE。

honk 在初始化 tracing 之前就收集設定診斷。載入或設定驗證提前失敗時，先把已有的非終止診斷寫到標準錯誤，每條只輸出一次，然後由二進位程式傳回一次脫敏後的終止錯誤。載入成功時，診斷會等到設定指定的 tracing 訂閱器就緒後再輸出。之後執行時的致命錯誤仍按原有方式寫入日誌檔。

啟動時保持核心 admission 關閉，直到使用者態能夠接收每個重定向流：

1. 真實模式取得 `/run/honk-core.lock`，最多等待 240 秒讓前一個執行個體退出，並把程序 PID 發布到已鎖檔案；`honk-core reload` 讀取該 PID 並送出 `SIGHUP`。未取得鎖的後繼執行個體在讀取設定和開啟狀態資料庫之前退出。Mock 模式不取得程序全域鎖。
2. 載入並驗證設定、選擇 `global.data_dir`，在任何網路 I/O 前初始化程序 bypass mark，提升 `RLIMIT_NOFILE`，並取得一次不可變的描述符預算快照。
3. 在網路重新整理前恢復持久化訂閱。只有沒有有效已恢復內容的訂閱，才參與五秒首次拉取寬限期。
4. 真實執行個體完成鎖交接後，再探測固定 NFQUEUE 佇列的前置條件。mock 模式、不帶 `ebpf` 的模式，或前置檢查失敗時，記錄一則 warning，只在目前程序關閉 NFQUEUE；前置檢查不會拒絕保留的 nftables table，因為安裝階段會回收殘留的自有狀態。
5. 真實模式下，`src/daens.rs` 透過 rtnetlink 建立 FD 持有的 `daens` 命名空間和 `dae0`/`dae0peer` 鏈路。引擎優先嘗試 L2 netkit pair，只有核心回報不支援 netkit 時才回退到 veth。程序留在宿主命名空間；只有同步的 socket、鏈路和掛載操作會透過 `daens::with_daens_netns` 進入 `daens`。
6. 載入 BPF 物件並繫結真實資料路徑 hook。預設物件透過 `include_bytes!` 嵌入，`--bpf-object` 提供執行時覆蓋。啟用 `ebpf` feature 時，`build.rs` 會定位物件，拒絕過期或沒有 BTF 的產物，在移除繼承的 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS` 之後用 nightly 重建，驗證 `.BTF`，再複製到 `OUT_DIR` 供嵌入。`dae0` 就緒後，啟動流程依[介面協調](./datapath.md#介面協調)執行，繫結順序和失敗條件都由那一節定義。`local_ip` 遵循[本地路由不變量](./overview.md#執行時不變量)。
7. 沿用或建立固定的 `UDP_DECISION_SEQUENCE` 分配器，並驗證它的 map ABI、BTF、加鎖值、token 範圍和耗盡狀態。NFQUEUE 啟動時會再查一次加鎖的分配器狀態；如果沒有可安全復原的 generation，就保持暫存關閉。
8. 建構使用者態 Router、出站執行時 registry、DNS 執行時、GroupManager、cache DB、可選的 Clash API，以及控制面 supervisor。
9. 繫結透明 TCP/UDP listener，發布完整的 listener FD 集，啟動獨立 DNS 和 UDP 接收迴圈。只有生效開關還開著時，才啟動 NFQUEUE 服務，以及它的 ingest actor、correlator、watchdog 和獨立的佇列壓力取樣器，取樣器每秒取樣一次。
10. 檢查 NFQUEUE 健康狀態，發布 ready，開放 pending verdict admission，最後把
    `DATAPATH_STATE_MAP[0]` 設為 ready。之後 TCP accept loop 在控制面 supervisor
    裡執行。

`RealEbpfBackend` 負責 aya program、map、link、持久分配器處理和真實的 NFQUEUE 整
合。`MockEbpfBackend` 在沒有特權核心資源時，提供同樣的控制面介面。請求的 NFQUEUE
路徑如果過不了鎖交接後的固定佇列前置檢查，或者過不了隨後 admission 之前的佇列、
規則、健康檢查，honk 會記錄一則 warning 並關閉 NFQUEUE；這個啟動降級在 reload 之
後仍然生效，見[全域設定參考](../reference/global.md)。持久化 token generation 恢復
失敗，以及服務 admission 之後的失敗，仍然是 fatal。

物件 admission 會在程序名 probe 和任何 Aya loader 之前，拒絕隱式的 `ByName` map pinning。外部物件必須宣告未 pin 的 map；包括持久分配器在內，所有 pin 路徑都由 core 顯式提供，免得 loader 造出的別名逃出啟動復原。

真實 backend 在 pin map 之後啟動失敗時，啟動 guard 只刪除本次成功建立的臨時 pin；沒能替換的已有 pin，以及無關的已有 pin，都不歸本次所有。`UDP_DECISION_SEQUENCE` 和 `ROUTING_GENERATION_SEQUENCE` 在啟動失敗和普通清理之後都會保留；啟動成功時，臨時 pin 的所有權轉給 backend 清理。

關閉時在資源消失之前逆序釋放所有權。順序是：fence NFQUEUE；關閉資料路徑 admission；拒絕新的使用者態工作；取消並排空持有的 verdict 和 UDP initializer；停止 UDP driver 和 removal 處理；停止介面 watcher，並等進行中的批次結束；卸載 BPF hook；依[業務連線寬限等待](../reference/global.md#關閉)規則執行可選等待；關閉剩餘連線；退役出站執行時；停止 NFQUEUE；停止 DNS controller 和 persistence；最後清理 generation 持有的 BPF 狀態。普通清理保留固定分配器。之後 listener 和 `daens`/link-pair 的所有權離開作用域。

UDP receive-priority 的輔助後設資料不可用時，真實 backend 會保留 receive-trace fallback 用的 link 和 map。每個位址族都必須有完整的 enter/exit 對：失敗就卸載這一對，不會因此停用另一個位址族。兩個位址族都依賴 `__skb_recv_udp` 上共享的 hook，它失敗時兩者都不可用。註冊時會檢查 socket 位址族，所以缺少對應 hook 對的 listener 會報告不可用，而不是在沒有證據的情況下靜默註冊。每個 backend 只嘗試一次 fallback，失敗或只成功一部分也一樣。listener reload 會重新檢查原生輔助後設資料的支援和註冊結果，但不會重試掛載；改了核心或 BTF 支援後需要重啟。追蹤缺失只影響已經記錄的核心路由證據，不改變路由，也不影響 UDP 交付。`cleanup()` 先卸載 ingress hook，join ring consumer，然後在 BPF 物件釋放之前 drop `receive_trace`；即使 backend 自己還活著，也會釋放這些資源，不等到它的 Drop。普通清理仍保留兩個持久化 sequence pin。

## 透明代理入口

真實 TCP 和 UDP listener 在 `daens` 裡建立，帶上透明 socket 選項和有效的 `global.so_mark_from_dae`；這個值配成零時用 `0x100`。資料路徑依這個 mark 把它們識別成 honk 自己的 listener，而不是普通本地服務。已接受的 TCP socket 會繼承 mark，所以每個 accept loop 在處理流之前先把它清零。Mock listener 只是宿主命名空間裡的普通 socket，沒有特權透明選項。

原始目的位址依下表還原：

| 入口 | 首選來源 | 回退 |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | 下文所述的受約束 provenance 規則 |

真實 TCP 先驗證 accepted-FD 的所有權，再用這個 socket 上不可變的 SYN handoff。證明缺失或已被替代時，honk 關閉 socket，不會退而使用當前 tuple 後設資料。普通 UDP 依擷取的 incarnation 和 decision token，以非破壞性方式讀取 handoff。所有權已經確認的 `ControlPlaneRouting` 結果，或者允許缺 handoff 的 token-zero UDP，仍可以用 `Router::route_action`。最終的 `must` 和 `block` 結果不受 Clash mode 覆蓋；透明 DNS 保留自己的所有權邊界。

埠 53 上控制器和原始轉發的歸屬，依[有序流量規則契約](../reference/routing.md#出站目標與-must)處理，畸形的非 `must` UDP 也走那條通用回退。

真實透明 UDP/53 無論交給控制器還是原始轉發，都要求有效的逐封包 `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` 憑據，以及當前已提交的路由 generation，tuple handoff 替代不了。透明 TCP/53 必須有 SYN handoff；只有原始 `must` TCP 還要求當前路由 generation，並在原始 I/O 之前固定設定、語義群組和出站 runtime。非 `must` TCP 保留控制器的查詢 admission，不做那個路由 generation 檢查。缺少必需後設資料，或必需的 generation 檢查失敗時，在 I/O 之前就拒絕 admission。實體相容性見[handoff ABI 與 UDP 攜帶位](./datapath.md#map-清單)。

## 嗅探與流初始化

嗅探器向標準初始化器提供資訊，能幫它解決暫存的決策，但嗅探器不持有 verdict，也沒有自己的卸載路徑。

TCP 嗅探最多讀 4096 位元組，從中提取 TLS SNI 或 HTTP `Host`。傳回的緩衝區屬於流狀態，會在中繼開始前寫進已選出的出站，所以嗅探不會消費應用資料。`dial_mode: ip`、最終的 direct/block 或 `must` handoff、命中 TCP negative cache，這幾種情況都跳過 TCP 嗅探。連續三次失敗後，同一目的位址和出站簽名會被抑制十分鐘；嗅探成功則移除 negative 條目。

UDP 網域探索會解密 QUIC v1/v2 的 Initial packet，重組 CRYPTO fragment，再解析 TLS ClientHello 的 SNI。每流 session 五秒過期，最多檢查八個 Initial packet，CRYPTO stream 限制在 64 KiB。遇到第一個 ClientHello 分片時，initializer 最多保留八個 FIFO follower，最多等 250 ms。failed-DCID cache 用來限制非 QUIC 或不可解密流量上的重複工作。

`dial_mode: domain` 會對嗅探到的 TCP 或 QUIC 名稱做一次 DNS reality check。目的位址的同族答案精確匹配時接受；只有另一位址族的答案時，為相容雙棧仍然保留這個名稱。同族不匹配、查詢失敗或逾時，就丟棄嗅探到的名稱，改依 IP 繼續。

`connection/` 是每流 route/sniff/mode/selection 的標準邊界。Socket UDP 入口和 NFQUEUE 持有的 payload 都在同一個 `UdpEndpointPool` 裡預留同樣的 `UdpInitLease`；NFQUEUE 沒有第二套 Router 或撥號器，也沒有克隆封包、重放或主動重傳的路徑。暫存流在 token 驗證通過的終態轉換之前，算出唯一的最終出站和 mark。

`TuplesKey` 的 40 位元組 `#[repr(C)]` 佈局裡有一個顯式的三位元組 `padding`。核心會把全部 40 位元組都納入 hash，所以每個建構入口都必須把這個欄位置零；`build_tuples_key` 會零初始化標準 key，retirement 會拒絕 padding 非零的 key。

權威 URLTest 建立失敗時，仍會對延遲排序的前三名候選重試一輪。由 Score 負責的建立失敗，可以依序嘗試另一個合格葉節點，並在排名前先排除失敗的身份，即使一般評分仍把它排在第一。Score 的兩次嘗試共用同一個絕對 deadline，並保留固定的 generation、Selector 選擇，以及首選實際走過的 final 邊。型別化拒絕、本地撥號容量耗盡、取消和關閉都是終態，排空 race 時發現的已完成拒絕也一樣；一旦寫入應用資料，或 relay 已經建立，就不再重放。

- `src/sniffing.rs` — 只處理 TCP，提取 TLS SNI 和 HTTP Host，最多 4096 位元組，並傳回緩衝位元組供轉發。`parse_client_hello_body` 與 `control/quic.rs` 裡的 QUIC sniffer 共用。

## UDP endpoint 管線

### 目的位址 provenance

`udp_ingress.rs` 負責目的位址驗證和有界 admission，`sockets.rs` 負責 syscall/cmsg 解碼。真實透明 listener 必須有權威的 ORIGDST；普通 listener 和 mock listener 依下面的回退規則處理。所有路徑都會在預留 endpoint 之前拒絕無效後設資料：

1. ORIGDST cmsg 存在、有效且已指定時，它就是權威來源。未指定的 ORIGDST 無效，不能回退到其他來源。
2. 沒有 ORIGDST 時，只有精確的 DNS query 加上已指定的 `PKTINFO` 目的位址，才能形成 `IP:53`。
3. 其他情況下，只有非 wildcard 的 listener bind 能提供目的位址。
4. 缺失、畸形、重複、截斷或未指定的後設資料，會在 slow-path 預留或保留 payload 之前丟掉。

UDP 入口在任何可能等待的驗證之前先擷取 initializer epoch。原始 UDP/53 依 Config → backend 的讀鎖順序驗證；帶 mark 的直連先取 Router 讀鎖。在一致快照下驗證策略 generation，並固定語義群組，或者固定封包攜帶的不可變直連 mark 表項，然後透過既有的 epoch gate 預留並入隊。同一個 tuple 上不相容的普通、原始、其他群組或直連 mark 封包會被拒絕，而不是誤借其他 transport。非 `must` 的有效 DNS 保留獨立的查詢預算；UDP/53 不建立普通 UDP conn-state，也不建立 decision token。重組後的分片經 [NFQUEUE](./nfqueue.md#lan-dns-分片) 共用這份 admission；只有確認原始排隊封包已移除後，才發布工作。

歸控制器所有的畸形 UDP/53 可以保留相容的 controller handoff 事實，用於通用路由；但不相容的終局原始 handoff 及其過期封包事實會被丟棄。

### Transport 與事務

普通 transport 用 `PacketTransport`。原生 handler 包裝真實 socket，tunnel 則直接
實作 packet framing。來源共享協議提交型別化的 source attachment，讓多個 endpoint
view 共用一個 transport receiver；具體包括 VLESS XUDP/Mux.Cool、Hysteria2、TUIC，
以及所有 `MultiTargetTransport`。控制面不建立 loopback bridge。

Endpoint 建立是事務性的：

1. 先把 `(client, original destination)` 預留成 `Initializing`。lease 持有首個 datagram、queue permit、slow-path permit、token、generation 和 cancellation epoch。
2. 路由、嗅探、選擇，並準備合格的 transport。發布之前先建立透明的 anyfrom reply socket。
3. 只提交選中候選的 `PreparedUdpTransport<T>` 或 source preparation。可失敗的 commit 傳回選中的 `Arc<T>` 或 attachment；drop loser 會自動復原。
4. 啟動 endpoint driver，並等它的 ready barrier。
5. 在共享 epoch fence 下，把精確的 `Initializing` identity 原子替換成 `Ready`。
6. 把保留的首包轉過去，透過已提交的 transport 傳送，並等 acknowledgement。
7. 依 FIFO 順序傳送嗅探保留的 fragment 和沒被碰過的 queue follower，然後進入 steady 的傳送和接收路徑。

透明 UDP preparation 在路由和選擇完成之後開始，到選中 transport 的協議狀態
commit 完成才結束。權威路徑和冷啟動 URLTest 共用一個絕對的
`max(10s, 4 × connect_timeout)` deadline，覆蓋解析、實體撥號 admission、控制協商、
stagger 和滿容量時的等待，以及 commit。到期後不再啟動後續候選，並在傳回前排空所
有已啟動的 preparation。嗅探和路由在這個邊界之前；reply socket 建立、發布和
packet I/O 在它之後，受既有事務和 I/O 上限約束。不會自動重放 packet。

`udp_endpoint/source.rs` 為來源共享協議索引 owner，索引依據是 reused runtime
identity、正規化 client、協議/UDP path，以及 `ActualPeer` 或
`RewriteTo(original destination)`。它持有一條協議 association、一個 receiver 和
多個 endpoint send view。完整的 `(client, destination)` endpoint map 仍然是權威，
持有 route、token、generation 和逐 flow Score。reply classification 不會把已佔用
的 wrong-owner、`Initializing` 或 `Retiring` 條目當成 foreign；只有缺失的
`ActualPeer` key 才能做 foreign delivery，而且沒有逐 flow Score。domain route 保
持 original destination 的 scope。遲到的 send、reply、removal callback 在採取動作之
前，會重新驗證 owner、token、generation 和 endpoint identity。Source sharing 不
會合並 kernel/NFQUEUE 的 flow ownership：每個標準 endpoint 仍保有獨立的 decision
token、generation、terminal transition 和五元組 retirement fence。

關閉 `rprx` 時，共用的 source admission 和 shutdown join 仍然啟用，只有 VLESS 分
支受 feature gate 限制。Hy2/TUIC 經有界重組保留真實來源；它們的 QUIC send guard
在 source gate admission 之後開始，並由 driver 保留到最終 I/O 結果分類完成。

每個透明 socket 在一次 readiness 輪次裡透過 `recvmmsg` 最多收八個 datagram。每個 slot 獨立保留 ORIGDST、PKTINFO 和逐封包 `SO_MARK` 後設資料；packet 保持核心順序，某條後設資料異常時也只丟棄對應的 slot。佇列排空後，下一次喚醒先用一個 slot；如果讀取滿載，就立刻恢復八 slot 的 batch，省掉稀疏流量上的準備開銷。這個上限把排程公平性和 payload 儲存限制在每 socket 512 KiB；現在每個位址族四個 socket，雙棧全開時共 4 MiB。listener 迴圈只做驗證、預留和入隊，從不等待 `PacketTransport` I/O。Endpoint driver 持有全部 transport 呼叫。首次傳送和穩態傳送都用 transport 的 deadline：預設五秒，QUIC 用從路徑 SRTT 派生的 deadline。逾時或失敗可能發生在部分資料已被接受之後，所以 datagram 不重放；單包擁塞可以丟掉這個包繼續，終止性失敗則結束受影響的流或 source。

SOCKS5 UDP 在整個 source association 生命週期內保持 TCP `UDP ASSOCIATE` 控制流；控制流 EOF 或意外的控制資料都算 association 失敗。它的 connected UDP socket 向伺服器實體 `BND.ADDR` 中繼傳送；回覆是網域就解析，位址未指定就換成控制連線對端的 IP。每個 header 寫入自己的目的地，每個應答傳回頭部裡的真實來源，網域來源只投影成擷取到的名稱和埠。`PacketTransport::relay_addr()` 是第一個目的地，所以 SOCKS relay 自己不會被誤認成遠端 peer。

回覆走的是在 `daens` 裡建立、透明繫結到封包原始目的位址的 anyfrom socket。通過 transport peer 驗證後，以網域撥號的 endpoint 一律用原始 IP、埠和位址族回覆，即使遠端 DNS 選了別的位址。以 IP 撥號的 endpoint 保留自己的 original-destination socket。普通流和共享 source 的 receiver 共用一個程序級 full-cone 回覆 socket 快取，依 peer 位址索引，每個 endpoint 容量上限七個，空閒超過一個 NAT 逾時就清理。超出上限的新 peer 會關閉最久未使用的 socket；描述符預算耗盡時，主回覆 socket 也照此處理，於是外來回復給新流讓位。埠 53 的回覆另外共享每個位址族一個透明 socket，並用 `IP_PKTINFO` 或 `IPV6_PKTINFO` 選出精確的源 IP。從 TPROXY listener 回覆會帶上內部的 `dae0` 源位址，所以不可用。來自其他來源的回覆沒有精確的 `REDIRECT_TRACK` 記錄，`dae0_ingress` 改用只有客戶端的 `CLIENT_REPLY_TRACK` 訊框資訊把它送回客戶端，不經過主機轉發，限制性的轉發策略也不會丟掉它。收到這類回覆並不授權客戶端隨後向該來源發來的包：`lan_egress` 不會從來自 `dae0` 的包學習反向方向，那些包仍走正常路由。

reload 在開始等待之前推進 cancellation epoch。Initializer 在 await 之前擷取這個
epoch 和 incarnation generation；如果 cancellation 比 `commit_ready` 先線性化，
就阻止發布。reload 會取消並排空 `Initializing` lease 及其保留資源，`Ready`
endpoint 仍依既有生命週期走。已有原始 UDP 的 `Ready` session，只要語義群組名相同
且符合該生命週期，就可以保留；`Initializing` 不能跨 reload 存活。編譯策略發布之
後，過期的排隊路由後設資料仍會被 admission 檢查拒絕。每次 retirement，包括它的
`Retiring` tombstone，以及每個 acknowledgement，都指定 token 和 generation，所以
延遲的工作刪不掉替代的 mapping。

只有編譯後的流量計劃確實變了，而且舊策略或新策略包含直連 mark 時，才退役直連的
`Ready` endpoint，免得後續流量沿用舊的 socket mark。沒有變化、不相關的 reload，
以及新舊策略都沒有直連 mark 的路由變更，都會保留這些 endpoint。顯式標記為使用者態
所有的 WAN UDP 決策，包括帶 mark 的 `direct(must)`，會在 tuple/reader fence 下同
時清理 token 為零的 conn state、handoff 和 redirect track；原生 LAN
direct/offloaded 決策和更新的非零 token 保持不變。

NFQUEUE 入口由 `PendingUdpVerdicts` 持有 token/generation、phase、FIFO verdict guard 和最終的直連 mark。admission 接收自己持有的 `Bytes`，對應唯一保留的 payload；direct/block 完成後把 initializer 交給核心，proxy 則把身份轉入 `Ready`。commit 順序、deadline 和生命週期由 [NFQUEUE 協議](./nfqueue.md#終態轉換)維護。

## Queue 與描述符預算

每個 UDP 流最多保留 64 個 datagram，首包也算在內。所有流共享精確的 8 MiB payload permit 預算。admission 在複製之前取得每流 slot 和全域 byte permit；FIFO 飽和時丟棄最新的 datagram。NFQUEUE 有獨立的 ingest actor，限制為 256 個條目和 8 MiB 排隊 payload。

啟動時，`honk-core` 會嘗試提升軟 `RLIMIT_NOFILE`，只快照一次實際生效值，並把預算輸入
上限設為 1,048,576。DNS socket 先獨立分出 `min(transient_dials, 256)`，同時受剩
餘描述符約束。接下來依 `min(after_dns / 8, 8192)` 分配 VLESS carrier，再用剩下的
預算決定 UDP endpoint 數量。到了上限時，固定分割如下：

| owner | 容量 | 描述符記帳 |
| --- | ---: | ---: |
| 固定/執行時預留 | 256 | 256 |
| 已接受 TCP 流 | 16,384 | 每個 6 = 98,304 |
| 保留 TCP pool | 2048 | 每個 1 = 2048 |
| 臨時出站 dial | 1024 | 每個 1 = 1024 |
| DNS 自有 socket | 256 | 每 socket 一個額度；endpoint 網路 bootstrap 預留兩個，原始代理節點的 resolver socket 不計入，見 [DNS admission](./dns.md#解析管線) |
| VLESS 實體 carrier | 8192 | 每個 1 = 8192 |
| UDP endpoint | 32,768 | 每個 10 = 327,680 |
| **合計** |  | **437,760** |

一個 UDP endpoint 的記帳包括這些：relay socket、可能存在的 SOCKS5 控制流、自己的
anyfrom reply socket，以及程序級外來池裡的一份；每個 endpoint 容量共八個回覆
socket。一個 TCP 流會記入 accepted/outbound socket，加上兩對各含兩個 FD 的 splice
pipe。更小的限制用同樣的飽和分割；VLESS carrier 算出來是零時就保持零。

啟動時還會把 UDP endpoint 限制在 `MemTotal` 的四分之一以內，每個 endpoint 按 64 KiB
算：2 GiB 主機是 8,192，8 GiB 及以上到 32,768 的硬上限。實測一個 Shadowsocks 共
享 source 約佔 35 KiB，每多一個目的地約 11 KiB，所以這份預算給每流狀態更多的
transport 留了餘量。不讀 cgroup 的記憶體限制。

程序 VLESS-carrier 的 semaphore 由 traffic generation 和 DNS runtime fork 共享。
carrier 在 actual I/O 的 provisional、active、draining 和 idle 狀態下一直持有
permit，直到 task teardown 才釋放。實體 FD 的權威上限是這個程序 gate，不是逐節點
pool limit 的總和。耗盡時傳回型別化的 local capacity rejection，不影響節點
health 或 Score。

其餘 descriptor headroom 是有意不分配的：`RLIMIT_NOFILE` 高，不代表記憶體或排程能
力一樣多。TCP 從描述符匯出的 floor 起步，封頂 16,384 個流。它可以借用空閒的非
TCP headroom，但要留一半作為 burst reserve，並且不超過 floor 的兩倍。已有流不會
被切斷，固定 reserve 留給控制面 FD。

各 admission 上限彼此獨立：

| admission | 上限 |
| --- | ---: |
| TCP 流 permit | 描述符匯出的 floor，加上對觀測到的 idle non-TCP headroom 的有界借用 |
| VLESS 實體 carrier | 啟動時固定的 `min(after_dns / 8, 8192)` 程序 gate |
| 冷 non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| UDP DNS 客戶端生命週期 | 程序級 `min(1536, MemTotal / 4 / 256 KiB)`，跨 reload 共用 |
| 所有 controller DNS 查詢生命週期 | 每個 generation 2,048，TCP 與 UDP 共用 |
| DNS 自有 socket / endpoint 網路 bootstrap | 獨立描述符分割支援的程序 gate，最多 256 個額度，跨 reload 共享 |
| DNS 代理 stream / 非原始 UDP 的 packet 準備 | 不超過 DNS socket 上限的程序級保守邏輯 lease；不是所有代理 FD 的總上限 |
| NFQUEUE ingest actor | 256 個條目和 8 MiB |

代理 carrier 的所有權仍獨立管理；查詢與 socket 的 admission 約束見 [DNS admission](./dns.md#解析管線)。

TCP accept 用的是描述符匯出的流預算，沒有獨立的 256 項上限。[Joined removal worker](./datapath.md#使用者態維護與計數) 處理 TCP、UDP 和 expiry hint；UDP 保留 1024 條訊息的 channel，以及去重用的 `removal_dirty` 補償。只有自己的 I/O 和後端退役都完成後，才確認精確的 tombstone。

透明 TCP 先等任一 IP 族的 listener 變成可讀，再預留共享流 permit，最後用非阻塞系統呼叫完成 accept。所以空閒 listener 不佔流容量，達到上限後到達的連線還留在核心的 listen backlog 裡。`/stats` 的 `tcp` 物件提供 `activeFlows`、`limit` 和 `capacity.rejected`；最後一個統計的是等待 permit 的 accept-loop，不是 accept 之後被丟棄的連線。動態上限低於 256 時，啟動會記錄一則 warning；閘道器部署應提高服務的 `RLIMIT_NOFILE`。

## TCP 中繼與 conn-state 所有權

兩端都是普通 `TcpStream` 時，`relay_splice` 執行兩個並行的 `splice(2)` pump。每個方向持有一條最多 64 KiB 的非阻塞 pipe，所以全雙工中繼最多請求四個 pipe FD 和 128 KiB pipe page。遇到 EOF 就對另一端的 write side 做 half-close，並允許反方向繼續排空。

每個方向的首次 splice 同時是一次 capability probe。如果在任何位元組暫存之前傳回 `EINVAL`、`ENOSYS`、`EXDEV` 或策略拒絕，也就是 `EPERM`，就可以無損回退到使用者態 copy，並設定程序全域 latch，後續連線跳過 probe。pipe 建立失敗同樣發生在任何位元組移動之前，所以只讓當前連線改用 copy，不設定 latch。其他錯誤，或者位元組已經暫存之後才說不支援，都會讓中繼失敗，而不是冒資料丟失的風險。TLS 或協議包裝的流走 `relay_auto`，它一律使用以 select 為基礎的 copy loop。

未啟用 Encryption 的 Vision TLS/REALITY carrier 先走 copy loop。兩個方向都進入 Direct、且連線已經轉發 256 KiB 之後，relay 會在兩個方向都不持有未寫出位元組的位置交接：一個方向在讀取邊界，另一個方向掛起在讀取上。這時 relay 把 carrier 的 TCP socket 借給同一個雙向 splice 引擎，Vision/TLS 堆疊仍歸 relay 所有，carrier pressure 取樣也在借出的 socket 上繼續。probe 不支援或 pipe 建立失敗時，還沒有位元組移動，relay 就回到同一個 Vision 流的 copy loop；每條連線只嘗試一次交接。兩個階段共用連線計數器，統計覆蓋整條連線，first-response 回呼只觸發一次。

copy pump 在讀取新輸入之前，先 flush 嗅探或協議設定階段已經緩衝的位元組；輸入暫時
空閒時也會 flush 待發位元組。每個方向先用 8 KiB 緩衝區。第一次讀滿就判定為大流量，
該方向此後改用 65,535 位元組緩衝區，讓滿載 read 正好裝下一個最大的 AnyTLS frame，
不會拆成多次 8 KiB write，也不留下單位元組的尾訊框，只有首訊框較小。空閒和小流量連線不
會擴容，所以一條空閒連線的 copy 緩衝區是 16 KiB，不是 128 KiB。應用不必再發一個
請求，也不必關閉連線，就能把當前請求送出去。

首次 EOF 之後，兩條中繼路徑只限制空閒排空的時間：`DRAIN_DEADLINE` 是沒有任何位元組進展的 30 秒。活躍的 survivor 可以持續超過 30 秒；靜默的 survivor 不能一直佔用 accepted socket。

客戶端不發 FIN 或 RST 就消失的情況，另外單獨限制：TPROXY TCP listener 啟用 TCP keepalive，空閒 3600 秒、間隔 15 秒、探測 4 次，accepted socket 繼承這套設定。靜默客戶端大約一小時後結束它的 relay；仍線上的空閒客戶端會應答探測，所以長時間空閒的連線保持開啟。這種情況會回報為客戶端側的 `TimedOut`；核心有待處理的 ICMP/ARP 軟錯誤時，則是 `HostUnreachable` 或 `NetworkUnreachable`。兩種都依取消結算 Score。

Accepted TCP FD 在 tuple 路由、pin 或取得清理 authority 之前，必須帶著原始 SYN 的有效證明；這個證明由 `honk_tcp_passive` 在握手完成時寫入。不可變的 handoff 和 incarnation 必須匹配當前的 conn/handoff/redirect 所有權。證明缺失或已被替代時，關閉 socket，但不刪除當前 tuple。admission 在同一個 backend 讀 guard 內完成驗證，保留 tuple-local 的 `TcpFlowPins` 引用和精確的 `TCP_LIVE_PINS` incarnation。核心的 Closing/redirect 老化檢查只查這個 incarnation 的原生 pin，所以存活的空閒或半關閉 owner 能恢復傳輸，不用靠 timer 偽造時間戳。新的 SYN 不繼承舊的 pin。

Janitor 的收集階段在消耗 candidate budget 之前先排除 pinned TCP，並在 backend 寫所有權下再查一次當前 pin。child 的 socket storage 保留自己的證明，和 janitor 的狀態無關。退役只用 guard 擷取的 incarnation，不會去選 tuple 的後繼佔用者。

I/O 完成後，joined retirement worker 持有已通過 admission 的 TCP 退役、socket、tracker/close completion 和出站統計 guard，即使等待方取消也不會丟所有權。它的 `FlowPin` 在同一個 backend 寫 guard 內釋放 local 和精確 native pin，然後才檢查外部 owner；釋放失敗就不能確認清理成功。admission 之前取消會同步 Drop native pin，實體 tuple 的回收交給原子 janitor，不聲稱已經確認。控制面的 `RetirementPort` 把 native Drop 錯誤發到當前 worker epoch 的 critical channel，並透過 joined worker handle 收回 hint receiver。Worker 和 janitor 在關閉 warning 之後仍會 join 已通過 admission 的工作，不執行 abort。

普通 UDP 只在冷 admission、非同步準備之前擷取一次驗證過的 `UdpFlowOwner`，裡面有 token 和可選的非零 kernel incarnation；這個 owner 貫穿 initializer、endpoint 和 tombstone。Ready enqueue 不會多查一次 backend。Token-zero UDP 只要任一埠是 53，以及畸形目的埠 53 的回退，都保持無狀態；源埠 53 的 transport 不是控制器 DNS，模型執行不聲稱有原生證明。Hint/janitor 請求真正刪除 conn 之後，只透過 tombstone 和 acknowledgement 退役匹配 client/destination/incarnation 的 endpoint，也包括 batch 出錯前已經完成的那部分刪除。只涉及輔助項、`Missing`、`Superseded`、外來 incarnation、無狀態 endpoint 或無身份 owner 的，都不授權退役。

NFQUEUE 冷 cell 重建會在同一個讀鎖 guard 內保留 conn-state 快照，並呼叫 backend 自有的 UDP admission 驗證。retirement 所有權解決不了，或身份超出 allocator 範圍時，不能重建 ActiveDirect 放行；已經通過 admission 的 fast follower 仍保留原有的無查詢路徑。

真實 relay 完成後，TCP owner 先依實際結果結算一次 Score 和 relay-error 統計，再傳播退役失敗。退役失敗不會把成功的 relay 證據改成取消。TCP 補池仍要求 relay 成功並且退役已確認；主動取消保留自己的中性路徑。

`splice.rs` 的 `relay_splice` 在普通 `TcpStream` 之間用雙向零複製 `splice(2)`，並傳播半關閉。每個方向的首次 splice 都會探測 capability。在任何位元組進入管線之前，EINVAL、ENOSYS、EXDEV、EPERM 會觸發無損 copy 回退，並設定程序級停用標誌；建立管線失敗也會回退到 copy，但不設這個標誌。不要還原單向 splice，它曾導致逾時。

`relay_auto` 對 TLS 或協議封裝的流用同一個基於 select 的 copy loop。`vision.rs` 把 Direct Vision carrier 的 socket 借給同一個雙向引擎。兩條路徑都會在首次 EOF 時半關閉對端，剩下的排空時間只受空閒期限 `DRAIN_DEADLINE` 限制：連續 30 秒沒有位元組進展才結束，不會截斷仍在傳輸的另一方向。這樣，一個不發資料的對端就無法讓任務和 socket 長期停在 CLOSE-WAIT。UDP 走 `UdpEndpointPool`。

## Reload 與執行時 generation

SIGHUP 為每次嘗試單獨收集診斷。不管載入和設定驗證成功與否，warning 都只報一次；被拒絕的嘗試會另外報一次脫敏後的原因，不進入執行時發布流程。報告這次的診斷不會替換當前執行時狀態，也不會新增最近失敗嘗試的快取。

共用 reload 事務在指紋比較、no-op 判斷和重啟檢查之前，先正規化候選設定的 NFQUEUE 生效值，並保留已經記錄的、較早或較晚的資料路徑 admission 前啟動降級。原生 API 的寫入前檢查和完整驗證共用這套重啟策略，不改寫請求的來源文字；參見[啟動例外](../reference/global.md)和[原生設定 API](../reference/api.md)。

`apply_runtime_config` 先建構替代的 Router、GroupManager、出站 registry、DNS 執行時和路由計劃，不動 live state。提交順序是：

1. fence NFQUEUE readiness，並完成同步的核心 grace barrier。
2. 拒絕新的透明代理 admission。
3. 取消 correlator cell 和 token-bound original，推進 UDP initializer epoch，排空 `Initializing` lease，等 correlator 和已通過 admission 的 commit-pump 工作變空，並排空精確的 endpoint retirement。
4. 編譯這個 generation 的 `RoutingPushPlan`。在下列發布 guard 內，只有
   compiled plan、learned facts 有變化，或資料路徑健康需要恢復時，才呼叫
   `EbpfBackend::publish_routing_plan(&plan, learned_domains)`。後端會啟用
   inactive slot，暫存這個 generation 持有的 IP/source/MAC/domain 事實 map，使用
   完整的 256 位謂詞值，把生成的函式掛到每個相關 target，最後切換
   `ROUTING_POLICY_ROOT`。呼叫成功後，原生顯式啟用會以自己的 backend 重置 mode；
   使用者態接著在同一序列邊界內發布替代的 outbound registry、DNS runtime pointer、
   Router、設定、群組和 projection snapshot。root 已經提交之後，如果 mode reset 失
   敗，就把新 generation 提交為 degraded，並保持 admission fence。發布完成後，退
   役舊 generation，替換它的 UDP 與 Selector warm coordinator，並同步健康檢查節
   點、URLTest 群組和自訂群組的檢查 URL。已經提交但處於 degraded 的 generation 也
   會走完這些步驟，只是 admission 繼續 fence。停止 warm coordinator 會取消可能依
   賴另一個 coordinator 的 retention-reconciliation 等待；coordinator 退出之前，
   仍會 abort 並 join 自己派發的子任務。QUIC warm 釋放和終止關閉會在 client 槽位上
   依序執行，即使沒啟用原生任務所有權也一樣；取消釋放不會提前清空槽位，終止關閉仍能
   取得 client。
5. 開放 pending admission，最後重開 NFQUEUE。規則派生 feature bit 存在 policy descriptor 中，不再單獨發布到靜態 flag map。

`control/reload/transaction.rs` 在候選準備和提交之外持有 `reload_lock`。新 generation 發布時，依次取得 `router` → `config` → `datapath_flags.publication()`，這一項只在原生顯式來源啟用時取得，然後是 `ebpf`；隨後是 DNS projection-publication guard → `group_manager` → `outbound_id_map` → `active_routing_plan` → `runtime_registry`。在這些 guard 內，provider 的 DNS publication guard 會等到 backend staging 完成後再取，緊挨著 registry 權限替換之前，並一直持有到原來的 DNS pointer 提交點。所以 backend staging 不再佔用 provider admission 鎖，而 registry 轉移、回呼安裝和 Score 權限發布仍會阻止新的舊 generation DNS admission。原生 no-op 啟用取 `config` → flags publication → `ebpf`，不替換 Router。`mode.rs` 的獨立 mode/fence 更新依 flags mutex → `ebpf` 取鎖；`reset_for_activation` 不會重新取這兩個鎖，也不 await。NFQUEUE fence/reopen 在 router/config 發布 guard 之外執行。這裡只是記錄現有的鎖邊，不代表允許新增鎖邊；改動仍要遵守 CONTRIBUTING §2/§11 和人工審查。

`RoutingPushPlan::compile` 是唯一一條使用者態 lowering 路徑；呼叫方不選 slot，也沒有獨立的 domain-publication 握手。`routing_policy.rs` 的 ABI 是：`RoutingInput` 128 位元組、`RoutingDecision` 24 位元組、`RoutingPolicyDescriptor` 24 位元組。真實 eBPF 要求 Linux 6.12+；生成的程序名匹配程式碼在固定偏移讀取之前檢查 `pname_len`，以符合 6.12 的 verifier。已載入路由 slot 的 BTF 必須暴露當前的輸出佈局。

提交前失敗時，保留目前作用中的程式碼和事實，不再重放舊的路由計劃。fence 之後發布被拒絕時，控制器會恢復群組連通性並重開舊 generation；連通性恢復失敗就繼續拒絕 admission。root 切換成功後，新 generation 就算提交了；之後如果 NFQUEUE 重開失敗，保留已發布的新 generation，繼續 fence admission，直到後面一次成功的 reload 修好。

候選建構只在路由輸入和內容指紋都沒變時，沿用不可變的使用者態 `Router` 和編譯好的 DNS router。Hosts 和被引用的 Geo 資源在解析前計算指紋；內容一變就強制替換。只有完整的 `RoutingPushPlan` 和 learned-domain projection 位元組都沒變時，才跳過 native 路由發布；資料路徑健康狀態仍會強制執行一次恢復性發布。

`control/reload/dns.rs` 負責 hosts/policy 準備、DNS router 和 hosts 的沿用，以及候選 forwarder 的建構；`transaction.rs` 保留 generation 繫結、發布鎖、fence 和退役順序。

`DnsServiceProvider` 是一個一致的 DNS generation pointer。請求 lease 會保留它所屬 generation 的 forwarder、projection、transport pool 和出站執行時，直到退役。出站 registry 也按 generation 持有：沒變化的 node runtime 只在提交點轉移，舊 registry 把這些 runtime 標記為已移出，然後開始平順退役。現有的 stream 和 `Ready` UDP endpoint 保持引用，同時舊 reusable pool 停止接受新工作並排空。

編譯路由的發布有自己獨立於 DNS runtime generation 的[程序生命週期上限](./routing.md#同步槽與原子發布)。發布之後，排隊中的 UDP53 和原始 `must` TCP53 後設資料可能依上面的 admission 規則被拒絕；已經通過 admission 的 DNS 查詢仍依固定的 generation 排空。

`DrainTracker` 是程序全域的 accepted-flow gate。reload 和關閉都會設定 reject-new；僅用於關閉的[業務連線寬限等待](../reference/global.md#關閉)不改變 reload 的退役語義。

Selector 和 UDP warm 的所有權仍繫結 generation，見[預熱所有權](./groups.md#預熱與所有權)。

- `src/mode.rs` — `DatapathFlagsHandle` 在同一把非同步互斥鎖下依序更新 `ModeState` 和 `DATAPATH_FLAGS_MAP`。Initialize、mode、GLOBAL、static 四種更新會和 NFQUEUE 的 fence、reopen、disable 協調，避免 API 更新在 reload 中重新發布 ready。fence 完成要求 READY=false、成功的同步核心 grace，以及 fenced 清理掉所有未交付的 Preparing/Pending/Aborted 狀態。

### 需要重啟的變更

目前程序級的消費者在下列任一值變化時拒絕 `SIGHUP` reload：

| 區域 | 需要重啟的欄位 |
| --- | --- |
| listener/資料路徑 | `global.tproxy_port`、`global.tproxy_mark`、`global.tproxy_port_protect`、`global.pprof_port`、`global.so_mark_from_dae`、`global.lan_interface`、`global.wan_interface`、`global.auto_config_kernel_parameter` |
| 程序狀態 | `global.log_level`、`global.data_dir`、`global.store_subscribe` |
| DNS listener | `dns.bind` endpoint 或 transport 的語義變更 |
| Clash API | `experimental.clash_api.external_controller`、`external_ui`、`secret`、`default_mode`；生效的 `assets.ui.url` 和 `assets.ui.route` |
| 原生 API | 任意 `experimental.native_api` 變更；生效的 `assets.geodata.geosite`、`assets.geodata.geoip`、`assets.geodata.route`；`assets.geodata.auto_update`、`assets.geodata.cron`、`assets.geodata.checksum` |
| 持久化 | `experimental.cache_file.enabled`、`store_dns` |
| NFQUEUE | `global.nfqueue_enable`，已記錄資料路徑 admission 前啟動降級時除外（[例外說明](../reference/global.md)） |
| 健康檢查與 TLS | `global.check_interval`、生效的第一個 `global.tcp_check_url`、啟用 HTTP 檢查時的 `global.tcp_check_http_method`、選中的 `global.udp_check_dns` 目標，或原生 TLS/uTLS 模式切換（參見[健康檢查 reload 語義](../reference/global.md#reload-健康檢查與-tls-模式)） |

UI 和 geodata 的生效設定裡，包含從 `assets.route` 繼承來的值。如果這個預設出口的變更影響到啟動階段持有的任一下載出口，就需要重啟。`assets.subscription` 的預設值和訂閱條目設定交給訂閱協調處理。

舊值和新值都能解析時，`dns.bind` 的語義比較用的是解析後的 bind endpoint，所以只是拼寫不同、實際描述同一個 endpoint 的變更不會強制重啟。

`EbpfBackend` 負責這些事：token/state 檢查；`commit_udp_decision(key, token, transition)`；經過 token 驗證的 abort 和 removal；核心 staging 的 quiescence；相容復原用的持久化 allocator 驗證；狀態查詢和重置；以及 routing 和 map 操作。12 位元組 pin 的 `next` 儲存完整的 raw token，也就是兩位 generation 加 28 位 sequence，啟動時不會重寫。只有暫存路徑的 fence 和排空都完成，並且候選 generation，直到 3 在內的全部更高 generation，都沒有出現在 live 的 conn-state、handoff、redirect 或 retirement-fence map 裡，才允許 reset。復原後的舊 allocator 會從 reset 值單調遞增，所以整個字尾都必須是空的。

## 訂閱編排

啟動時先解析已經存下的內容，再開始網路重新整理。恢復結果有效且非空時，節點會立刻可用，這個訂閱也不再等那五秒的首次拉取。只有沒能有效恢復的 direct 訂閱才會進入共享 grace；經路由的拉取會等路由就緒，不阻塞啟動。之後仍在背景繼續網路重新整理。

`ControlPlane::run` 第一次被 poll 時就取得控制命令接收端的所有權，早於所有啟動階段的 await。這個已經開始執行的 future 一旦傳回或被丟棄，就算 listener 啟動失敗，也會關閉通道；這樣卡在滿佇列上的訂閱投遞才能解除等待，呼叫方隨後也才能等 supervisor 關閉。

`SIGHUP` 依 fetch 身份穩定訂閱 ID，身份由 URL、設定的 User-Agent 和 headers 組成。它會把目前生效的訂閱裡的節點帶進候選設定，但不恢復快取內容。網路失敗、解析失敗，或結果裡沒有可用節點時，生效中的節點會保留，上一次有效的內容也不會被替換。持久化失敗不算致命錯誤：驗證通過的節點仍可合併，舊內容仍可恢復。定期重新整理和立即重新整理走同一條序列的 runtime 發布路徑，訂閱節點不會寫回設定檔。

內容驗證和執行時發布是分開報告的。節點集合的 admission 失敗時，只輸出一次脫敏診斷，並保留目前生效的設定；已經儲存的內容不會復原。

啟用 `global.store_subscribe` 後，驗證通過的原始回應會存進固定狀態資料庫 `<data_dir>/state/honk.db` 的 `subscription_body` 表。key 由請求 URL、設定的 user-agent 覆蓋值和有序 headers 決定。完整內容在一次 SQLite 事務裡替換，單份最多 8 MiB，總量最多 32 MiB。啟動時會從 `<data_dir>`、`/var/share/honk` 和 CWD 下找到的第一個私有舊 `.sub` 目錄，一次性匯入已啟用訂閱的內容；已有行優先，複製過的檔案和臨時檔案會被刪除，沒匯入的內容保留，等後續符合條件的啟動再處理。遷移和失敗細節見[訂閱參考](../reference/subscription.md#抓取持久化與恢復)。

- `src/subscription.rs` 負責拉取和解析；`subscription/store.rs` 持有 SQLite 內容儲存，以及相對 FD 的舊儲存匯入。`subscription/supervisor.rs` 持有授權和在途工作；`supervisor/schedule.rs` 管理 provider 的重新整理期限，`supervisor/startup.rs` 恢復快取內容，並執行只限 direct 的共用五秒啟動寬限。啟動和穩態用同一份 supervisor state；在途工作獨立保留擷取的 revision 和發布確認，關閉時會等它結束，reconcile 不會丟棄可能已經提交的確認。
- 常駐程式的拉取和恢復路徑，與 `honk-tool sub` 的本地檔案共用內容格式檢測。
  `Simple`/`Custom` 接受 BOM、可換行的標準 Base64 和 URL-safe Base64、原始分享鏈
  接、Clash YAML/JSON、SIP008、sing-box JSON，以及 Surge、Surfboard、Loon、
  Quantumult X 的記錄。`src/subscription/json.rs` 和 `records.rs` 正規化外部記錄，
  `clash.rs` 建構並驗證型別化節點。只匯入節點，不匯入完整設定裡的路由、DNS 或群組。
  原生 JSON 會保留用 Unicode 代理項對編碼的名稱。不支援的節點直接跳過；身份重複
  時保留第一個可用節點；空結果不替換目前生效的訂閱。匯入的 Trojan、AnyTLS、QUIC 節點必
  須用 TLS，不會靜默降級成明文。Clash 和 sing-box 的 TCP ALPN 歸入共享的 TLS 模
  型，不放進 TUIC 的 QUIC 欄位。共享建構子的跳過 warning 只帶從 1 開始的代理序號
  和靜態拒絕原因，不含原始節點記錄或憑據。

## 原生觀測 API

`native-api` 是獨立且需要顯式編譯的 feature，用 `--features native-api` 或 `native-ui` 建構；full 和 `-native-api` 的發布產物也包含它。它提供一個預設關閉的 listener，啟用後在控制面 admission 之前繫結。可選的 phase watch 只在 admission 開放後才報 running，在關閉 fence 之前報 draining；現有的 health handle 可以把 running 細化為 degraded。讀取 generation 和 health 期間會保留 config 發布屏障，但不改變發布鎖序。HTTP 可用並不代表資料面健康。

`native_api/server.rs` 完整持有 listener、64 連線的 JoinSet、唯一的一秒 sampler 和 native tracker consumer，直到關閉時 join。header 預算五秒。30 秒讀空閒期限只在這條連線沒有進行中的請求時生效；請求從 body 結束算到回應完成都算進行中。停滯的寫入另有獨立的 30 秒期限；健康 SSE 和慢 handler 可以超過 30 秒。accept 出錯時記日誌後重試，EMFILE、ENFILE、ENOBUFS、ENOMEM 退避 100 ms；連線任務失敗只記日誌，不終止 server。HTTP 關閉共享五秒 grace，然後等已通過 admission 的真實阻塞憑據任務結束。

`crate::observe` 擁有程序身份和引擎側的有界儲存，獨立於客戶端；`observe.rs` 裡的 `Observation`、flows、rules、catalog 身份和 `DnsRecorder` 都屬於它。`native_api` 只負責 HTTP 投影。沒有啟用 `native-api` 時，觀測 hook 會編譯成零開銷的 inert 替身。TCP/UDP/DNS 的 producer 在真實執行點擷取不可變的來源證據，已接受的發布在既有屏障下發出 generation 事件。逐流完整性描述的是已擷取的執行進度，與生命週期和總體覆蓋無關；native-only 的 final handoff 不會重複生成舊的選路證據，也不聲稱完整的核心透明觀測。日誌直接擷取審查過的結構化安全欄位，不轉發 Clash 的格式化輸出；`/events` 和 `/logs` 的續傳都是 ready → replay → live。

`native_api/handlers.rs` 為每個資源只註冊一份方法分派；共用安全邊界仍先於方法和資源驗證執行。`observe/flows/record.rs` 持有型別化摘要、輸入及證據步驟，留存預算計入實際持有的堆容量、snapshot 與有界核心字典預留，JSON 只在 wire 邊界投影。核心生命週期與模式命令傳回型別化結果，而不是 HTTP 錯誤或 JSON。

`observe/flows/producer.rs` 持有 FlowGuard 更新及 TCP/UDP、DNS 共用的群組選擇證據投影。DNS wire 輸入模型歸入統一 record；`observe/flows/dns.rs` 保留 lookup/catalog scope 與 DNS 專屬擷取。`auth.rs` 持有 session、有界 admission 和唯一受追蹤的阻塞任務；storage 子模組發布短時持有的憑據狀態，不跨 KDF 或 SQL 持有狀態鎖。

`native_api/events/http.rs` 負責事件 query/cursor 解析、Accept 協商以及與日誌共用的 HTTP 流回應；replay、簽名、訂閱和訊框預算核算仍歸 `native_api/events.rs` 所有。

`control/connection/observation.rs` 根據已擷取的 handoff、route、selection 和 transport 事實組裝 TCP/UDP 證據。連線編排不構造 wire record，也不使用當前設定重算曆史；關閉記錄時不分配 capture，精確連線關閉仍獨立於記錄。

`DnsRecorder` 在 `observe/dns/history.rs` 中持有具體的客戶端 DNS 歷史；記錄 epoch、入口 admission 及按位元組/條數淘汰歸引擎所有。`native_api/dns/log.rs` 讀取同一持鎖檢視，完成 cursor 繫結的過濾、listener secret 遮蔽及完整記錄的 JSON 分頁投影。

`observe/flows/dns.rs` 與 outbound flow observer 為 scoped/retained 工作繫結實際 lookup、attempt 與 generation 身份。session attachment、邏輯 open/readiness 重試與新實體連線、協議確認分開。可選非同步 scope 借用呼叫方 pin 的操作，不復制大型 future 狀態；pin 不越過操作的所有權/析構邊界。核心證據使用不可變編譯字典與封包繫結 witness；UDP receive priority 來自原生輔助後設資料，或嚴格對應 syscall/batch 的 receiver-owned fallback。丟失只改變證據，不改變路由或封包交付。

既有原生 sampler 透過 `DatapathFlagsHandle` 同步實際流需求，保留模式/NFQUEUE 位，僅在後端寫入成功後提交追蹤 admission。等待後端所有權後重新讀取需求，sampler 停止並 join 後再同步一次；不新增 writer、timer 或路由重編譯。核心對每次呼叫沿用同一 flags 快照來控制可選 witness 生產，已保留的擷取與真實路由判定不受後續需求變化重解釋。

TCP copy 成功讀取與 splice 成功寫入即時累加既有逐出站 atomics；成功接受的嗅探字首僅計一次，部分寫失敗也保留已寫位元組。Relay 關閉或取消不再次累加總量。既有統計與原生取樣共用這些計數，UDP 原逐包語義不變。Wire 契約、上限與未知欄位見 [API 參考](../reference/api.md#原生-api)。

出站讀取保留共用計數的 `kind/name` 與完整 UInt64，reload 不重置計數生命週期。`telemetry.rs` 沿用唯一的一秒 sampler（Skip），無客戶端也保留各 600 點/600 秒的流量與記憶體歷史。關閉對應記錄開關並重啟後釋放緩衝，不插值或補零。記憶體讀取實際 RSS/cgroup v2 檔案，未知值為 null，未實作 kernel memory 核算。

`configuration/accepted.rs` 持有啟動擷取的 `.dae` accepted 來源及發布 fence，`native_api/config.rs` 只投影權限與 HTTP。原生協調器在讀盤前序列化 API 寫入和 SIGHUP 載入，`configuration::Activation` 為 native 與 nonnative 呼叫方共用 reload、reply、訂閱 reconciliation 鏈。HTTP 斷開不取消 daemon-owned 任務，同 scope/key/body 重放共用結果；PUT 的 202 僅代表耐久寫入且真實 reload 已排隊。外部編輯器仍可能在最後檢查與 rename 間 race，rename 後目錄 fsync 失敗必須報告已寫但耐久性未確認，不能稱為復原。

`native_api/config/http.rs` 持有來源 HTTP adapter。協調器持續負責資料庫記錄，直到 awaited blocking promotion 結束；HTTP 取消與關閉不改變該所有權。待記錄的新 accepted 來源不會被錯誤標成舊的持久化 revision。

accepted 來源在真實 no-op 或 commit 時隨原有 config 發布屏障更新，遵循上述包含 datapath flags publication 的鎖序及訂閱 revision fence。拒絕 reload 保留舊快照/generation 但不復原已寫檔案；提交後 degraded 保留新快照/generation 並令 operation 失敗。API operation 的真實結果投影到 GET、`runtime.last_reload` 與 `operation.updated`，SIGHUP 本身不建立 API operation。註解變更可更新 source hash/config revision 而不推進 runtime generation，有效群組成員變更影響 revision，健康變化不影響。

Selector 寫入由同一 `control/reload` owner 序列化，TCP/UDP 分開儲存，both 原子發布；Clash 寫 both、讀 TCP 投影。精確連線關閉繫結 TCP UUID 或 UDP token/generation/source view，等待實際 transport 與 backend/driver 退役，而非只刪除 tracker 記錄。同一 owner 的重複關閉共用完成結果與失敗，不存在或已被替換的 owner 才是 Gone。群組中斷依擷取的群組路徑與網路關閉舊 owner，在同步 guard 外等待。群組 PATCH 使用 parser span 和原始來源協調器，寫前及 reload lock 下都檢查 accepted revision，獨立檢查 hash 與依賴。Provider 並行發布可使已寫檔案不能啟用，必須保留 written/committed 區分。自動策略的分網路 pin/clear 已開放，pin 成員只屬於當前 GroupManager。

主檔案建立/刪除沿用相同協調器、parser span、revision fence 與 reload reply，但等真實啟用後才傳回 201/200。訂閱 supervisor 持有繫結身份的初次拉取延遲，所有離線 admission 都攜帶這些排除項和有效執行時資料目錄。Geodata 先暫存並驗證所有資產，再經 FD 相對替換；臨時不可變 `SourceUpdate.geo_sources` 同時進入 reload 的兩條路徑，發布後不再由 accepted 來源後設資料保留。Router/DnsRouter 保留實際載入位元組的後設資料，觀測依 router-before-config 鎖序且不重讀磁碟；部分檔案替換與提交後 degraded 如實報告，不承諾復原。

暫存 writer 傳回保留的 installed-file FD 及耐久結果。Geodata 從待替換檔案轉為 installed guard，不再重新開啟檔案重建所有權。路徑、inode 與位元組複查仍拒絕外部編輯；可見但未確認耐久的替換仍明確報告。

啟用執行只產生一份型別化完成結果，分別投影到 operation、管理回應和 SIGHUP 日誌。協調器接受下一項修改前，建立回應保留已提交的資源表示。來源後設資料在取得 config 寫鎖前準備，發布時複核擷取的 revision/generation。Rename 前的依賴複查將邏輯讀取方繫結到標準目標及位元組：有序 hosts/ECH 引用、訂閱宣告位置與 geodata 型別。複查重新發現 source/glob 和依賴選擇，但不重複編譯未變化的已通過 admission 的候選；交換兩個讀取方的檔案目標仍會衝突。

Probe worker 擁有有界準備/排隊/執行/清理，DNS 診斷使用真實 generation 與精確快取 owner，provider refresh 由 SubscriptionSupervisor 拉取並等待 revision-fenced publication；GET 不偽造這些 producer。Routing trace 只模擬當前 compiled predicate，不做 DNS/探測/選群組；當前規則字典只在 parser 來源可用時提供脫敏 source location。Runtime settings 由一個 owner 先驗證全量 merge 再發布，native+Clash mode 共用 `DatapathFlagsHandle`。Native 啟用時模式不恢復/持久化；顯式接受設定啟用（含 no-op）重置 Rule 與 settings，provider/network refresh 不重置。

`native_api/settings.rs` 分別管理各類自動診斷收集需求：成功的 flow GET 或顯式 flow-event kind/`flow_id` 開啟 flows，logs stream 開啟 logs，成功的 DNS-log GET 開啟 DNS log。普通 events 只維持自己的 attachment，不開啟這三個 recorder。admission 失敗及普通 API/validation 請求不增加診斷需求。每個 stream lease 只釋放自己取得的集合；每類 recorder 獨立保有最後需求釋放後的六十秒 grace，不由其他讀取/stream 續期。設定 permission 與顯式 runtime On/Off 仍有優先權；顯式啟用重置 override，provider/network refresh 保留。

Probe 準備階段將擷取的計劃消費為具體位址的可執行嘗試或明確的家族位址不可用結果。DNS-owned resolver 保留 generation 及 canonical accepted-positive 應答資格；即使另一家族有位址，終止性 packet refusal 也拒絕整個準備。健康 ticket 與探測設定在同一發布屏障內擷取。

Native cold/warm HTTP probe 與 URLTest 共用 dial/TLS/ALPN 和 H1/H2 exchange；native 保留總 deadline 且不寫 Score，傳統呼叫方保留分階段預算。臨時 runtime 的 joined cleanup 傳回型別化結果：私有 child panic 令 operation 失敗並阻止之後成功確認暫停，但保留已完成的測量證據；主動取消不偽造不健康樣本。

顯式啟用已提交 routing/config 後，若 backend mode 重置失敗，保留先前的 mode/source，但各項設定已恢復為已接受的值。事務報告 committed-degraded 並關閉 admission，operation 失敗。這不表示 mode 已重置為 Rule，也不表示舊設定仍生效。

原生 mode 資源暫緩提供：固定 PUT 契約無法表達生命週期衝突，也無法表達 owner/backend 不可用；同一 capability 覆蓋讀寫，所以 GET/HEAD/PUT 均傳回 `404 capability_not_supported`。內部臨時模式、Clash 控制與上述啟用 reset 不受影響。

### 終止所有權

`control/lifecycle/teardown.rs` 的共用網路清理在有無 listener epoch 時都適用，涵蓋部分啟動。獨立 DNS supervisor 保留已回收 child 的失敗，並經 joined teardown 傳播；主動關閉導致的取消是中性的，但 owner panic 會使清理失敗。

網路維護任務屬於 `RuntimeEpoch`。延遲快取 writer 屬於程序，僅在終止關閉時 join。

已開始的阻塞工作無法靠取消 async waiter 停止，持有它的 owner 必須等待實際 join。通用清理/join 階段使用十秒 `STAGE_TIMEOUT`，逾時的 async task 會被 abort，teardown 報告失敗。`control/cache.rs::StateTick` 是例外：十秒後記錄 warning 並繼續 join 實際維護任務及在途阻塞 SQLite 寫入，不 abort。取消這次等待時，handle 仍留在 owner 中，可再次等待；owner 被 Drop 時只發出停止訊號，外層 task 繼續持有阻塞寫入。因此總關閉時間沒有嚴格十秒上限。TCP 連線任務 panic 時記錄日誌並回收，不停止引擎。關閉時可選的[業務連線寬限等待](../reference/global.md#關閉)在 joined teardown 之前執行。

健康檢查 owner 也會在五秒 drain deadline 後繼續等待實際 drain（包括其阻塞解析任務），再傳回 deadline 錯誤。若後續清理發現子任務失敗，該失敗優先於 deadline 錯誤。

## Clash API 與 cache DB

可選 Clash-compatible axum server 是共享引擎 handle 上的使用者態檢視與修改介面；endpoint 細節見 [API 參考](../reference/api.md)。任一 API 成功繫結，或任一設定群組使用 `interrupt_connections` 時啟用連線後設資料；真實 transport 關閉不等於移除記錄。Selector 寫入與 accepted-manager 替換序列化，Clash 寫 both、讀 TCP。執行時快取表位於固定狀態資料庫 `<data_dir>/state/honk.db`；舊 `cache_file.path` 與 `cache_id` 僅用於一次匯入舊 `cache.db`，不決定使用中的資料庫位置。升級後不設 `cache_file.enabled` 即預設儲存 Selector 選擇與延遲樣本；`true` 額外啟用 mode/GLOBAL 以及配合 `store_dns` 的 DNS 應答，`false` 停用這類快取持久化。Mode 僅在 native 未啟用時持久化。目錄鎖覆蓋全部已持有 SQLite connection 的存活期，包括 cache writer connection 到執行緒退出。見 [Experimental 參考](../reference/experimental.md)。

- `src/stats.rs` — `StatsManager` 持有固定、無分配的 `GET /stats` UDP schema。`udp.nfqueue` 包含 listener/correlator 計數、actor 佇列深度、排隊位元組數與最舊條目的等待時間、當前佇列深度、跨 hard rebind 累積的程序生命週期核心丟包數、最近一次核心讀取的可用性與累計讀取錯誤、held/peak guard gauge、生效接收緩衝大小、終態 verdict、token exhaustion/rotation、verdict error 與 `receiptToVerdict`。該延遲從 listener 收包計到 verdict 成功，不是核心佇列駐留時間。頂層 `warm.sessions` 報告保留的 `anytls`、`vless` pool session 及各協議 QUIC client。
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash REST/WS API 與外部 UI。UI 目錄缺失或為空時在背景下載；URL/detour 優先順序見[設定指南](../configuration.md)。`GET /stats` 傳回使用者態統計，不是 eBPF `OUTBOUND_STATS`；已驗證的 `/stats.score.groups[]` 包含 `name`、TCP/UDP 原因計數、`verification` 與 `budget`。Mode/GLOBAL 修改透過 `DatapathFlagsHandle` 原子組合 reload fence 與最新 mode/static bit；Selector 修改透過 group manager。Score 群組保留 `type: "url_test"`，在 `now` 顯示當前聚合 TCP 勝者，並拒絕 `PUT /proxies/{name}`。不傳回 score cell 或私有 target 資料。
- Clash API 成功繫結或任一群組設定 `interrupt_connections` 時才啟動連線後設資料追蹤。API 關閉只移除自己的 consumer；由群組觸發的中斷仍然有效。

## 相關文件

- [資料路徑設計](./datapath.md)
- [路由設計](./routing.md)
- [NFQUEUE 設計](./nfqueue.md)
- [出站設計](./outbound.md)
- [群組設計](./groups.md)
