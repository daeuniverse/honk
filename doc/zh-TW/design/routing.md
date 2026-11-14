# 編譯式路由決策面

## 範圍

路由只有一套手寫語意模型，執行方式可以不同。使用者態 `Router` 解釋規範化的 policy
IR；受限編譯器把同一份 IR 編譯成原生 eBPF 比較程式碼。核心不會去解釋第二套 policy
表示。真實後端的核心基線是 Linux 6.12。

封包解析、特殊與本機排除、DNS 接管判斷、conntrack、mode 與健康檢查、NFQUEUE
所有權、重新導向和回包統計，仍由靜態 TC 程式負責。生成函式只管
`RoutingInput -> RoutingDecision`。採用編譯策略不代表 honk 把每個首包都送到
使用者態；native-direct 和已有流快取路徑仍在核心執行。

## 規則語意

規範化的 IR 儲存有序 RuleId、展示資訊、條件和 outbound/mark/must 動作。priority
越小越先匹配，同優先順序保持穩定的原始碼順序。dae 解析器依原始碼順序分配 `0, 1, ...`，
流量規則的內容和順序完全由使用者設定決定。啟動、reload 和介面變化都不再注入閘道器
位址的 `direct(must)` 規則，也沒有隱藏的核心位址白名單。條件之間是 AND，同一條件的
候選值之間是 OR；否定只作用一次，涵蓋整個條件。fallback 是獨立的終結動作。空展開
不能丟掉：正向空集合為 false，負向空集合為 true，不能因為 geo 資源裡沒有匹配項就
放寬複合規則。

設定模型和解析器在
[`crates/honk-config/src/routing.rs`](../../../crates/honk-config/src/routing.rs)
及對應的路由解析模組裡。`RoutingRule` 儲存出站標籤、優先順序、mark 和顯式的終結
`must` 標誌；`RoutingCondition` 儲存正向和否定匹配列表。`RoutingOutbound` 是一個
字串目標，指向代理群組或內建的 `direct`/`block`。`ClashRuleDisplay` 保留簡單匹配型別，
對複合、否定或解析器記錄的 `must` 語句使用 `complex`。`Config::validate` 拒絕
直接指向已設定節點的規則或 fallback；應該用群組，也可以是只篩一個節點的群組。

## 核心路由

核心路由保留使用者態的匹配語意：

- 一般 domain 的 pattern、suffix、keyword、regex 和 geosite 在同一條件內按 OR
  匹配，否定作用於整個聯集。suffix、regex、keyword、大小寫和 geosite 屬性的行為
  不變。
- 目的 IP 和來源 IP 保留 IPv4/IPv6 身份，涵蓋 `/0`、裸主機位址和重疊字首。
- 埠區間包含兩端；TCP/UDP 和 IPv4/IPv6 mask 可以同時包含兩種值。
- pname 保留設定端 15 位元組規範化和子字串匹配語意。核心裡的行程位元組按與 handoff
  相同的 lossy UTF-8 和 trim 規則轉換，熱路徑不配置堆記憶體。
- 缺失的 pname、MAC、DSCP 不等於一般零值。domain 缺失時不滿足正向條件，也不會
  觸發負向條件的 veto。
- 設定的 `(must)` 是終結結果：設定顯式的 `must` 決策欄位，並跳過嗅探。Clash 模式
  不能覆蓋 `must` 或 `block`。

LAN/WAN 的 TCP/UDP 目的埠 `53` 先經過既有入口和控制面排除，然後只執行一次正常
有序策略，不單獨掃 must 規則；本機 listener 不能提前放行一般 LAN DNS。[路由參考](../reference/routing.md#出站目標與-must)
定義 DNS 所有權和[顯式本機路由遷移](../reference/routing.md#顯式本地路由)。

舊的 lowering 會丟掉 full/regex、把協定 OR 降成 TCP、截斷規則鏈、讓 DNS 只投影
第一條整規則、讓重疊 LPM 遺失祖先 bitmap。這些都不是需要保留的相容行為。共享 IR 和
獨立的 golden 案例要能阻止這些錯誤，不能把舊缺陷編碼進新後端。

## 唯一 policy 與網域事實

`CompiledRoute` 儲存中繼資料和 `CompiledCondition` 列表，不再另外維護一組正負
matcher 欄位。每個條件有一個 `CompiledPredicate` 和一個否定標誌。網域條件引用
policy 內不可變的已編譯 matcher registry。規則名只用於展示，不能當作 bitmap 身份；
相同的網域謂詞可以在同一個 policy 內共享 PredicateId。

### 原始碼組織

- [`crates/honk-core/src/routing/`](../../../crates/honk-core/src/routing/) —
  用戶態 `Router`、按優先順序排序的編譯規則、`route_action`，以及 `BinaryLpmTrie` 和
  Geo 資源的輔助程式碼。`domain.rs` 負責網域 matcher、`GeositeMatcher` 和建構期的
  內部去重表。`geo.rs` 在每次建構 `Router` 時只解析一次
  `geoip.dat`/`geosite.dat`，而且只解碼被引用到的類別。`category@attr` 在第一個
  `@` 處分開，屬性 key 按不區分大小寫的方式篩選。啟動時，流量路由和 DNS 路由共用
  同一份 Geo 資源快照；兩者編譯完成後就釋放原始快照，已編譯的 matcher 和指紋仍由
  各自的 router 持有。
- [`crates/honk-core/src/control/routing_matcher.rs`](../../../crates/honk-core/src/control/routing_matcher.rs)：
  把 IR 編譯成 `RoutingPushPlan`，不改 map。
  [`crates/honk-core/src/ebpf/real/routing.rs`](../../../crates/honk-core/src/ebpf/real/routing.rs)
  負責 generation map、擴充載入、目標掛接和發布。
- [`crates/honk-ebpf/src/route.rs`](../../../crates/honk-ebpf/src/route.rs) —
  靜態根和槽位介面，以及固定 ABI 的分派，不含直譯器或備用規則引擎。靜態 TC 呼叫方
  在這次同步呼叫前後負責封包解析和決策執行。
- 舊的 sockops/sk_msg 重新導向實驗不屬於目前資料路徑。部分核心版本出現 panic 報告後，
  這些實驗程式碼已被移除。現在只支援 TC 重新導向，載入器只尋找現有的程式名稱。

使用者態參考實作和核心編譯器用的都是這套表示。DNS 和 sniff 產生的是全部網域謂詞的
真值位，不是首條命中的完整流量規則。用於否定規則的謂詞也投影自己的正向真值，由
求值器負責否定。一個已知 domain 即使沒有匹配任何謂詞，也會產生一個存在的零 bitmap；
這個 IP 的最後一個有效 owner 消失時，才刪除條目。

DNS association 仍按 IP 組織，與來源用戶端無關，多個有效 owner 之間按 OR 聚合。它
不能證明共享 IP 上每條連線的精確 SNI。dial-mode reality check 和允許的 sniff
重路由仍由使用者態負責；遷移不會把 unknown 一律 punt，也不隱式改變四種 dial mode 的
語意。

## 生成函式 ABI

固定佈局放在 `honk-ebpf-common`，欄位只用固定寬度整數。Rust 的 enum 佈局、引用、
`String` 和 allocator 物件都不跨邊界。

`RoutingInput` 裡有網路序的來源位址和目的位址、規範化的 16 位元組 MAC key、規範化的
行程位元組及其長度、主機序埠、協定和 family mask、DSCP，以及 provenance/presence
資訊。`RoutingDecision` 裡有 outbound、mark、must、domain-finality 和 RuleId。
獨立的純量傳回碼用來區分成功結果與 evaluator 不可用或執行失敗。

`RoutingInput.flags` 分別儲存 MAC 存在位和 direct-finality permission。靜態
caller 從本次執行策略所用的同一份 Rule-mode flags 快照重建 permission，不再讀
一次 map。輸入仍是 128 位元組。loader 會拒絕最後一個欄位仍是 `mac_present` 的舊外部
eBPF 物件，所以用這個使用者態 compiler 之前必須先重建這些物件。

`domain_final` 表示在目前 dial mode 下，後續的網域觀察改變不了這一階段的路由。
三種情況會成立：policy 裡沒有網域謂詞；停用了網域重路由；或者已經取得完整的
learned-domain bitmap。Rule 模式下，如果從首條 live 規則到目前命中規則，包含目前
這條，字首都不依賴網域，那麼一般的 direct action 也可以成為 final，後置的網域
規則覆蓋不了 first-match。folded-false 規則不計入字首；正向和取反的網域謂詞都計入。
fallback 用同一套字首證明。沒有捕獲到 Rule-mode permission 時不套用這個額外證明，
以保留 Global 模式原有的交接和網域嗅探 authority。

非 DNS 流量裡，非 `must` 的 direct 結果如果網域 finality 還沒確定，交給使用者態時
必須編碼成 `ControlPlaneRouting`；如果照舊寫成最終 direct，TCP/UDP 初始化就會
跳過嗅探。這條非 DNS 路徑保留已知 direct、must、block 和 mode direct offload 的
終態語意。埠 53 的所有權按上面的參考處理。

輸入只在路由 miss 時初始化：重用現有的 per-CPU packet scratch，快取封包不會清空它。
slot 的 volatile 存取防止 LLVM 刪掉輸入或摺疊輸出。pname 規範化由一個獨立驗證、
有界的 global subprogram 完成，避免 Unicode 分支和 WAN parser 的狀態相乘。

靜態 caller 把邏輯結果轉成原有的 datapath action。`ControlPlaneRouting` 不是
`TC_ACT_*`。evaluator 出錯時，caller 執行原有的 fail-closed 清理，包括尚未完成的
UDP Preparing claim，不能把故障偽裝成一個請使用者態補判的請求。

## 受限原生後端

後端發出有型別的 8 位元組 BPF 指令、經過檢查的 label/fixup、常數比較、mask、map
lookup 和終結結果寫入。它不負責 TLS/QUIC 解析、撥號、mode、健康檢查或通用 VM。大
的 IP、MAC、domain 集合保留為索引，不展開成成千上萬條立即數比較。

emitter 在生成指令之前先摺疊空的內嵌謂詞：正向空謂詞讓整條規則不可能命中，取反空
謂詞不增加條件。規則因此變成無條件時，生成就在它的 action 處結束。後續規則和
fallback 不能留下不可達指令，否則核心會在語意驗證前拒絕載入。保留下來的 action
仍用原始 RuleId 和中繼資料。

每個 generation 都有自己的目的 IPv4/IPv6、來源 IPv4/IPv6 LPM maps、MAC 索引和
domain hash map。IP 按 family 分開，避免 IPv6 字首誤匹配 mapped IPv4。更具體的
LPM 條目繼承所有匹配祖先謂詞的位，最長字首查詢因此不會破壞規則順序。每個
generation 用完整的 `DomainRouting` bitmap，不再共享一個可能被新字首提前遮擋的雙
bank LPM value。

事實是值，不是指標。每個類別，也就是 domain、目的 IP、來源 IP、MAC，每次呼叫
最多解析一次：lookup 把 map value 裡 32 位元組的 `DomainRouting` bitmap 複製到該類別固定
的堆疊區域；輸入沒有這項事實，或 map 裡沒有條目時，就把區域填零。之後每處使用
都基於這次解析，不再讀任何 map 指標。每個條件直接在自己的區域裡測 bit，全零 bitmap
會讓所有正向 bit 都不成立，正好對應「沒有條目」；測完再套用否定。domain 在入口解析，
因為命中後還要置 `domain_final`。每條規則先執行完整的正向和取反目的埠、來源埠
條件，再執行其餘條件。

非 domain 事實在第一個真正到達的使用點解析，而不是在規則入口。每個使用點檢查本次
呼叫的 `R8` readiness mask 中對應類別的 bit，只有完整複製或填零結束後才置位。map
miss、缺失 MAC、非法 family 和已有全零 bitmap 都算已解析。前面的使用點如果被短路
跳過，bit 仍是零，後面的使用點仍會去解析。每次呼叫從空 mask 開始，不跨呼叫或
generation 保留狀態。逐使用點的 lazy guard 會增加程式碼，但能跳過已被前置條件拒絕
的路徑上的事實工作；這不代表已經測得淨吞吐量提升。

verifier 不能把 mask 的初值當成常數。如果用 `mov 0` 置零，它在每種解析歷史下都是
一個精確值；值不同的狀態互不吸收，後面每條行程名稱鏈都要按值的數量重走。#280 策略
在 Linux 6.12.107 上處理 160,415 條指令；四條事實規則排在二十九條行程名稱規則之前
的策略則是 368,874 條。所以入口從剛清零的 decision `mark` 把 mask 讀回來：
verifier 不會把記憶體讀取摺疊成剛存入的常數，低 32 位是未知值，執行時則恆為零。
三個 lazy 區域都用同一欄位的獨立讀取來預填，讓先於解析被驗證的使用點讀到已初始化的
堆疊；存入的字各自獨立，不和 mask 共享 scalar id。如果直接把 mask 暫存器存進去，
兩者會被關聯，狀態又分裂成 133,354 條。

每個 guard 都是對 mask 暫存器本身的一條 `jset`，兩條邊上都會細化被測的 bit，跳過
邊和解析邊到 bit 測試時一致。如果先複製到 `R0` 再測，跳過邊上的暫存器沒有細化，
那就是 82,234 條。三者齊備時，兩份策略分別為 53,741 和 100,645 條處理指令，接近
在規則入口無條件解析；在常數 mask 上只改 `jset` 則沒有變化。執行時，每處事實使用
都在解析完成之後。這些是 Linux 6.12.107 上的測量；如果 verifier 將來能沿儲存追蹤
記憶體內容，mask 又會變回常數。由於 mask 從 `mark` 讀回，入口從不往該欄位寫入設定
值。帶 mark 或 `must` 的 fallback，只在全部規則都失敗後到達的 fallback 出口寫入
mark、`must` 和直連 mark 索引；一般 fallback 不增加寫入。

複製 bitmap 可以限制 verifier 狀態增長。指標型別取決於 lookup 結果，verifier 不
會把 NULL 和 map 指標合併成一個狀態。於是一個跨越後續規則仍然存活的事實指標，會
讓它後面所有指令的狀態數成倍增長。兩條 `sip && dip && dport` 規則放在十五條行程
名稱規則前面，就能把一份策略推過 1,000,000 條指令預算：#280 在 Linux 6.12 上去掉這
兩條處理 159,837 條指令，加上就超過 1,000,000。複製出來的 bitmap 是純量，其餘
狀態相容時，已記錄的非精確純量狀態可以吸收其他路徑。

分支佈局同樣受 verifier 約束。verifier 先探索未定條件跳轉的 fall-through，所以
每個分叉，包括 IPv4/IPv6 分派，都把從 map value 複製的路徑放在 fall-through，把
填零放在跳轉目標。先被記錄的填零路徑一旦有 bit 測試可預測，就會變成精確值，無法
吸收後來的未知值。同一核心上實測，這份策略去掉兩條規則時處理 53,383 條指令，加上時
為 53,741。verifier-budget 測試通過只能證明可載入，不能證明這個指令數。IPv4/IPv6
仍分別構造 key、選擇 map，再合流到一次 lookup；只清零 IPv4 key 的 padding，不
清零那些馬上就會被覆蓋的位元組。

事實準備先用 hash 合併重複 key，只排序唯一 key，再在原向量裡繼承祖先位並壓縮保留
容量。內部跳轉由 assembler 自己分配的 ordinal label 標示，只有規則 source record
保留診斷文字。輸入和輸出偏移從共享 ABI 宣告推導，不再單獨維護一份偏移表。

策略身份 hash 涵蓋帶長度邊界的規範化規則欄位、有序 domain registry key 和選定的
geo digest。它不遍歷派生 trie，也不依賴 `Debug` 文字。有效的 no-op reload 身份
保持不變：只修改被忽略的行程名稱字尾，不應該重新發布相等的 native plan 並丟掉
sniff-only facts。

每個事實 LPM 保留 2,048,000 條容量，不預先分配；學習到的 domain hash 保留 65,536
條。字首數量和謂詞數量是獨立的：一個 GeoIP 謂詞可以包含幾十萬個字首。emitter 在
每次插入指令前檢查 1,000,000 條指令預算，耗盡時立即傳回錯誤，不再繼續展開指令或
fixup。

事實位按每個 generation 分配資源：目的 IP、來源 IP、MAC 各有 256 個 ID，按不同的列表計數，不按規則數量計數。引用同一個 IP 列表的規則共享 ID，列表按 interned matcher 身份識別；引用同一個 MAC 列表的規則也共享 ID，列表按值識別，順序敏感。取反仍保留在規則條件上。網域謂詞另有 256 個 ID，規範化 matcher key 相等時就共享。分支距離必須能用一個有符號 16 位指令偏移表示，否則以 `routing jump out of range` 錯誤拒絕發布。

容量和 verifier 限制都是明確的錯誤，不能截斷規則鏈，也不能把缺失的 outbound 預設
成 direct。生成源對映記錄 RuleId 和規範化規則描述。raw loader 重用現有的
syscall/BTF 基礎，不引入執行時的 clang/LLVM，也不寫另一個 ELF writer。函式原型
必須真實；raw `func_info` 和 `line_info` 用指令槽偏移，不能直接套用 ELF `.BTF.ext`
的位元組偏移。

## 同步槽與原子發布

每個相關的 TC 程式都暴露兩個真正保留的、非內嵌的 BTF-global 函式：
`honk_route_slot0` 和 `honk_route_slot1`。沒有安裝的函式傳回錯誤，其中不含
fallback 規則引擎。放行流量之前，後端把策略掛到每個已載入的 LAN/WAN L2/L3 路由
目標上。啟動時至少載入一個目標。後續目標在後端鎖之外驗證，兩個路由槽的目標中繼資料會
保留下來。提交時先掛上提交當時有效的路由 generation，即使驗證期間策略已經更新，
然後才發布為可繫結。之後每次發布都包含已提交目標，並且不去取得 verifier 的鎖。

`ROUTING_POLICY_ROOT` 是單項 map-in-map，指向不可變的 `RoutingPolicyDescriptor`。
descriptor 標出 slot、policy generation、feature bit，以及供診斷使用的 active
domain-map ID。一次路由只取一個 descriptor，再同步呼叫一個槽；快取命中的封包不會
多出這次 lookup。

已提交的路由 generation 不迴繞。`ROUTING_GENERATION_SEQUENCE` 跨行程重啟保留預留
值，20 位空間最多預留 1,048,575 次，其中包括失敗的發布和只替換 descriptor 的
NFQUEUE fence。耗盡時保留目前策略、拒絕進一步發布，並讓 NFQUEUE fence 保持關閉；
只要 host 分片佇列還可能存活，就不能刪除這個 pin。策略沒變可以跳過重編譯，但佇列
fence 仍會發布新的 descriptor generation。實體 carrier 格式見[資料路徑
ABI](./datapath.md#map-清單)，排隊中繼資料和 generation 生命週期見[控制面
admission](./control-plane.md#透明代理入口)。

控制器只呼叫一次 backend 發布，傳入不可變的 plan 和完整的 learned-domain slice。
後端自己挑 inactive slot，並在局部持有候選，呼叫方不必選槽，也沒有
pending-domain 握手。靜態 plan 重用和 DNS projection ownership 仍然是分開的。

發布與現有 reload、DNS publication fence 序列化：

1. 編譯並驗證完整候選，保留 active policy。
2. 建立並填入本 generation 的事實 maps，包括 learned-domain 快照。
3. 用這些確切的 map FD 和合法 BTF 載入生成擴充。
4. 給全部相關 TC target 的 inactive 槽完成掛接。
5. 最後只替換一個 generation root。
6. 更新成功傳回後，才允許退役舊 TC 槽和舊 maps；使用者態 IR/reference lease 獨立
   保有自己的生命週期。

Linux 6.12 在 map-in-map 更新成功傳回之前，會等舊的 non-sleepable BPF 呼叫結束：
[`maybe_wait_bpf_programs`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
用的是 `synchronize_rcu()`。一般 root store、固定延遲或者「有兩個槽」，都不是等價
的 grace。不能依賴不受支援的 freplace `BPF_LINK_UPDATE`，也不要 detach 或掛接
活躍槽。

root commit 之前，後端發布必須 all-or-nothing。map 建構、verifier、任意一個
inactive 槽掛接失敗，都保留舊程式碼和舊事實。不能用關閉資料路徑 admission 來掩蓋
錯誤，因為關閉狀態會直接放行流量；也不能把所有流量 punt。規則派生的 flags 和
domain writer 必須屬於同一個 policy generation。mode/NFQUEUE 協調和已有流仍由
原來的 controller 管理。

穩定的 policy pin 只保留 generation root。診斷工具透過 descriptor 找到 active
domain map，不能假設把同名 map 重新 pin 一次就能改變已載入程式持有的引用。

## 驗證與驗收

完整實作必須涵蓋現有的全部 matcher，並通過下面這些檢查：

- 獨立 golden：順序、OR/AND/not、缺失事實、must/block/mark、IPv4/IPv6、字首重疊、
  pname 規範化、domain 投影和容量失敗。
- 把 reference 的完整 decision 和真實生成的 BPF 相比較，不只比 outbound 或生成
  結構，還要包含來源中繼資料和 finality。
- 真實 TC/cgroup/netns：native direct、proxy、block、DNS、LAN/WAN、TCP/UDP 和
  快取流；queue/token 路徑保留真實的 NFQUEUE 合約測試。
- staging、verification、掛接故障，連續換 generation，以及舊讀者場景，用來證明
  不存在半發布，舊流的所有權也不變。
- 配對測量完整路由和流量的成本、冷熱事實、reload、JIT 大小和記憶體峰值。強化後的
  packed-data/AOT bounded-loop 是基線；埠微基準不能代表整個引擎沒有退化。

### 分支驗證記錄

目前 CI 的真實核心基線是固定的 Ubuntu Linux `6.12.0-061200-generic` VM。CI 在
hosted runner 上建構測試 executable，再到這個 VM 裡執行完全相同的產物，不會在
guest 內重新編譯。`just test-routing` 和依賴它的 `just test-netns` 共用同一個
完整、前置條件已就緒的一次性 VM gate，沿真實 root/slot 路徑檢查優先順序、完整
decision 中繼資料、容量失敗和發布失敗後的保留，然後執行所有權和 netns 套件。工具鏈、
兩個物件和 VM 環境的前置條件見 `honk-real-ebpf-tests` skill；受保護的夾具不在
共享主機上執行。

效能測量和歷史原型、實驗室記錄有意不放在本設計頁。reload 基準定義見
[`crates/honk-core/benches/reload.rs`](../../../crates/honk-core/benches/reload.rs)；
[`CI workflow`](../../../.github/workflows/ci.yml) 選擇 VM 檢查，
[`run-vm-gate.sh`](../../../.github/ci/run-vm-gate.sh) 負責主機準備和 VM 命令，
[`pins.env`](../../../.github/ci/pins.env) 定義固定映像。

## 相關文件

- [路由設定參考](../reference/routing.md)
- [資料路徑](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [控制面](./control-plane.md)
