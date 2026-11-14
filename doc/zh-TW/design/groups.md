# 代理群組選擇、健康檢查與預熱設計

honk 將代理群組解析為葉節點出站，追蹤其健康狀態，並限制預熱資源的保留量。

## 範圍

群組執行時由下列部分組成：`GroupManager`、`AliveDialerSet`、一律編譯的 Score 評分器、冷啟動 URLTest 準備流程，以及預熱資源協調器。群組欄位與策略語法見[群組參考](../reference/groups.md)。行程級的健康檢查、預熱與撥號設定 key 見[全域參考](../reference/global.md)。

## 代理群組管理器與選擇管線

`SharedGroupManager` 是穩定、可熱切換的 handle：

`SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>`

普通 reload 會建構一個完整的替代 `GroupManager`。它先透過 `migrate_selector_choices_from`，把 TCP 和 UDP Selector 裡仍然存在的成員身分分別遷過去，再安裝連線中斷、預熱和持久化回呼，最後切換內部 `Arc`。已刪除節點的選擇不會轉到同名的新節點上。原生 API 和 Clash API 的選擇寫入，以及管理器替換，都由同一個 `control/reload` owner 依序處理；寫入已被替換的管理器無法確認。因此讀取方看到的只會是完整的舊管理器或新管理器。

共用 reload 的正規化在 `control/reload/fingerprint.rs` 裡做。它依名稱保留設定群組的 UUID 和 `created_at`，插入、刪除、重排都不影響。改名即視為新群組，不繼承舊身分；程式化改名如果還帶著舊 UUID，也會重新生成。SIGHUP、明確啟用，以及 provider/runtime reload，包括 no-op 比較，都依這條規則處理，與原生觀測是否啟用無關。

`src/group/` 對外介面與內部實作依職責拆分：

| 模組 | 職責 |
| --- | --- |
| `mod.rs` | `GroupManager` 型別、共享 handle 與選擇計畫入口 |
| `resolver.rs` | 巢狀群組展開、成員/葉節點內省、環路切斷與 Selector 選擇遷移 |
| `filter.rs` | 依網路與位址族過濾存活性 |
| `policy.rs` | Selector、URLTest、LoadBalance、Fallback 選擇與延遲排名 |
| `score.rs`、`score/selection.rs` | Score 共享狀態、公開契約及依目標的群組選擇 |
| `score/ranking.rs`、`score/budget.rs` | 普通排名；保留的業務額度與在途記帳 |
| `score/evidence.rs`、`score/feedback.rs` | 作用域結果／來源規則與 exact-once 觀測所有權 |
| `score/comparison/`、`score/verification.rs` | 有界觀測儲存、成對響應證據、驗證問題、唯一的可選工作派送遍歷和唯讀成對關係；`score/tests/` 依職責拆分場景 |
| `state.rs` | URLTest/Fallback 快取、Selector 選擇與回呼 |

選擇遵循一條不變量：解析和存活性過濾完成後，撥號路徑只用策略選出的結果。Selector 返回有效的手動選擇，URLTest 返回目前勝者，LoadBalance 返回下一個成員，Fallback 返回固定成員，Score 返回排序後的合格葉節點，其中包含確定性的冷探索。失敗後的重試 race 由 `connection/` 負責，其他地方不再加並行 race。

唯一的多候選例外是沒有測量值的頂層 URLTest 群組。已有測量值的 URLTest，以及所有非 URLTest 計畫，都是權威的單葉節點計畫。未設定 `final` 的群組如果只剩一個唯一葉節點，而 TCP 存活性過濾把它排除了，那麼只有當目前 Selector 選擇路徑能到達該節點時，才會把它作為權威的最後嘗試。此時健康狀態仍是 dead，但真實撥號可以證明恢復，而且不會洩漏到其他成員或 `direct`。UDP 仍執行正常的存活性排除。最後嘗試服務會記一則限流 warning，每個群組 60 秒一則；預熱 peek 保持靜默。

UDP 選擇會先排除規範協定或設定不支援 UDP 的轉送葉節點，即使還沒有健康觀測也一樣。TCP 存活不能讓 VMess 或只支援 TCP 的節點獲得 UDP 資格。這些葉節點也不參與 Score 驗證，發布群組連通性時，不能把它們當成既有 capability 又存活的依據。`block` 仍是終態動作。Selector 已選的節點不具備 UDP capability 時，只能依原規則走顯式 `final`，不能改選兄弟成員。這類與目標相關的 VLESS UDP/443 拒絕策略仍在 admission 處終止，不能靠候選過濾繞過。

## 策略語意

| 策略 | 執行時行為 |
| --- | --- |
| Selector | TCP 和 UDP 各維護一份選擇。健康過濾之前，依序尋找對應網路的執行時選擇、`group.default`，再找第一個成員；只有 tag 缺失或不是成員時才繼續往後找。沒有合格葉節點時，只執行顯式 `final` 或同葉 TCP 最後嘗試。原生 API 可寫 tcp、udp 或 both；Clash 寫 both，讀的是 TCP 投影。寫入 both 時一次驗證、原子發布。有效選擇依網路持久化。啟用 `interrupt_connections` 時，會關閉捕獲了該群組路徑的舊 transport owner，不只是刪掉 tracker。 |
| URLTest | 選擇最小的減半遞推移動平均，TCP 和 UDP 各存一份選擇，套用 tolerance 滯後，並在撥號和選擇查詢時 lazy 重算。真實選擇變化時可以呼叫 `InterruptCallback`。 |
| LoadBalance | 依宣告順序輪流使用合格成員。每個群組的 TCP 和 UDP 各有一個獨立的 `AtomicUsize` 游標。輪轉從不呼叫 `InterruptCallback`。 |
| Fallback | TCP 和 UDP 各自固定為宣告順序裡的第一個合格成員。該成員死亡前一直固定；更靠前的成員恢復也不會觸發 failback。 |
| Score | 用 `policy: score` 顯式選擇後，Score 依據實際可靠度、新鮮目標品質和有界驗證，選出一個健康合格的葉節點；歷史樣本數量不算效能加分。不寫策略時仍預設 Selector。 |

群組中斷依連線建立時捕獲的已選群組身分或路徑，加上網路選擇，精確匹配 TCP/UDP owner。它不依目前群組成員或葉名稱重建匹配，也不依賴流 recorder 是否啟用。顯式選擇在發布前捕獲舊集合；回呼在同步 guard 之外執行，然後等待選中的網路確認關閉。選擇沒變就不會重撥。TCP 繫結 UUID、cancel 和 completion；UDP 繫結 token、generation 和 source view，並確認 backend 和 driver 已經退役。共享 XUDP 不會關閉其他 view 的 carrier，也不重放資料。選擇已經發布、但關閉確認失敗時可以返回錯誤，這不表示回滾。

同一已捕獲 owner 的並行 close 共用實際完成結果。退役失敗也由所有等待者繼承；不會僅因為已經處於 Closing 或 Failed 就報告 `Gone`。不存在或已被替換的 owner 仍是 `Gone`。自動中斷回呼只發起退役，需要確認的呼叫者等待該 owner 的 completion。

群組設定和執行時選擇是分開的。受限的原生 JSON Patch 依解析器記錄的來源位置，經既有協調器寫入 `.dae`，完整驗證後才執行真正的 reload。已接受的設定 revision 和磁碟檔案的 SHA-256 分別驗證，啟用前還會再查一次 revision。設定裡的 `icon` 只以驗證通過的 HTTP(S) URL 或 data URI 展示；至少 8 位元組長的 listener secret 值會被遮蔽。honk 不推測圖示，也不下載圖示。自動策略的固定成員只存在於目前 GroupManager 中，設定一啟用就失效。節點和 provider 的建立、刪除走另一套主檔案來源交易；修改既有條目仍用來源 PUT，見[API 參考](../reference/api.md#主檔案項目與-geodata-管理)。

### Score 評分與生命週期

Score 先經過與其他策略相同的存活性過濾。過濾用的 health family 描述與代理伺服器之間的連通性，單獨攜帶的 target family 決定評分分桶。所以經 IPv4 到達的伺服器仍能承載 IPv6 業務目標，而評分絕不會讓已判定死亡的節點重新入選。過濾後的計畫只包含一個權威葉節點，只有冷 URLTest 仍可依既有規則做推測性準備。

精確 key 是 `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`。domain 會轉成 ASCII 小寫，去掉末尾的一個點，保留連接埠；IP 目標保留 socket address。第二個有界的 `(group, TCP/UDP, target family or no family, NodeId)` 聚合層為冷目標提供先驗，也接收無目標的預熱樣本。精確目標、target-family 和全域聚合層依衰減後的有效證據分層混合：精確證據變多時逐步覆蓋聚合證據，老化後又逐步讓出權重。遞迴選擇帶著同一 target context，並把葉節點結果歸因到路徑上的每個 Score 群組。

目標路徑失敗仍計入全域、位址族和精確目標的數值結果，但硬失敗狀態只在精確目標上建立。型別化代理、認證、協定訊框或共享 carrier 故障，setup 前的未知錯誤，以及無目標失敗，都歸為節點故障；setup 前明確的目標拒絕仍算目標側。節點故障 fence 依賴它的目標和探測證據：無關目標失敗不會讓設定探測失效，探測失敗只撤銷自己目前的槽位。子 cell 繼承節點 incarnation、失敗時間和共享源事件身分。遲到的 fanout 仍逐流計失敗，但不能重新開啟已經恢復的同一事件。同一次分派裡的 carrier、來源、packet endpoint 或共享撥號故障，每條受影響的流，包括同一 H2MUX 連線上的各流，都報告該故障唯一的事件身分；獨立產生的故障仍各自計入。

carrier 來源由實際持有代理連線的邊界標記，不能從一般 QUIC 錯誤推斷。經過健康 packet 代理、連線已建立後的端到端 DoQ／DoH3 失敗，不證明代理 carrier 失敗。Packet-backed DNS endpoint 單獨保留實際的 adapter 故障，只在型別化 endpoint 遺失時附加這個來源，不覆蓋已緩衝的流重置、EOF 或畸形 H3 響應。setup 前的未知失敗仍依上面的保守規則處理。H2MUX 流重置和使用者態流錯誤仍屬於單流，連線 I/O 和 GOAWAY 屬於節點。AnyTLS session 仍活躍時出現的 TCP SYNACK 超時屬於目標；靜默 session 退役和 UoT 服務 open 失敗仍屬於節點。VMess 連一個響應標頭位元組都沒收到就 EOF 時，意義不確定，保留為 I/O 失敗；部分或畸形的響應標頭，以及真正的 carrier 錯誤，仍保留節點來源。XUDP END|ERROR 關閉的是多目標共享源，繫結流仍歸因於共享源失敗，不能虛構出某一個失敗目標。

業務 attempt 和終態證據都採 30 分鐘半衰期。setup 失敗在 Beta 信賴界裡受到更重的懲罰。首次取得資格需要四個有效的 useful 完成。新鮮的定向業務 RX 能把已取得的資格保留到事件時間之後 60 秒，但不增加完成數；失敗和 reload 會撤銷 lease。低於門檻的 RX 不能重新授予冷啟動資格，也不能恢復僅因 reload 失效的資格；真正失敗後的恢復走下面四個 reporter 的規則。歷史可靠度繼續影響 utility 和晉升。全域、位址族、精確目標的計數重疊時不相加，混合與保持成熟度仍用實際衰減後的計數。

首次選擇的效能啟發式保留獨立的事件時間，以及觀測次數上限為四的 `WeightedMean` 慣性。各指標 60 秒後降低信賴度、120 秒時過期，不受歷史完成數影響。設定探測 RTT 提供基線，新鮮且可比的目標響應和分方向 goodput 可以覆蓋基線。探測 RTT、setup 和首響應分別在自己的測量範圍內正規化，不把意義不同的毫秒值混在同一個池裡。HTTP 探測身分包含正規化 URI 和方法，探測 domain 和健康位址族也各自隔離。這套啟發式只用來提出候選，不是晉升證明。

普通首次選擇在服務池內比較相對 utility 和資格。不合格，或失敗後尚未恢復的現任，可以立刻轉往池內另一個成員。第一個發生在 setup/TX 之後、且嚴格晚於適用失敗／reload 邊界的合格定向 Traffic RX，會清除探索延遲，但只允許有額度的半開驗證。在同一個 cell 連續的失敗後可用性 cohort 中，四個不同 reporter 才能清除硬失敗事件，並授予目前 60 秒的資格 lease；歷史失敗不會被清空，也不會憑空虛構一個終態成功。即使其他目標已經恢復了節點聚合層，每個精確目標仍需自己的四份信用；只有 reload 造不出失敗來源。setup、單向 TX、探測、預熱和取消都不能恢復節點；取消會保留事實 RX。原始 cell 和父節點 incarnation 仍然是權威。

只有真正改選其他葉節點的普通逃逸，才能壓過可選驗證。失敗現任如果仍是普通贏家，可執行的備選仍能在預算內試探；失敗、退避和額度檢查繼續生效。

現任已經訓練、合格並恢復後，評估集裡所有合格挑戰者都要與這個固定的現任比較。晉升證據單獨維護。優先用雙方的精確目標觀測；沒有時，依規範順序挑至多八個雙方都響應、且挑戰者已合格的共同目標，等權比較；再不然就用同一個目前設定探測 cohort。先檢查支援資格，再套用目標數量上限，不能依測量值好壞挑目標。方向指標必須在同一組已選響應目標上一起合格，未知方向仍然是未知。跳過尚未合格、或因上限被截斷的已匹配共同目標時，比較保持部分覆蓋：已合格的子集仍能用於晉升和唯讀關係，但該成員的響應缺口仍待解決。沒有匹配上的目標，以及沒有保留共同時間塊的目標，不屬於這次比較的 cohort。

業務比較保留四個共同的 15 秒時間塊，各自在塊起點後 60 秒到期。設定探測攜帶生產者的實際週期 `I`，塊寬是 `max(15s, 2I)`，仍然只保留四塊，於是正常的 30s／60s 週期不必提高探測頻率也能累積到四個獨立 reporter。探測支援的到期時間取兩者中較早者：最早支援塊的起點加四倍塊寬，或者較弱一側最近一次支援加 `max(60s, 2I)`。未知週期沿用業務時間規則；週期為零或無法表示時不產生比較證明。週期和設定請求一起組成探測身分，每個指標仍要求雙方各有四個不同 reporter。無關的聚合均值、setup 和預熱不算證明；失敗、reload、incarnation 和探測 cohort 邊界繼續生效。

分方向 goodput 只有在以下條件都滿足時才貢獻優勢：某個已知方向至少提升 10%；其他已知方向都沒有退化超過 10%；響應沒有變慢超過 10%；而且合格的終態可靠度不低於現任。未知的上傳或下載仍然是未知，不當成零，也不算勝出；已知方向一升一降會報告為權衡。合格的實際可靠度優勢和成對響應優勢仍參與比較。綜合優勢必須跨過既有的保持門檻，上限仍是 `0.005`。支撐量取全域、位址族、精確完成數各自衰減後的最大值，不能相加。稀疏的精確證據不會削弱成熟保護。效能缺失或過期本身不構成優勢；保持現任不等於確認它可用，也不阻止在預算內試用，而且不新增固定的停留時間。

`ScoreFeedback` 是不可變的歸屬和來源工廠；每次啟動產生獨立觀測，clone 的意義不變。已選的業務計畫持有 `ScoreAttempt`，它的 `begin()` 可以失敗，成功後返回唯一的、已通過 admission 的 `ScoreBusinessGuard`。guard 負責取消清理，直到在既有的物理或邏輯 I/O 起點把所有權交給 `ScoreReporter`。setup 和首響應依事件時間各發布一次。TCP 已接受的寫入，以及 UDP 已成功傳送和交付的進展，進入互不重疊的 1–10 秒事件驅動視窗。被測方向至少要傳輸 64 KiB，流還要有雙向進展和響應；這個視窗不增加 Beta 成功次數。終態最多結算一次，不會重複加入已發布的位元組；最後一個未完成 handle 釋放時取消。拒絕、取消和關閉只撤銷 attempt，不製造失敗，已經實際發生的觀測會保留。空閒或應用層限速不是壅塞證據；不新增取樣任務、負載重放或連線遷移。

Score 權限切換之前捕獲的普通待開始嘗試，只要不持有可選 token，就可以繼續轉送，但不評分。guard 保留原始業務身分，不發布目前證據，也不發額度。失效的可選工作仍會被拒絕，不能降級成免費的挑戰者撥號。物理 runtime admission、路由和型別化拒絕的語意都不變。

TCP relay 在 copy 和 splice 路徑中區分用戶端斷開與上游失敗。用戶端側的 reset、abort、broken pipe、未連線 socket、異常 EOF、socket 超時或主機／網路不可達錯誤，對 Score 依中性取消結算，不撤回已接受的 RX，也不清除既有失敗／退避；relay 仍返回原始 I/O 錯誤，連線錯誤統計保持不變。同類上游錯誤、協定錯誤及未明確歸因的本機失敗保留既有失敗處理。日誌等級較低本身不代表錯誤中性。

業務 RX 回報獨立於吞吐視窗：首次合格非零 RX 立即發布，隨後每個 reporter 每秒至多一次。普通單向 TX 回呼不補發被限頻的接收事件，也沒有定時器把靜默變成進展。共享源首次確認成功的非零傳送，可補認在其序列傳送開始後已交付的回包，使用實際 RX 時間而非確認時間；排隊、失敗或已退役的傳送不能授予證據。限頻中的失敗後 RX 仍可能等待下一次可發布 RX 或終態，不保證一個自然秒內恢復。活躍發布更新可用性及作用域內恢復門檻，不增加 Beta 終態。

共享源 witness 描述的是傳輸嘗試區間，不是 UDP 請求與回包的逐包關聯：匹配的 peer 可能在此區間內返回延遲資料。時間點記錄在通過 core source gate 後、backend 佇列 admission 前，只有傳送成功獲接受後才可用於證據；它不證明是哪一個 datagram 導致回包。

可選工作在節點專屬工作開始時記帳，早於 DNS 和物理撥號 admission 等待；這與業務 reporter 的邊界不同。帶撥號 admission 作用域的 TCP 撥號，在首個物理嘗試獲准後，或重用 session/QUIC 連線上的邏輯 open 開始前啟動 reporter；等待冷物理撥號 admission 時不啟動。回呼只執行一次；未經過這兩個邊界便已完成的路徑保留完成時的備援回呼。

尚未開始工作的作用域，只有仍在等待物理撥號 admission 時，超時才屬於本機容量拒絕。admission 前的 DNS 解析超時仍是普通超時，保留既有的合格候選重試路徑。分類先檢查作用域，再取消 future；取消只移除該次申請的待 admission 登記。

普通路徑和 race 後的 TCP ready/bare 補池仍記錄 setup 品質，但其成功與失敗都不改變真實流量的連敗計數或探索退避。UDP driver 在自己的健康回呼可能同步退役 endpoint 之前判定終態，避免該回呼把錯誤改寫成中性的取消或成功。主動退役在沒有回包時保持中性，已有回包時計為成功；行程關閉和單包壅塞保持中性，回包空閒到期僅在從未收到回包時計為超時。

對仍存活的 endpoint，已證明的 QUIC 通路停滯會退役共享 carrier，因此 Score 依節點故障歸因，即使目前錯誤屬於單包壅塞或已有回包後的空閒到期。拒絕、主動退役和本機回包交付取消保留原有優先順序；Alive 仍獨立分類原始 I/O 錯誤。

Traffic reporter 覆蓋透明 TCP/UDP、受支援的 DNS exchange 和 UI 下載，DNS 歸因跟隨實際 carrier，包括 UDP 截斷後的 TCP 重試。`HealthProbe` 只在全域聚合探測槽記錄設定測量品質，不結算業務可靠度或清除真實連敗；`Warmup` 只記錄 setup 品質。視需要 delay 測量保留 API/Alive 延遲歷史，但不建立沒有消費者的 Score exchange reporter，也不把任意目標失敗計入真實撥號序列；實際 session 準備仍可報告預熱品質。獨立 QUIC 握手提供 DataUdp 探測品質和既有存活性恢復，不虛構吞吐或業務成功。

每個保留的 `(group, TCP/UDP, target family)` 預算固定兩件事：首次成員數 `n`，和冷啟動額度 `B`。成員數不超過四個時 `B` 覆蓋全部成員，否則取 `ceil(sqrt(n)) + 1`。額度從原始業務賺得：每開始一次原始業務，計數為 `N`，額度增加 `1/q`。通常 `q = 16`。如果該群組在這個網路上的近期原始業務依五分鐘半衰期換算每秒至少兩筆，並且該作用域近期至少有三個可選試用結果，依十分鐘半衰期、衰減權重超過 2.5，其成功不低於 80%，那麼 `q = 8`。證據需要的試用次數是固定的，所以試用有效的忙碌群組能更快累積額度，空閒群組則維持較小的比例。目標拒絕不計入這裡的試用結果，reload 會清除這些結果。

普通選擇處於 observedUsable，並且本次讀取涉及的每個作用域近期結果成功率都低於 20% 時，可選試用暫停。近期失敗達到兩次及以上時，等失敗衰減；只有一次時，每次只放行一個試用。暫停的作用域拒絕試用，效果和額度耗盡一樣：每個被拒絕的候選計入 `budgetBlocked`，以 `budget` 呈現等待原因，已有試用在途的成員仍顯示 `inFlight`。沒有可用的選擇時，探索繼續進行，因為這是 Score 脫離故障的途徑；恢復性延續不受影響。

設已賺得額度為 `E`、已花費的可選試用為 `V`、未開始的預留為 `R`，始終滿足 `V + R <= B + floor(E)`；未花費的已賺得額度最多為八。`N` 包含被選為試用的原始業務，但重試、clone、巢狀重複計數、讀取、時間流逝、證據過期和新目標都不能產生額度。一次原始計畫經過的每個作用域只計一次；延續嘗試即使進入其他群組、網路或目標位址族，也不能再次賺得額度。根業務計數對整個巢狀路徑去重。保留作用域在成員變化和 reload 後仍持有額度；只有刪除群組或重啟才結束這段生命週期。

reload 後，已開始的試用仍結算歷史結果與成本計數。只有 `(group, node)` 仍是目前設定成員時，其結果才影響目前試用收益；已移除成員不能暫停或加速替補成員的額度累積。保留成員仍可跨 authority 變化貢獻結果。

預留只在節點專屬工作開始時支出；釋放最後一個未開始引用或使未開始預留失效會退款，開始後取消不退款。reload 保留已開始工作的在途記錄，直到結算或既有到期邊界。UI 與訂閱重定向、DNS 重試和 TCP 替代嘗試保留原始業務身分，不能產生試用額度或把既有試用重標為免費恢復。可選工作只有一條路徑：已授權的定向 rank 依派送順序遍歷已評估挑戰者，為帳本首個接受的成員預留一份額度；預算拒絕結束遍歷，在途拒絕則嘗試下一個成員。每個成員針對其未決問題在同一目標上至多有一個尚未得到回答的試用，資格問題跨目標計算。缺少流量時仍無結論。真實失敗保留 5 分鐘至 6 小時退避，除非真正的作用域內 RX 開啟恢復；試用不取得已提交現任保護。

成員的未決問題只有一個，依下面的順序取第一個成立的：

- 連敗後的恢復；
- 沒有近期可用性時的可用性；
- 成對問題。條件是普通選擇本來能比較這個成員，但所選成員與它的原始比較對缺少本作用域的業務響應，而且該響應要新鮮、非部分，並且晚於所選成員最近一次退化。這裡的本作用域，精確目標就是該目標本身，聚合讀取則是共同目標；
- 以上都不成立時為資格。

設定探測不能解決成對問題。派送順序先放沒訓練過的成員，再依未決問題的進展從多到少排；成對問題的進展，是與參考成員共享有效時間塊的挑戰者 reporter 數量。然後依最久未被選中排。從未被選中過的成員，用設定探測提示打破平局。近期順序只在歸屬工作於 begin 時獲准後推進，未開始、被拒絕或未計分的預案不改變順序。除恢復外，只有完成數加上未完成工作仍少於所選成員完成數的成員才會被派送。首次選擇跟隨證據；先訓練挑戰者會擠掉探測優先的所選成員，所以冷啟動探索要等所選成員取得一次完成後才開始。唯讀的 question、action 和 wait 取自同一順序裡的第一個成員；wait 只附加帳本目前的預算或在途拒絕。節點來源明確區分失敗時間與失效邊界；借用的 cell stamp 統一目前父節點和有效 fence 檢查，不增加快取。

Carrier 壓力提示獨立於業務結果和效能評分。與 Score 繫結的 runtime 在 honk→代理伺服器的物理連線上觀測持續 TCP RTT／重傳或 QUIC RTT／丟包壓力，既有五秒心跳接收新鮮事件。提示只在既有驗證頻率、資格與退避約束內重新開啟比較新鮮度問題，不改變 utility、資格、失敗計數、Alive 或既有連線。晉升仍需真實業務觀測支援。

取樣使用 1–10 秒活躍區間，要求有新 ACK 進展，以及至少 4 KiB payload 位元組進展或 32 個 QUIC DATAGRAM frame。RTT 先以四個活躍樣本訓練基線，再要求連續三個區間同時達到基線的 1.5 倍且增加至少 20 ms。傳送側重傳／丟包壓力要求足夠出站 payload、至少 32 次傳送、三個重傳／遺失封包、非零重傳／遺失位元組及 5% 計數比，連續滿足三個區間。這只是壓力啟發式，不是應用丟包率，計數未必對應同一批封包。未知／空閒區間不能證明壓力或恢復；兩個合格正常區間才能重新解鎖事件。每個 runtime／carrier 位址族至多每 30 秒發布一次，提示在 60 秒後過期，讀取不續期。

健康過濾位址族不一定是位址 race 最終使用的 socket 位址族。生產者保留實際位址族槽，Score 則把最新新鮮事件視為節點 owner 需要重新比較的提示，而非目標／位址族效能懲罰。只有被測 carrier 承載的網路接收提示，Shadowsocks TCP 壓力不影響原生 Shadowsocks UDP。熱連線上的設定探測可能貢獻 carrier 活動，但不能成為業務證據。普通 UDP 丟包、裸 SOCKS／direct splice、反向丟包及代理到目標的丟包仍未知。reload fence 舊事件和已替換的 owner，不匯出 carrier 或目標身分。

Score 狀態隨 manager 初始化，證據條目視需要填入，由 mutex 保護且僅存於目前行程記憶體：精確 cell 使用 4,096-entry LRU，聚合 cell 使用另一個 4,096-entry LRU。精確目標證據衡量 transport 品質，並不是語意解鎖 capability 的結果；需要這種粗粒度 cohort 時，可用既有 routing 或 geosite 規則選擇專用服務 Score 群組。已提交的行程內 reload 會重用同一狀態 `Arc`、發布新的合法 `(group, member)` 集合並修剪已刪除 cell；已刪除成員的延遲回饋會被忽略。行程重啟會清空一切。Score 不提供調整項；評分 cell 與僅由 scorer 持有的目標資料不會進入日誌、持久化儲存或任何 API 輸出，既有的 `/connections` 目標後設資料保持不變。

獨立比較儲存最多保留 512 個 cell，邏輯記帳分配上限為 1 MiB，包含儲存／vector 容量及持有 key 的容量。這個界限不是行程 RSS：分配器開銷、其他 Score 狀態和行程其餘部分均不在其中。淘汰或拒絕後，比較證據保持未知，不會退回成無關均值。

中性 cell 保留在有界 LRU 中，不在其他 reporter 仍持有 incarnation 時提前刪除。reload 清空設定探測基線並拒絕舊 generation 探測觀測；已通過 admission 的業務流對存續成員和匹配 incarnation 仍可報告。淘汰後的舊 reporter 不能重建 cell。

#### 有條件的驗證結論

預設目標是在已觀測業務可用性的保護下比較響應品質，有可比證據時普通晉升才納入分方向 goodput。轉送仍立即選擇。`provisional` 與 `observedUsable` 描述目前路徑的業務證據；唯讀 `challengers` 另行報告所選成員與已評估挑戰者之間新鮮的成對響應關係，不存在全群組比較結論。10% 指標容差表示實際意義上的近似等價，不是誤判機率，也不是全域最佳證明。

關係不使用普通切換門檻或完成數成熟度，而是對實際響應值使用包含邊界的對稱 10% 容差（`high - low <= 0.1 × low`），支援零值和亞毫秒響應，邊界只容許浮點捨入誤差：落在容差內為 `equivalent`，否則響應更低的一方更快。關係讀取所選成員的原始比較對（即普通晉升讀取的同一批比較對），且只讀取其中新鮮的合格響應指標；可靠度、可用性、分方向 goodput 與保持仍由普通選擇負責。每項關係標明其依據，並隨該響應指標到期。

比較對不需要聯合對齊：每個挑戰者與所選成員的原始比較對只依自身共享時間塊判斷，不同挑戰者的歷史之間不產生驗證需求。不新增探測、不複製請求，也不保證任意負載下必然完成。

同一判定器識別可用性與響應證據缺口，安排下一次預算內真實流量驗證，並生成唯讀 API 摘要。精確目標檢視不會把共同目標或探測證據標為 `targetResponse`；HEAD/QUIC 成功最多支援其目前設定測量 cohort，不證明業務目標可用或持續頻寬。`nextBusinessFlow` 表示未來真實工作需求，不是已預留或已派送 I/O；`question` 與 `waitReason` 區分證據問題，以及預算、在途、可比流量和退避等待。缺少傳輸證據不產生問題或工作：分方向 goodput 等待真實負載，不在背景測速，也不複製使用者請求。聚合讀取檢查已保留 IPv4/IPv6 預算的等待狀態，不建立或花費作用域。

業務比較支援保留 60 秒邊界，設定探測比較採用上述隨週期調整的保留視窗與最近支援邊界。業務失敗與提交 reload 撤銷近期可用性，但不清空長期可靠度。API 讀取即時重算有效性，不推進取樣或計數；已授權 Apply 利用既有有界歷史記錄臨時、可用與驗證選擇。詳見 [API 語意](../reference/api.md#score-驗證資訊)。

每個 Score 群組／網路只擁有一個已提交的服務候選池，所有父群組入口與 target 共用。普通首次選擇、失敗逃逸、恢復、晉升和可選試用都從池內選擇，勝者不再額外佔用一個名額。冷啟動把普通首選納入已排名名額，更新排名時先考慮普通資格，再比較 utility 與探測平局，避免未合格成員擠掉唯一可用服務。容量 k 仍隨真實業務變化：原始開始數依五分鐘半衰期衰減，再換算到 30 分鐘證據半衰期；在 `q = 16` 下賺得的可選開始額度，一半用於讓每個挑戰者保持四個有效完成。記換算後需求為 D，則 k = 1 + ⌊D/128⌋；超過四個唯一候選的檢視下限為 3，上限為 min(25, ⌈√n⌉ + 1)，45 個候選時為 8。更小的群組只使用實際可用成員。檢視大於 k 時，從這 k 個名額中保留一個十分鐘輪轉位置。輪轉成員被選為普通服務勝者時，與一個已排名成員交換位置，成員集合不變，被換出的成員獲得新的輪轉週期；不能僅因輪轉到期就驅逐該服務勝者。該上限集中工作，但不保證足夠的可比流量或全域最佳選擇。

只有已授權 Apply 初始化或更新候選池。每五分鐘重新排名一次；容量擴大等待該更新，需求下降引起的收縮要求 k 至少下降 2。連續三次節點級失敗或權威健康過濾可以提前換入替補，但不增加容量。僅在過濾／重試檢視中暫缺，或某個精確目標失敗，本身不會移除共享成員。沒有替補時，失敗成員仍可在預算內恢復。reload 重置成員與容量並保留衰減後的需求；Readonly／Peek 使用已提交成員，初始化前則使用臨時有界投影。

巢狀名額儲存直接子群組名稱，而不是可設定 UUID。該子群組提供不同的合格代表節點時，Apply 在同一名額內替換舊代表；暫缺子群組和直接成員不會被誤判為代表發生變化。Selector 只 Apply 已選子群組，即使子群組目前已提交的 Peek 看不到成員，也不能阻斷這次 Apply。Selector 父群組不另建 Score 池或錢包；獨立設定為 Score 的祖先仍擁有各自預算。

完整解析子群組後仍無候選時，可以撤回該子群組保留的名額，包括健康／capability 過濾及 Selector 固定選擇不可用的情況；僅重試排除造成的缺席不能撤回。選擇 IPv6 `final` 前，內部 IPv4 預檢透過同一選擇路徑推導可能的候選池，但不提交池、不預留工作或更新計數。預檢必須具有目前 authority，不改變公開 Peek 的語意。

每份尚未開始的策略選路嘗試，都會在 begin 時、證據鎖內、節點專屬 I/O 之前重新檢查其捕獲的普通服務池義務。成員離池或池尚未初始化時，以型別化取消拒絕，並退還未開始的預留；過期普通計畫和重試都不能把這種拒絕降級成免費工作。已開始的嘗試與 relay 保留原有生命週期及結算規則。新重試雖然沿用原始業務身分，仍須重新通過 admission。因此，活躍連線可能跨越已退出候選池的成員，k 不是所有現存連線所用節點的歷史聯集上限。

原生 pin 使自動代理群組依 Selector 行事時，不為該 owner 附加普通 Score 池義務；原有 attribution 和巢狀普通 Score owner 的池義務仍須保留。即使多個子群組別名共用葉節點，候選觀測仍保留各成員的健康排除事實；Score utility 與資格原因只更新通過篩選的行。

顯式 `final` 只豁免其所屬群組的普通候選池，普通選擇該路徑的 Score 祖先仍須約束葉節點。唯一 TCP 葉節點恢復路徑也進入同一個池，不能藉此改選未選中的 Selector 兄弟。獨立健康探測和預熱觀測不屬於策略選中的業務，保留原有作用域。探測基線仍可用；比較單元的 admission 跟隨服務池成員，並保留四個近期 Apply 勝者及初始收集的既有例外。原有信用、身分和 TTL 規則不變。成員檢查受 k 限制；池重新排名對候選排序，輪轉則遍歷一次。

近期失敗排除會讓不具普通資格的成員退出待驗證，直到該失敗早於效能證據期限。排除不表示該成員的指標已測得近似等價或無退化，分層權重衰減仍可能讓它更早重新取得普通資格。響應退化會要求重新整理比較證據，它只把 setup 或響應樣本與同一精確目標的歷史比較；聚合 cell 混合了延遲本就不同的目標，因此聚合比較只因 carrier 壓力重新開啟，不因跨目標差異開啟。

近期可用性要求所選 cell 的連續可用性 cohort 中有四個不同的 Traffic reporter，每個都在 setup 和非零 TX 之後回報定向非零 RX；流尚未結束也能取得資格。每個 reporter 及其 clone 在同一 cell/cohort 內只計一次，後續合格 RX 僅更新 cohort 的事件時間。這不表示四條目前仍開啟的流，也不表示統計獨立；全域／位址族／精確目標的重疊計數不能相加。探測、預熱、單向 TX，以及早於 setup/TX 的 RX 都不能取得可用性證據。

適用失敗、提交 reload 或至少 60 秒的進展間隔會重置 cohort。一個恢復接收的 reporter 不能復活四份舊信用；存續 reporter 可在失敗／reload 與 incarnation 邊界內各貢獻真正新增的 RX。終態與活躍回報共用去重，只依實際 RX 時間補發合格進展，不能使用清理時間或跨越已過期視窗。中性取消保留事實 RX 而不增加成功。可用性本身不授予冷啟動資格；只有真正失敗 cohort 的四個新 reporter 才能取得上述恢復 lease。資格和恢復缺口仍獨立於比較支援接受有界試用。

一次已授權的多候選 rank 只增加一個最終原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`insufficientEvidenceHeld` 表示沒有挑戰者獲得晉升，且普通 utility 贏家缺少合格的共同效能比較，並不表示沒有可靠度歷史。`directionalTradeoffHeld` 表示無挑戰者晉升時，存在已知方向一升一降的權衡。`ordinarySwitch` 獨立統計同一 `(group, network, family, target)` 歷史中的普通已提交 A→B 變更，不含首次選擇和試用；`switchFlap` 是其中八次普通選擇內返回前一贏家的子集。`deadFiltered`、`failStreakExcluded`、`exploreBackedOff` 累計受影響候選，不是失敗連線數。歷史仍是 4,096 筆 LRU，缺失／淘汰歷史不能證明發生了切換。Peek、proxy/stat 讀取、單例旁路和最後嘗試不增加這些原因計數。經認證的 `/stats.score` 匯出固定群組／網路原因、驗證和預算欄位，以及證據快取總量，不匯出 scorer 私有節點／目標／cell 身分。試用結果與耗時／setup 成本計數描述實際觀測工作，不表示反事實額外失敗或因果額外開銷。

Clash 將 Score 群組表示為 `type: "url_test"`，在 `now` 中報告目前聚合 TCP 勝者，並拒絕 `PUT /proxies/{name}`。

### URLTest 排名與滯後

延遲採減半遞推移動平均：

`next = (previous + sample) / 2`

第一筆樣本直接初始化平均值。這個演算法沿用 dae 的 `min_moving_avg` 語意：近期變化能較快體現，單次抖動不會成為既定值。

`SelectionNetwork::Tcp` 和 `SelectionNetwork::Udp` 各自保留勝者。TCP 用 TCP 探測的平均值；群組設定了自訂目標時，改用 `(member tag, check_url)` 的平均值。UDP 先用 `DataUdp`，再用 `DnsUdp`。如果在目前位址族下，所有合格候選在這兩個域保留的移動平均值裡都沒有真實的 UDP 排名依據，就沿用 TCP 的選擇。僅由撥號失敗產生的合成樣本不會讓這個退回失效；真實樣本被歷史環狀緩衝區淘汰後，保留下來的排名依據仍然有效。所以有效的退回順序是 `DataUdp → DnsUdp → TCP`。

有效 tolerance 是 `max(configured tolerance, 1 ms)`，即 `group.tolerance.max(1)`。滿足下式時保留目前選擇：

`best latency + tolerance >= incumbent current measured latency`

目前選擇的基線在每次選擇時重新讀取，不保留勝出時的舊值，所以已經退化的現任可以被替換；這與 sing-box 的 `Select()` 行為一致。現任如果帶著未清除的失敗標記，即 strike，就跳過滯後，立即替換這個剛失敗的節點。

探測失敗只更新活性和冷卻，不產生合成延遲樣本，也不記排名 strike。只有連續兩次真實撥號失敗，才會追加一個不顯示的 10 秒合成佔位樣本，並記一次失敗 strike。單次瞬時失敗，也就是這條流量被重試 race 救回的那種，不留下任何選路狀態。連續計數只在真實撥號成功時清零，所以探測仍存活但撥號失敗的節點仍會繼續累積失敗。真實歷史和移動平均都保留，但帶有未清除撥號失敗 strike 的候選會排在所有未降級候選之後。strike 只有連續 `max(strikes, 2)` 次真實成功後才會清除，避免不穩定節點靠一次探測成功就重新排到第一。

真實流量也會直接回饋排名，但只對 TCP 生效。每個節點為自己新鮮的撥號延遲維護一個自引用 EMA，α=1/8，前 3 次撥號算預熱期。命中就緒連線池的撥號沒有網路往返，不計入。連續 3 次撥號慢於 `max(min(2×EMA, EMA+500 ms), 250 ms)`，在 `report_dial_latency` 裡寫作 `max(min(2×ema, ema+500ms), 250ms)`，就記一次失敗 strike 並觸發緊急探測。250 ms 的下限是為了避免目前選中的低延遲節點因正常負載抖動誤判，例如從 60 ms 變成 120 ms。探測的移動平均不受影響。誤報，也就是目標分佈變化而非節點變差，會自行恢復：緊急探測成功後，連續的探測成功會清除 strike。漸進式劣化仍由探測週期負責；UDP 劣化還是依探測週期加 `DataUdp` 流量閾值處理。

權威 URLTest 建立失敗保留既有的單輪前三名候選重賽。重賽的新 deadline 不會建立另一份原始 Score 業務，即使首輪在自己的 deadline 之後才結束。Score 所屬建立失敗則至多依序嘗試一個不同葉節點，在排名前排除失敗 `NodeId`，不要求普通評分先改選。Score 兩次嘗試共享一個絕對建立 deadline 和物理撥號預算；規範解析保留 Selector 選擇，只允許首選真正經過的 final 群組邊，顯示名稱不授權備援。型別化本機拒絕、未通過 admission 時容量耗盡、取消和 generation 關閉均為終態；應用負載寫入後不重試。

群組的 `check_url` 會建立獨立的 TCP-only 存活性和延遲狀態，key 為 `(member tag, check_url)`。失敗只會從使用該目標的群組中排除該成員。Selector 群組忽略 `check_url` 並印出 warning。URLTest 在超過 `idle_timeout` 後暫停探測；未設定時使用健康層預設的 30 分鐘，下一次真實選擇會立即喚醒探測。

## 巢狀代理群組與成員身分

`Group.groups` 指定子群組。每個子群組只貢獻一個候選：該子群組策略針對目前網路和位址族選出的葉節點。父群組將其作為一個成員排名或固定，不把所有後代合併進父策略。

解析受 `MAX_GROUP_DEPTH = 8` 和每次遍歷的 visited set 限制。建構階段還會對群組邊執行 DFS，切斷每條形成環的邊並印出 warning，防止異常群組圖阻塞選擇或內省。

成員邊與顯式 `final` 邊使用同一個有界遞迴解析器。子群組策略沒有合格選擇時，
只沿自己的設定 final 繼續；父群組仍把該子群組視為已選成員。Final 鏈保留選擇鏈和
Score 歸屬。普通成員/展示清單不包含 final 邊；健康註冊、預熱發現、Score 成員
和 datapath 連通性使用包含 final 的可達集合。葉節點健康轉換會重算所有受影響
祖先的 alive slot，而不只更新首次對映到的一個群組。IPv6 健康位址族重試會先選
可用的普通 IPv4 代理路徑，再執行 final，業務目標位址族不變。缺失或成環的
final 仍然拒絕；這裡不重試傳輸錯誤或終態 packet rejection。

Selector 在候選展開和健康過濾前繫結具體節點或子群組成員；依名稱設定的預設選擇和 Clash 寫入在節點 tag 重複時，依宣告順序繫結第一個匹配的 `NodeId`；原生成員 ID 可選擇特定直接成員。服務選擇只對已選子群組執行 Apply，再檢查父群組健康條件；不預覽未選兄弟，也不要求子群組已提交的 Peek 必須先成功。TCP 與 UDP 的已選路徑不可用時，都只能透過其明確設定的 final 繼續選擇。候選保留來源子群組的引用，不再根據顯示 tag 反查身分。選中的自動策略子群組仍可在自己的成員範圍內選擇其他葉節點。唯一 TCP 葉節點的最後嘗試遍歷也遵守每一級 Selector 選擇，而顯式延遲測試仍可檢查全部成員以發現恢復。

展示和 API 輸出仍使用成員 tag；即使物理撥號落到更深的葉節點，實際選擇也會單獨保留具體節點或子群組身分：

| API | 返回內容 |
| --- | --- |
| `node_names_in_group` | 直接節點 tag 加子群組 tag |
| `leaf_node_names_in_group` | 該群組下可達且去重的真實葉節點 |
| `delay_test_members` | 每個有效成員一個 `(member tag, current leaf)` 對 |
| `selection_chain` | 從群組經已選子群組到葉節點的目前鏈 |

自訂 URL 探測會在每個週期重新解析 `delay_test_members`。子群組透過其目前選擇接受探測，但結果記錄在子群組 tag 下。因此父群組把子群組視為一個穩定成員，符合 sing-box RealTag 語意。

## 冷啟動 URLTest UDP 準備

只有沒有可用測量值的頂層 URLTest 計畫，才能準備多個 UDP transport。候選依絕對偏移 `0 ms`、`30 ms`、`80 ms` 啟動，之後每隔 `80 ms` 啟動一個，同時最多三個準備任務。絕對排程可以避免較早的慢任務把後面所有啟動時間一起推後。

第一個成功且仍然合格的候選勝出。出現勝者或到達 deadline 時，honk 會在 scheduler 返回之前中止並排空所有已啟動的 loser。隨後它再次檢查勝者資格，並在 endpoint 發布或傳送第一個應用封包之前提交協定狀態。只有已經觀察到的準備 `Err` 會影響流量健康。未啟動的任務、取消、已經變為不合格的成功結果，以及成功排空的 loser，都是中性的；排空時發現的已完成錯誤仍算已觀察錯誤，會計數。AnyTLS 用呼叫者自己的 provisional pool slot，所以 loser 不會發布 session。QUIC 協定建構 detached client，只發布最終勝者；loser client 連同它的推測任務一起關閉。

權威單節點計畫和冷啟動 URLTest 共用一個絕對的 transport preparation deadline：`max(10s, 4 × connect_timeout)`。它在前面的準備開始前就建立，覆蓋代理主機名稱解析、物理撥號 admission、協定／控制協商、stagger 等待、滿三個任務時的容量等待，以及最終勝者的 commit；到期後不再啟動新候選。此前的嗅探／路由，以及之後的 reply socket 建立、endpoint driver ready 和封包傳送，不在這段 deadline 之內，繼續依各自的生命週期或 I/O 上限處理。

## 健康狀態與探測

`AliveDialerSet` 使用節點 `NodeId` UUID 作為節點健康狀態、註冊、歷史、緊急觸發器與延遲集合的 key。顯示名只用於日誌和探測查詢，不是身分。每個節點有六個獨立狀態：三個域分別覆蓋 IPv4 與 IPv6。

| 失敗來源 | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| 週期探測 | 3 | 3 | 3 |
| 真實流量 | 10 | 3 | 50 |

探測失敗和流量失敗各有獨立的計數器。探測失敗用 5 秒到 300 秒的指數冷卻。另有一個 `min(5s, check_interval)` 的恢復排程器，只檢查冷卻已到期的死亡域和位址族；深度退避的狀態仍依 300 秒節奏繼續探測，不會永久停掉。

週期檢查用 `Tcp`/IPv4 和 `DataUdp`/IPv4 的冷卻分別決定 TCP 探測和共享 UDP 探測的 admission。TCP 還在冷卻，不會阻止已經到期的 UDP 探測。派送時兩個條件都還沒出冷卻的節點不會建立 worker，留到後續週期再查。只做 TCP 的緊急探測只清除節點的 TCP IPv4/IPv6 冷卻，兩個 UDP 域的冷卻保留。

相較之下，Go 版 dae 用 TCP=1，一次短暫的探測丟包就會在 URLTest 選擇前把目前節點從候選集裡移出，繞過 tolerance 滯後。

死亡狀態通常需要連續兩次探測成功才能恢復。相關鏈路、位址或路由變化後，`notify_network_change` 會清除舊冷卻、預先標記為死亡狀態並觸發探測，使一次新的成功即可驗證恢復。新註冊節點有 60 秒寬限期；其間非強制失敗會寫入記錄，但不計入死亡。探測歷史為每個節點、域和位址族保留 100 筆。

| 探測路徑 | 行為 |
| --- | --- |
| TCP | 透過節點向 `tcp_check_url` 傳送設定的 HTTP 方法；HTTP 探測不適用時，改成裸 TCP 連線。`ProxyHttpProber` 把 HTTP 的執行交給 outbound 的共享測量路徑。只有 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Session)` 成立時才重用 runtime，否則探測結束後關閉 guarded cold runtime。只有成功的 warm-path RTT 會進入對應 TCP 位址族的狀態；setup 和目標交換失敗只更新 liveness/cooldown，不貢獻 latency，也不記 ranking strike。 |
| UDP 健康 | 透過節點的 packet path，向第一個 `udp_check_dns` 目標送出一個最小的 DNS query。它單獨檢查 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Udp)`；這個 requirement 沒有預熱時，探測結束後關閉 guarded cold runtime。成功時記錄 RTT，並把 `DnsUdp` 和 `DataUdp` 標為存活。失敗時給兩個 UDP 域各加一次 probe failure，除非同一週期裡獨立的 Score QUIC handshake 成功；那種情況下只讓 `DnsUdp` 失敗，`DataUdp` 保持存活。它絕不改動 TCP state。 |
| Score QUIC 品質 | 每次週期性 UDP 探測，都會透過每個 Score 葉節點單獨做一次 ALPN 為 `h3` 的真實 TLS-in-QUIC 握手，目標是第一個設定的 `global.tcp_check_url`，而且必須是有效的 HTTPS URL。測得的時長提供獨立的 `DataUdp` 探測品質，既不增加業務成功，也不虛構吞吐；DNS 探測失敗、但握手成功時，仍可恢復 `DataUdp` 活性。沒有 URL，或 URL 不是 HTTPS 時，這個探測停用；非 Score 的葉節點既不建這次握手，也不建 Score cell。 |
| 依群組 URL | 用和全域 TCP 探測相同的臨時暖路徑計時，探測動態解析出的 `(member tag, current leaf)` 對。狀態是 TCP-only，連續三次失敗即死亡，冷卻和恢復規則同上，連續兩次成功才恢復。reload 時 `sync_group_check_urls` 替換有效的群組/URL 登錄表。 |

`has_udp_state(node)` 用來區分兩種情況：節點從沒觀察過 UDP，以及節點已被明確觀察為死亡。對普通 endpoint，終止性的 send/receive error，以及從未收到 reply 時的 idle expiry，會在 driver 捕獲到 terminal 的 per-flow Score outcome 之後回報 `DataUdp` failure。對來源共享協定，transport health 由 source owner 回報，每個繫結 endpoint 仍保留並結算自己的 Score reporter；匹配的 reply 屬於對應 endpoint，外來的 reply 沒有 flow Score owner。source 的 terminal event 會退役它的 endpoints，並把 terminal outcome 分派給這些流。

型別化 policy、size，以及 `PacketRejection::Capacity` 拒絕，對候選都是 terminal，但不影響 health 或 Score；CLI 呼叫方收到的是 capacity error，不是 `NotApplicable`。單包壅塞、已有 reply 之後的 idle expiry、主動退役、節點死亡取消和行程關閉，也都不影響健康。alive→dead 轉換會呼叫帶 `(NodeId, name)` 的控制面回呼，清除 pool connection 和 UDP endpoint。同族的另一個 UDP 域已經明確存活時，就跳過這個 UDP 域的死亡清理，避免被阻斷的 `:53` 探測把正常流一起清除。

每個節點最近一次真實 TCP 延遲樣本每 60 秒寫入狀態資料庫；啟動時只恢復不超過 24 小時的樣本。存活性不從快取恢復。合成的 10 秒佔位樣本帶標記，不出現在歷史裡，不進入移動平均，也不會當作最近真實樣本持久化。選擇降級由失敗 strike 計數負責，與佔位樣本無關。

- `src/alive/` API 包括 `register_node`、`notify_check_*`、`report_*_traffic` 和 `record_dial_failure`。群組表和 `(member tag, check_url)` 狀態仍以名稱為 key，因為群組沒有 NodeId、成員可能是子群組，即 sing-box RealTag。`mod.rs` 負責狀態、閾值、registry 和 eBPF 連通性推送回呼。`probe.rs` 負責 HTTP/raw-connect 的 `probe_node`，以及經 `dial_udp_transport` 的 DNS `probe_node_udp` 測量。`runner.rs` 負責健康檢查的 admission、取消和排空，並行探測週期，以及週期、恢復、緊急三種探測迴圈。`collection.rs` 負責 `DialerCollection` 的延遲、移動平均和撥號失敗追蹤。`latencies.rs` 用操作複雜度 O(1)、容量 10 的環狀緩衝區，測量的 `SystemTime` 提供真實的 Clash 歷史記錄時間。`last_real_sample()` 會排除合成條目，以免儀表板顯示虛構的 10000 ms。

`honk-outbound/src/urltest.rs` 負責 HTTP 請求建構和測量，URL 解釋委託給
`honk-config::check` 的規範解碼器。core 和 generation URLTest 還共享顯式的冷
session 預熱，並在建立資源或回饋之前保留一個可以失敗的節點 admission；獨立工具呼
叫保留 handler 內部的 setup 和 CLI 外層的 deadline。請求使用不含憑證的 authority，
只保留非預設連接埠，去掉 fragment，原始路徑、查詢字串和點段照舊；只有查詢字串的 URL 寫
成 `/?query`。HTTPS 會驗證憑證並協商 `h2,http/1.1`，停用 server push。第一輪用
HEAD，第二輪用設定的方法，delay 測試是 HEAD；兩輪最終響應的解碼狀態都必須是有效
的 200–499。HTTP/1 會在同一輪內先讀取臨時響應標頭再讀最終響應，但不支援協定切換；
每輪響應標頭累計上限 16 KiB。HTTP/2 的響應標頭清單用同樣的上限。

HTTP/2 探測連線遇到第一個本機檢測到的協定錯誤就終止，避免後面的遠端 reset 掩蓋已
經拒絕的響應標頭錯誤、誤觸發首輪樣本退回。已取消流的記錄保留視窗是每輪超時的兩倍，
覆蓋兩輪請求的預算，遲到的合法 warm 流訊框仍可忽略。每次探測最多保留兩筆流記錄；完
成或取消時隨連線釋放，不等記錄過期。

報告值是第二輪熱路徑的 RTT，不含代理撥號、目標 TLS 和 session 準備。第二輪傳輸失
敗時可以返回已驗證的第一輪樣本；HTTP/1 要求沒有部分響應，HTTP/2 接受正常的
GOAWAY 或遠端 `REFUSED_STREAM`，畸形或部分響應仍然算失敗。冷可重用探測會關閉
guarded runtime，HTTP/2 driver 在完成或取消後停止。準備、撥號、TLS、HTTP/2 啟動
和每輪請求各有階段預算，core 保留連線超時。delay URL 留空時用
`https://www.gstatic.com/generate_204`。健康排程由 `alive` 負責，只有真實流量會
增加撥號失敗 strike；群組 delay 的並行上限仍是 10。API 返回的首輪預熱退回值不會作
為設定方法的 Score 證據發布；只有成功測得的第二輪才更新該方法的品質 cohort。

## UDP 候選資格

`filter_alive_candidates` 依節點和位址族決定 UDP 選擇：

- `DataUdp` 存活或 `DnsUdp` 存活：可選擇。
- 兩個 UDP 域都明確死亡：排除，即使 TCP 存活。
- 從未記錄過 UDP 狀態：繼承 TCP 存活性。

TCP 健康但 UDP 已失效的節點不再接收封包流，尚未啟用 UDP 探測的部署不受影響。

## eBPF 連通性發布

eBPF alive slot 屬於群組，不屬於單一節點。對每個域和位址族，發布值取所有可達葉成員狀態的 OR，並保留一個 TCP admission 例外：群組裡恰好只有一個唯一葉節點，且沒有設定 `final`。單一節點狀態轉換觸發的回呼會重新計算該群組的值，絕不直接寫正在轉換的節點自己的值。admission 不覆蓋使用者態選擇：即使 slot 仍存活，選中的空 Selector 路徑仍會拒絕流量。

reload 先把舊群組或新群組佈局需要的所有 slot 置為存活，讓轉換期 fail-open。發布新路由 generation 後，honk 再寫入精確的新群組快照。這樣群組重排不會繼承過時的 ordinal 狀態；精確發布中途失敗時，還沒填的轉換 slot 保持 fail-open，不會錯誤地把某個群組標成失效。

## 預熱與所有權

預熱有三個相互獨立的機制：

| 機制 | 候選與生命週期 | 保留資源 | 邊界 |
| --- | --- | --- | --- |
| 啟動預連線 | 僅在啟動時執行一輪；先取各群組目前選擇，再依設定順序。只有可池化裸 TCP 的代理節點合格。 | 向池中存入一條服務端裸 TCP 連線 | `'auto'` 最多選擇 8 個節點；`0` 關閉。它不持有策略 retention bit。 |
| Selector 固定 | 追蹤每個 Selector 的 TCP 設定選擇葉，包括不健康的顯式選擇；共享葉依 UUID 去重。UDP 預熱另依 UDP 選擇。 | TCP path 選擇的可重用 session（AnyTLS 或 VLESS H2/shared Mux.Cool）、一個 QUIC client/connection，否則一條服務端裸 TCP | 有效選擇變化會立即喚醒；10 秒週期修復遺失、已消費或已過期狀態。 |
| UDP 預熱集 | 需明確啟用；每輪對每個位址族重新選擇各群組 top `min(N, 3)` 的可重用 UDP 葉節點，再依 UUID 全域去重。 | UDP path 選擇的可重用狀態，包括 VLESS H2/shared/separate Mux.Cool pool，或一個 QUIC client | 最多同時 4 個預熱嘗試；行程保留集會重新排名並以 `4 × N` 為上限。 |

Selector 和 UDP ownership 是 reusable node runtime 上兩個互相獨立的 bit。
`WarmRequirement::Session` 跟隨 TCP path，`WarmRequirement::Udp` 跟隨 UDP path。
所以只有 UDP 的 VLESS pool 不會改變 direct-TCP warming 或 bare-TCP eligibility。
移除一個 owner 時，另一個 owner 仍可保留共享 pool；最後一個適用的 owner 釋放後，
才停止後續重用並排空資源。active 流不會被切斷，啟動預連線只往池裡放初始連線。

reload 時，設定沒變的節點把現有 `NodeRuntime` 轉給 replacement，包括 AnyTLS、
VLESS pool/source key 和 QUIC 狀態；設定變了的節點得到 fresh runtime。現有
outbound maintenance pass 會和其他 idle resource 一起回收未受 retention 的 idle
VLESS carrier，不建立新的 protocol timer。

原生探測固定成員到葉節點的 association 以及 generation owner，不推進策略狀態。實際的 TCP-connect、HTTP 和 TCP/UDP DNS 測量保留傳輸協定、用途、位址族和冷熱狀態；過期或取消的結果不發布新的健康狀態。探測、geodata 和共享下載使用設定的目標，不設位址或連接埠白名單。誰能寫設定、誰控制訂閱內容，誰就決定這些目標；provider 內容屬於可信的設定。探測仍然固定解析出來的 IP。參見[有界探測](../reference/api.md#有界探測)。

## 撥號 admission 預算

`max_concurrent_dials` 預設為 64，並為物理代理連線和協定握手各建立一個 generation-local semaphore。設定值會被啟動時算出的不可變行程級描述符 gate 限制。reload 可以改動替代 generation 的本地上限，但重疊的新舊 generation 仍共享同一個行程 gate。

Ready 池命中和已預熱 generation 傳輸上的邏輯流不佔額度。`block` 不會撥號；`DirectHandler::dial` 和其他物理連線一樣經過 `admit_physical_dial`。已經下放到資料路徑的直連流量，以及透過已標記的 HTTP 用戶端直連的 UI 下載，不使用這個 handler 的 admission gate。裸 TCP 池命中仍要執行協定握手，所以仍受撥號預算 admission。

每條 VLESS 物理 carrier 還要從啟動時確定的行程 carrier gate 取得 permit，reload
generation 和 DNS fork 共用這個 gate。permit 跨越 provisional、active、draining
和 idle carrier I/O，一直持有到 task teardown。這個全域 gate 就是權威邊界；
Mux.Cool 不再疊加逐節點兩 carrier 的限制。

## 相關文件

- [出站設計](./outbound.md)
- [控制面設計](./control-plane.md)
- [群組參考](../reference/groups.md)
- [全域參考](../reference/global.md)
