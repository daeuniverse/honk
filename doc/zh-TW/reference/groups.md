# 代理群組參考

`group { ... }` 設定代理群組及其成員選擇規則。每份設定最多可定義 250 個頂層使用者群組；更高的路由序號由 ABI 保留。

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://probe.example:8443/check,192.0.2.10,2001:db8::10'
        icon: 'https://example.com/icon.svg'
        tolerance: 50
        idle_timeout: 1800
        interrupt_connections: true
        final: direct
    }

    proxy {
        filter: group('hk')
        filter: name('backup')
        policy: select
        default: 'hk'
        final: direct
    }
}
```

## 欄位

| Key | 預設值 | 含義 |
| --- | --- | --- |
| （子節名） | 必填 | 在路由和 API 中用作出站的群組 tag；內部欄位為 `name`。 |
| `policy` | `selector` | 成員選擇策略；接受的拼寫見[策略](#策略)。 |
| `filter: name(...)` | `[]` | 依節點名稱選擇節點；結果存入 `filters` 和 `nodes`，符合的項目由解析器解析為節點 UUID。 |
| `filter: subtag(...)` | `[]` | 依產生節點的訂閱目前的 tag 選擇節點；結果存入 `filters` 和 `nodes`，tag 來自訂閱項目，見[內部模型](./subscription.md#內部模型)。 |
| `filter: group(...)` | `[]` | 把巢狀群組 tag 加入 `groups`；接受逗號分隔的引數和豎線分隔的 tag。 |
| `default` | `null` | `selector` 的初始或備援成員 tag。 |
| `final` | `null` | 群組策略沒有合格選擇時使用的目標，見 [`final`](#final)。 |
| `check_url` | `null` | 給非 Selector 策略用的依群組 TCP 健康檢查目標，見 [`check_url`](#check_url)。 |
| `tolerance` | `50` | URLTest 切換門檻，單位為毫秒，見 [`tolerance`](#tolerance)。 |
| `idle_timeout` | `null` | URLTest 群組連續多少秒沒有被選用後暫停成員探測，見 [`idle_timeout`](#idle_timeout)。 |
| `interrupt_connections` | `false` | 選擇變化時關閉受影響的使用者態傳輸，見 [`interrupt_connections`](#interrupt_connections)。 |
| `icon` | `null` | 原生群組讀取傳回的群組圖示，見 [`icon`](#icon)。 |
| —（`check_interval`，dae 中不可設定） | `null` | 依群組的間隔欄位，單位為秒。目前的執行時不讀取該欄位，而使用全域間隔。 |
| —（`id`，dae 中不可設定） | 隨機 UUID | 欄位缺少時產生的內部群組識別碼。 |

本文區分三個詞：健康檢查是代理群組週期性執行的檢查；延遲測試是透過 API 或介面按需觸發的測試；探測是一次測量，前兩者都由探測組成。

### final

群組策略沒有合格選擇時使用的目標；巢狀時同樣生效。

取值是節點、群組、`direct` 或 `block`。預設 `null`，也就是沒有設定 final 目標；內部欄位為 `final_outbound`。

未知目標會使設定在啟動或 reload 時以 `invalid-group-final-target` 被拒絕。`final` 節點仍受健康檢查約束。繞回自身的 `final` 路徑不選擇任何節點，也不會退回 `direct`。

```dae
group {
    hk {
        filter: name('HK')
        final: direct
    }
}
```

### check_url

給非 Selector 策略用的依群組 TCP 健康檢查目標。

該值取 HTTP(S) URL；沒寫協定的目標按 HTTP 處理。URL 後面可以接逗號分隔的 IPv4 或 IPv6 字面位址，這些位址使用 URL 的連接埠，並先於 DNS 傳回的位址嘗試；無效的項目會被忽略。

預設 `null`。

不要在 Selector 上設定：honk 只記一條 warning，從不探測這個 URL。但 Selector 的 TCP 選擇仍會讀取該 URL 的健康狀態，未探測即視為健康，於是 TCP 健康檢查不再約束該群組。該 key 不影響 UDP。

```dae
group {
    hk {
        filter: name('HK')
        policy: urltest
        check_url: 'https://probe.example:8443/check,192.0.2.10,2001:db8::10'
    }
}
```

### tolerance

另一個 URLTest 成員的延遲要低出多少毫秒，群組才切換過去。

該值寫成純整數：`tolerance: 50`，不能寫 `50ms`。有效下限為 1 ms。

預設 `50`；dae URLTest 群組未明確設定時，繼承 `global.check_tolerance`。

URLTest 群組會保留目前成員，直到另一個成員的延遲比它低出 `max(tolerance, 1 ms)`。目前成員沒有新的測量值，或近期有失敗時，不享有這份保留。

```dae
group {
    hk {
        filter: name('HK')
        policy: urltest
        tolerance: 50
    }
}
```

### idle_timeout

URLTest 群組連續多少秒沒有被選用後暫停成員探測；作用類似 Clash 的 `lazy`。

該值寫成純整數：`idle_timeout: 1800`，不能寫 `30m`。`idle_timeout: 0` 表示兩次選擇之間就進入閒置，它不是連線逾時。

預設 `null`，此時使用 1800 秒。

URLTest 群組在第一次被選中之前保持閒置，之後只要連續 `idle_timeout` 秒沒有流量選中它，就再次轉入閒置。閒置期間暫停成員的週期探測，下一次選中時恢復。只要還有非 URLTest 群組，或者有活躍的 URLTest 群組能到達某個節點，該節點就繼續接受探測。

```dae
group {
    hk {
        filter: name('HK')
        policy: urltest
        idle_timeout: 1800
    }
}
```

### interrupt_connections

選擇變化時，依擷取的群組身分和網路關閉受影響的使用者態傳輸。

該值接受 `true`/`false`、`yes`/`no`、`on`/`off` 或 `1`/`0`，不區分 ASCII 大小寫。上述取值以外的值會使設定被拒絕。

預設 `false`。

這會退役傳輸，而不只是移除追蹤記錄；共享 UDP carrier 保留未受影響的檢視。LoadBalance 輪換從不關閉連線。只有真正發生選擇變化的網路受影響，並依既有流量擷取的群組路徑比對，不用目前的葉節點清單倒推。

```dae
group {
    hk {
        filter: name('HK')
        interrupt_connections: true
    }
}
```

### icon

原生群組讀取傳回的群組圖示。

該值取帶主機名稱且不含認證資訊的絕對 HTTP(S) URL，或 data URI；最多 2048 個字元，不能含空白。

預設 `null`。

不符合上述格式的值會使設定被拒絕。原生群組讀取會遮蔽至少 8 位元組長的 listener secret 值，不推測圖示。

```dae
group {
    hk {
        filter: name('HK')
        icon: 'https://example.com/icon.svg'
    }
}
```

## 策略

| 規範名 | 接受的 dae 拼寫 | 行為 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | TCP 和 UDP 各自維護執行時選擇：先看對應網路的選擇，再看 `default`，最後取第一個現存成員，全部在健康過濾之前決定。健康狀態不會把有效選擇換成兄弟成員；選擇可以是直接節點，也可以是巢狀群組 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 選擇減半移動平均 `(prev + sample) / 2` 最低的存活成員；近期失敗尚未恢復的成員排在其他成員之後。`tolerance` 限制切換。TCP 與 UDP 選擇相互獨立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 對存活成員輪詢；每個群組以及 TCP/UDP 網路各有獨立計數器。連向同一目標的相鄰連線會從不同節點出去，TCP 與 UDP 也各自輪換，因此把 session 繫結到用戶端位址的服務會斷線：登入狀態失效，Cloudflare 會重新要求驗證其放行狀態。需要穩定出口時改用 `urltest` 或 `score`。 |
| `fallback` | `fallback` | 分別為 TCP 和 UDP 依成員順序固定第一個存活成員；更靠前的成員恢復後不會立即切回。 |
| `score` | `score` | 依實際可靠性、新鮮的目標品質與有界驗證選擇一個存活成員；TCP/UDP 和目標 IPv4/IPv6 證據各自隔離。 |

策略名稱不區分 ASCII 大小寫。解析器比對前會去掉任何括號字尾，因此 `fixed(0)` 也可以用。無法辨識的策略會當作 `selector` 處理，診斷資訊會註明群組名稱；舊策略名 `honk` 明確無效，必須改用 `score`。

直接成員的順序來自節點清單，與過濾器行和引數順序無關：`filter: name(backup, primary)` 不會把 `backup` 排到前面。巢狀群組排在全部直接成員之後，依 tag 的書寫順序排列。這個順序決定 Selector 的首個成員、Fallback 優先順序和 LoadBalance 輪換順序。

要明確指定 Fallback 優先順序，把每個節點放進單獨的子群組，再依序列出這些子群組：

```dae
group {
    primary-only {
        filter: name('primary')
    }
    backup-only {
        filter: name('backup')
    }
    preferred {
        filter: group('primary-only', 'backup-only')
        policy: fallback
    }
}
```

TCP 依 TCP 探測延遲排序；設定了 `check_url` 時，依該群組的 `check_url` 探測排序。UDP 先依資料 UDP 探測延遲排序，其次依 DNS UDP；沒有 UDP 測量值的成員排在最後，不會借用它的 TCP 延遲。`check_url` 不影響 UDP。在任何成員產生 UDP 測量值之前，UDP 沿用該群組的 TCP 選擇。

選擇缺少，或者選中的成員已不屬於該群組時，才退回 `default` 或宣告順序裡的第一個成員。選中的成員沒有合格葉節點時，TCP 和 UDP 都不會改選兄弟成員：只能繼續執行明確設定的 `final`，或下述針對同一葉節點的 TCP 最後嘗試。選中的巢狀群組仍執行自己的策略，因此 URLTest 可以在該子群組內部挑另一個葉節點。

選中的子群組會先解析自己的明確 `final`，然後向父群組傳回空結果。這不代表可以改選其他 Selector 兄弟成員，也不代表可以重試終態的協定拒絕。IPv6 目標仍會先嘗試經 IPv4 代理健康狀態可達的普通已選葉節點，之後才走 final 路徑。

UDP 資格同時要求協定或設定支援，以及健康條件。VMess 和明確僅支援 TCP 的葉節點會在選擇與 Score 比較之前被排除，TCP 選擇不受影響。Selector 選中的節點沒有 UDP capability 時，也不會改選兄弟成員；內建 `block` 仍保持終態。capability 過濾繞不過已選節點針對特定目標的 UDP 策略拒絕。

不同節點共用同一個顯示 tag 時，依名稱指定的預設選擇和 Clash 寫入會在健康過濾之前，繫結群組內宣告順序裡第一個符合成員的 `NodeId`。原生 API 的成員 ID 可以直接選中某個直接成員。健康狀態不會把任何一個選擇改到同名的健康節點上。依名稱指定的 `final` 節點同樣繫結設定裡第一個符合的宣告，不會被健康的同名節點替換；選擇和 `final` 節點的健康註冊使用同一個身分。

群組只有一個葉節點、沒有設定 `final`，而 TCP 健康狀態排除了這個節點時，honk 仍可把它當作最後嘗試，但目前 Selector 的選擇路徑必須能到達它。這不能繞過選中的空子群組，也不表示退回 `direct`。節點保持失效，直到真實流量或探測讓它恢復；UDP 仍依正常規則排除失效成員。走到這種最後嘗試時，honk 會記錄限流 warning，每個群組每 60 秒一條。

每個已設定 Selector 的代理葉節點都維持預熱。解析巢狀選擇後，honk 會依葉節點協定保留可重複使用的多工 session、QUIC client 或一條到伺服器端的裸 TCP 連線；`direct` 與 `block` 不需要預熱資源。Selector 的固定預熱跟隨 TCP 選擇，UDP 預熱集使用 UDP 選擇。

原生 `PUT /api/v1/groups/{groupId}/selection` 用直接成員的 `member_id` 更新選擇，`network: "tcp"|"udp"|"both"` 必填。`both` 會一起驗證、原子發布，TCP 寫入不會連帶改變 UDP。Clash 寫入對映為 `both`，`now` 明確顯示 TCP 選擇。兩者共用 `control/reload` owner、依網路分開的持久化和預熱回呼。依網路的選擇在 reload 和持久化後仍然保留，中斷只在真正關閉後確認。自動代理群組可以在執行時固定成員；下次設定啟用，或透過 DELETE 請求清除固定成員時，固定失效。

群組 PATCH 依解析器記錄的來源位置，改寫可寫的 `.dae` 檔案裡的 `policy`、`default`、`final`、`tolerance`、`idle_timeout`、`interrupt_connections` 和 `check_url`。其他原文字元組保持不變。改動會走完整驗證、持久寫入和真實 reload，不只停留在記憶體。請求必須帶針對群組 ETag 的強 `If-Match`，並獨立於來源檔案 hash 驗證。寫入後啟用被拒絕時，磁碟內容不會復原。`icon` 可以在設定或來源編輯器裡改，不屬於受限 PATCH 欄位；`name` 與 `filters` 同樣不受支援。詳見[原生群組控制](./api.md#節點與代理群組)。

### URLTest 冷啟動

在任何成員有延遲測量值之前，路由到 URLTest 群組的連線會讓多個成員 race，採用最先連通的一個。TCP 最多啟動三個成員，間隔 200 ms。UDP 在 0、30、80、160 ms 依序啟動成員，之後每隔 80 ms 再啟動一個，同時最多三個，並在勝出者確定前不傳送應用資料。巢狀在其他群組中的冷啟動 URLTest 群組只貢獻一個成員，不參與 race。

### Score 策略

Score 始終編譯，但只有群組上寫 `policy: score` 才會啟用；省略策略仍預設 Selector。Score 沒有執行時調節項。可靠性只保護 admission：歷史成功次數再多，也不能長期排除一個已驗證、樣本更少卻更快的節點。

Score 在普通健康過濾之後選出唯一要用的葉節點，代理健康位址族和業務目標位址族相互獨立。首次選擇所用的 utility 分數和 `WeightedMean` 效能啟發式保持不變。候選的觀測足夠多時，比較的是實際失敗風險，不是樣本最多者的信賴下界。證據稀疏的候選會獲得有界試用。設定的探測品質只是基準，新鮮可信的目標業務證據仍能覆寫它；數值相等時依宣告順序和穩定身分決定。健康現任成員的晉升比較使用另一套有界證據，不能只看啟發式。

可選試用以 `(group, TCP/UDP, target family)` 作用域為單位管理預算，每個保留的作用域各有一份：

- 初始額度：作用域建立時固定成員數 `n` 和冷啟動額度 `B`。成員不超過四個時，`B` 覆蓋全部成員；否則 `B` 為 `ceil(sqrt(n)) + 1`。
- 賺取額度：每次原始業務開始都會增加 `1/q` 的額度，並計入 `N`；`q` 通常為 16。只有兩個條件同時成立才改用 `q = 8`：該群組在這個網路上近期的原始業務換算為每秒至少兩條，依五分鐘半衰期統計；作用域近期至少有三個可選試用結果，成功率至少 80%，依十分鐘半衰期統計，且衰減權重超過 2.5。證據所需的試用次數是固定的，所以試用確實有效的繁忙群組能更快累積到足夠額度，閒置群組則維持較小的比例。目標拒絕不計入試用結果，reload 會清除這些結果。
- 低收益暫停：普通選擇已被觀測到可用，且本次讀取涉及的每個作用域近期成功率都低於 20% 時，只要有兩次以上近期失敗，就暫停可選試用，直到這些失敗衰減。只有一次近期失敗時，試用每次只放一個。被暫停的作用域拒絕的候選會計入 `budgetBlocked`，讀出來是 `budget` 等待，與額度耗盡時相同；已經有一個試用進行中的成員仍顯示 `inFlight`。沒有可用選擇時繼續探索，Score 才能從故障中恢復；恢復過程照常進行，不受這些暫停影響。
- 預算上限：已支出的試用 `V` 加上尚未開始的預留 `R`，始終不超過 `B` 加已賺額度的整數部分。未花掉的已賺額度最多為八。
- 計數：`N` 包括被選中的試用，但重試、複製和巢狀重複歸因不能放大計數；根計數會對巢狀群組去重。時間、讀取、新目標和證據過期都不產生額度。保留的作用域在 reload 和成員變化後仍保持額度。
- 支出與退還：節點專屬工作會在 DNS／admission 等待之前就支出額度，這個時間點與實體、邏輯報告器的開始時間不同。工作開始前釋放最後一個引用，預留額度會退還；工作開始後取消，則不退還。恢復重試單獨計數，不動可選預算。
- 進行中上限：對同一個目標，每個成員每個未決問題最多只有一個沒有回應的試用。除恢復外，成員獲得試用還要滿足：它的完成數加上未完成工作，仍少於目前選擇成員的完成數。
- 失敗處理：試用不會成為普通現任。真實失敗保留指數退避和連續三次失敗的普通排除；退避到期後仍可嘗試恢復。

業務可靠性仍依 30 分鐘半衰期統計。啟發式效能信賴度單獨老化，120 秒後過期，與樣本數量無關。setup 和首個回應會立即發布；後續的傳輸進展依 1–10 秒的不重疊視窗統計，被測方向至少要有 64 KiB，流也要有雙向進展和回應。視窗不會增加終態次數。goodput 隨業務需求變化，不等於鏈路容量；沒有流量也不能當作壅塞。八次有效完成之後，成熟保護仍為 `0.005`，支撐量取各適用層分別衰減後的最大值。不合格的現任成員和尚未恢復的業務失敗可以繞過這層保護；只靠已恢復的歷史失敗量則不行。

只有普通選擇真正切換到另一個葉節點，才優先於可選驗證。失敗現任仍被選中時，不會阻止一個還有額度、可以執行的挑戰者試用；試用本身也不會清除失敗記錄或退避。

晉升比較在共享的服務候選池裡進行：池內所有合格挑戰者都與同一個固定現任比較。池容量 k 隨需求變化，大群組還受 √n 上限約束。普通選擇和試用選擇都受池約束，勝者不額外佔名額，見[有條件的驗證結論](../design/groups.md#有條件的驗證結論)。

比較使用的目標有三種來源：雙方的精確目標；至多八個依規範順序選出、回應支援已合格的共同目標；或同一份目前設定探測 cohort。共同目標先判定支援資格，再套用數量上限，不能依測量值挑選。如果跳過了尚未合格或被上限截斷的已比對目標，比較就是不完整的，該成員的回應缺口仍然待解決。方向指標在同一組已選回應目標上取交集。

業務證明使用四個共同的 15 秒區塊，在各自起點後 60 秒到期。設定探測依實際週期 `I` 使用四個 `max(15s, 2I)` 區塊，有效期還受較弱一側最近一次支援時間加 `max(60s, 2I)` 的限制。每個指標仍要求雙方各有四個不同的 reporter；探測週期改變後，不能繼承舊的探測支援。

方向優勢要求至少提升 10%，其他已知方向都沒有退化超過 10%，回應變慢不超過 10%，且合格終態可靠性不低於現任。未知方向保持未知；一升一降依權衡報告，不用最佳方向的分數掩蓋。成對回應與合格可靠性優勢仍參與既有的保持門檻判定。Score 不新增調節項，詳見[生命週期設計](../design/groups.md#score-評分與生命週期)。

唯讀的成對關係與上面的切換決策分開。它只描述回應時間，用對稱的 10% 近似等價容差比較實際回應值，不看完成數成熟度，也沒有毫秒下限；可靠性和方向保護仍由切換邏輯負責。缺少成對回應時，honk 會在預算內請求可比的業務流量，而不是做頻寬測速。詳見[有條件的驗證結論](../design/groups.md#有條件的驗證結論)。

setup/TX 之後的定向 Traffic RX 可以在流結束前開啟一次半開恢復，但受預算限制。在精確 cell 連續失敗後的 cohort 裡，要有四個不同的 reporter 才能清除硬失敗事件，並授予目前 60 秒的資格 lease；只收到一次回應，或其他目標恢復後的聚合結果，都不夠。歷史失敗仍計入 utility 和晉升，也不會憑空造出終態成功。初始冷資格仍要求四個有效的 useful 完成；RX 可以續期已經獲得的 lease，但光靠 reload 不會授予恢復。首個合格 RX 之後，每個 reporter 依事件發布，每秒至多一次。目標路徑失敗只改變精確目標的硬狀態，聚合的數值結果仍然保留；明確的 carrier／代理故障，以及 setup 之前的未知失敗，仍依節點歸因，並會 fence 依賴它的證據。詳見[作用域恢復與可選驗證](../design/groups.md#score-評分與生命週期)。

業務評分仍依群組、transport、目標位址族、正規化目標和節點身分分別隔離；全域、位址族和精確目標的可靠性分層混合，但不把重疊的完成數相加。目標效能只在新鮮且可比時覆寫基準。探測 RTT 單獨保留 protocol/family 身分，以及正規化後的 HTTP URI 和方法身分；預熱只貢獻 setup 品質。一次真實結果會向它經過的每個 Score 群組各歸因一次。

透明 TCP/UDP、受支援的 DNS exchange 和 UI 下載都會回饋真實的業務 attempt。設定的 HTTP/UDP/QUIC 探測只提供近期品質：它們不增加業務成功數，也不清除真實的連續失敗。手動 Clash delay 保留 Alive/API 歷史，但不作為設定 Score 的基準，也不會把任意目標上的失敗變成真實撥號降級；實際準備過程仍記入預熱品質。獨立的 Score QUIC 握手保留既有的 DataUdp 健康恢復，但不會虛構位元組流量。

持續且實際測得的 carrier 壓力可以重新開啟預算內的比較，但不增加業務失敗，也不直接改變贏家。這是一種提示性證據，從 honk 發給代理伺服器，不是端對端 UDP 丟包率，也不是首請求保證；無法觀測的路徑仍保持未知。詳見[提示範圍](../design/groups.md#score-評分與生命週期)。

所有評分狀態都只在目前行程的記憶體裡。精確的 node-target cell 用一個容量上限為 4,096 的 LRU，聚合 cell 用另一個 4,096 項 LRU。精確目標證據衡量的是實際 transport 品質，不代表某個服務在語意上已經解鎖；需要這種粗粒度 cohort 時，用現有的 routing 或 geosite 規則選出專用的服務 Score 群組。成功的行程內 reload 重用同一份共享狀態，並移除已刪除群組或成員的 cell；行程重新啟動則清空狀態。評分 cell 和只由 scorer 持有的 domain/IP key 不會寫進日誌、持久化儲存或任何 API 輸出。已建立連線的中繼資料不受影響。

為相容 Clash，Score 仍由 honk 自動選擇，但對外表示為 `type: "url_test"`；`now` 顯示目前聚合後的 TCP 勝者，並拒絕對該群組執行 `PUT /proxies/{name}`。

獨立的比較儲存最多有 512 個 cell，邏輯分配上限為 1 MiB，包含所持有 key 與 vector 的容量。這不是行程 RSS 上限，分配器開銷和其他狀態都不在其中；缺少或被淘汰的支援保持未知。

TCP 建立失敗且可重試時，Score 群組處理的請求最多再依序試一個不同的合格葉節點，不需要普通評分先切換。兩次嘗試共用 deadline 和既有的撥號 admission。Selector 邊界，以及首選實際走過的 final 邊，仍然起決定作用；這裡不新增 direct/final 備援，也不重送應用負載。提交 reload 會清空探測基準，但保留有效的進行中業務證據；中性 cell 仍受既有 LRU 容量約束。

每次實際執行的多候選選擇只記錄一個互斥原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`ordinarySwitch` 記錄同一作用域內普通選擇已提交的 A→B 變更，不含首次選擇和試用；`switchFlap` 是其中在八次普通選擇內又回到前一贏家的子集。候選過濾和退避計數保持獨立。Peek 以及展示、API 讀取保持中性。經認證的 `/stats.score.groups[]` 匯出固定的群組／網路原因、驗證和預算欄位；`/stats.score.cache` 描述證據與比較儲存。試用結果和 setup／總耗時成本都是實際觀測值，不能當作額外失敗或開銷的因果估計。詳見 [API 原因語意](./api.md#score-選路原因欄位)，它不匯出 scorer 私有的節點或目標身分。

取樣在共享預算內補上可用性、回應、普通資格和恢復方面的缺口。只有資格／恢復的缺口也補上後，honk 才會對新鮮的等價 cohort 停止強制取樣；缺少傳輸證據時，則等待真實負載出現。`scoreVerification` 區分臨時轉發、已觀測可用性、新鮮的成對 `challengers` 關係、證據問題 `question` 和等待原因 `waitReason`；聚合讀取會檢查保留的 IPv4/IPv6 等待狀態，不花費額度。詳見 [API 驗證](./api.md#score-驗證資訊)。這些關係是可撤銷的經驗觀測，不是最佳候選辨識，也不保證未來的網路行為。

每個挑戰者與所選成員的比較，只在各自共享的時間區塊內判斷，不會在挑戰者之間聯合對齊。可選工作只有一個派送順序：先派送未訓練的成員，再依成員未決問題的進展排序，最後依最久未被選中排序。試用保留業務額度和進行中上限，不重送請求。唯讀的 `question`、`nextAction` 與 `waitReason` 報告這個順序裡的首個成員，不暴露目標身分。

## 宣告

每個群組都是 `group { ... }` 中的命名子節。同名宣告不會合併，以最後一份為準。不要在包含檔案裡重複宣告同一個群組來擴充它。

`filter:` 項目累加。其他 key 都以最後一次出現的值為準，較早的無效值不會被檢查。

## 過濾解析

1. 單獨的 `group('tag')` 行把巢狀 tag 加入 `groups`，不作為節點述詞求值。巢狀 tag 可以貢獻該群組目前策略選出的葉節點。包含其他述詞或尾隨文字的 `group(...)` 行會被忽略並回報診斷資訊；如果群組內只有這一條過濾器，該群組的成員為空。
2. `name(...)` 比對 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 對映到目前訂閱 tag 並比對該 tag。普通引數是精確比對，`keyword:` 是子字串比對，`regex:` 使用 [Rust regex 語法](https://docs.rs/regex/latest/regex/#syntax)。比對區分大小寫；同一述詞中的多個引數互為替代選項。正規表示式無效時，honk 忽略該過濾器行；其他過濾器行仍可提供成員。
3. 同一行中由 `&&` 連接的述詞依 AND 求值。在述詞前加 `!` 會對其取反。不同的 `name(...)` 與 `subtag(...)` `filter:` 行之間依 OR 求值；單獨的 `group(...)` 行只加入巢狀候選。
4. 每次訂閱重新整理後都會重建過濾後的成員關係。因此訂閱來源變化後，即使節點 UUID 沒變，舊的成員關係也不會留下。
5. 既沒有節點過濾器也沒有巢狀群組的群組會接收目前全部節點。明確的 `group()`、空過濾器、空巢狀群組或訂閱重新整理後變空的過濾器均不選擇節點。這些空結果在 JSON/YAML/TOML 序列化、重新解析和重新整理後仍然保留；有效的同層過濾器繼續依 OR 提供候選，`final` 保持獨立。

honk 會忽略無法解析的過濾器，並在診斷中註明它在群組內節點過濾器中的序號；只有非空的獨立 `group(...)` 行不參與計數，混合述詞行仍參與計數。`group()` 會產生 `empty-subgroup` warning。需要全部節點時請刪除過濾器；明確的 `group()` 目前不選擇任何節點。注入的 `direct` 與 `block` 是出站，不是節點池成員：無過濾器的群組、`keyword:`、`regex:` 和 `subtag(...)` 都不會選中它們，只有依名稱寫出的過濾器才會收入，例如 `filter: name(direct)`。

```dae
group {
    paid-nodes {
        filter: subtag(paid, regex: '^premium-') && !name(keyword: 'Expired')
    }
    named-nodes {
        filter: name('primary', 'backup')
    }
    literal-names {
        filter: name('a&&b', 'a,b', 'keyword: HK')
    }
    provider-only {
        filter: subtag('paid') && !subtag('expired-provider')
    }
}
```

值含 `&&` 或 `,` 時應加引號，例如 `name('a&&b')`。`name(keyword: 'HK')` 比對子字串，`name('keyword: HK')` 則只比對名稱恰好為 `keyword: HK` 的節點。

內嵌節點等沒有目前訂閱 tag 的節點永遠不比對 `subtag(...)`，因此會比對 `!subtag(...)`。只允許訂閱節點時，再加一個正向 `subtag(...)`。

巢狀群組建議寫成 `group('hk', 'jp')`，也可以寫 `group(hk|jp)`。引號在這裡不保護 `|` 和 `,`：`group('hk|jp')` 仍會加入兩個群組，並產生 `legacy-quoted-list`。重複的 tag 會被去掉。

## 巢狀代理群組

巢狀 tag 必須指向已宣告的群組；未知 tag 會使設定在啟動或 reload 時以 `invalid-nested-group-reference` 被拒絕。群組管理器建圖時會刪除每條構成環的邊並記錄 warning。巢狀選擇深度上限為 8。每個巢狀群組貢獻其自身策略選出的單一葉節點，因此每次撥號最終都會解析到一個節點。

面向 Clash 的群組輸出保留成員 tag：`all` 欄位列出直接節點名稱和巢狀群組 tag，而不展開巢狀群組。面向葉節點的健康狀態與連通性遍歷會展開這些 tag 下的實際節點。

## 相關文件

- [節點參考](./nodes.md)
- [路由參考](./routing.md)
- [群組設計](../design/groups.md)
