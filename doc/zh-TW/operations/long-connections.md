# 長連線與 keepalive

honk 不自行產生應用層的 keepalive 封包。carrier 保持開啟，不代表它承載的每條 UDP 流都還存活。

## UDP：回覆維持 endpoint 存活

endpoint 連續 120 s 沒有回覆就退役。成功傳送和 carrier keepalive 都不會重設這個計時器，所以純上行流即使持續傳送資料，仍會到期。到期後，後續封包在 admission 允許時會新建 endpoint，舊封包不會重放。從未收到回覆的流以逾時結算 Score；成功交付過回覆的流，之後因閒置退役不影響健康，仍以成功結算 Score。

每個普通 endpoint 因沒有回覆而到期，都計一次 `DataUdp` 健康失敗。節點的 60 s 註冊寬限期結束後，連續 50 次被計入統計的失敗，會讓該節點在那個探測域和位址族上不可用。同一 key 收到回覆或探測成功會把連續計數歸零，單靠成功傳送不會歸零。共享 UDP association 只在傳送過資料、且從未收到任何回覆時，才回報一次無回覆健康失敗。其他目的地收到過回覆後，仍無回覆的 view 可以到期並以逾時結算 Score，但不會讓整個 source 降級或退役。見[健康與 Score](../design/groups.md)。

核心狀態另有獨立的 [UDP 閒置續期規則](../design/datapath.md#udp-生存期續期)。核心條目還沒過期，不會阻止使用者態的回覆閒置計時到期；使用者態也不會替靜默的核心條目續期。核心狀態被回收時，所屬 endpoint 一併退役，之後的封包需要新建 endpoint。transport keepalive 不會設定外部 NAT/conntrack 狀態。

honk 在達到下列任一上限時丟棄新對映：整個行程 32,768 個 endpoint，兩個位址族合計；啟動時的描述符預算；記憶體預算，即 `MemTotal` 的四分之一，每個 endpoint 按 64 KiB 計，2 GiB 時為 8,192。honk 不淘汰已有對映，也不排隊保留被拒絕的 datagram；NFQUEUE 裡的原始封包同樣丟棄。被拒絕的次數見需驗證的 Clash `GET /stats` 中的 `udp.capacity.rejected`。只有描述符是較小的那個限制時，提高服務的 `RLIMIT_NOFILE` 才有效。[慢路徑/佇列預算](../design/control-plane.md#queue-與描述符預算)可能更早拒絕工作。

## TCP：閒置不是中繼期限

已建立的中繼沒有通用的使用者態閒置逾時，`global.relay_idle_timeout_secs` 不起作用。已接受的中繼只要仍存活，就保留它的核心記錄。首次 EOF 後，剩餘方向要連續 30 s 沒有位元組進展才結束；連線、嗅探與握手期限只適用於建立階段。

Linux TCP keepalive 在面向用戶端的透明 socket 上採閒置 3600 s、間隔 15 s、4 次探測，在出站 dial 和 TCP carrier 上採 15 s、10 s、3 次探測。線上的閒置對端可以一直應答；探測只證明傳輸可達，不證明應用層有進展。見 [TCP 中繼所有權](../design/control-plane.md#tcp-中繼與-conn-state-所有權)。

## Carrier keepalive

H2/gRPC 不發週期性 HTTP/2 PING，包括 VLESS H2MUX、XHTTP 和 DNS-over-HTTPS H2，只依賴實際流量和 TCP keepalive。TCP 連線健康，並不代表遠端應用的 session 可用。

QUIC keepalive 間隔：Hysteria2/TUIC 為 10 s，Juicity 為 5 s，DNS-over-QUIC/HTTP3 為 15 s。TUIC datagram 模式按同一間隔傳送 heartbeat；UDP-over-stream 只用 QUIC keepalive。

Hysteria2/TUIC/Juicity 在連線本地閒置 120 s 後回收，仍有作用中邏輯使用者的連線不會被切斷。對端協商的 QUIC 閒置逾時和遠端應用策略各自獨立。QUIC PING 和 TUIC heartbeat 都不算對封裝 UDP 流的回覆。

## 檢查項

- 檢視最後一次應用回覆和最終狀態，不要只看上傳計數或 carrier 是否存活。
- 區分計時器到期、[出站健康門控](../design/datapath.md#出站存活狀態)和容量拒絕。
- 外部防火牆/NAT 和遠端應用的閒置策略要單獨檢查。
