# 使用者空間網路堆疊

同一批封包共用一個接收時間戳記。`Stack` 提供以下接收介面。

| 呼叫 | 行為 |
| --- | --- |
| `receive(now, packet)` | 驗證檢查碼並回傳 `Rx`。WireGuard 使用這個入口。 |
| `receive_reported(packet, options, on_source)` | `ReceiveOptions::new(ingress_at, meta)` 提供接收時間與裝置中繼資料。驗證通過後，在更新協定狀態前呼叫來源回呼。`ReceiveReport` 區分已驗證的來源與協定接收結果，並提供新被動 TCP 連線的 `FlowId`。`with_context` 需要事先配置來源儲存空間。`with_realm` 提供半開連線的准入回呼，並在接收後恢復服務時鐘。 |
| `try_receive_realm_tcp(ingress_at, service_at, packet, on_source)` | 在未配置來源儲存空間的堆疊上，回呼可要求延後處理已驗證的完整 TCP 封包。回傳 `Err` 時保留原時鐘、收包計數與丟包計數。 |
| `reassemble_for_dispatch(ingress_at, service_at, packet)` | 由編號 0 的擁有者重組分片，再選擇傳輸層擁有者。重組完成的封包仍占用記憶體預算。 |

只有透明模式可採用裝置提供的檢查碼資訊。Endpoint 模式遇到 `RxMeta::VERIFY` 以外的中繼資料會回傳 `DropReason::Unsupported`。

## 獨立 TUN 多佇列

`host_facts: false` 支援 1 到 8 個佇列。多佇列使用一個非實體 realm，每個佇列各由一個 `PacketDriver` 驅動自己的 Stack。半開 TCP、待處理 UDP 與 ICMP 限額在 realm 內共享。每個佇列的 RX 緩衝區和 FIFO 均在啟動時向共用的 384 MiB 擷取預算預留空間。FIFO 按最大 IP 封包與中繼資料大小計費。實體 XDP 維持原本的 1 或 2 個擁有者。

單佇列可選用獨立 HostFacts scope，且維持單一來源讀取者。獨立 DNS 在 plain scope 學習，多佇列分片共用同一個 plain DNS 範圍。請參閱 [TUN 資料路徑](./datapath.md#linux-tun-endpoint)。

完整的協定、記憶體與排程設計請參閱[英文版](../../en/design/netstack.md)。
