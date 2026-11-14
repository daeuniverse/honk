# honk 快速上手

依本頁安裝、設定並啟動 honk。honk 是 Linux 上的實驗性 eBPF 透明代理引擎，設定欄位與實作細節見文末連結。

> 注意
>
> honk 仍處於 alpha 階段。真實模式會載入 eBPF、掛接 TC/cgroup hook、建立 `dae0`/`daens`、調整 sysctl，預設還會佔用 NFQUEUE 320。首次部署時請保留一條帶外管理通道。

## Linux 核心要求

### 核心版本

```shell
uname -r
```

- 僅支援 Linux；真實透明代理必須以 `root` 執行。
- 編譯式路由及其 map-in-map 同步發布保證要求 Linux `6.12+`。較舊的核心會在掛接前遭拒。
- `netkit` 不是必需項；核心不支援時 honk 自動退回 veth。

`lan_interface` 用來代理從區域網路進入閘道器的流量，`wan_interface` 用來代理閘道器本機發起的流量：

- 只設定 LAN：只代理轉送流量。
- 只設定 WAN：只代理本機流量。
- 兩者都設定：同時代理轉送和本機流量。
- `wan_interface: auto` 跟隨 metric 最低的 IPv4 預設路由。

### 核心設定

桌面和伺服器發行版通常已經啟用所需 feature；OpenWrt、Armbian、VyOS 等精簡系統需要額外確認。檢視目前的核心設定：

```shell
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

真實資料路徑至少需要以下核心選項提供的 capability：

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_SCHED=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_XGRESS=y
CONFIG_NET_NS=y
```

TCX 後端需要 `CONFIG_NET_XGRESS`。這個選項是隱藏的，由 `CONFIG_NET_CLS_ACT` 選中；舊的 `CONFIG_NET_CLS_BPF` 和 `CONFIG_NET_SCH_INGRESS` 都不需要。參見 [hook 與 qdisc 所有權](./design/datapath.md#介面-hook-集合)。

預設啟用首包保留的 UDP 還需要：

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NFT_CT=y|m
CONFIG_NFT_QUEUE=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
```

必須啟用 cgroup v2 和 `CONFIG_CGROUP_BPF`。真實資料路徑會在根 cgroup 上掛接 socket 身分 hook 和 TCP `sock_ops` 程式 `honk_tcp_passive`。兩項缺任何一項，啟動都會失敗。根 cgroup 的 `sock_ops` 槽位如果已經被 flags=0 的舊式程式佔用，啟動同樣會失敗，用 `bpftool cgroup attach` 掛上的程式也算。

`honk_tcp_passive` 會收到主機上每次 TCP `sock_ops` 回呼，每條連線若干次；遇到不屬於 honk 命名空間的 socket 就直接返回。TCP 歸屬證明不需要核心內建 BTF、ftrace 或內建 IPv6，有外部的原始 BTF 檔就夠了。

啟動時一律會載入原始 BTF。eBPF 載入器把它當成目標 BTF，並從中取出程式名稱和接收追蹤所需的偏移。選擇檔案的順序如下：

1. `HONK_VMLINUX_BTF` 指定的檔案。
2. 未設定覆寫路徑時，讀取 `/sys/kernel/btf/vmlinux`。
3. 前一預設路徑不可讀時，讀取 `/usr/lib/debug/boot/vmlinux`。OpenWrt 的 `vmlinux-btf` 套件會把檔案安裝在此處。

只有可選的 `native-api` UDP 接收追蹤後備機制會掛接 fentry/fexit 程式，供 UDP 接收優先順序的輔助中繼資料無法取得時使用。它需要核心內建 BTF 和 ftrace，`HONK_VMLINUX_BTF` 無法取代核心內建 BTF；缺少時就降級執行：

```text
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
```

`udp_recvmsg` 或 `udpv6_recvmsg` hook 缺失或不相容時，只會停用對應 socket 位址族的後備機制；兩個位址族都依賴共用的 `__skb_recv_udp` hook。後備機制部分成功或失敗後，listener reload 不會重試，改完核心或 BTF 支援後要重新啟動。見[接收追蹤所有權](./design/control-plane.md#啟動與關閉)。

### bpffs

eBPF map 必須固定在 bpffs，不能使用一般目錄：

```shell
sudo install -d -m 0755 /sys/fs/bpf
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
mountpoint /sys/fs/bpf
```

若系統不會自動掛載，可加入 `/etc/fstab`：

```fstab
bpf /sys/fs/bpf bpf defaults 0 0
```

## 安裝

### 預編譯二進位檔

從 [GitHub Releases](https://github.com/daeuniverse/honk/releases) 下載與裝置架構相符的套件。每個套件名稱都以變體字尾結尾；舊版本的 full 建置沒有字尾：

| 變體 | 套件字尾 | Release 標籤 | 內容 |
|---|---|---|---|
| full | `-full` | `fullapi` | Clash API、原生 API 與內嵌 doona UI；平台為 `x86_64` 和 `aarch64`，libc 為 gnu 和 musl |
| clash-api | `-clash-api` | `clashapi` | 僅 Clash API；不含原生 API 與內嵌 UI，只發行 musl 套件 |
| native-api | `-native-api` | `nativeapi` | 僅原生 API；不含 Clash API 與內嵌 UI，只發行 musl 套件 |

musl 套件是靜態二進位檔，適合閘道器部署。

| 記憶體分配器變體 | 發行標籤 | 適用情境 |
| --- | --- | --- |
| 無 `-stock` 字尾：jemalloc | `jemalloc` | 優先考慮輸送量。 |
| `-stock`：系統記憶體分配器 | `stockalloc` | 較在意 RSS 峰值的小記憶體裝置。 |

每個發行版本的 Downloads 一節依 `{allocator}-{API}-{arch}-{libc}` 標籤列出所有封存檔。

精簡變體一律 fail-closed。在 `-clash-api` 上啟用 `experimental.native_api` 會啟動失敗；沒有 `native-ui` 卻設定 `ui: embedded` 或 `ui: embedded-lite`，同樣會失敗。`--store db` 和原生設定管理需要 `native-api`。`embedded-lite` 會選擇更輕量的 doona lite 預覽版。

```shell
pkg=honk-core-<version>-<target>-full   # 或依下載的套件改為 -stock-full、-clash-api、-stock-native-api 等
awk -v file="$pkg.tar.gz" '$2 == file' SHA256SUMS | sha256sum -c -   # SHA256SUMS 從同一個 release 下載
tar -xzf "$pkg.tar.gz"
sudo install -m 0755 "$pkg/honk-core" /usr/local/bin/honk-core
honk-core --version
```

裝有 GitHub CLI 時，還可以用 `gh attestation verify "$pkg.tar.gz" -R daeuniverse/honk` 確認該套件由本儲存庫的發行工作流程建置。

發行的二進位檔已內嵌 eBPF 目標檔，不需要另外安裝 `honk-ebpf`。執行時也不會呼叫 `ip`、`nft`、`iptables` 或 `nsenter` 子行程。

### 發行版套件

正式版本還附帶 `x86_64` 與 `aarch64` 靜態 musl full 建置的套件：Debian 和 Ubuntu 用 `.deb`，Fedora 和 RHEL 用 `.rpm`，Arch Linux 用 `.pkg.tar.zst`。套件會安裝 `/usr/bin/honk-core`、`honk-core.service` 和 `/etc/honk/example.dae`，因此不需要再照[使用 systemd 執行](#使用-systemd-執行)操作。

```shell
sudo apt install ./honk-core-<version>-x86_64.deb       # Debian、Ubuntu
sudo dnf install ./honk-core-<version>-x86_64.rpm       # Fedora、RHEL
sudo pacman -U ./honk-core-<version>-x86_64.pkg.tar.zst # Arch Linux
sudo cp /etc/honk/example.dae /etc/honk/config.dae      # 然後按需修改
sudo systemctl enable --now honk-core
```

升級套件會重新啟動正在執行的 `honk-core.service`，移除套件則會停止並停用該服務。honk 與 dae 會掛接到同一批網路介面上，不能同時執行：該服務宣告了 `Conflicts=dae.service`，啟動其中一個就會停止另一個。從 dae 切換過來時，還要執行 `sudo systemctl disable dae`，避免 dae 開機自動啟動。

### 從原始碼建置

編譯含真實 eBPF 的原始碼版本需要下列工具：

- 根目錄 `rust-toolchain.toml` 中固定的 Rust stable，含 `rustfmt` 和 `clippy`；
- `crates/honk-ebpf/rust-toolchain.toml` 中固定的 nightly，含 `rust-src` 和 `llvm-tools`；
- `.github/ci/pins.env` 中固定的 `bpf-linker` 版本；
- C/C++ 工具鏈、CMake、Clang、LLVM、libclang、libbpf 標頭檔、binutils、pkg-config 和 Git；
- 能連線到 crates.io 和 GitHub 的網路。

Debian/Ubuntu：

```shell
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm libbpf-dev pkg-config \
  cmake libclang-dev binutils git curl ca-certificates
```

Arch Linux/CachyOS：

```shell
sudo pacman -S --needed \
  base-devel clang llvm libbpf cmake pkgconf git curl ca-certificates
```

複製儲存庫，然後安裝儲存庫指定的 Rust 工具鏈：

```shell
git clone https://github.com/daeuniverse/honk.git
cd honk
rustup toolchain install $(grep -oP '^channel\s*=\s*"\K[^"]+' rust-toolchain.toml) \
  --profile minimal --component rustfmt --component clippy
rustup toolchain install $(grep -oP '^channel\s*=\s*"\K[^"]+' crates/honk-ebpf/rust-toolchain.toml) \
  --profile minimal --component rust-src --component llvm-tools
source .github/ci/pins.env
cargo install bpf-linker --version "$BPF_LINKER_VERSION"
```

建置目前的 `main`：

```shell
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
(
  cd crates/honk-ebpf
  cargo build --release \
    -Zbuild-std=core --target bpfel-unknown-none
)

readelf -S crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf \
  | grep -q '\.BTF'
cargo build --release -p honk-core --features ebpf
sudo install -m 0755 target/release/honk-core /usr/local/bin/honk-core
```

`RUSTFLAGS` 會覆寫 eBPF crate 的 BTF 引數，而 Aya 無法載入缺少 `.BTF` 的目標檔，所以清除環境變數和檢查 `.BTF` 這兩步不能省。

## 最小設定

先用只走直連的設定確認資料路徑能正常啟動，再加入訂閱或代理節點。把 `br-lan` 換成用戶端流量實際進入的 LAN 介面；只代理本機時刪除 `lan_interface`。

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    data_dir: '/var/lib/honk'
    log_level: info
    dial_mode: domain
    auto_config_kernel_parameter: true
}

routing {
    fallback: direct
}
```

安裝設定：

```shell
sudo install -d -m 0700 /etc/honk /var/lib/honk
sudo install -m 0600 /path/to/config.dae /etc/honk/config.dae
```

預設的執行階段根目錄是 `/var/lib/honk`。舊根目錄 `/var/share/honk` 裡的資源仍可依各路徑規則繼續使用；舊快取和訂閱匯入會把符合條件的狀態複製到 `state/honk.db`。自訂 `data_dir` 也遵循同樣的退回順序。快取、訂閱儲存、ECH/UI 和其他唯讀依賴若是相對路徑，會依序在 `global.data_dir` 選定的執行階段目錄、`/var/share/honk` 和呼叫端的舊位置尋找，取第一個存在的。相對日誌只在該執行階段目錄下建立，不會寫到設定檔所在目錄。

在前景啟動：

```shell
sudo /usr/local/bin/honk-core --config /etc/honk/config.dae
```

日誌出現 `honk-core is running` 後，先用真實 LAN 用戶端確認能上網，再新增節點、訂閱、代理群組、路由和 DNS。依下列步驟換成最小代理設定：

1. 保留只走直連設定的 `global` 小節。
2. 新增範例中的 `node` 和 `group` 小節。
3. 把整個 `routing { fallback: direct }` 小節換成 `routing { fallback: proxy }`。不要追加第二個 `routing` 小節。
4. 把範例位址和憑證換成真實節點的資訊。

```dae
node {
    edge: 'socks5://user:password@proxy.example.com:1080'
}

group {
    proxy {
        filter: name('edge')
        policy: fixed(0)
    }
}

routing {
    fallback: proxy
}
```

代理伺服器使用網域時，應在 `global` 中設定獨立的 bootstrap resolver，避免 DNS 自我攔截：

```dae
bootstrap_resolver: '1.1.1.1:53'
```

完整設定方法見[中文設定指南](configuration.md)。儲存庫中的 `config.dae`、`config.min.dae` 和 `example.dae` 包含範例介面或節點，部署前必須依實際網路修改。

### 單臂閘道器

honk 不支援這種部署，相關提問和問題回報不予答覆。

單臂閘道器也常被稱為旁路由：`lan_interface` 和 WAN 是同一個介面或橋接器，用戶端把 honk 主機設為閘道器，主機再從同一介面把流量轉給上游路由器。這類主機要設定下列三個核心引數。honk 不會自行設定，`auto_config_kernel_parameter` 也不改這三項，見[全域設定參考](reference/global.md)。

- 開啟 `send_redirects` 時，核心會向用戶端送出 ICMP 重新導向，讓用戶端把流量直接送給上游路由器，流量就繞過了 honk。`all` 和介面的值只要有一個是 `1`，核心就會送出重新導向，所以兩者都要設為 `0`。
- honk 只會把第一個已繫結 LAN 介面的 `rp_filter` 設為 `0`，但核心取 `all` 和介面兩者中較大的值，所以 `all` 上的 `1` 或 `2` 會蓋過這個設定。要把 `all` 設為 `0`。

把 `br-lan` 換成 `lan_interface` 中的介面名稱，然後載入該檔案：

```shell
sudo tee /etc/sysctl.d/60-honk-single-arm.conf <<'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.br-lan.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
EOF
sudo sysctl -p /etc/sysctl.d/60-honk-single-arm.conf
```

該檔案在每次開機時也會生效。檢查取值，三項都應該是 `0`：

```shell
sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.br-lan.send_redirects net.ipv4.conf.all.rp_filter
```

收到重新導向的用戶端可能還會沿用學到的路由一段時間，測試前先讓它重新連線一次。

#### 直連流量不通

症狀是用戶端能開啟走代理的網站，卻打不開直連的網站，`ping` 也不通，而 honk 主機本身的對外連線正常。走代理的 TCP 和 UDP 由 honk 在主機上接管，再由主機另外建立連線；直連流量和 ICMP 則由主機轉送，因此只丟棄轉送流量的防火牆只會影響後者。以下兩種防火牆設定會造成這種情況。

Docker 通常會把 iptables `FORWARD` 鏈的預設策略設為 `DROP`，所有轉送流量都會被丟棄。先檢查預設策略，如果第一條命令輸出 `-P FORWARD DROP`，就在 Docker 的 `DOCKER-USER` 鏈中放行從 LAN 介面進出的流量：

```shell
sudo iptables -S FORWARD | head -1
sudo iptables -I DOCKER-USER -i br-lan -o br-lan -j ACCEPT
```

另一些防火牆會丟棄連線追蹤標記為 `INVALID` 的封包，OpenWrt 的預設區域就是這樣。上游路由器和用戶端在同一網段，會直接回覆用戶端，於是主機只看得到直連連線的一個方向，連線追蹤就會把這條連線後續的封包標成 `INVALID`。對轉送流量做位址偽裝後，回覆會經由主機返回；代價是上游路由器會把所有用戶端都看成主機的位址：

```shell
sudo iptables -t nat -A POSTROUTING -o br-lan -j MASQUERADE
```

OpenWrt 上則改為在 LAN 區域開啟 IP 動態偽裝。以上 iptables 規則在重新啟動後都會失效，請把需要的那條寫進主機的防火牆設定。

### 網頁介面與 API

把下面任一組設定加入設定檔，然後重新啟動 honk。這些範例只監聽本機位址；其他欄位和反向代理要求見 [experimental 參考](reference/experimental.md)。

doona 透過原生 API 提供。下例使用內嵌介面的 `full` 發行版本；建置時啟用 `native-api` 的版本也可以改用另外安裝的 doona 目錄，把 `ui` 設為該目錄的路徑即可。

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        password_auth: true
        config_write: true
        ui: 'embedded'
    }
}
```

啟動後開啟 `http://127.0.0.1:9527/ui/`。

- `enabled` 啟用原生 API listener；`listen` 指定監聽位址和連接埠。
- `password_auth` 啟用密碼登入。首次存取時建立管理員帳號，帳號儲存在 `data_dir` 下的 `state/honk.db` 裡，不在設定檔中。
- `config_write` 允許通過驗證的使用者寫入設定並 reload。含 listener 憑證的原始檔仍然唯讀。
- `ui: 'embedded'` 提供內嵌在二進位檔中的標準版 doona，啟動時不會下載面板。

doona lite 是更輕量的預覽版，建置要求、存取位址和登入步驟與上面的內嵌範例相同。用下面的設定取代標準版 doona 設定：

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        password_auth: true
        config_write: true
        ui: 'embedded-lite'
    }
}
```

Clash 面板要透過 Clash API 存取。使用啟用了 `clash-api` 的建置，例如 `full` 或 `clash-api` 發行版本，並把 secret 換成一個夠長的隨機字串：

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: '<a long random string>'
    }
}
```

`external_controller` 啟用 Clash listener，`external_ui` 指定面板目錄。首次啟動時如果目錄不存在或是空的，honk 會下載 zashboard。開啟 `http://127.0.0.1:9090/ui/`，在面板裡填入設定的 `secret` 連線 API。API 用它驗證，靜態介面檔案不需要驗證就能存取。

同時包含兩種 API feature 的建置可以一起執行，例如 `full`。把 `native_api` 和 `clash_api` 並排寫在同一個 `experimental` 小節裡，各自使用不同的監聽連接埠。

### GeoIP 和 Geosite

只有設定引用 `geoip:` 或 `geosite:` 時才需要下載：

```shell
sudo curl -fL --retry 3 -o /var/lib/honk/geosite.dat \
  https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -fL --retry 3 -o /var/lib/honk/geoip.dat \
  https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
```

引擎依下列順序選擇第一個存在的一般檔案：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`
4. `./<name>`
5. `/usr/local/share/honk/<name>`
6. `/usr/share/honk/<name>`
7. `/usr/local/share/dae/<name>`
8. `/usr/share/dae/<name>`
9. `/etc/dae/<name>`

## 使用 systemd 執行

建立 `/etc/systemd/system/honk-core.service`：

```ini
[Unit]
Description=honk transparent proxy engine
Wants=network-online.target
After=network-online.target
Conflicts=dae.service

[Service]
Type=notify
User=root
WorkingDirectory=/var/lib/honk
ExecStart=/usr/local/bin/honk-core --config /etc/honk/config.dae --disable-timestamp
ExecReload=/usr/local/bin/honk-core reload
Restart=on-failure
RestartSec=2s
TimeoutStopSec=30s
LimitNOFILE=1048576
LimitMEMLOCK=infinity
UMask=0077

[Install]
WantedBy=multi-user.target
```

啟動並設為開機自動啟動：

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now honk-core
sudo systemctl status honk-core
sudo journalctl -xefu honk-core
```

嚴格的 capability bounding、唯讀 `/proc/sys` 和 `NoNewPrivileges=yes` 都要先驗證再加。啟動需要 BPF、網路管理、網路命名空間、掛載、sysctl 和透明 socket 權限。

## 使用 Docker 執行

[GitHub Container Registry](https://github.com/daeuniverse/honk/pkgs/container/honk) 上的映像 `ghcr.io/daeuniverse/honk` 包含 musl `full` 發行版的二進位檔，以及儲存庫固定版本的 GeoIP 和 Geosite 檔案，建置時會對每個下載檔案做 SHA-256 驗證。映像標籤是去掉 `v` 的版本號，例如 `ghcr.io/daeuniverse/honk:0.1.0-beta.4`；`latest` 只指向正式版，不含預發行版。映像有 linux/amd64 和 linux/arm64 兩種架構，拉取不需要登入。

honk 要載入並掛接 eBPF 程式、建立 `dae0` 和 `daens` 命名空間、修改 sysctl，還要在主機的 bpffs 上固定 map，所以容器以特權模式執行，並共用主機的網路和 PID 命名空間。它對主機的改動和直接安裝一樣，沒有任何隔離。主機必須符合[核心要求](#linux-核心要求)，包括 Linux 6.12+ 和已掛載的 bpffs。

依[最小設定](#最小設定)準備 `/etc/honk/config.dae` 和 `/var/lib/honk`，然後在 `.env` 中寫入發行版本號，再啟動儲存庫中的 `docker-compose.yml`：

```shell
curl -fLO https://raw.githubusercontent.com/daeuniverse/honk/main/docker-compose.yml
echo 'HONK_VERSION=<version>' > .env   # 例如 0.1.0-beta.4
sudo touch /run/honk-core.lock
sudo docker compose up -d
sudo docker compose logs -f
```

該檔案把主機的 `/sys`、`/etc/honk`、`/var/lib/honk` 掛載進容器，並以唯讀方式掛載 `/etc/localtime`，讓容器的日誌時間戳和 geodata 更新時間跟隨主機時區。主機沒有 `/etc/localtime` 時，請刪除這項掛載，改在服務的 `environment` 裡把 `TZ` 設為 `CST-8` 這類 POSIX 字串。設定目錄的掛載會蓋過映像裡只走直連的預設設定；`/var/lib/honk` 儲存執行階段狀態，例如原生 API 的管理員帳號，重新啟動或升級後仍然保留。要 reload 設定，執行 `sudo docker compose exec honk honk-core reload`。映像自帶 iproute2 和 nftables，容器又和主機共用網路命名空間，所以 `sudo docker compose exec honk ip rule`、`ip route show table all`、`tc filter show dev <網絡卡> ingress` 和 `nft list ruleset` 顯示的就是主機的狀態。

鎖定檔的掛載讓容器和原生執行個體共用 `/run/honk-core.lock`，容器因此無法接管正在執行的資料路徑。停止後也要保留這個檔案，不要刪除、替換或截斷仍可能被執行個體持有的鎖定檔。每次開機都要先建立鎖定檔，再啟動容器。使用 systemd 的主機可以設定不截斷既有檔案的開機建立規則：

```shell
echo 'f /run/honk-core.lock 0600 root root -' | sudo tee /etc/tmpfiles.d/honk-container.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/honk-container.conf
```

其他 init 系統也要在開機啟動容器之前，以不截斷的方式建立這個檔案。直接用 `docker run` 或 `podman run` 部署時，同樣要掛載這個鎖定檔。

如果主機使用外部的原始 BTF 檔，而不是 `/sys/kernel/btf/vmlinux`，把下面內容存成與 `docker-compose.yml` 同目錄的 `docker-compose.override.yml`。Compose 的每條命令都會載入它，升級時也一樣。把 `source` 改成主機的原始 BTF 檔路徑，環境變數則寫容器內的掛載路徑：

```yaml
services:
  honk:
    environment:
      HONK_VMLINUX_BTF: /run/honk-vmlinux
    volumes:
      - type: bind
        source: /usr/lib/debug/boot/vmlinux
        target: /run/honk-vmlinux
        read_only: true
        bind:
          create_host_path: false
```

升級時修改 `.env` 中的 `HONK_VERSION`，然後重新建立容器：

```shell
sudo docker compose pull
sudo docker compose up -d
```

在儲存庫的簽出目錄裡執行 `sudo docker compose build`，可以直接用已發行的版本建置同一個映像，不必拉取。

## 檢查執行狀態

程式啟動不等於資料路徑可用。日誌應顯示真實 eBPF 後端、介面 hook、listener 和控制面都已就緒。

介面繫結狀態對應下列日誌：

| 介面狀態 | 日誌級別與頻率 | 訊息 |
| --- | --- | --- |
| hook 已就緒 | 繫結時記錄一次 `info` | `configured interface is bound` |
| 介面不存在，或 `auto` 沒有預設路由 | 一次 warning，之後為 `debug` | `configured interface is not bound yet` |
| 掛接失敗 | 一次 warning，之後為 `debug` | `configured interface attach failed; retrying` |
| 不支援的連結型別 | 一次 error | `configured interface is not supported` |

`GET /runtime` 會在 `interface_binding` 中以降級狀態回報未繫結的介面。見 [API 參考](./reference/api.md#原生-api)。

```shell
ip link show dae0
sudo bpftool prog show
sudo bpftool map show
sudo journalctl -u honk-core --since '5 minutes ago'
```

若從原始碼建置了 `honk-tool`，可執行一次唯讀診斷：

```shell
cargo build --release -p honk-tool
sudo ./target/release/honk-tool diagnose \
  --api http://127.0.0.1:9090 --pin-root /sys/fs/bpf
```

最後必須從真實用戶端分別驗證應直連和應代理的 TCP、UDP、DNS，以及部署需要的 IPv4/IPv6。`dae0` 存在或 API 可存取，都不能取代端對端驗證。

## reload 與停止

```shell
sudo systemctl reload honk-core
# 或
sudo /usr/local/bin/honk-core reload
```

是否套用成功，看執行日誌裡的 `applied` 或 `rejected`。介面、TPROXY、`data_dir`、NFQUEUE 開關、DNS 繫結、Clash API listener/secret、快取等程式層級設定變更時，需要重新啟動。執行期間出現或消失的介面不用 reload，介面觀察器會自動繫結和釋放它們。

正常停止：

```shell
sudo systemctl stop honk-core
```

不要用 `kill -9` 做日常停止。honk 會先關閉資料路徑 admission，再 fence NFQUEUE，然後拆掉 hook 和 link。同一部主機只能執行一個真實資料路徑執行個體，`/run/honk-core.lock` 用來避免固定資源衝突。

## 無 root 開發

`--mock-ebpf` 可以驗證設定、API、DNS 和使用者空間出站，但不會攔截任何真實流量。

把以下內容存成 `/tmp/honk.dae`：

```dae
global {
    data_dir: '/tmp/honk'
    nfqueue_enable: false
    preconnect_node_count: 0
    udp_warm_node_count: 0
}

routing {
    fallback: direct
}
```

```shell
cargo run --release -p honk-core -- \
  --config /tmp/honk.dae --mock-ebpf
```

## 目前 capability 與限制

- 出站支援 Direct、Block、SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess 和 VLESS。
- UDP 支援 Direct、SOCKS5、Shadowsocks、Trojan、AnyTLS、Hysteria2、TUIC、Juicity，以及獨立 packet permission 已開啟的 VLESS。VLESS 的退回編碼和多工 carrier 是兩個獨立選擇；VMess 仍只支援 TCP。見 [VLESS 節點參考](reference/nodes.md#vless-udp-and-multiplexing)。
- 群組支援 Selector、URLTest、LoadBalance、Fallback 和 Score。
- DNS 上游支援 UDP、TCP、DoT、DoH、DoH3 和 DoQ，也可經由 node/group 出站。
- `direct` 和 `block` 是內建節點，不要在設定中重複宣告。
- `nfqueue_enable` 預設開啟，固定使用佇列 320，並獨佔 `inet honk_nfqueue` / `udp_decision`。同一網路命名空間中的防火牆管理器不能改動這些物件。
- mock 建置，以及沒有啟用 Cargo `ebpf` feature 的建置，都不提供透明代理。一般的 `cargo build --release` 不含真實資料路徑，必須加上 `--features ebpf`。
- 目前沒有 VMess UDP 和無 root 資料路徑，也不支援非 Linux 系統。

## 常見問題

| 現象 | 處理 |
| --- | --- |
| `bpf-linker` 不存在 | 依「從原始碼建置」一節安裝，並把 Cargo 的 bin 目錄加入 PATH。 |
| `no BTF parsed for object` | 清除 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS`，重新建置 eBPF 目標檔，並用 `readelf` 確認 `.BTF`。 |
| 核心或 verifier 拒絕編譯式路由 | 使用支援 BPF/BTF 和 freplace 的 Linux `6.12+`；保留完整的 verifier 日誌和產生規則的定位資訊，不要略過啟動失敗。 |
| pin map 回報 `Invalid argument` | `/sys/fs/bpf` 不是 bpffs；依上文重新掛載。 |
| mock 啟動成功但流量不經過 honk | 這是預期行為；改用含 `ebpf` feature 的建置，並以 root 啟動。 |
| NFQUEUE disabled 或 queue busy | 檢查 nftables/NFQUEUE 核心支援、佇列 320 的佔用者和殘留的 honk 執行個體；確實不需要時設定 `nfqueue_enable: false`。 |
| LAN 流量未被代理 | `lan_interface` 為空或介面名稱錯誤；honk 不會自動改用 `lo`。介面名稱無誤時看下一項。 |
| `GET /runtime` 出現 `interface_binding` 降級 | 某個已設定的介面還沒繫結，日誌裡有介面名稱。`pending`：介面不存在，或 `auto` 條目沒有 IPv4 預設路由。`unsupported_type`：連結型別遭拒，例如 `lo`、VRF 裝置或 `dae0`，請改成受支援的介面或其成員。`attach_failed`：TCX link 無法建立、更新或驗證，原因見日誌中的 warning。介面狀態列位見[原生 API 參考](./reference/api.md#原生-api)。 |
| 單臂閘道器的用戶端繞過 honk，或轉送的流量被丟棄 | 把 `all` 和 LAN 介面的 `send_redirects` 設為 `0`，並把 `net.ipv4.conf.all.rp_filter` 設為 `0`，見[單臂閘道器](#單臂閘道器)；直連流量仍不通時，見[直連流量不通](#直連流量不通)。 |
| VLESS/VMess 回報 `No handler for protocol` | 建置缺少 `rprx`；使用預設 feature，或明確加上 `rprx`。 |
| Geo 規則載入失敗 | 把 `geoip.dat`/`geosite.dat` 放進設定的 `data_dir`，或檢查文件列出的舊目錄和共用目錄；不需要 Geo 規則就刪掉。 |
| GNU 二進位檔在 VyOS/精簡系統無法執行 | 改用同架構的 musl 發行版本。 |

## 繼續閱讀

- [設定指南](configuration.md)
- [全域設定](reference/global.md)
- [節點與協定](reference/nodes.md)
- [訂閱](reference/subscription.md)
- [群組策略](reference/groups.md)
- [路由規則](reference/routing.md)
- [DNS 設定](reference/dns.md)
- [CLI](reference/cli.md)
- [架構概覽](design/overview.md)

## 檢查解析器改動

在儲存庫根目錄執行 `just parser-ci`，需要固定版本的 stable Rust、Go 1.26 以上、Python 3.11 以上，以及網路。案例寫法見 `crates/honk-config/conformance/README.md`；oracle 及其授權條款見 `tools/dae-parse/README.md`。

該命令依序執行下列檢查：

1. 建置固定版本的 dae oracle。
2. 拉取上游範例，並驗證清單中的 SHA-256。
3. 比較解碼後的結構與已記錄的方言差異。
4. 重放已儲存的模糊測試輸入。

Cargo 相依性已快取時，`just fuzz-replay` 只需要 stable Rust。它使用與模糊測試目標相同的斷言。重放失敗會印出輸入路徑；輸入處理停滯時，五秒後判定失敗。

設定程式碼、oracle、模糊測試輸入、語料來原始檔或它們的建置輸入有變更時，會執行 `parser` CI 任務；指定 `ci:full` 時也會執行。一般工作區命令不會啟用 `conformance` 和 `fuzz-checks`，所以不需要 Go 或 nightly。

每週模糊測試任務使用下列設定：

| 設定 | 值 |
| --- | --- |
| Rust 版本通道 | `crates/honk-ebpf/rust-toolchain.toml` 中固定的 nightly |
| cargo-fuzz 版本 | 由 `.github/ci/pins.env` 固定 |
| 目標 | `document`、`share_link`、`lexer` |
| 執行時間與並行數 | 每個目標執行 480 秒，兩個 worker |
| 上傳的產出 | 發現的問題與語料檔 |

把保留的問題輸入放在 `fuzz/artifacts/<target>/` 下，就能在 stable 上重放。只有 sanitizer 偵測到的問題仍需使用 nightly 模糊測試目標。
