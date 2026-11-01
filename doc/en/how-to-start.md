# honk Quick Start

Install, configure, and start honk, an experimental eBPF transparent proxy engine for Linux.

> **Warning**
>
> honk is still alpha. Real mode loads eBPF programs, attaches TC and cgroup hooks, creates `dae0`/`daens`, changes sysctls, and uses NFQUEUE 320 by default. Keep an out-of-band management path available during the first deployment.

## Linux kernel requirements

### Kernel version

```shell
uname -r
```

- Only Linux is supported. The real transparent datapath must run as `root`.
- Linux `6.12+` is required for compiled routing and its synchronous map-in-map publication guarantee. Older kernels are rejected before attachment.
- `netkit` is optional. honk falls back to veth when the kernel does not support it.

`lan_interface` intercepts traffic entering the gateway from the LAN. `wan_interface` intercepts traffic originated by the gateway itself:

- LAN only: intercept forwarded traffic only.
- WAN only: intercept locally originated traffic only.
- Both: intercept forwarded and locally originated traffic.
- `wan_interface: auto` follows the lowest-metric IPv4 default route.

### Kernel configuration

Desktop and server distributions usually enable the required features. Check them explicitly on minimal systems such as OpenWrt, Armbian, and VyOS. Display the current kernel configuration with:

```shell
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

The real datapath requires the capabilities represented by at least these kernel options:

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

The TCX backend needs `CONFIG_NET_XGRESS`, a hidden option selected by `CONFIG_NET_CLS_ACT`, not legacy `CONFIG_NET_CLS_BPF` or `CONFIG_NET_SCH_INGRESS`. See [hook and qdisc ownership](./design/datapath.md#interface-hook-sets).

Held-first-packet UDP, which is enabled by default, additionally requires:

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NFT_CT=y|m
CONFIG_NFT_QUEUE=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
```

cgroup v2 with `CONFIG_CGROUP_BPF` is required. The real datapath attaches socket-identity hooks and the TCP `sock_ops` program `honk_tcp_passive` to the root cgroup. Startup fails if either is unavailable. A legacy program with flags=0 already occupying the root cgroup's `sock_ops` slot also prevents startup, including one attached with `bpftool cgroup attach`.

`honk_tcp_passive` receives every host TCP `sock_ops` callback, a few per connection. It returns immediately for sockets outside honk's namespace. TCP ownership proof requires neither in-kernel BTF, ftrace nor built-in IPv6; an external raw BTF file is sufficient.

Startup always loads raw BTF for the eBPF loader's target BTF and the process-name and receive-trace offsets. It selects the file in this order:

1. The file specified by `HONK_VMLINUX_BTF`.
2. `/sys/kernel/btf/vmlinux` when no override is set.
3. `/usr/lib/debug/boot/vmlinux` when the preceding default path is unreadable. OpenWrt's `vmlinux-btf` package installs this file.

Only the optional `native-api` UDP receive-trace fallback, used when UDP receive-priority ancillary metadata is unavailable, attaches fentry/fexit programs. It needs the in-kernel BTF (`HONK_VMLINUX_BTF` does not substitute) and ftrace, and degrades without them:

```text
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
```

A missing or incompatible `udp_recvmsg` or `udpv6_recvmsg` hook disables only that socket family's fallback; the shared `__skb_recv_udp` hook is required by both. A partial or failed fallback attachment is not retried on listener reload: restart after changing kernel/BTF support. See [receive-trace ownership](./design/control-plane.md#startup-and-shutdown).

### bpffs

eBPF maps must be pinned on bpffs, not an ordinary directory:

```shell
sudo install -d -m 0755 /sys/fs/bpf
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
mountpoint /sys/fs/bpf
```

If the system does not mount bpffs automatically, add this entry to `/etc/fstab`:

```fstab
bpf /sys/fs/bpf bpf defaults 0 0
```

## Installation

### Prebuilt binaries

Download the package matching the device architecture from [GitHub Releases](https://github.com/daeuniverse/honk/releases). Every name ends in its variant (older releases name the full build without a suffix):

| Variant | Package suffix | Release label | Contents |
|---|---|---|---|
| full | `-full` | `fullapi` | Clash API, native API and the embedded doona UI (`x86_64`/`aarch64`, gnu and musl) |
| clash-api | `-clash-api` | `clashapi` | Clash API only; no native API and no embedded UI (musl only) |
| native-api | `-native-api` | `nativeapi` | Native API only; no Clash API and no embedded UI (musl only) |

The musl packages are static binaries intended for gateways.

| Allocator variant | Release label | Intended use |
| --- | --- | --- |
| No `-stock` suffix: mimalloc | `mimalloc` | Prioritize throughput. |
| `-stock`: system allocator | `stockalloc` | Small devices where the RSS high-water mark matters more. |

Each release's Downloads section lists every archive with its `{allocator}-{API}-{arch}-{libc}` label.

The lean variants fail closed: enabling `experimental.native_api` on `-clash-api`, or `ui: embedded` or `ui: embedded-lite` without `native-ui`, fails startup. `--store db` and native configuration administration require `native-api`. `embedded-lite` selects the lighter doona lite edition (preview).

```shell
pkg=honk-core-<version>-<target>-full   # or -stock-full, -clash-api, -stock-native-api, as downloaded
awk -v file="$pkg.tar.gz" '$2 == file' SHA256SUMS | sha256sum -c -   # SHA256SUMS comes from the same release
tar -xzf "$pkg.tar.gz"
sudo install -m 0755 "$pkg/honk-core" /usr/local/bin/honk-core
honk-core --version
```

With the GitHub CLI installed, `gh attestation verify "$pkg.tar.gz" -R daeuniverse/honk` also confirms that the package was built by this repository's release workflow.

Release binaries embed the eBPF object, so `honk-ebpf` does not need to be installed separately. At runtime, the engine does not invoke `ip`, `nft`, `iptables`, or `nsenter` subprocesses.

### Distribution packages

Formal releases also attach packages of the static musl full build for `x86_64` and `aarch64`: `.deb` for Debian and Ubuntu, `.rpm` for Fedora and RHEL, and `.pkg.tar.zst` for Arch Linux. Each installs `/usr/bin/honk-core`, the `honk-core.service` unit and `/etc/honk/example.dae`, so [Run with systemd](#run-with-systemd) does not apply.

```shell
sudo apt install ./honk-core-<version>-x86_64.deb       # Debian, Ubuntu
sudo dnf install ./honk-core-<version>-x86_64.rpm       # Fedora, RHEL
sudo pacman -U ./honk-core-<version>-x86_64.pkg.tar.zst # Arch Linux
sudo cp /etc/honk/example.dae /etc/honk/config.dae      # then edit it
sudo systemctl enable --now honk-core
```

Upgrading the package restarts a running `honk-core.service`; removing it stops and disables the service. honk and dae attach to the same interfaces and cannot run at the same time: the unit declares `Conflicts=dae.service`, so starting either service stops the other. When switching from dae, also run `sudo systemctl disable dae` so that dae does not start at boot.

### Build from source

The real-eBPF source build below uses:

- the stable Rust version in the root `rust-toolchain.toml` (`rustfmt`, `clippy`);
- the nightly in `crates/honk-ebpf/rust-toolchain.toml` (`rust-src`, `llvm-tools`);
- the `bpf-linker` version in `.github/ci/pins.env`;
- a C/C++ toolchain, CMake, Clang, LLVM, libclang, libbpf headers, binutils, pkg-config, and Git;
- network access to crates.io and GitHub.

Debian/Ubuntu:

```shell
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm libbpf-dev pkg-config \
  cmake libclang-dev binutils git curl ca-certificates
```

Arch Linux/CachyOS:

```shell
sudo pacman -S --needed \
  base-devel clang llvm libbpf cmake pkgconf git curl ca-certificates
```

Clone the repository, then install its pinned Rust toolchains:

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

Build the current `main` branch:

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

`RUSTFLAGS` overrides the eBPF crate's BTF flags. Aya cannot load an object without `.BTF`, so do not omit the environment cleanup or the check.

## Minimal configuration

Start with a direct-only configuration to verify the datapath, then add subscriptions or proxy nodes. Replace `br-lan` with the LAN interface receiving client traffic. Remove `lan_interface` to intercept only local traffic.

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

Install the configuration:

```shell
sudo install -d -m 0700 /etc/honk /var/lib/honk
sudo install -m 0600 /path/to/config.dae /etc/honk/config.dae
```

The default runtime root is `/var/lib/honk`. Existing artifacts under the legacy `/var/share/honk` root remain usable through the documented per-path fallback. Legacy cache and subscription imports copy eligible state into `state/honk.db`. Custom `data_dir` values use the same fallback order. Relative caches, subscription stores, ECH/UI and other read-only dependencies check the configured directory, then `/var/share/honk`, then their caller-specific legacy path. Relative logs are created only below the configured directory.

Start honk in the foreground:

```shell
sudo /usr/local/bin/honk-core --config /etc/honk/config.dae
```

After `honk-core is running` appears, verify connectivity from a real LAN client before adding nodes, subscriptions, groups, routing, and DNS. To apply the minimal proxy example:

1. Keep the direct-only configuration's `global` section.
2. Add the example's `node` and `group` sections.
3. Replace the entire `routing { fallback: direct }` section with `routing { fallback: proxy }`. Do not append a second `routing` section.
4. Replace the example address and credentials with a real node.

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

When a proxy server uses a hostname, add an independent bootstrap resolver under `global` to avoid recursive DNS interception:

```dae
bootstrap_resolver: '1.1.1.1:53'
```

See the [configuration guide](configuration.md) for the complete configuration flow. The repository's `config.dae`, `config.min.dae`, and `example.dae` contain example interfaces or nodes and must be adapted before deployment.

### Single-arm gateways

This setup is not supported; questions and bug reports about it are not answered.

On a single-arm gateway, also called a bypass router, `lan_interface` and the WAN are the same interface or bridge: clients use the honk host as their gateway, and the host sends their traffic back out through that interface to the upstream router. Set the three kernel parameters below on such a host. honk does not set these three, and `auto_config_kernel_parameter` does not change that (see the [global reference](reference/global.md)).

- With `send_redirects` on, the kernel sends clients ICMP redirects that point them at the upstream router, and their traffic then bypasses honk. The kernel sends redirects when either the `all` or the interface value is `1`, so set both to `0`.
- honk sets `rp_filter` to `0` only on the first bound LAN interface, but the kernel applies the higher of the `all` and interface values, so a value of `1` or `2` under `all` overrides it. Set `all` to `0`.

Replace `br-lan` with the interface named in `lan_interface`, then load the file:

```shell
sudo tee /etc/sysctl.d/60-honk-single-arm.conf <<'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.br-lan.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
EOF
sudo sysctl -p /etc/sysctl.d/60-honk-single-arm.conf
```

The file is also applied at every boot. Check the values; each should be `0`:

```shell
sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.br-lan.send_redirects net.ipv4.conf.all.rp_filter
```

A client that already received a redirect may keep the learned route for a while; reconnect it to the network before testing.

### Web UI and APIs

Add one of the following blocks to the configuration, then restart honk. These examples listen only on the local machine. See the [experimental reference](reference/experimental.md) for all other fields and reverse-proxy requirements.

**doona (native API).** The example below uses a `full` release, which embeds the UI. A build with `native-api` can instead serve a separately installed doona directory: set `ui` to that directory's path.

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

Open `http://127.0.0.1:9527/ui/` after startup.

- `enabled` starts the native API listener; `listen` sets its address and port.
- `password_auth` enables password login. On the first visit, create the administrator account; honk stores it under `data_dir` in `state/honk.db`, not in the configuration file.
- `config_write` permits authenticated configuration writes and reloads. Sources containing listener credentials remain read-only.
- `ui: 'embedded'` serves the standard doona bundled in the binary; it does not download a dashboard at startup.

**doona lite.** The embedded example uses the same build requirements, address and login procedure. This lighter edition is a preview. Choose this block instead of the standard doona block:

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

**Clash API for Clash dashboards.** Use a build with `clash-api` enabled, such as the `full` or `clash-api` release. Replace the secret with a long random string:

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: '<a long random string>'
    }
}
```

`external_controller` starts the Clash listener. `external_ui` selects the dashboard directory; honk downloads zashboard on first start when that directory is missing or empty. Open `http://127.0.0.1:9090/ui/` and use the configured `secret` to connect the dashboard to the API. The API uses the secret for authentication; static UI files are public.

Both APIs can run together in a build that includes both features, such as `full`. Put `native_api` and `clash_api` beside each other inside one `experimental` block; keep their separate listen ports.

### GeoIP and Geosite

Download these files only when the configuration references `geoip:` or `geosite:`:

```shell
sudo curl -fL --retry 3 -o /var/lib/honk/geosite.dat \
  https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -fL --retry 3 -o /var/lib/honk/geoip.dat \
  https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
```

The engine selects the first existing regular file in this order:

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`
4. `./<name>`
5. `/usr/local/share/honk/<name>`
6. `/usr/share/honk/<name>`
7. `/usr/local/share/dae/<name>`
8. `/usr/share/dae/<name>`
9. `/etc/dae/<name>`

## Run with systemd

Create `/etc/systemd/system/honk-core.service`:

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

Start the service and enable it at boot:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now honk-core
sudo systemctl status honk-core
sudo journalctl -xefu honk-core
```

Do not add strict capability bounding, a read-only `/proc/sys`, or `NoNewPrivileges=yes` before validating it. Startup needs BPF, network administration, network namespace, mount, sysctl, and transparent-socket privileges.

## Run with Docker

The image `ghcr.io/daeuniverse/honk` on [GitHub Container Registry](https://github.com/daeuniverse/honk/pkgs/container/honk) contains the musl `full` release binary and the GeoIP and Geosite files pinned by the repository; the build checks every download against its SHA-256 checksum. Each release is tagged with its version without the `v`, for example `ghcr.io/daeuniverse/honk:0.1.0-beta.4`; `latest` follows formal releases only, never pre-releases. Images are published for linux/amd64 and linux/arm64, and pulling needs no login.

The container runs privileged in the host's network and PID namespaces, because honk loads and attaches eBPF programs, creates `dae0` and the `daens` namespace, changes sysctls and pins maps on the host's bpffs. It therefore changes the host exactly as a native installation does and provides no isolation. The host must meet the [kernel requirements](#linux-kernel-requirements), including Linux 6.12+ and a mounted bpffs.

Prepare `/etc/honk/config.dae` and `/var/lib/honk` as in [Minimal configuration](#minimal-configuration), then start the repository's `docker-compose.yml` with the release version in `.env`:

```shell
curl -fLO https://raw.githubusercontent.com/daeuniverse/honk/main/docker-compose.yml
echo 'HONK_VERSION=<version>' > .env   # for example 0.1.0-beta.4
sudo touch /run/honk-core.lock
sudo docker compose up -d
sudo docker compose logs -f
```

The file mounts `/sys`, `/etc/honk` and `/var/lib/honk` from the host. The configuration mount replaces the image's direct-only default, and `/var/lib/honk` keeps the runtime state, such as the native API administrator account, across restarts and upgrades. Reload the configuration with `sudo docker compose exec honk honk-core reload`. The image ships iproute2 and nftables, and the container shares the host's network namespace, so `sudo docker compose exec honk ip rule`, `ip route show table all`, `tc filter show dev <interface> ingress` and `nft list ruleset` show the host's state.

The lock-file bind shares the native instance's `/run/honk-core.lock`, preventing containers from taking over an active datapath. Leave this file in place after stopping; never delete, replace or truncate an active lock. It must exist before automatic container startup on every boot. On systemd hosts, arrange non-truncating boot-time creation:

```shell
echo 'f /run/honk-core.lock 0600 root root -' | sudo tee /etc/tmpfiles.d/honk-container.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/honk-container.conf
```

On other init systems, create the file without truncation before the container's boot-time start. Direct `docker run` or `podman run` deployments must bind the same lock file too.

If the host uses an external raw BTF file instead of `/sys/kernel/btf/vmlinux`, save this as `docker-compose.override.yml` beside `docker-compose.yml`. Compose loads it for every command, including upgrades. Adjust `source` to the host's raw BTF file; the environment variable names the mounted path inside the container:

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

To upgrade, change `HONK_VERSION` in `.env` and recreate the container:

```shell
sudo docker compose pull
sudo docker compose up -d
```

In a repository checkout, `sudo docker compose build` builds the same image from the published release instead of pulling it.

## Check runtime status

A running process does not prove that the datapath is usable. The logs should show that the real eBPF backend, interface hooks, listeners, and control plane are all ready.

Interface binding produces the following logs:

| Interface state | Log level and frequency | Message |
| --- | --- | --- |
| Hooks are ready | `info`, once on binding | `configured interface is bound` |
| Interface is absent, or `auto` has no default route | One warning, then `debug` | `configured interface is not bound yet` |
| Attachment fails | One warning, then `debug` | `configured interface attach failed; retrying` |
| Link type is unsupported | One error | `configured interface is not supported` |

`GET /runtime` reports unbound interfaces through the `interface_binding` degradation. See the [API reference](./reference/api.md#native-api).

```shell
ip link show dae0
sudo bpftool prog show
sudo bpftool map show
sudo journalctl -u honk-core --since '5 minutes ago'
```

If `honk-tool` was built from source, run its read-only diagnosis:

```shell
cargo build --release -p honk-tool
sudo ./target/release/honk-tool diagnose \
  --api http://127.0.0.1:9090 --pin-root /sys/fs/bpf
```

Use a real client to exercise direct and proxied TCP, UDP, and DNS traffic, plus IPv4/IPv6 where required. The presence of `dae0` or a reachable API is not an end-to-end traffic check.

## Reload and stop

```shell
sudo systemctl reload honk-core
# or
sudo /usr/local/bin/honk-core reload
```

Use the running process logs and their `applied` or `rejected` result to determine whether the reload succeeded. Changes to interfaces, TPROXY settings, `data_dir`, the NFQUEUE switch, DNS bind, the Clash API listener/secret, cache settings, and other process-scoped fields require a restart. An interface that appears or disappears at runtime needs no reload: the watcher binds and releases it.

Stop normally with:

```shell
sudo systemctl stop honk-core
```

Do not use `kill -9` for routine shutdown. honk first closes datapath admission, fences NFQUEUE, and then removes hooks and links. Only one real datapath instance may run on a host; `/run/honk-core.lock` prevents fixed-resource conflicts.

## Unprivileged development

`--mock-ebpf` can exercise configuration, API, DNS, and userspace outbounds, but it never intercepts real traffic.

Save this configuration as `/tmp/honk.dae`:

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

## Current capabilities and limitations

- Outbounds: Direct, Block, SOCKS5, Shadowsocks/2022, Trojan, AnyTLS, Hysteria2, TUIC, Juicity, VMess, and VLESS.
- UDP: Direct, SOCKS5, Shadowsocks, Trojan, AnyTLS, Hysteria2, TUIC, Juicity, and VLESS when its independent packet permission is enabled. VLESS fallback encoding and multiplex carrier are separate choices; VMess remains TCP-only. See the [VLESS node reference](reference/nodes.md#vless-udp-and-multiplexing).
- Groups: Selector, URLTest, LoadBalance, Fallback, and Score.
- DNS upstreams: UDP, TCP, DoT, DoH, DoH3, and DoQ, optionally through a node or group.
- `direct` and `block` are built-in nodes and must not be redeclared.
- `nfqueue_enable` defaults to enabled, always uses queue 320, and exclusively owns `inet honk_nfqueue` / `udp_decision`. Firewall managers in the same network namespace must not modify those objects.
- Mock builds and builds without the Cargo `ebpf` feature do not provide transparent proxying. Plain `cargo build --release` omits the real datapath; use `--features ebpf`.
- VMess UDP, a rootless datapath, and non-Linux platforms are not currently supported.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `bpf-linker` is missing | Install it as shown in the source-build section and add Cargo's bin directory to PATH. |
| `no BTF parsed for object` | Clear `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`, rebuild the eBPF object, and confirm `.BTF` with `readelf`. |
| The kernel or verifier rejects compiled routing | Use Linux `6.12+` with BPF/BTF and freplace support. Keep the full verifier log and the generated rule attribution; do not bypass the startup failure. |
| Pinning a map returns `Invalid argument` | `/sys/fs/bpf` is not bpffs; mount it as shown above. |
| Mock mode starts but traffic bypasses honk | This is expected. Build with the `ebpf` feature and run as root. |
| NFQUEUE is disabled or queue 320 is busy | Check nftables/NFQUEUE kernel support, the queue owner, and stale honk instances. Set `nfqueue_enable: false` only when staging is intentionally unnecessary. |
| LAN traffic is not intercepted | `lan_interface` is empty or names the wrong interface. honk does not substitute `lo`. If the interface is named correctly, see the next row. |
| `GET /runtime` shows an `interface_binding` degradation | A configured interface is not bound yet; the logs name it. `pending`: it does not exist or an `auto` entry has no IPv4 default route. `unsupported_type`: the link type is refused (for example `lo`, a VRF device or `dae0`); name a supported interface or a member. `attach_failed`: the TCX link could not be created, updated or verified; see the warning in the logs. See the [native API reference](./reference/api.md#native-api) for interface-state fields. |
| On a single-arm gateway, clients bypass honk or forwarded traffic is dropped | Set `send_redirects` to `0` for `all` and the LAN interface, and `net.ipv4.conf.all.rp_filter` to `0`. See [Single-arm gateways](#single-arm-gateways). |
| VLESS/VMess reports `No handler for protocol` | The build lacks `rprx`; use the default features or add `rprx` explicitly. |
| A Geo rule fails to load | Put `geoip.dat`/`geosite.dat` in the configured `data_dir`, or verify the documented legacy/share search locations; remove unused Geo rules if not needed. |
| A GNU binary does not execute on VyOS or a minimal system | Use the musl release for the same architecture. |

## Further reading

- [Configuration guide](configuration.md)
- [Global configuration](reference/global.md)
- [Nodes and protocols](reference/nodes.md)
- [Group policies](reference/groups.md)
- [Routing rules](reference/routing.md)
- [DNS configuration](reference/dns.md)
- [CLI](reference/cli.md)
- [Architecture overview](design/overview.md)

## Check parser changes

From the repository root, run `just parser-ci` with the pinned stable Rust compiler, Go 1.26 or newer, Python 3.11 or newer, and network access. Case instructions are in `crates/honk-config/conformance/README.md`; oracle and licence details are in `tools/dae-parse/README.md`.

The command performs these checks in order:

1. Build the pinned dae oracle.
2. Fetch upstream examples and verify their manifest SHA256 values.
3. Compare decoded structure and recorded dialect differences.
4. Replay saved fuzz inputs.

With Cargo dependencies cached, `just fuzz-replay` needs only stable Rust. It uses the same assertions as the fuzz targets. A replay failure prints the input path; a hung input fails after five seconds.

The `parser` CI lane runs when configuration code, the oracle, fuzz inputs, corpus source documents or their build inputs change. It also runs with `ci:full`. Ordinary workspace commands enable neither `conformance` nor `fuzz-checks`, so they require neither Go nor nightly.

The weekly fuzz job uses:

| Setting | Value |
| --- | --- |
| Rust channel | Nightly pinned in `crates/honk-ebpf/rust-toolchain.toml` |
| cargo-fuzz version | Pinned in `.github/ci/pins.env` |
| Targets | `document`, `share_link`, `lexer` |
| Duration and concurrency | 480 seconds per target, two workers |
| Uploaded artifacts | Findings and corpus files |

Place a retained finding under `fuzz/artifacts/<target>/` to replay it on stable. Sanitizer-only findings still require the nightly fuzz target.
