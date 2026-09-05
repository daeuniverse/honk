# honk Quick Start

honk is an experimental eBPF transparent proxy engine for Linux. This guide covers the installation, configuration, and startup steps needed by regular users. See the links at the end for configuration fields and implementation details.

> **Warning**
>
> honk is still `v0.0.1-alpha`. Real mode loads eBPF programs, attaches TC and cgroup hooks, creates `dae0`/`daens`, changes sysctls, and uses NFQUEUE 320 by default. Keep an out-of-band management path available during the first deployment.

## Linux kernel requirements

### Kernel version

```shell
uname -r
```

- Only Linux is supported. The real transparent datapath must run as `root`.
- The current eBPF program uses `bpf_loop`, which requires upstream Linux `5.17+` unless the distribution backports it.
- Linux `6.8+` is recommended. The `bpf_redirect_peer` fast path is also available on kernels with the safe backports in `5.15.164+`, `6.1.99+`, and `6.6.40+`; other supported kernels automatically use ordinary redirect.
- `netkit` is optional. honk falls back to veth when the kernel does not support it.

`lan_interface` intercepts traffic entering the gateway from the LAN. `wan_interface` intercepts traffic originated by the gateway itself:

- LAN only: intercept forwarded traffic only.
- WAN only: intercept locally originated traffic only.
- Both: intercept forwarded and locally originated traffic.
- `wan_interface: auto` follows the lowest-metric IPv4 default route.

### Kernel configuration

Desktop and server distributions usually enable the required features. Minimal systems such as OpenWrt, Armbian, and VyOS need explicit checking. Display the current kernel configuration with:

```shell
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

The real datapath requires the capabilities represented by at least these kernel options:

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_CLS_BPF=y|m
CONFIG_NET_SCH_INGRESS=y|m
CONFIG_NET_CLS_ACT=y
CONFIG_NET_NS=y
```

Held-first-packet UDP, which is enabled by default, additionally requires:

```text
CONFIG_NF_TABLES=y|m
CONFIG_NF_TABLES_INET=y|m
CONFIG_NETFILTER_NETLINK_QUEUE=y|m
CONFIG_NFNETLINK_QUEUE=y|m
```

`pname(...)` routing requires cgroup v2. Without cgroup v2, the remaining features can still start, but process-name routing is disabled.

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

Download the package matching the device architecture from [GitHub Releases](https://github.com/daeuniverse/honk/releases):

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`

The musl packages are static binaries intended for gateways. Packages without the `-stock` suffix use mimalloc for throughput; `-stock` packages use the system allocator and suit small devices where the RSS high-water mark matters more.

```shell
tar -xzf honk-core-<version>-<target>.tar.gz
sudo install -m 0755 honk-core-<version>-<target>/honk-core /usr/local/bin/honk-core
honk-core --version
```

Release binaries embed the eBPF object, so `honk-ebpf` does not need to be installed separately. At runtime, the engine does not invoke `ip`, `nft`, `iptables`, or `nsenter` subprocesses.

### Build from source

A source build requires:

- Rust stable;
- `nightly-2026-07-20`, `rust-src`, and `llvm-tools-preview`;
- `bpf-linker 0.10.3`;
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

Install the Rust toolchains:

```shell
rustup toolchain install stable --profile minimal
rustup toolchain install nightly-2026-07-20 --profile minimal \
  --component rust-src --component llvm-tools-preview
cargo install bpf-linker --version 0.10.3
```

Build the current `main` branch:

```shell
git clone https://github.com/daeuniverse/honk.git
cd honk

# The current eBPF Cargo config contains a maintainer-local linker path.
# Use the bpf-linker installed in PATH on a clean machine.
sed -i 's|linker=/root/.cargo/bin/bpf-linker-wrapper|linker=bpf-linker|' \
  crates/honk-ebpf/.cargo/config.toml

unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
(
  cd crates/honk-ebpf
  cargo +nightly-2026-07-20 build --release \
    -Zbuild-std=core --target bpfel-unknown-none
)

readelf -S crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf \
  | grep -q '\.BTF'
cargo +stable build --release -p honk-core --features ebpf
sudo install -m 0755 target/release/honk-core /usr/local/bin/honk-core
```

`RUSTFLAGS` overrides the eBPF crate's BTF flags. Aya cannot load an object without `.BTF`, so do not omit the environment cleanup or the check.

## Minimal configuration

Start with a direct-only configuration to prove that the datapath works, then add subscriptions or proxy nodes. Replace `br-lan` with the LAN interface that actually receives client traffic. Remove `lan_interface` when only local traffic should be intercepted.

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

The default runtime root is `/var/lib/honk`. Existing artifacts under the legacy `/var/share/honk` root remain usable through the documented per-path fallback; honk does not automatically relocate them; writable state remains active in place. Custom `data_dir` values use the same fallback order. Relative caches, subscription stores, ECH/UI and other read-only dependencies check the configured directory, then `/var/share/honk`, then their caller-specific legacy path; relative logs are created only below the configured directory.

Start honk in the foreground:

```shell
sudo /usr/local/bin/honk-core --config /etc/honk/config.dae
```

After `honk-core is running` appears, verify connectivity from a real LAN client before adding nodes, subscriptions, groups, routing, and DNS. The following is the smallest proxy structure; replace the address with a real node:

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

### GeoIP and Geosite

Download these files only when the configuration references `geoip:` or `geosite:`:

```shell
sudo curl -fL --retry 3 -o /var/lib/honk/geosite.dat \
  https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -fL --retry 3 -o /var/lib/honk/geoip.dat \
  https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
```

The engine selects the first existing regular file in this order: `$DAE_LOCATION_ASSET/<name>`, `<data_dir>/<name>`, `/var/share/honk/<name>`, `./<name>`, `/usr/local/share/honk/<name>`, `/usr/share/honk/<name>`, `/usr/local/share/dae/<name>`, `/usr/share/dae/<name>`, then `/etc/dae/<name>`.

## Run with systemd

Create `/etc/systemd/system/honk-core.service`:

```ini
[Unit]
Description=honk transparent proxy engine
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
User=root
WorkingDirectory=/var/lib/honk
ExecStart=/usr/local/bin/honk-core --config /etc/honk/config.dae
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

## Check runtime status

A running process does not prove that the datapath is usable. The logs should show that the real eBPF backend, interface hooks, listeners, and control plane are all ready.

```shell
ip link show dae0
sudo bpftool prog show
sudo bpftool map show
sudo journalctl -u honk-core --since '5 minutes ago'
```

If `honk-tool` was built from source, run its read-only diagnosis:

```shell
cargo +stable build --release -p honk-tool
sudo ./target/release/honk-tool diagnose \
  --api http://127.0.0.1:9090 --pin-root /sys/fs/bpf
```

Finally, use a real client to exercise direct and proxied TCP, UDP, and DNS traffic, plus IPv4/IPv6 where required. The presence of `dae0` or a reachable API is not an end-to-end traffic check.

## Reload and stop

```shell
sudo systemctl reload honk-core
# or
sudo /usr/local/bin/honk-core reload
```

Use the running process logs and their `applied` or `rejected` result to determine whether the reload succeeded. Changes to interfaces, TPROXY settings, `data_dir`, the NFQUEUE switch, DNS bind, the Clash API listener/secret, cache settings, and other process-scoped fields require a restart.

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
cargo +stable run --release -p honk-core -- \
  --config /tmp/honk.dae --mock-ebpf
```

## Current capabilities and limitations

- Outbounds: Direct, Block, SOCKS5, Shadowsocks/2022, Trojan, AnyTLS, Hysteria2, TUIC, Juicity, VMess, and VLESS.
- UDP: Direct, SOCKS5, Shadowsocks, Trojan, AnyTLS, Hysteria2, TUIC, Juicity, and non-legacy VLESS modes. VMess and legacy VLESS are TCP-only.
- Groups: Selector, URLTest, LoadBalance, Fallback, and Score.
- DNS upstreams: UDP, TCP, DoT, DoH, DoH3, and DoQ, optionally through a node or group.
- `direct` and `block` are built-in nodes and must not be redeclared.
- `nfqueue_enable` defaults to enabled, always uses queue 320, and exclusively owns `inet honk_nfqueue` / `udp_decision`. Firewall managers in the same network namespace must not modify those objects.
- Mock builds and builds without the Cargo `ebpf` feature do not provide transparent proxying. Plain `cargo build --release` omits the real datapath; use `--features ebpf`.
- VMess UDP, a rootless datapath, Dockerfile/docker-compose definitions, and non-Linux platforms are not currently supported.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `bpf-linker-wrapper` is missing | Replace the maintainer-local path with the `bpf-linker` in PATH as shown in the source-build section. |
| `no BTF parsed for object` | Clear `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`, rebuild the eBPF object, and confirm `.BTF` with `readelf`. |
| The verifier reports `unknown bpf func`/`bpf_loop` | Upgrade the kernel or use a distribution kernel that explicitly backports the helper. |
| Pinning a map returns `Invalid argument` | `/sys/fs/bpf` is not bpffs; mount it as shown above. |
| Mock mode starts but traffic bypasses honk | This is expected. Build with the `ebpf` feature and run as root. |
| NFQUEUE is disabled or queue 320 is busy | Check nftables/NFQUEUE kernel support, the queue owner, and stale honk instances. Set `nfqueue_enable: false` only when staging is intentionally unnecessary. |
| LAN traffic is not intercepted | `lan_interface` is empty or names the wrong interface. honk does not substitute `lo`. |
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
