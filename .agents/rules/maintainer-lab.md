## Maintainer lab

Read with: `AGENTS.md` (Current validation guidance: the REALITY `dest` certificate constraint) and `doc/en/design/outbound.md` (REALITY client).

The maintainer's own interop setup, kept for reference; contributions do not require it.

Install boring-sys prerequisites (`AGENTS.md`, Technology stack) and its REALITY-hooks checkout
at pinned `/root/code/boring-rprx/boring-sys`. Cross-build with `ci/zig*`, not containers.

REALITY / xtls-rprx-vision interop uses two live servers, not the unprivileged suite:
- Lab `10.10.10.70`: sing-box 1.12, systemd `sing-box-rprx`, `/etc/sing-box/rprx.json`.
  Ports: 8443 vless+reality+vision; 8444 vless+reality; 8445 vmess+ws+tls self-signed
  (require `skip_cert_verify`/`insecure=1`); 8446 vmess bare tcp.
  LAN HTTP: `10.10.10.70:18080`, systemd `bench-http18080`.
- Public `103.238.129.118`: Xray 26.3.27, same ports, `xray-rprx.service`, degraded
  ~75 ms / ~15% loss.
JA4 was verified on .70 with `/usr/local/bin/ja4probe` (`ja4probe`, source
`/root/code/ja4probe`). Lab drivers: `honk-outbound/examples/`
(`reality_hook_spike.rs`, `reality_lab59.rs`).
