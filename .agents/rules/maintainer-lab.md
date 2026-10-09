## Maintainer lab

Read with: `AGENTS.md` (Current validation guidance: the REALITY `dest` certificate constraint) and `doc/en/design/outbound.md` (REALITY client).

The maintainer's own interop setup, kept for reference; contributions do not require it.

Install boring-sys prerequisites (`AGENTS.md`, Technology stack) and its REALITY-hooks checkout
at pinned `/root/code/boring-rprx/boring-sys`. Cross-build with `ci/zig*`, not containers.

REALITY / xtls-rprx-vision interop uses two live servers, not the unprivileged suite:
- LAN lab host: sing-box 1.12, systemd `sing-box-rprx`, `/etc/sing-box/rprx.json`.
  Ports: 8443 vless+reality+vision; 8444 vless+reality; 8445 vmess+ws+tls self-signed
  (require `skip_cert_verify`/`insecure=1`); 8446 vmess bare tcp.
  LAN HTTP on port 18080 of the same host, systemd `bench-http18080`.
- Public host: Xray 26.3.27, same ports, `xray-rprx.service`, degraded
  ~75 ms / ~15% loss.
JA4 was verified on the LAN lab host with `/usr/local/bin/ja4probe` (`ja4probe`, source
`/root/code/ja4probe`). The manual lab driver is `honk-outbound/examples/reality_lab59.rs`;
production ClientHello/authentication checks live in `honk-outbound/src/reality/wire_tests.rs`.

XHTTP split-download (`downloadSettings`) interop was verified on a LAN lab VM, torn down afterwards. Topology: official Xray 26.3.27; port 443 VLESS (mlkem768x25519plus decryption, Vision) + XHTTP + TLS h2 with a
self-signed certificate for `up.lab.test` and `down.lab.test`; port 8443 a dokodemo tunnel into the
same inbound, so GET and POST meet in one hub only when the client pairs them; a TCP+UDP echo on
`127.0.0.1:9000` behind a Freedom allow rule. Point the link's `downloadSettings` at 8443 with SNI
`down.lab.test`, then run
`HONK_XHTTP_SPLIT_LINK=<link> HONK_XHTTP_SPLIT_ECHO=127.0.0.1:9000 cargo test -p honk-outbound --features rprx --lib lab_split -- --ignored`.
Sessions attributed to `127.0.0.1` in Xray's access log arrived through the download tunnel.
