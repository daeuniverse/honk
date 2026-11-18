Added

- Chain nodes: `via: front -> mid -> land` in `node {}` sends TCP, not UDP, through two to four nodes in turn. Hops after the first must be SOCKS5, Shadowsocks, Trojan, VMess or VLESS, without XHTTP, Vision, VLESS Encryption or TCP multiplexing. A chain keeps its own ID, health and Score, and the APIs list it with protocol `chain`.
