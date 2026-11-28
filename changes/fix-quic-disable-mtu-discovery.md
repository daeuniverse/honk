Fixed

- Clash accepts `disable-mtu-discovery: true` on TUIC and Juicity nodes, fixing the Hysteria2-only import error. Both protocols honor the same QUIC path MTU discovery setting as Hysteria2 in sing-box subscriptions, client records, and share links.
