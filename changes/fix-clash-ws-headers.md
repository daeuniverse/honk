Fixed

- Clash and sing-box subscriptions import WebSocket upgrade headers other than `Host`, so nodes that require `ws-opts.headers.User-Agent` are no longer dropped. The headers participate in node identity and are sent on the upgrade.
- Direct and supplied-TCP WebSocket dials enforce the same header limits and reserved-name rules as subscription admission, before network I/O.
