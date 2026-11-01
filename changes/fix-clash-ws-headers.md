Fixed

- Clash and sing-box subscriptions import WebSocket upgrade headers other than `Host`, so nodes that require `ws-opts.headers.User-Agent` are no longer dropped. The headers participate in node identity and are sent on the upgrade.
- Direct and supplied-TCP WebSocket dials enforce the same header limits and reserved-name rules as subscription admission, before network I/O.
- sing-box keeps empty WebSocket header strings and rejects invalid or conflicting claims instead of silently dropping them.
- Structured node errors retain the actual transport or header field instead of being mislabeled as XHTTP errors.
- Clash WebSocket Host extraction retains its first-usable scalar and lazy fallback behavior while additional headers remain strictly checked.
- Subscription stream-normalization failures retain their canonical field alongside the original entry index, preserving transport context without exposing supplied header names or values.
