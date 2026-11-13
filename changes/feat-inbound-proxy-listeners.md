Added

- Authenticated inbound proxy listeners under `inbound`: RFC 1929
  username/password SOCKS5 and HTTP(S) `Proxy-Authorization: Basic`
  (CONNECT tunnels plus absolute-form forwarding), sharing one user table
  per section, so manually configured clients traverse the same routing
  rules and outbound groups as transparently intercepted traffic.
- The `user()` routing condition matches sessions by their authenticated
  inbound username (the mihomo `in-user` analogue); intercepted traffic
  never matches the positive form.
