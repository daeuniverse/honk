Fixed
- External UI downloads now reject HTTPS-to-plaintext redirect downgrades and strip URL credentials across redirect hops.
- Clash delay endpoints now cap group member fan-out at 256 (`413 Payload Too Large`) and clamp nonzero `timeout` query parameters to 30 seconds.
- `group {}` parsing now rejects swallowed same-line group settings with `multiple-group-statements` and diagnoses trailing text after `name(...)`, `subtag(...)`, and parenthesized `policy:` values.
- `dns.use_host` now normalizes redundant `.` segments and path separators before deduplicating host sources.
