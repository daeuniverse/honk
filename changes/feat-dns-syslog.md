Added

- Add default-off `dns-syslog` Cargo support to send client DNS outcomes to a configured TCP syslog receiver with `global.syslog_dns_enabled` and `global.syslog_addr`, independently of native API history.
- Preserve complete DNS answers and include deduplicated IP, CNAME and record-type arrays for search.
- Include monotonic processing time as numeric `duration_ms` and final upstream name as `upstream` in DNS audit events; cache responses use `cache`, and results without upstream metadata use null.
- Configure sender hostname and application name in syslog headers and JSON using `global.syslog_hostname` and `global.syslog_app_name`.
- Reuse one TCP connection with octet-counted whole events, bounded batching and reconnect backoff.
- Emit a fixed RFC 5424 header and JSON schema; optionally prefix CEE with `global.syslog_cee_enabled` (default false), and reject obsolete format-template settings.
- Preserve final-upstream and response-source metadata when a concurrent DNS query reuses an in-flight result without a cache hit, including stale-cache fallback.
- Include a readable `message` in DNS audit JSON so CEE syslog receivers can display each event; VictoriaLogs maps it to `_msg` instead of using its missing-message placeholder.
