Fixed

- Group probes measure up to 10 members at once, so a slow member no longer leaves later members at `deadline`.
- Probe target resolution failures are logged with the host and DNS error instead of appearing only as `address_unavailable`.
- Probe targets fall back to bootstrap DNS when the running DNS configuration cannot answer, so `asis` routing no longer reports every probe as `address_unavailable`.
