Fixed

- Group probes measure up to 10 members at once, so a slow member no longer leaves later members at `deadline`.
- Probe target resolution failures are logged with the host and DNS error instead of appearing only as `address_unavailable`.
