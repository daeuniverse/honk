Fixed

- Dead `DataUdp` and `DnsUdp` health states require two consecutive successful probes to recover instead of reviving on a single probe success, and clear stale failure backoff on the first recovery probe so the recovery cycle can confirm the second.
