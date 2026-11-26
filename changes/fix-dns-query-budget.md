Fixed

- Reserve foreground DNS singleflight capacity so background stale-refresh bursts cannot reject active queries.
- Cache hostname DNS upstream bootstrap addresses per runtime generation with bounded TTL and negative backoff instead of re-resolving on every query.
- Enforce a single per-query deadline across DNS bootstrap, candidate-address retries, UDP truncation fallback, and response re-queries.
- Fail closed instead of falling back to bootstrap DNS when request or response routing rules reject a lookup.
