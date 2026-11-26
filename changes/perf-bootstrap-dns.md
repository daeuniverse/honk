Changed

- Cache domain-upstream bootstrap DNS addresses per DNS runtime generation with TTL clamping (30–300 s), stale fallback, same-family affinity, and invalidation on network changes or full DNS cache flush.
- Harden bootstrap DNS with UDP retransmits, policy-aware dual-stack completion windows, RCODE validation, and non-blocking system resolver fallback.
