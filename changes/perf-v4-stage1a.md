Internal

- Look up a received TCP packet's flow slot once when determining Endpoint ownership and RX qualification; the admission rules are unchanged.
- Avoid repeated topology queries on quiet XDP service turns while retaining link-loss detection and Core forwarding checks.
- Reserve AF_XDP TX owner slots without a linear scan; partial frame completions cannot release a packet owner.
- Publish borrowed RX packets once per batch without allocating retained slots, preserving frame custody on a callback panic.
- Share a bounded scope lock across eligible physical Endpoint TCP input and deliver stream readiness after unlocking; mixed packets still follow per-packet admission.
- Generate physical Endpoint replies from the retained return path without reacquiring the scope lock; queued CPU output keeps priority.
- Drain already accepted output on graceful packet-scope shutdown without waiting for unrelated ingress.
