Internal

- Look up a received TCP packet's flow slot once when determining Endpoint ownership and RX qualification; the admission rules are unchanged.
- Avoid repeated topology queries on quiet XDP service turns while retaining link-loss detection and Core forwarding checks.
- Reserve AF_XDP TX owner slots without a linear scan; partial frame completions cannot release a packet owner.
