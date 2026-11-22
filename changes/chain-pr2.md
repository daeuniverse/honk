Added

- Define a TCP proxy chain of two to four supported nodes with `via: front -> mid -> land` in `node {}`. Later hops must support an existing stream and cannot use hostname-based TLS ECH discovery. Groups can select a chain, and the native API reports it as `chain` with its own health and Score. Its ID stays stable across display-name changes and changes when a hop's physical identity or order changes.
- A completed VMess exchange no longer counts as a relay failure when its physical WebSocket peer closes normally before the empty upload terminator.
- Queued native probes keep their admitted DNS and bootstrap configuration across reload, including separate XHTTP download peers. They skip physical peer lookups when the destination has no eligible address.
- A successful Clash delay test of an unregistered ordinary node updates its display history without changing health or Score.
- `honk-outbound` builds with `rprx` and `owned-tasks` enabled together without `flow-observation`.
