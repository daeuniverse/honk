Added

- Define a TCP proxy chain of two to four supported nodes with `via: front -> mid -> land` in `node {}`. Groups can select a chain, and the APIs list it as `chain` with its own health and Score. Its ID stays stable when only display names change and changes when a hop's physical identity or order changes.
- A completed VMess exchange no longer counts as a relay failure when its physical WebSocket peer closes normally before the empty upload terminator.
