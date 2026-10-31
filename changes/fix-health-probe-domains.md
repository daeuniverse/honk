Fixed

- A TCP health-check cooldown no longer skips a node's due UDP probe, and an emergency TCP probe no longer clears UDP cooldowns.
- Health-check cycles skip worker creation when both TCP and UDP probes are cooling down.
