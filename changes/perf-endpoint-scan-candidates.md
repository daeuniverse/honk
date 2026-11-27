Changed
- Packet endpoints skip repeated TCP retirement scans while ownership is unchanged. XDP peer reclamation skips unused trailing slots without changing when a peer can be released.
