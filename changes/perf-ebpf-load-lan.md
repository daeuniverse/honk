Changed

- Startup verifies only the TC programs the configured interfaces bind (plus one routing target when they bind none), so a WAN-only Ethernet host no longer loads the LAN or L3 variants. Later variants are verified outside the shared backend lock and become bindable only after receiving the current routing generation; a failed variant does not block independent variants. Logging and event-consumer cancellation preserve the original map FDs required by deferred loads.
