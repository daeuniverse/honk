Changed

- Startup verifies only the TC programs the configured interfaces bind (plus one routing target), so a WAN-only Ethernet host no longer loads the LAN or L3 variants. A variant first needed later, such as `auto` moving to a PPP or WireGuard device, is verified by that reconcile.
