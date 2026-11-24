Added

- Chains and group exits can carry UDP when every hop supports tunneled TCP and the last hop supports Trojan or native VLESS UDP. Configured Trojan chains may share an association across a client’s destinations. Multi-hop group exits open one association per flow. Group exits, including one-node collapses, cancel a pending first datagram if its selected path is withdrawn before the transport accepts it.
- Routed UDP failures affect the identified carrier, framing operation or ordered prefix in the matching UDP domain and address family. Active recovery uses an explicitly configured `udp_check_dns` target on the original path. Removing that path ends its active checks.
- A reload that reassigns a group slot or changes its composed UDP capability can raise its minimum routing generation. Cached flows that need a new endpoint on that slot are dropped before dialing if their generation is missing or too old.
