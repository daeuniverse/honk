Added

- Let Native XDP and ingress TCX evaluate IPv6 TCP/UDP packets carrying up to eight Hop-by-Hop, Destination Options or routing extension headers with segments left 0. Admitted Direct packets enter Linux unchanged for its own extension handling; Endpoint packets retain the existing Stack parser. A ninth extension header, Fragment, AH/ESP, No Next Header, unknown next headers, routing headers with segments left and zero IPv6 payload length remain refused.
