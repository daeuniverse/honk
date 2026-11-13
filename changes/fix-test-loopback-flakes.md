Internal

- Tests that free an ephemeral port and rebind it, or open TCP and UDP on one port number, now use a loopback address of their own, which keeps them off the shared 127.0.0.1 port pool and narrows the AddrInUse race with parallel tests; a wildcard bind elsewhere can still take a freed port.
- The UDP endpoint closure tests check that the endpoint released its socket through a weak handle instead of rebinding the freed port.
