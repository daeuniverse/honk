Added

- Support concurrent multi-upstream DNS racing groups via `name: race(u1, u2, ...)` in `dns.upstream`, returning the fastest valid answer while cancelling slower legs.
