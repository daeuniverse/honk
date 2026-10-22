# Security policy

## Supported versions

Fixes land on `main` and ship in the next release and Debug build. Only the newest release and the newest Debug build receive them.

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/daeuniverse/honk/security/advisories/new) (**Security → Report a vulnerability**). Do not open a public issue or discussion.

Include:

- `honk-core --version` and the release archive or build you run;
- the configuration needed to reproduce, with passwords, UUIDs, subscription URLs and API tokens removed;
- what an attacker can do, and from where (LAN client, WAN, a subscription source, a proxy server).

There is no guaranteed response time. Maintainers coordinate the fix and the advisory with the reporter.

## Scope

In scope:

- the eBPF datapath and any path that runs with root or `CAP_NET_ADMIN`/`CAP_BPF`;
- authentication and authorization of the Clash API and the native API, including sessions and bearer secrets;
- crashes, hangs or unbounded memory growth that traffic or a remote peer can trigger;
- parsing of untrusted input: subscriptions, share links, DNS answers and protocol frames;
- release integrity: archives that do not match `SHA256SUMS` or their build provenance.

Out of scope:

- weaknesses of the proxy protocols themselves, or of a remote proxy server;
- settings that deliberately remove a protection, such as anonymous loopback access to the native API;
- attacks that already require root on the host running honk.
