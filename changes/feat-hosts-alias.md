Added

- A `use_host` rule file may map a name to one domain instead of addresses. A/AAAA queries for that name answer with a CNAME to the domain plus its resolved records, and hostnames honk resolves through its bootstrap resolver, such as node server hosts and download URL hosts, connect to the domain's addresses when they match the alias.
