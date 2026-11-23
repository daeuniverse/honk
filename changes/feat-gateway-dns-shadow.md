Added

- Physical XDP Endpoint LANs can report which new flows would qualify for native direct routing from their own DNS answers. Shadow mode does not change packet delivery; set `datapath.dns_projection: false` to disable it.
- Fix musl build errors in the TUN filter and XDP Host interface queries without changing their runtime requirements.
