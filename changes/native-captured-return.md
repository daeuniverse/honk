Added

- Physical Transit Native can return an eligible captured original through its private TAP before protocol commitment, while retaining ordered ownership until target entry and reader grace complete.
- Native now requires a joined cold restart with matching 56-byte claim keys, 72-byte values and 64-byte metadata; old objects and readers are rejected rather than adopted. Host Native and late TCP sniff return remain unsupported.
- Captured return currently drops reply/NAT-translated inputs and cross-realm inputs during Pending/Armed/Draining before reservation or redirect; replies during Draining need retransmission. Full Native acceptance remains unverified.
- Give canonical return-program candidates distinct pins for repeated scope updates within one closed epoch, and release construction-only BTF reservations after the installed inventory remains funded.
- Preserve exact pre-attachment publication bytes in a separate startup checkpoint so later legitimate exports cannot overwrite startup evidence.
- Separate private TAP administrative MTU from full physical original extents and account sequential BTF/parser and static-loader preparation by their peak, without increasing capture budgets or shrinking packet samples.
- Validate captured-return receipt configuration generations as unsigned 64-bit values, including the valid initial generation zero, without relaxing nonzero attachment or scope identities.
- Observe live captured-return fixture claims by their complete packet key, without opening a publication writer or invoking the retirement-only full-map scan.
- Distinguish unavailable test-only flight observations from fatal identity errors, while requiring actual observed fields for final proof; bind fixture Endpoint acceptance to original custody receipts and retain separate follower-queue accounting.
- Account exact owned TAP teardown transitions in the existing live topology watcher and require sticky terminal capture and reader-Grace proofs before releasing originals or completing shutdown.
- Reject active captured-owner readback after its required entry witness is lost, and exercise missing-entry retention through exact owned witness release rather than unsupported tracing-link detach.
- Select crate-local libtest names when spawning retained-negative and empty-Runtime children, so exact filters execute the intended cases instead of silently matching zero tests.
