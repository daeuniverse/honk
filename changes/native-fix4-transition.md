Added

- Define bounded Native publication transition recording and per-hook epoch-tagged closed-branch counts, with explicit provisional/sealed counter semantics and the unchanged incremental reservation floor of 598,016 + 100,516*T bytes for T registered targets.
- Document the separate startup manifest and joined-shutdown artifact, explicit NOT_PUBLISHED/PUBLISHED_DURABILITY_UNKNOWN/PUBLISHED_DURABLE export results, and the consumer requirement to retain a matching durable result and artifact digest before teardown.
- Document ring eviction and crash incompleteness, the absence of packet-causality guarantees, and bilingual evidence collection instructions. Focused implementation and real-hook checks are NOT_RUN; this contract does not establish Native acceptance or crash-surviving history.
