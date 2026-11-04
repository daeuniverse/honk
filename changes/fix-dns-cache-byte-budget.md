Fixed

- Bound each DNS cache shard's answer bytes to `max(entry capacity × 1 KiB, 65,535 bytes)`, evicting LRU entries when large answers fill the budget.
- Inline DNS cache insert/remove accounting in size-optimized builds.
