⚠️ **CI report** 776f2f0f vs `main` 346e667d: 2 limits exceeded (eBPF VM not run: `ci:ebpf`; full lanes not run: `ci:full`)

- **`honk-core` peak memory in the smoke 108 MB**, limit 48 MB (`main` 40 MB)
- **slowest test 61 s**, limit 60 s (`c28_health_tests::warm_then_measure`, `main` 58 s)

**Tests**
<details><summary>5 added, 0 removed</summary>

- `udp_associate_gives_up_after_greeting`
- `reload_persists_selector_choice_before_manager_publication`
- `subscription_store_rejects_foreign_owner_before_chmod`
- `udp_pick_keeps_tcp_mirror_with_only_synthetic_failures`
- `udp_pick_switches_after_real_evidence_survives_ring_eviction`

</details>

**Logs**
<details><summary>2 new WARN lines in passing tests</summary>

```
reload::transaction: persist callback installed before publication (reload_persists_selector_choice_before_manager_publication)
reload::transaction: persist callback installed before publication (reload_rebases_static_diagnostics)
```

</details>

**Measurements**
<details><summary>9 metrics, 2 over limit</summary>

| | This PR | `main` | Change | Limit |
|---|---|---|---|---|
| `honk-core` peak memory in the smoke | **108 MB** | 40 MB | +68 MB | 48 MB |
| Slowest test | **61 s** | 58 s | +3 s | 60 s |
| `honk-core` CPU in the smoke | 0.31 s | 0.30 s | +0.01 s | 0.36 s |
| Reload wall (vs base, same job) | 0.98× | — | — | 1.20× |
| Reload CPU | 1.01× | — | — | 1.20× |
| Reload allocations (vs base, same job) | 10 | — | 0 | 1.20× |
| eBPF object instructions | 1,842 | 1,842 | 0 | 2,026 |
| DNS smoke | 4 queries, 4 expected names | pass | — | pass |
| rustc | 1.98.1 (pinned), cache hit | 1.98.1 | — | — |

</details>
<!-- ci-report -->
