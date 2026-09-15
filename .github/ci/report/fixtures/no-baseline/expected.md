✅ **CI report** 5555aaaa vs `main` (no baseline): no limits exceeded (eBPF VM not run: `ci:ebpf`; parser lane not run: `ci:full`; full lanes not run: `ci:full`)

**Tests**
<details><summary>2 tests, 1 ignored, no baseline</summary>

</details>

**Measurements**
<details><summary>4 metrics, 0 over limit</summary>

| | This PR | `main` | Change | Limit |
|---|---|---|---|---|
| `honk-core` peak memory in the smoke | 18 MB | no baseline | — | 32 MB |
| `honk-core` release binary | 19 MB | no baseline | — | — |
| Slowest test | 50 s | no baseline | — | 60 s |
| `honk-core` CPU in the smoke | 0.04 s | no baseline | — | 0.50 s |

</details>
<!-- ci-report -->
