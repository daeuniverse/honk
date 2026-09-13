⚠️ **CI report** aaaabbbb vs `main` ccccdddd: 2 limits exceeded (eBPF VM not run: `ci:ebpf`; full lanes not run: `ci:full`)

- **`honk-core` peak memory in the smoke 101 MB**, limit 100 MB (`main` 90 MB)
- **slowest test 61 s**, limit 60 s (`slow::case`, `main` 50 s)

**Measurements**
<details><summary>2 metrics, 2 over limit</summary>

| | This PR | `main` | Change | Limit |
|---|---|---|---|---|
| `honk-core` peak memory in the smoke | **101 MB** | 90 MB | +11 MB | 100 MB |
| Slowest test | **61 s** | 50 s | +11 s | 60 s |

</details>
<!-- ci-report -->
