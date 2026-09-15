⚠️ **CI report** aaaabbbb vs `main` ccccdddd: 2 limits exceeded (eBPF VM not run: `ci:ebpf`; parser lane not run: `ci:full`; full lanes not run: `ci:full`)

- **`honk-core` peak memory in the smoke 33 MB**, limit 24 MB (`main` 20 MB)
- **slowest test 61 s**, limit 60 s (`slow::case`, `main` 50 s)

**Measurements**
<details><summary>3 metrics, 2 over limit</summary>

| | This PR | `main` | Change | Limit |
|---|---|---|---|---|
| `honk-core` peak memory in the smoke | **33 MB** | 20 MB | +13 MB | 24 MB |
| `honk-core` release binary | 19.5 MB | 19.5 MB | +37 KB | 21.4 MB |
| Slowest test | **61 s** | 50 s | +11 s | 60 s |

</details>
<!-- ci-report -->
