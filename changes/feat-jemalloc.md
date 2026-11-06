Changed

- The shipped `honk-core` binary now allocates through jemalloc instead of mimalloc; `-stock` archives still use the system allocator.
- The `honk-core` Cargo feature formerly named `mimalloc` is now `jemalloc`; builds with `--no-default-features` keep the system allocator.
- Release downloads label the default allocator `jemalloc-*` instead of `mimalloc-*`.
- Removed the mimalloc-only `HONK_MI_COLLECT_SECS` and `MIMALLOC_PURGE_DELAY` environment variables and the worker idle-collection machinery they controlled.
- Runtime jemalloc options use `_RJEM_MALLOC_CONF`, not `MALLOC_CONF`: the crate prefixes jemalloc symbols and the environment variable with `_rjem_`.
