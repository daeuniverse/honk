Internal

- Move the aya family to userspace `aya` 0.16, `aya-obj` 0.6, `aya-log` 0.4 and kernel-side `aya-ebpf` 0.3, adapting call sites to the new map, loader and TC context APIs while preserving programs, map names and shared binary layouts.
- Make shared payload padding explicit and restrict locked-value `Pod` implementations to the three audited payloads; reject stale BTF schemas without changing existing field offsets or map-value sizes.
