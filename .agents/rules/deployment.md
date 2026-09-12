## Deployment

Read with: `release.md` for the tarballs; `security.md`; `real-ebpf.md` for kernel requirements.

- **Native:** root `honk-core` handles eBPF load, netns/link creation, transparent TPROXY sockets, sysctl. Self-contained: one config, embedded eBPF, optional `experimental.clash_api`.
- **Gateway / VyOS:** copy a `just build-core` binary or static `build-musl` (`x86_64-unknown-linux-musl`, workspace `release-musl` profile). `just deploy-vyos HOST=...` builds musl, scps, and smoke-runs; `just deploy` is absent.
- **Releases:** `v*` tags → GitHub Actions → four target triples × two allocators → eight tarballs (`release.md`, CI / releases).
- **Docker:** README-referenced `Dockerfile` / `docker-compose.yml` are absent. Containers require `--privileged --network=host --pid=host`, mounted `/sys`, and an `ebpf` build or `--bpf-object`/`--mock-ebpf`.
- **Cleanup:** graceful shutdown follows runtime NFQUEUE fencing/table-last order. `just clean-all` removes `dae0`/`daens`, ephemeral BPF pins and policy routes, never rollback-compatible `UDP_DECISION_SEQUENCE`. Never reset/delete it for normal exhaustion; the fenced supervisor rotates to legacy-safe empty suffixes or backs off. For startup-rejected corrupt/incompatible pins: keep staging fenced → stop every honk process → verify queue/token-bound maps gone → remove pin once → restart. **Never start a second real datapath instance:** `/run/honk-core.lock` prevents fixed-name overlap.

