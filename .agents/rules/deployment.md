## Deployment

Read with: `release.md` for the tarballs; `security.md`; `real-ebpf.md` for kernel requirements.

- **Native:** root `honk-core` handles eBPF load, netns/link creation, transparent TPROXY sockets, sysctl. Self-contained: one config, embedded eBPF, optional `experimental.clash_api`.
- **Gateway / VyOS:** copy a `just build-core` binary or static `build-musl` (`x86_64-unknown-linux-musl`, workspace `release-musl` profile). `just deploy-vyos HOST=...` builds musl, scps, and smoke-runs; `just deploy` is absent.
- **Releases:** `v*` tags → GitHub Actions → sixteen binary tarballs, `.deb`/`.rpm`/Arch packages of the two static musl full builds, the doona source tarball and `SHA256SUMS` (`release.md`, CI / releases).
- **Docker:** the root `Dockerfile` repackages a published release's musl `full` tarball (`HONK_VERSION`, checked against its `SHA256SUMS`) and the `pins.env` geodata in `/usr/local/share/honk` on Alpine; it compiles nothing. `install/docker.dae` is the image's direct-only default config. `docker-compose.yml` runs it `privileged`, `network_mode: host`, `pid: host`, mounting `/sys`, `/etc/honk` and `/var/lib/honk` (runtime state).
  Bind the pre-existing `/run/honk-core.lock` file too: native and container instances must lock the same inode. Create it without truncating before container startup on every boot; never replace or delete it while an instance can run. Compose refuses to create a directory for a missing lock source.
- **Cleanup:** graceful shutdown follows runtime NFQUEUE fencing/table-last order. `just clean-all` removes `dae0`/`daens`, ephemeral BPF pins and policy routes, never rollback-compatible `UDP_DECISION_SEQUENCE`. Never reset/delete it for normal exhaustion; the fenced supervisor rotates to legacy-safe empty suffixes or backs off. For startup-rejected corrupt/incompatible pins: keep staging fenced → stop every honk process → verify queue/token-bound maps gone → remove pin once → restart. **Never start a second real datapath instance:** `/run/honk-core.lock` prevents fixed-name overlap.

