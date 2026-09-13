### CI / releases

`.github/workflows/ci.yml` runs fmt + clippy, the workspace gate, and an Ubuntu hosted-VM eBPF job. The VM job boots the pinned Linux 6.12 image, BTF-checks the kernel object, mounts bpffs, installs the geo assets required by eBPF-feature routing tests, runs the full `honk-core --features ebpf --lib` gate, then runs the real NFQUEUE/nftables netns contract, TC/cgroup link lifecycle, pinned allocator rollback-compatibility test, and root-only network tests serially without a job container.

`.github/workflows/release.yml` on `v*`: `cargo test --workspace --no-fail-fast` with the temporary routing exclude below (`cmake` + `libclang-dev` required for boring-sys), then `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl`. Native gnu uses `cargo build`; the other three use **zig cc/c++ `ci/zigcc` / `ci/zigcxx` wrappers**. Cross CMake injects ASM `--target` flags rejected by GCC and, in Rust-triple spelling, zig; wrappers strip/re-anchor on `$ZIGCC_TARGET`. Musl sets `link-self-contained=no` for zig CRT. Each target ships default mimalloc and `-stock` without `mimalloc` (lower RSS high-water on small gateways). Build eBPF once on host with latest nightly/pinned prebuilt `bpf-linker`; **verify `.BTF`** before packaging. Publish GitHub Release tarballs; `alpha`/`beta`/`rc` tags are prereleases.

### Release process (standing convention)

- **Tag naming:** `v0.0.1.beta.N` (strictly incrementing; check `git tag -l | sort -V | tail`). Tag the current `main` tip after it is pushed and its branch CI is green.
- **Trigger:** tag push runs the full workflow above and creates the GitHub Release with `generate_release_notes: true` as a base.
- **Release notes (agent-curated, dae `v2.0.0` style):** replace auto notes with this format after Release creation:

    ```markdown
    ## Highlights

    <2-5 bullets: what this release means to a gateway operator>

    ## What's Changed

    ### New Features

    - <subject> by @<github-author> in <short-hash>

    ### Bug Fixes

    - <subject> by @<github-author> in <short-hash>

    ### Performance

    - <subject> by @<github-author> in <short-hash>

    ### Documentation

    - <subject> by @<github-author> in <short-hash>

    **Full Changelog**: https://github.com/daeuniverse/honk/compare/<prev-tag>...<tag>
    ```

    - Attribute commits to GitHub-resolved authors (`gh api repos/daeuniverse/honk/commits/<sha> --jq .author.login`), never raw git `Author:` names: the daeuniverse-org Release must show org-visible identity.
    - Group commits by their `type(scope)` prefix (`feat` → New Features, `fix` → Bug Fixes, `perf` → Performance, `docs`/`bench` → Documentation, `refactor`/`test` → fold into the nearest section or omit).
    - Apply `gh release edit <tag> --repo daeuniverse/honk --notes-file <file>` only after the build and workflow `release` job finish; the Release page does not exist earlier.

- **Deployment:** after tagging, use the canonical musl mimalloc gateway tarball. Note development/manual `scp` deployments in the PR/issue of record when they differ from release artifacts.

