# CI results report

The `changes` job writes `ci-report-selection`; `lint`, `test`, `parser`, `smoke`, `ebpf-check`, `ebpf`, `ebpf-recent`, `aarch64`, `features`, `cross-musl`, and `review-bot` write schema-versioned lane artefacts described in `schema.md`, and the reload workflow writes `ci-report-reload`. `report.yml` runs after either workflow, checks out only the default branch, joins the triggering run with the latest completed pull-request companion for the same head, and compares it with the preceding successful `main` push.

The reporter handles pull-request runs only and skips cancelled source runs. It reads per-attempt job conclusions and bounded artefact files as data, never imports, sources, evaluates, or executes artefact or pull-request content, and upserts the marker-bearing comment authored by `github-actions[bot]` on every matching open base-repository pull request. An empty selection object means CI has not finished; malformed non-empty selections remain validation errors.

The reload comparator gates allocation count and allocated-byte growth at the existing 20% threshold, requires at least ten candidate samples, and rejects any no-op flag writes, DNS publications, slow-path entries or eBPF writes. Wall/CPU ratios are advisory on shared runners: a timing ratio alone does not fail the benchmark, while a candidate reload of one second or more still does. All four ratios remain in the step summary and JSON. The renderer retains its 1.20× timing warnings as advisory measurements; those warnings do not fail the job or set the reload report's `gate_passed` field. Pure timing regressions therefore require review rather than an automatic failure.

Run `python3 ci/test-compare-reload-benchmark.py` for the comparator's dependency-free regression checks.

The renderer interface is:

```text
python3 .github/ci/report/render.py --candidate DIR --baseline DIR --selection FILE --jobs FILE --out body.md
```

Run `python3 .github/ci/report/render.py --self-test` from the repository root. The self-test compares all nine fixtures byte for byte and checks an expanded test inventory against both the archive importer and renderer, including acceptance at 512 KiB and rejection above it; `fixtures/ordinary.md` extends the agreed fork layout with parser conformance and saved-input replay rows.

The parser path filter selects config code, the Go oracle, fuzz inputs, manifest source documents, and their build inputs. `ci:full`, failed change detection, pushes and manual CI runs also select it. Its check name is `dae-config parser (conformance + fuzz replay)`. An unselected parser lane has its own policy note, separate from code and eBPF skips.

The parser job uses stable Rust plus Go from `tools/dae-parse/go.mod`; ordinary workspace tests need neither Go nor nightly. `ci-report-parser` records conformance counts and replay inputs and names the first failing case/path. Weekly fuzzing uses the pinned eBPF nightly and `CARGO_FUZZ_VERSION`, runs the three targets sequentially for 480 seconds each with two workers, and uploads `fuzz-inputs` even after failure. It has read-only repository permissions and creates no issues.

Fork acceptance requires this reporter version on the fork's default branch before testing a branch that uploads `ci-report-parser`. Otherwise the old reporter cannot validate the fourth selection filter or display the new metrics.

The 512 KiB JSON limit likewise requires both `report.yml` and the renderer on the default branch. A pull request changing these files does not activate its own reporter: until those changes land, the trusted default-branch workflow still rejects reports above its previous limit.
