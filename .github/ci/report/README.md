# CI results report

The `changes` job writes `ci-report-selection`; `lint`, `test`, `parser`, `smoke`, `ebpf-check`, `ebpf`, `ebpf-recent`, `aarch64`, `features`, `cross-musl`, and `review-bot` write schema-versioned lane artefacts described in `schema.md`, and the reload workflow writes `ci-report-reload`. `report.yml` runs after either workflow, checks out only the default branch, joins the triggering run with the latest completed pull-request companion for the same head, and compares it with the preceding successful `main` push.

The reporter handles pull-request runs only. It reads per-attempt job conclusions and bounded artefact files as data, never imports, sources, evaluates, or executes artefact or pull-request content, and upserts the marker-bearing comment authored by `github-actions[bot]` on every matching open base-repository pull request.

The renderer interface is:

```text
python3 .github/ci/report/render.py --candidate DIR --baseline DIR --selection FILE --jobs FILE --out body.md
```

Run `python3 .github/ci/report/render.py --self-test` from the repository root. The self-test compares all eight stage-1 fixtures byte for byte; `fixtures/ordinary.md` extends the agreed fork layout with parser conformance and saved-input replay rows.

The parser path filter selects config code, the Go oracle, fuzz inputs, manifest source documents, and their build inputs. `ci:full`, failed change detection, pushes and manual CI runs also select it. Its check name is `dae-config parser (conformance + fuzz replay)`. An unselected parser lane has its own policy note, separate from code and eBPF skips.

The parser job uses stable Rust plus Go from `tools/dae-parse/go.mod`; ordinary workspace tests need neither Go nor nightly. `ci-report-parser` records conformance counts and replay inputs and names the first failing case/path. Weekly fuzzing uses the pinned eBPF nightly and `CARGO_FUZZ_VERSION`, runs the three targets sequentially for 480 seconds each with two workers, and uploads `fuzz-inputs` even after failure. It has read-only repository permissions and creates no issues.

Fork acceptance requires this reporter version on the fork's default branch before testing a branch that uploads `ci-report-parser`. Otherwise the old reporter cannot validate the fourth selection filter or display the new metrics.
