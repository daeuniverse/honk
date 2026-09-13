# CI results report

The `changes` job writes `ci-report-selection`; `lint`, `test`, `ebpf-check`, `ebpf`, `ebpf-recent`, `aarch64`, `features`, `cross-musl`, and `review-bot` write schema-versioned lane artefacts described in `schema.md`, and the reload workflow writes `ci-report-reload`. `report.yml` runs after either workflow, checks out only the default branch, joins the triggering run with the latest completed pull-request companion for the same head, and compares it with the preceding successful `main` push.

The reporter handles pull-request runs only. It reads per-attempt job conclusions and bounded artefact files as data, never imports, sources, evaluates, or executes artefact or pull-request content, and upserts the marker-bearing comment authored by `github-actions[bot]` on every matching open base-repository pull request.

The renderer interface is:

```text
python3 .github/ci/report/render.py --candidate DIR --baseline DIR --selection FILE --jobs FILE --out body.md
```

Run `python3 .github/ci/report/render.py --self-test` from the repository root. The self-test compares all eight stage-1 fixtures byte for byte; `fixtures/ordinary.md` is the verbatim agreed fork comment.
