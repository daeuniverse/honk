# dae-parse

A test oracle: reads one dae configuration on stdin and prints what dae's own
parser (`github.com/daeuniverse/dae/pkg/config_parser`) decoded, as JSON, so the
conformance test in `crates/honk-config/tests/conformance.rs` can compare it with
honk's reading of the same text. Exit status is 0 for both accepted and rejected
input; a rejection is `{"error": "..."}`. `-version` prints the pinned dae commit
and the Go version.

```sh
cd tools/dae-parse && go build -o /tmp/dae-parse .
printf 'global {\n  log_file: honk.log\n}\n' | /tmp/dae-parse
```

`fetch.py` downloads the upstream example files the manifest cites, at the pinned
commit, and verifies each against the manifest's SHA-256; a mismatch fails with
the file name. Nothing from dae is committed to this repository.

## Licence

This tool links dae, which is licensed under AGPL-3.0-only. honk's own code,
including this directory's `main.go`, stays under honk's licence (GPL-3.0-only,
see the repository root); GPLv3 section 13 permits linking the two, and the
resulting `dae-parse` binary carries the AGPL obligations for the dae parts. It
is a development and CI tool: it is never shipped, never linked into `honk-core`,
and building it is optional (`just parser-ci`). Upstream: https://github.com/daeuniverse/dae.
