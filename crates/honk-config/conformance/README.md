# Conformance cases

`manifest.toml` lists every input the parser conformance test runs
(`tests/conformance.rs`, feature `conformance`). Each `[[case]]` records what the
two parsers do with one input, separately:

| Key | Meaning |
| --- | --- |
| `id` | Stable identifier; the dialect reference links to it. |
| `input` | A repository-relative file, usually under `cases/`; or `source = { file = "<repo path>", lines = "a-b" }` for a ```dae fence in a honk document (`a` is the first line inside the fence, `b` the last, one-based inclusive) or `source = { dae = "<path in the dae repository>", lines = "a-b" }` for an upstream file cited under `[upstream]` and fetched at its pinned commit. Exactly one of `input`/`source`. |
| `wrap` | Optional section name that encloses a fragment before parsing, e.g. `"routing"`. |
| `layer` | `structure`: the decoded structure is compared. `typed:<test>` / `loading:<test>`: the case exists for its acceptance and diagnostics; the named existing test owns the typed or file-loading behaviour (the runner checks the test exists, it does not run it). |
| `honk`, `dae` | `accept` or `reject` for each parser. |
| `honk_diagnostics` | The exact diagnostic codes honk emits for this input, in order. |
| `compare` / `differences` | `compare = "equal"` when both accept and the structures are identical; otherwise `differences = [{ path, dae, honk, reason }]` naming every place they differ (`{ absent = true }` for a missing item). Any unrecorded difference, and any recorded one that no longer occurs, fails the case. |
| `unknown_sections` | Root blocks honk does not recognise (dae keeps them; honk only counts them). |

To add a case: write the input under `cases/<group>/`, add a `[[case]]` with your
expectation, then run

```sh
just parser-ci                                   # everything, needs Go and network
CONFORMANCE_CASE=<id> just parser-ci             # one case
cargo run -p honk-config --features conformance --example project -- <file>   # honk's projection
cd tools/dae-parse && go run . < <file>                                       # dae's
```

A failure prints the case id, the first differing path and both values. An
intended difference goes into `differences` with the path and a reason, never a
whole-case waiver.
