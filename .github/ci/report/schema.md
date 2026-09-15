# Per-lane CI report schema

Each producer writes one UTF-8 JSON object to `<lane>.json`. The reporter accepts schema version 1 and rejects files larger than 256 KiB, duplicate lanes, lane/file-name mismatches, unknown metrics, and invalid field types.

| Field | Type | Required | Contract |
|---|---|---:|---|
| `schema_version` | integer | yes | Contract version; currently `1`. |
| `run_id` | positive integer | yes | GitHub Actions run that produced the observation. |
| `run_attempt` | positive integer | yes | Attempt number within `run_id`; newer attempts replace older ones upstream. |
| `lane` | string | yes | Stable logical lane identity; it must equal the JSON file stem. |
| `matrix` | object of string to string | yes | Comparison identity such as target, features, allocator, toolchain, kernel, and workload; candidate and baseline must match exactly. |
| `measured_sha` | string | yes | Commit measured by this producer. |
| `baseline_sha` | string or null | yes | Commit measured in the same job when the metric has its own baseline, otherwise `null`. |
| `units` | object of string to string | yes | Declared unit for every entry in `values`; its value must match that metric's `unit`. |
| `values` | object | yes | Named observations understood by `render.py`; unknown names make the report incomplete rather than silently disappearing. |
| `values.<name>.value` | JSON value | yes | Observation payload; its shape is defined by the named metric renderer and is ignored when unavailable. |
| `values.<name>.unit` | string | yes | Unit or stable display vocabulary for this observation. |
| `values.<name>.available` | boolean | yes | Whether `value` is a real observation. |
| `values.<name>.reason` | string | no | Why an observation is unavailable or not comparable; never represents a zero value. |
| `signals` | array | yes | Bounded easy-to-miss observations rendered after metric data. |
| `signals[].kind` | string | yes | Stable signal name understood by `render.py`. |
| `signals[].detail` | string | yes | Untrusted display text describing the observation. |
| `failure` | object or null | yes | Failure information absent from the checks panel, or `null` when none exists. |
| `failure.summary` | string | when non-null | One-line explanation of what failed. |
| `failure.detail_lines` | array of strings | when non-null | At most 20 lines, each at most 300 UTF-8 bytes; longer collections render inside `<details>`. |

Stage 1 accepts these value names and canonical units: `test_inventory` (`test-names`), `ignored_tests` (`tests`), `slowest_test` (`seconds`), `dns_smoke` (`queries-and-names`), `smoke_memory` (`MiB`, the release `honk-core` measured by the `smoke` lane), `smoke_cpu` (`seconds`), `binary_size` (`bytes`, the release `honk-core` file), `reload_benchmark` (`ratios`), `toolchain` (`rustc-cache`), `vm_environment` (`kernel-accelerator`), `conformance_cases` (`cases`), and `fuzz_replay_inputs` (`inputs`). The ordinary layout fixture also carries `ebpf_instructions` (`instructions`); no stage-1 producer emits it.

`ci-report-selection` is the separate policy record. Its `selection.json` contains the event, dispatch inputs, labels, `code`/`docs`/`ebpf`/`parser` filter outputs, filter outcome, intended lane names, run ID, and run attempt.

## Parser lane

`ci-report-parser` contains `parser.json`, with lane `parser`. The lane writes and uploads the report even after failure, with 30-day retention and the same 256 KiB limit. `failure.summary` names the first failing conformance case; `failure.detail_lines` starts with its first differing path. Replay failures name the saved input. Setup or build failures point to the job steps rather than inventing a case.

`conformance_cases.value` is an object with nonnegative integer fields `total`, `equal`, `bounded`, and `rejected_as_expected`. The three outcome counts cannot exceed the total; failed cases may be unclassified. `fuzz_replay_inputs.value` is the nonnegative number of inputs attempted, including the failing input when replay stops early. Missing results are unavailable observations, not zeros. The renderer shows one row per metric; neither count has a performance limit.
