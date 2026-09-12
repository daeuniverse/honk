---
name: honk-change
description: Use for any honk change to plan, review, verify and prepare the PR.
---

Read first: `AGENTS.md` and the rules files its Task routing table names for the contracts touched.

## Steps

1. Plan first, in a file or draft PR text. Name the failing input and the line producing it at `origin/main`, with its SHA. Write one imperative sentence per commit and say what is deliberately left alone. Tests: `AGENTS.md`, "Testing instructions". For a non-behavioural change (docs, workflow, extraction), say why reproduction and hunk ablation do not apply. Name the substitute check: byte comparison, link check or workflow stub.
2. Inventory the impact of each contract touched: users in other crates, tests and benches that construct it directly, CI workflows that run them, pages in `doc/en/` and `doc/zh/`, and any second implementation. Mark each changed, checked unaffected or left as a finding. If the change reaches another module, change that module rather than leaving a shim.
3. Have a second mind review the plan before code.
4. One commit per step: `AGENTS.md`, "Code style guidelines".
5. Verification and reporting: `AGENTS.md`, "Testing instructions" and "Current validation guidance". For input-to-structure code, also compare a fixed input set before and after. List every changed output and its reason.
6. Have a reader who has not seen the plan read the diff and write what a user would experience differently.
7. PR text: `AGENTS.md`, "Code style guidelines" (PR bodies).
8. Batch same-theme few-line fixes in one PR with one commit each. Put edge findings in the rolling tracker issue and serious reproducible defects in their own issues.

## Checklist

- [ ] Plan records the input, source revision, commits, exclusions and applicable check.
- [ ] Impact inventory gives every consumer a disposition.
- [ ] A second mind reviewed the plan before code.
- [ ] Commit steps follow "Code style guidelines".
- [ ] Verification follows the named root sections; input-to-structure comparisons account for changed outputs.
- [ ] A reader without the plan described the diff's user-visible effects.
- [ ] PR text follows "Code style guidelines".
- [ ] Fixes and findings are batched by step 8.
