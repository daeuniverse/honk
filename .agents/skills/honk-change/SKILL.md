---
name: honk-change
description: Use for any honk change to plan, review, verify and prepare the PR.
---

Read first: `AGENTS.md` and the rules files its Task routing table names for the contracts touched.

## Steps

1. Classify the change as Low, Medium or High (`AGENTS.md`, "Change workflow", Risk classes); when unsure, take the higher class. The class sets the plan depth, proof and review for the steps below. Low: the commit message is the plan. Medium: a short plan. High: a written plan, in a file or draft PR text. A plan names the failing input and the line producing it at `origin/main`, with its SHA, gives one imperative sentence per commit and says what is deliberately left alone. Tests: `AGENTS.md`, "Testing instructions". For a non-behavioural change (docs, workflow, extraction), say why reproduction and hunk ablation do not apply and name the substitute check: byte comparison, link check or workflow stub.
2. Medium and High: inventory the impact of each contract touched: users in other crates, tests and benches that construct it directly, CI workflows that run them, pages in `doc/en/` and `doc/zh/`, and any second implementation. Mark each changed, checked unaffected or left as a finding. If the change reaches another module, change that module rather than leaving a shim.
3. Medium and High: have a second mind review the plan before code.
4. One commit per step: `AGENTS.md`, "Commits and pull requests".
5. Verification and reporting: `AGENTS.md`, "Testing instructions", "Current validation guidance" and "Change workflow" (Ablation; Performance baselines for hot paths). For input-to-structure code, also compare a fixed input set before and after. List every changed output and its reason.
6. Review by class: Low, read your own diff; Medium, a reader who has not seen the plan reads the diff and writes what a user would experience differently; High, that reader plus the `CONTRIBUTING.md` §6 deep review. Reviewers follow `.agents/rules/review.md`.
7. PR text: `AGENTS.md`, "Commits and pull requests" and "Writing".
8. Batch same-theme few-line fixes in one PR with one commit each. Put edge findings in the rolling tracker issue and serious reproducible defects in their own issues.

## Checklist

- [ ] The change has a risk class, and the plan matches its depth: input, source revision, commits, exclusions and applicable check.
- [ ] Medium and High: the impact inventory gives every consumer a disposition.
- [ ] Medium and High: a second mind reviewed the plan before code.
- [ ] Commit steps follow "Commits and pull requests".
- [ ] Verification follows the named root sections; behaviour hunks are ablated or listed; input-to-structure comparisons account for changed outputs.
- [ ] The review matches the class; for Medium and High, a reader without the plan described the diff's user-visible effects.
- [ ] PR text follows "Commits and pull requests" and "Writing".
- [ ] Fixes and findings are batched by step 8.
