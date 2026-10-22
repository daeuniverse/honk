<!-- English, one short paragraph per section: what is wrong, what changed, what was checked. Link long evidence instead of pasting it. Rules: AGENTS.md "PR bodies". -->

## Problem

<!-- What is wrong or missing, as a user or maintainer sees it. -->

## How I fixed it

<!-- What changed and where, not the reasoning that led there. -->

## Verified

<!-- The commands you ran and what you observed. Say what you could not verify. -->

---

Closes #

LLM disclosure (CONTRIBUTING.md §5): <!-- which files or areas are LLM-generated, which tools were used for analysis or review, and what you verified beyond LLM-written tests; "none" if no LLM was involved. -->

- [ ] `just fmt`, `just lint` and `just test-ci` pass.
- [ ] Held-packet changes: `just test-netns` passes (it uses the disposable VM gate).
- [ ] Changes in a CONTRIBUTING.md §2 area are human-originated, or §11 applies.
- [ ] `doc/en/` and `doc/zh/`, and `AGENTS.md` or `.agents/rules/`, match what I changed.
- [ ] The branch is based on the current `main`, and each commit is one `type(scope): subject` line.
