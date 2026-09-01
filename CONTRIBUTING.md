# honk LLM Contribution Policy

**Status:** project policy for `daeuniverse/honk`. Adapted from the `rust-lang/rust` LLM policy (2026-08), calibrated to honk's actual development model: a small human core team writing architecture and soundness-critical code, with LLM agents producing high-volume supporting code under review.

This policy exists so that contributors know the rules before they write code, and so reviewers can point to a public, actionable reason when enforcing them. It is not a stance on whether LLMs are good or bad; it is a statement of where understanding must live in this project.

---

## 1. Core principle

> LLMs may **fill**; humans must **own the invariants**.

It is fine to use LLMs to answer questions, analyze, distill, refine, check, suggest, review, and to generate code in the areas listed in §3. It is not acceptable for an LLM to originate changes in the soundness-critical areas listed in §2 unless the human author is already a domain expert who fully understands and stands behind every line.

The project cares more about authors **understanding** what the code does, **planning** how it will change, and **deciding** what it should look like, than about the code itself. A polished PR is not evidence of any of these.

## 2. Soundness-critical areas (human-authored only)

The following carry honk's core invariants — generation ownership, lock ordering, eBPF two-phase commit semantics, failure-direction guarantees. Changes here must be originated by a human who can defend the design line by line. LLMs may analyze, review, and suggest, but must not create the change:

- `crates/honk-core/src/ebpf/` (real backend, map lifecycle, routing push plans)
- `crates/honk-ebpf-common/` (ABI， aya Pods)
- `crates/honk-core/src/control/reload/` (transaction, fingerprints, retention decisions)
- `crates/honk-core/src/control/routing_matcher.rs` and the eBPF publication pipeline
- Lock acquisition order across `config`, `router`, `ebpf`, `group_manager`, `outbound_id_map`, `active_routing_plan`, `runtime_registry`, `reload_lock`
- `unsafe` code anywhere in the repository
- Failure/replay/degradation paths (datapath health, drain, NFQUEUE fencing)

Rationale: these areas fail in directions a diff cannot show. Their correctness depends on invariants that live across files, in `AGENTS.md`, and in reviewer memory — not in any single hunk.

## 3. LLM-created code (allowed, with conditions)

LLM-generated code is welcome in:

- Test units, integration tests, fault-injection fixtures
- Benchmarks and CI gates/scripts
- Mock backends and test harnesses
- Documentation and `AGENTS.md` updates
- Mechanical, behavior-preserving refactors outside §2 areas

**Conditions (all mandatory):**

1. **Pre-arranged.** The change fits an agreed division of labor, not a drive-by PR.
2. **Disclosed.** The PR description must state which files/areas are LLM-generated (see §5). Undisclosed LLM authorship is grounds for closing.
3. **Tested.** Any LLM-created production-adjacent code (fixtures, mocks that other tests depend on) must itself be exercised by CI. Benchmarks must carry their contract assertions in-tree.
4. **Human-reviewed.** A human maintainer has read the diff. LLM review never substitutes for human review or self-review.
5. **Invariants respected.** LLM-created code must obey every contract in `AGENTS.md` (e.g. never call `clear_routes` on the push path; generation-bound ownership; no new lock edges). Reviewers should assume the generator generalized the contract imperfectly and check the seams.

## 4. Review rules

1. **Human review is the merge gate.** LLM reviews (including external adversarial reviews) are advisory layers; at least one maintainer must approve with human judgment.
2. **No mechanical relay.** Do not respond to review comments by pasting them into an LLM and pasting the answer back. If we wanted an LLM's opinion we would ask it ourselves. We want *your* reasoning.
3. **Fast review owns the shallow, slow review owns the deep.** Maintainers' quick review of LLM filler code is expected to catch contract violations visible in the diff. Defect classes structurally invisible to fast review — negative-space omissions, cross-file invariant conflicts, concurrency/timing — are the explicit responsibility of the deep-review layer (see §6) and must not be assumed covered.
4. **Tests must attack, not mirror.** Reviewers of LLM-written tests should sample whether assertions are independently derived semantic claims (e.g. "old-generation entries survive one transition") or restatements of the implementation. Mirror tests are rejected regardless of coverage numbers.
5. **Reviewers may close non-compliant PRs** with a pointer to this document, no questions asked.

## 5. Disclosure

Every PR must answer, in its description or the PR template:

- Which parts (by file or area) are LLM-generated?
- Which LLM tools/agents were used, if any, for analysis or review?
- If LLM-written tests cover human-written core code: what did the author verify beyond the tests?

Disclosure calibrates reviewer trust. Hidden LLM involvement is treated as a breach of trust between author and reviewer, independent of code quality.

## 6. Adversarial deep review

PRs touching §2 areas, or modifying any invariant named in `AGENTS.md`, require a deep review pass in addition to normal review. The deep review must:

- Enumerate the negative space (inputs not fingerprinted, paths not gated, branches not tested);
- Verify failure direction (every new failure mode must fall toward the conservative side);
- Re-derive lock ordering if any lock site was added or moved;
- Cite findings by `file:line` and pin the reviewed head SHA.

An unbroken streak of "no findings" from any single reviewer — human or LLM — is itself a weak signal and increases the weight of an independent second pass.

## 7. What LLMs are for here (encouraged)

- Writing and expanding test matrices, fault injection, and benchmarks
- CI regression gates that turn performance/correctness claims into executable checks
- Keeping `AGENTS.md` synchronized with code changes
- First-pass review, evidence audit, and adversarial second-pass review under human direction
- Analysis, translation, summarization — without posting raw output where maintainers are expected to read it unmarked

## 8. What LLMs are not for here

- Originating changes in §2 areas
- Substituting for the author's mental model of merged code
- Producing PR descriptions, issue text, or review replies posted without disclosure
- Lowering any existing bar: clippy clean, full test pass, and `AGENTS.md` synchronization are required of LLM-assisted PRs exactly as of human ones — LLM PRs are held to a *higher* bar (unconditional tests, disclosure), never a lower one

## 9. Enforcement and scope notes

- Maintainers are not responsible for detecting LLM authorship; that responsibility lies with the author. Style is not evidence; do not accuse contributors of LLM use. Suspected undisclosed use is reported privately to maintainers.
- Harassment over LLM use — allowed or not — is a Code of Conduct violation.
- Some provisions are unenforceable. That is accepted: the goal is a bright line judged on actions (disclosure given or not), with intent considered only when deciding how to respond.
- This policy is easier to change than it was to adopt. Propose amendments by PR against this file.

## 10. The understanding clause

Merged code becomes the maintainer's burden. If you cannot explain, unprompted, what your PR does and why it is correct — including the parts an LLM wrote — the PR is not ready, regardless of how polished it is. We are building a community of deep experts in this codebase, not just artifacts that mechanically do the right thing.

*No programmer tapes.*
