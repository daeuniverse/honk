---
name: honk-config-change
description: Use for configuration contracts, parsers, reference docs and their core or outbound consumers.
---

Read first: `AGENTS.md`, `.agents/rules/configuration.md` and `.agents/rules/test-locations.md`.

## Steps

1. Decide which contract changes. For lexical semantics that differ from dae, add a row to `doc/en/reference/dialect.md` and `doc/zh/reference/dialect.md`. For a setting, update its reference page under `doc/en/reference/` and `doc/zh/reference/`. A refactor needs no doc change.
2. Run `cargo test -p honk-config`. This includes integration tests. `just test-config` runs `cargo test -p honk-config --lib` only; it is not equivalent.
3. If the change reaches honk-core or honk-outbound consumers, run the affected crate tests: `cargo test -p honk-outbound`, or `cargo test -p honk-core -- --skip test_routing_with_config_dae` (the exclusion the workspace gate keeps). Focused gates and test policy: `AGENTS.md`, "Current validation guidance" and "Testing instructions".
4. Update `AGENTS.md` or the relevant rules file if a convention changed.
5. PR text: `AGENTS.md`, "Code style guidelines" (PR bodies).

## Checklist

- [ ] Contract classified; the corresponding documentation step is complete or inapplicable.
- [ ] honk-config integration tests are included in the crate run.
- [ ] Affected core or outbound consumers have their crate checks.
- [ ] Changed conventions are recorded in the root or rules file.
- [ ] PR text follows "Code style guidelines".
