## Reviewing a change

Read with: `AGENTS.md` (Change workflow: risk classes; Intentional designs; Writing). `CONTRIBUTING.md` §4 sets the review rules and §6 the deep review for High changes; this file applies them and does not restate them.

### Scope

- Pin the base and head SHAs in the report. Cite `path:line` at the head SHA, or at the base SHA for code the change removed.
- Take the risk class from `AGENTS.md`. A High change gets the `CONTRIBUTING.md` §6 pass on top of this file.
- Skip behaviour listed under Intentional designs in `AGENTS.md` unless the change alters it.

### Evidence per finding

- **Reachability first.** Name the path from an entry point (packet, API request, config load, reload, timer) to the line. A defect with no such path is a hypothesis.
- **Behaviour findings** carry a reproduction: a test that fails at the head SHA, or a command and its output.
- **Structure findings** carry `path:line` plus the search output that shows the duplicate, the missing caller or the second implementation.
- **Severity carries its trigger path:** the input or event that reaches the defect and what the user then sees. A finding without a trigger path is downgraded.
- **Hypotheses:** a suspicion you could not reproduce goes to the Hypotheses list with the command or test that would settle it.
- **Pre-existing defects** that this change makes reachable get their own list, naming the base-SHA line and the new path to it.

### Over-design pass

Report over-design only when one of these holds, and name the simpler shape:

- a clearly simpler way reaches the same behaviour;
- a special case inserted into a shared path;
- a wrapper that buys no clarity;
- a near-duplicate of an existing helper (give its `path:line`);
- a re-implementation of a mechanism the platform or an existing dependency already provides.

### Report format

1. Verdict line: approve, approve with nits, or changes requested, with `base..head` SHAs.
2. Findings, highest severity first, each with scenario, evidence and the wanted fix.
3. Hypotheses, each with its settling command.
4. Pre-existing defects made reachable.

Success signal: every finding outside Hypotheses carries a reproduction or search output that a maintainer can re-run.
