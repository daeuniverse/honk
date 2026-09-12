---
name: honk-release
description: Use to prepare a honk release and follow the maintainer's tag and publication sequence.
---

Read first: `AGENTS.md` and `.agents/rules/release.md`; then `.github/workflows/release.yml`.

Publication belongs to the maintainer. Contributors can prepare the notes without publishing.

## Steps

1. Confirm the intended `main` tip has been pushed.
2. Confirm its branch CI from `.github/workflows/ci.yml` is green in GitHub Actions, through the web UI or API.
3. The maintainer creates and pushes the next tag at that tip. Tag naming: `.agents/rules/release.md`, "Release process (standing convention)".
4. The tag runs `.github/workflows/release.yml`. Wait for its test, build and release jobs to finish and create the GitHub Release.
5. The maintainer edits the Release notes. Notes format and author attribution: `.agents/rules/release.md`, "Release process (standing convention)". For author lookup and note editing, use the `gh` commands there or the GitHub commit pages and Release editor in the web UI; the GitHub commits and releases APIs are another option.

## Checklist

- [ ] The intended `main` tip is pushed and its branch CI is green.
- [ ] The maintainer created and pushed the next tag under the release rule.
- [ ] The tag workflow finished and created the Release.
- [ ] The maintainer edited the notes using the release rule's format and author attribution.
