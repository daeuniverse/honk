---
name: honk-release
description: Use to prepare a honk release and follow the maintainer's tag and publication sequence.
---

Read first: `AGENTS.md` and `.agents/rules/release.md`; then `.github/workflows/release.yml`.

Publication belongs to the maintainer. Contributors can prepare the notes without publishing.

## Steps

1. Confirm the intended `main` tip has been pushed.
2. Confirm its branch CI from `.github/workflows/ci.yml` is green in GitHub Actions, through the web UI or API.
3. Follow the version and changelog preparation rules in `.agents/rules/release.md`, "Release process (standing convention)". The maintainer tags the tested tip only after it contains the collected release section.
4. The tag runs `.github/workflows/release.yml`. Wait for its test, build and release jobs to finish and create the draft GitHub Release with generated notes.
5. The maintainer writes the draft's Highlights and checks the collected changelog entries and embedded doona pairing. Notes format: `.agents/rules/release.md`, "Release process (standing convention)".
6. The maintainer checks the assets against the build and publishes the draft. Publish commands: `.agents/rules/release.md`, "Release process (standing convention)".

## Checklist

- [ ] The intended `main` tip is pushed and its branch CI is green.
- [ ] The maintainer created and pushed the next tag under the release rule.
- [ ] The tag's base version matches `Cargo.toml`, and its exact version has a collected changelog section.
- [ ] The tag workflow finished and created the draft Release.
- [ ] The maintainer wrote the Highlights and checked the generated notes.
- [ ] The maintainer checked the assets and published the draft.
