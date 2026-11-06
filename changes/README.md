# Changelog fragments

For each pull request, add one Markdown file named after the branch slug. Replace `/` and other non-alphanumeric characters with `-`, use lowercase, collapse repeated hyphens, and trim hyphens at both ends. For example, `fix/dns-worker-timeout` becomes `changes/fix-dns-worker-timeout.md`.

The first line is `Added`, `Changed`, `Fixed`, `Removed`, `Security`, or `Internal`. Follow it with one or more `- ` bullet lines describing user-visible changes. You may leave blank lines. Do not add a PR number: the renderer looks up the commit that added the fragment.

```markdown
Fixed

- DNS workers stop waiting when a request times out.
```

Use `Internal` for contributor-facing changes. The renderer groups entries in the type order above and sorts filenames within each group. `README.md` is not a fragment.

PRs touching `crates/`, `Cargo.toml`, `Cargo.lock`, `ci/fetch-doona.sh`, or `.github/ci/pins.env` must add a new fragment. Modifying or renaming an existing fragment does not count. Files under `crates/*/tests/` and Markdown files do not require one; a test edited inside a production `.rs` file does. Maintainers can apply `no-changelog` when an entry is unnecessary.

CI validates every added or changed fragment from the PR head, including fragment-only PRs and PRs labeled `no-changelog`. Invalid fragments fail with their filename and the parser's reason.

## Preview and release

From the repository root, with Python 3 installed:

```sh
python3 .github/ci/changelog.py render
```

This prints the generated `## [Unreleased]` section without changing files. Install and authenticate [GitHub CLI](https://cli.github.com/) to include PR numbers. The renderer calls `gh api repos/{owner}/{repo}/commits/<sha>/pulls` for each fragment's adding commit and prefers a merged PR. If Git history or GitHub is unavailable, it warns on stderr and omits the number.

To collect fragments for a release, supply its version without `v` and its date:

```sh
python3 .github/ci/changelog.py release 0.1.0-beta.4 2026-10-28
```

This adds a dated section to `CHANGELOG.md`, updates comparison links, and deletes consumed fragments. The Unreleased heading and fragment note remain. Collection refuses duplicate versions, handwritten Unreleased entries, missing comparison links, and an empty fragment set.

Review warnings before publishing; offline entries have no PR numbers. Commit the changelog and fragment deletions with the release changes. Collection does not update Cargo versions or create a tag; follow the [release process](../.agents/rules/release.md#release-process-standing-convention).
