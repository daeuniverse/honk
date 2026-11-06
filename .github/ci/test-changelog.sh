#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
PYTHONPATH="$ci_dir" python3 - "$work" <<'PY'
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
from changelog import parse_fragment, render, release

for text, name in [('', 'fix-dns.md'), ('Fix\n- Timeout.', 'fix-dns.md'),
                   ('Fixed', 'fix-dns.md'), ('Fixed\n- ', 'fix-dns.md'),
                   ('Fixed\nParagraph.', 'fix-dns.md'), ('Fixed\n- Timeout.\n  continuation', 'fix-dns.md'),
                   ('Fixed\n- Timeout.', 'Fix_DNS.md')]:
    try:
        parse_fragment(text, name)
    except ValueError as error:
        assert name in str(error)
    else:
        raise AssertionError((text, name))
assert parse_fragment('Fixed\r\n\r\n- Timeout.\r\n', 'fix-dns.md') == ('Fixed', ['- Timeout.'])

os.chdir(sys.argv[1])
subprocess.run(['git', 'init', '-q'], check=True)
Path('changes').mkdir()
Path('changes/README.md').write_text('Not a fragment.\n')
Path('changes/z-dns.md').write_text('Fixed\n- DNS requests time out.\n')
Path('changes/a-ui.md').write_text('Added\n- Serve a local UI.\n')
Path('changes/a-dns.md').write_text('Fixed\n- Keep cached answers.\n')
with contextlib.redirect_stderr(io.StringIO()) as warnings:
    section, files = render()
assert section == '## [Unreleased]\n\n### Added\n\n- Serve a local UI.\n\n### Fixed\n\n- Keep cached answers.\n- DNS requests time out.\n'
assert warnings.getvalue().count('omitting PR number') == 3
assert Path('changes/a-ui.md').exists()

original = '# Changelog\n\n## [Unreleased]\n\nEntries live in [changes/](changes/) until release.\n\n[Unreleased]: https://github.com/o/r/compare/v0.1.0...HEAD\n'
Path('CHANGELOG.md').write_text(original)
for version, date in [('v0.2.0', '2026-10-28'), ('0.2.0-01', '2026-10-28'), ('0.2.0', '2026-02-30')]:
    try:
        release(version, date)
    except ValueError:
        assert Path('CHANGELOG.md').read_text() == original
    else:
        raise AssertionError((version, date))
with contextlib.redirect_stderr(io.StringIO()):
    release('0.2.0', '2026-10-28')
text = Path('CHANGELOG.md').read_text()
assert '## [0.2.0] - 2026-10-28\n\n### Added' in text
assert '[Unreleased]: https://github.com/o/r/compare/v0.2.0...HEAD' in text
assert '[0.2.0]: https://github.com/o/r/compare/v0.1.0...v0.2.0' in text
assert all(not path.exists() for path in files)
assert Path('changes/README.md').read_text() == 'Not a fragment.\n'
print('changelog: parse, render and release ok')
PY
