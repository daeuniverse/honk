#!/usr/bin/env python3
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys

TYPES = ('Added', 'Changed', 'Fixed', 'Removed', 'Security', 'Internal')
NOTE = 'Entries live in [changes/](changes/) until release.'


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=30).strip()


def parse_fragment(text, file):
    if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*\.md', Path(file).name):
        raise ValueError(f'{file}: use a lowercase branch slug')
    lines = text.strip().splitlines()
    bullets = [line for line in lines[1:] if line.strip()]
    if not lines or lines[0] not in TYPES or not bullets or any(not re.match(r'^- \S', line) for line in bullets):
        raise ValueError(f"{file}: expected a changelog type followed by one or more '- ' bullet lines")
    return lines[0], bullets


def render():
    files = sorted(path for path in Path('changes').glob('*.md') if path.name != 'README.md')
    fragments = [(path, *parse_fragment(path.read_text(), path)) for path in files]
    groups = {kind: [] for kind in TYPES}
    for path, kind, bullets in fragments:
        suffix = ''
        try:
            sha = command('git', 'log', '--follow', '--diff-filter=A', '--format=%H', '-1', '--', str(path))
            if not re.fullmatch(r'[a-f0-9]{40,64}', sha):
                raise ValueError('no commit adding this fragment in local history')
            pulls = json.loads(command('gh', 'api', f'repos/{{owner}}/{{repo}}/commits/{sha}/pulls'))
            pr = next((pr for pr in pulls if pr.get('merged_at')), pulls[0] if pulls else {})
            number = pr.get('number')
            if type(number) is not int or not 0 < number <= 2**53 - 1:
                raise ValueError('no associated PR found')
            suffix = f' (#{number})'
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f'changelog: {path}: omitting PR number: {error}', file=sys.stderr)
        groups[kind].extend(line.rstrip() + suffix for line in bullets)
    sections = [f'### {kind}\n\n' + '\n'.join(groups[kind]) for kind in TYPES if groups[kind]]
    return '\n\n'.join(['## [Unreleased]', *sections]) + '\n', files


def release(version, date):
    number = r'(?:0|[1-9][0-9]*)'
    identifier = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    if not re.fullmatch(rf'{number}\.{number}\.{number}(?:-{identifier}(?:\.{identifier})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', version):
        raise ValueError('release requires a SemVer version without a leading v')
    try:
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
            raise ValueError()
        datetime.date.fromisoformat(date)
    except ValueError:
        raise ValueError('release requires a valid YYYY-MM-DD date') from None
    path = Path('CHANGELOG.md')
    changelog = path.read_text()
    if f'## [{version}]' in changelog:
        raise ValueError(f'version {version} is already in CHANGELOG.md')
    unreleased = re.search(r'^## \[Unreleased\]\n(.*?)(?=^## \[|^\[Unreleased\]:|\Z)', changelog, re.M | re.S)
    if not unreleased:
        raise ValueError('CHANGELOG.md has no Unreleased section')
    if unreleased[1].strip() not in ('', NOTE):
        raise ValueError('release handwritten Unreleased entries before collecting fragments')
    link = re.search(r'^\[Unreleased\]: (https://\S+/compare/)(\S+)\.\.\.HEAD$', changelog, re.M)
    if not link:
        raise ValueError('CHANGELOG.md has no Unreleased comparison link')
    section, files = render()
    if not files:
        raise ValueError('no changelog fragments to release')
    released = section.replace('## [Unreleased]', f'## [{version}] - {date}', 1)
    changelog = changelog.replace(unreleased[0], f'## [Unreleased]\n\n{NOTE}\n\n{released}\n', 1)
    changelog = changelog.replace(link[0], f'[Unreleased]: {link[1]}v{version}...HEAD\n[{version}]: {link[1]}{link[2]}...v{version}', 1)
    path.write_text(changelog)
    for file in files:
        file.unlink()


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['render']:
            print(render()[0], end='')
        elif len(sys.argv) == 4 and sys.argv[1] == 'release':
            release(*sys.argv[2:])
        else:
            raise ValueError('usage: python3 .github/ci/changelog.py render | release <version> <date>')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f'changelog: {error}')
