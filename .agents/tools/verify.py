#!/usr/bin/env python3
"""Check that the split AGENTS.md is a byte-exact rearrangement of the pinned blob.

    python3 .agents/tools/verify.py <path-to-pinned-AGENTS.md>

Removes exactly the marked task-routing block from the root, then walks the
manifest in source order taking each fragment from its destination file. The
concatenation must equal the pinned blob, and every destination file must be
consumed completely, so any other added, removed or moved byte fails.
"""

import pathlib
import sys

sys.dont_write_bytecode = True
import split  # noqa: E402


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    lines = split.read_pinned(argv[1])
    original = b"\n".join(lines)
    files = {}
    for destination, _, _ in split.MANIFEST:
        files.setdefault(destination, pathlib.Path(destination).read_bytes())
    root = files[split.ROOT]
    start = root.find(split.ROUTING_START)
    end = root.find(split.ROUTING_END)
    if start < 0 or end < start or root.count(split.ROUTING_START) != 1:
        sys.exit("root must contain exactly one marked task-routing block")
    files[split.ROOT] = root[:start] + root[end + len(split.ROUTING_END) :]
    cursor = dict.fromkeys(files, 0)
    rebuilt = []
    for destination, text in split.fragments(lines):
        at = cursor[destination]
        got = files[destination][at : at + len(text)]
        if got != text:
            sys.exit(f"{destination}: fragment at byte {at} differs from the pinned blob")
        cursor[destination] = at + len(text)
        rebuilt.append(got)
    for destination, at in cursor.items():
        if at != len(files[destination]):
            sys.exit(f"{destination}: {len(files[destination]) - at} bytes beyond the manifest")
    if b"".join(rebuilt) != original:
        sys.exit("reassembled text differs from the pinned blob")
    print(f"ok: {len(original)} bytes, {len(files)} files")


if __name__ == "__main__":
    main(sys.argv)
