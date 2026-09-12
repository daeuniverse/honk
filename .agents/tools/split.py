#!/usr/bin/env python3
"""Split one revision of AGENTS.md into the root file and .agents/rules/*.

The manifest below assigns every line of the pinned AGENTS.md blob to exactly
one destination. Moved lines are copied byte for byte; the only new text is the
task-routing table inserted into the root between two marker comments.

    python3 .agents/tools/split.py <path-to-pinned-AGENTS.md>

verify.py checks the result against the same blob. Both scripts describe the
extraction commit only: later commits edit the files freely and re-splitting
means re-pinning the blob and the manifest.
"""

import hashlib
import pathlib
import sys

# sha256 of AGENTS.md at ed67329f459dd7e69411c898f797e6a913e61dd6.
PINNED_SHA256 = "25f8cc15c6937ee96c4d2d0ea36af0a5a0b4e8fc1c6ff5936c7f325718e5d92a"

ROOT = "AGENTS.md"

# (destination, first line, last line): 1-based, inclusive, in source order.
# Blank lines at fragment boundaries stay with the root where the root would
# otherwise join two paragraphs.
MANIFEST = (
    (ROOT, 1, 75),
    (".agents/rules/real-ebpf.md", 76, 117),
    (ROOT, 118, 141),
    (".agents/rules/release.md", 142, 185),
    (ROOT, 186, 208),
    (".agents/rules/maintainer-lab.md", 209, 218),
    (ROOT, 219, 221),
    (".agents/rules/maintainer-lab.md", 222, 224),
    (ROOT, 225, 249),
    (".agents/rules/test-locations.md", 250, 266),
    (ROOT, 267, 267),
    (".agents/rules/test-locations.md", 268, 271),
    (ROOT, 272, 272),
    (".agents/rules/configuration.md", 273, 334),
    (".agents/rules/deployment.md", 335, 342),
    (".agents/rules/security.md", 343, 350),
    (ROOT, 351, 385),
)

# Inserted into the root after this many source lines (the preamble).
ROUTING_AFTER_LINE = 6
ROUTING_START = b"<!-- task-routing:start -->\n"
ROUTING_END = b"<!-- task-routing:end -->\n\n"
ROUTING = ROUTING_START + b"""## Task routing

| Doing | Read first |
|---|---|
| any change | this file |
| honk-config, honk-tool, `doc/*/reference`, `dialect.md`, or a core/outbound consumer of `Config`, `Node`, `derive_id`, group filters, DNS routing | `.agents/rules/configuration.md` |
| real-kernel or eBPF work, `crates/honk-ebpf*`, `crates/honk-core/src/ebpf/`, mock-eBPF development | `.agents/rules/real-ebpf.md` |
| placing or finding tests, benchmarks | `.agents/rules/test-locations.md` |
| releases, CI workflows | `.agents/rules/release.md` |
| deployment, security-sensitive paths | `.agents/rules/deployment.md`, `.agents/rules/security.md` |
| REALITY / xtls interop verification against live servers | `.agents/rules/maintainer-lab.md` (the maintainer's lab; not required for contributions) |
""" + ROUTING_END


def read_pinned(path):
    data = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED_SHA256:
        sys.exit(f"{path}: sha256 {digest} is not the pinned blob {PINNED_SHA256}")
    return data.split(b"\n")


def fragments(lines):
    """Yield (destination, bytes) per manifest entry; every line used once."""
    expected = 1
    for destination, first, last in MANIFEST:
        if first != expected or last < first:
            sys.exit(f"manifest gap or overlap at {destination} {first}-{last}")
        yield destination, b"".join(line + b"\n" for line in lines[first - 1 : last])
        expected = last + 1
    if expected != len(lines):
        sys.exit(f"manifest covers {expected - 1} lines, blob has {len(lines) - 1}")


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    lines = read_pinned(argv[1])
    if lines[-1] != b"":
        sys.exit("pinned blob must end with a newline")
    out = {}
    for destination, text in fragments(lines):
        out.setdefault(destination, []).append(text)
    root = out[ROOT]
    head = b"".join(line + b"\n" for line in lines[:ROUTING_AFTER_LINE])
    if not root[0].startswith(head):
        sys.exit("routing insertion point is not inside the first root fragment")
    root[0] = head + ROUTING + root[0][len(head) :]
    for destination, parts in out.items():
        target = pathlib.Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"".join(parts))
        print(f"{destination}: {sum(len(p) for p in parts)} bytes")


if __name__ == "__main__":
    main(sys.argv)
