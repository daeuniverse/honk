#!/usr/bin/env python3
"""Fetch only manifest-cited dae sources and verify cached bytes on every run."""

import argparse
import hashlib
from pathlib import Path
import tomllib
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[2] / "crates/honk-config/conformance/manifest.toml")
    args = parser.parse_args()
    manifest = tomllib.loads(args.manifest.read_text())
    commit = manifest["upstream"]["commit"]
    for source in manifest["upstream"]["sources"]:
        name = source["file"]
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"invalid source path: {name}")
        url = f"https://raw.githubusercontent.com/daeuniverse/dae/{commit}/{name}"
        if source["url"] != url:
            raise SystemExit(f"source URL does not match pinned commit: {name}")
        destination = args.destination / path
        if destination.exists():
            data = destination.read_bytes()
        else:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read()
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise SystemExit(f"sha256 mismatch: {name}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        print(f"verified {name}")


if __name__ == "__main__":
    main()
