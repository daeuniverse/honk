#!/usr/bin/env python3
import os
import sys
from pathlib import Path


def load_metrics(path: str) -> dict[str, int]:
    lines = [line for line in Path(path).read_text().splitlines() if "RELOAD_METRICS " in line]
    if not lines:
        raise SystemExit(f"missing RELOAD_METRICS in {path}")
    fields = lines[-1].split("RELOAD_METRICS ", 1)[1].split()
    return {key: int(value) for key, value in (field.split("=", 1) for field in fields)}


baseline = load_metrics(sys.argv[1])
candidate = load_metrics(sys.argv[2])
if candidate.get("samples", 0) < 10:
    raise SystemExit("candidate benchmark recorded fewer than 10 samples")

failures: list[str] = []
for field in ("flag_writes", "dns_publications", "slow_paths", "ebpf_writes"):
    if candidate.get(field) != 0:
        failures.append(f"candidate {field}={candidate.get(field)} (expected 0)")
if candidate["wall_ns"] >= 1_000_000_000:
    failures.append(f"candidate wall_ns={candidate['wall_ns']} (expected <1000000000)")

rows = ["| metric | main | candidate | ratio |", "|---|---:|---:|---:|"]
for field in ("wall_ns", "cpu_ns", "allocations", "bytes_allocated"):
    old = baseline[field]
    new = candidate[field]
    ratio = new / old if old else float("inf")
    rows.append(f"| {field} | {old} | {new} | {ratio:.3f}x |")
    if old and new > old * 1.20:
        failures.append(f"candidate {field} regressed by more than 20% ({ratio:.3f}x)")

report = "\n".join(["## Identical reload benchmark", "", *rows, "", *(["PASS"] if not failures else ["FAIL", *[f"- {failure}" for failure in failures]])])
print(report)
if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
    with Path(summary).open("a") as output:
        output.write(report + "\n")
if failures:
    raise SystemExit(1)
