#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path


def load_metrics(path: str) -> dict[str, int]:
    lines = [line for line in Path(path).read_text().splitlines() if "RELOAD_METRICS " in line]
    if not lines:
        raise SystemExit(f"missing RELOAD_METRICS in {path}")
    fields = lines[-1].split("RELOAD_METRICS ", 1)[1].split()
    return {key: int(value) for key, value in (field.split("=", 1) for field in fields)}


parser = argparse.ArgumentParser()
parser.add_argument("baseline")
parser.add_argument("candidate")
parser.add_argument("--json", type=Path)
args = parser.parse_args()

baseline = load_metrics(args.baseline)
candidate = load_metrics(args.candidate)
if candidate.get("samples", 0) < 10:
    raise SystemExit("candidate benchmark recorded fewer than 10 samples")

failures: list[str] = []
for field in ("flag_writes", "dns_publications", "slow_paths", "ebpf_writes"):
    if candidate.get(field) != 0:
        failures.append(f"candidate {field}={candidate.get(field)} (expected 0)")
if candidate["wall_ns"] >= 1_000_000_000:
    failures.append(f"candidate wall_ns={candidate['wall_ns']} (expected <1000000000)")

rows = ["| metric | main | candidate | ratio |", "|---|---:|---:|---:|"]
ratios: dict[str, float] = {}
for field in ("wall_ns", "cpu_ns", "allocations", "bytes_allocated"):
    old = baseline[field]
    new = candidate[field]
    ratio = new / old if old else float("inf")
    ratios[field] = ratio
    rows.append(f"| {field} | {old} | {new} | {ratio:.3f}x |")
    if old and new > old * 1.20:
        failures.append(f"candidate {field} regressed by more than 20% ({ratio:.3f}x)")

report = "\n".join(["## Identical reload benchmark", "", *rows, "", *(["PASS"] if not failures else ["FAIL", *[f"- {failure}" for failure in failures]])])
print(report)
if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
    with Path(summary).open("a") as output:
        output.write(report + "\n")
if args.json is not None:
    args.json.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "run_id": int(os.environ.get("GITHUB_RUN_ID", "1")),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "lane": "reload",
        "matrix": {
            "target": "x86_64-unknown-linux-gnu",
            "workload": "identical-config",
        },
        "measured_sha": os.environ.get("HONK_RELOAD_MEASURED_SHA", "0000000"),
        "baseline_sha": os.environ.get("HONK_RELOAD_BASE_SHA") or None,
        "units": {"reload_benchmark": "ratios"},
        "values": {
            "reload_benchmark": {
                "value": {
                    "wall_ratio": ratios["wall_ns"],
                    "cpu_ratio": ratios["cpu_ns"],
                    "allocations_ratio": ratios["allocations"],
                    "bytes_ratio": ratios["bytes_allocated"],
                    "allocations": candidate["allocations"],
                    "baseline_allocations": baseline["allocations"],
                    "gate_passed": not failures,
                },
                "unit": "ratios",
                "available": True,
            }
        },
        "signals": [],
        "failure": None
        if not failures
        else {"summary": "reload benchmark gate failed", "detail_lines": failures[:20]},
    }
    temporary = args.json.with_name(f".{args.json.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
        os.replace(temporary, args.json)
    finally:
        temporary.unlink(missing_ok=True)
if failures:
    raise SystemExit(1)
