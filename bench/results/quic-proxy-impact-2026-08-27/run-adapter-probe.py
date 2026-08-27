#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
import platform
import resource
import statistics
import subprocess
import time
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def source_root(binary):
    root = Path(binary).resolve().parents[3]
    if not (root / "Cargo.toml").is_file():
        raise RuntimeError(f"cannot find source root for {binary}")
    return root


def revision(root):
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def cpu_model():
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def run(binary, node, samples):
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    result = subprocess.run(
        [binary, node, "127.0.0.1:443", str(samples)],
        check=True,
        text=True,
        capture_output=True,
    )
    wall_ns = time.monotonic_ns() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    parsed = [line.split("\t") for line in result.stdout.splitlines() if line]
    if len(parsed) != samples or any(len(row) != 2 for row in parsed):
        raise RuntimeError(f"{binary} returned invalid benchmark samples")
    return {
        "handshake_ns": [int(row[0]) for row in parsed],
        "total_ns": [int(row[1]) for row in parsed],
        "wall_ns": wall_ns,
        "user_cpu_ns": round((after.ru_utime - usage.ru_utime) * 1e9),
        "system_cpu_ns": round((after.ru_stime - usage.ru_stime) * 1e9),
        "stderr": result.stderr,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--pairs", type=int, default=10)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "adapter-probe.jsonl"
    raw.unlink(missing_ok=True)
    here = Path(__file__).resolve().parent
    protocols = [
        ("hy2", str(here / "hy2.txt")),
        ("tuic", str(here / "tuic.txt")),
        ("juicity", str(here / "juicity.txt")),
    ]
    rows = []
    for pair in range(1, args.pairs + 1):
        rotated = protocols[(pair - 1) % len(protocols) :] + protocols[: (pair - 1) % len(protocols)]
        arms = ("baseline", "candidate") if pair % 2 else ("candidate", "baseline")
        for protocol, node in rotated:
            for arm in arms:
                binary = args.baseline if arm == "baseline" else args.candidate
                measured = run(binary, node, args.samples)
                row = {"pair": pair, "protocol": protocol, "arm": arm, **measured}
                rows.append(row)
                with (out / "adapter-probe.jsonl").open("a", encoding="utf-8") as target:
                    target.write(json.dumps(row, separators=(",", ":")) + "\n")

    summaries = []
    for protocol, _ in protocols:
        for metric in ("handshake_ns", "total_ns"):
            paired = []
            for pair in range(1, args.pairs + 1):
                medians = {
                    row["arm"]: statistics.median(row[metric])
                    for row in rows
                    if row["protocol"] == protocol and row["pair"] == pair
                }
                paired.append(
                    (medians["candidate"] - medians["baseline"])
                    / medians["baseline"]
                    * 100
                )
            summary = {
                "protocol": protocol,
                "metric": metric,
                "paired_delta_pct": statistics.median(paired),
            }
            for arm in ("baseline", "candidate"):
                values = [
                    value
                    for row in rows
                    if row["protocol"] == protocol and row["arm"] == arm
                    for value in row[metric]
                ]
                summary[f"{arm}_median_ns"] = statistics.median(values)
                summary[f"{arm}_p95_ns"] = percentile(values, 0.95)
            summaries.append(summary)

    with (out / "summary.tsv").open("w", encoding="utf-8") as target:
        target.write(
            "protocol\tmetric\tbaseline_median_ns\tcandidate_median_ns\t"
            "paired_delta_pct\tbaseline_p95_ns\tcandidate_p95_ns\n"
        )
        for row in summaries:
            target.write(
                f'{row["protocol"]}\t{row["metric"]}\t{row["baseline_median_ns"]:.0f}\t'
                f'{row["candidate_median_ns"]:.0f}\t{row["paired_delta_pct"]:.3f}\t'
                f'{row["baseline_p95_ns"]}\t{row["candidate_p95_ns"]}\n'
            )
    baseline_root = source_root(args.baseline)
    candidate_root = source_root(args.candidate)
    metadata = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": platform.platform(),
        "cpu": cpu_model(),
        "pairs": args.pairs,
        "samples_per_arm": args.samples,
        "warmups_per_process": 5,
        "baseline_binary": args.baseline,
        "baseline_sha256": digest(args.baseline),
        "baseline_revision": revision(baseline_root),
        "baseline_quic_source_sha256": digest(
            baseline_root / "crates/honk-outbound/src/quic.rs"
        ),
        "candidate_binary": args.candidate,
        "candidate_sha256": digest(args.candidate),
        "candidate_revision": revision(candidate_root),
        "candidate_quic_source_sha256": digest(
            candidate_root / "crates/honk-outbound/src/quic.rs"
        ),
        "runner_sha256": digest(__file__),
        "probe_source_sha256": digest(here / "adapter_probe.rs"),
        "node_sha256": {name: digest(path) for name, path in protocols},
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
