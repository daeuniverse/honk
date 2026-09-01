#!/usr/bin/env python3
import json
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path.cwd()
ARMS = {
    "baseline": ROOT / "adapter_probe-baseline",
    "candidate": ROOT / "adapter_probe-candidate",
}
PROTOCOLS = ("hy2", "tuic", "juicity")
SCENARIOS = (
    ("delay40_loss1", 40, 1),
    ("delay100_loss3", 100, 3),
    ("delay300_loss10", 300, 10),
)
rows = []
try:
    for scenario, delay_ms, loss_pct in SCENARIOS:
        subprocess.run(
            [
                "tc", "qdisc", "replace", "dev", "lo", "root", "netem",
                "delay", f"{delay_ms}ms", "loss", f"{loss_pct}%",
            ],
            check=True,
        )
        for index, protocol in enumerate(PROTOCOLS):
            arms = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
            for arm in arms:
                started = time.monotonic()
                result = subprocess.run(
                    [str(ARMS[arm]), str(ROOT / f"{protocol}.txt"), "127.0.0.1:9443", "10"],
                    text=True,
                    capture_output=True,
                    timeout=300,
                )
                values = [
                    tuple(map(int, line.split("\t")))
                    for line in result.stdout.splitlines()
                    if len(line.split("\t")) == 2
                ]
                rows.append(
                    {
                        "scenario": scenario,
                        "protocol": protocol,
                        "arm": arm,
                        "returncode": result.returncode,
                        "completed": len(values),
                        "handshake_median_ns": statistics.median(v[0] for v in values) if values else None,
                        "handshake_p95_ns": sorted(v[0] for v in values)[min(len(values) - 1, 9)] if values else None,
                        "total_median_ns": statistics.median(v[1] for v in values) if values else None,
                        "elapsed_s": time.monotonic() - started,
                        "stderr": result.stderr,
                    }
                )
finally:
    subprocess.run(
        ["tc", "qdisc", "del", "dev", "lo", "root"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

print(json.dumps(rows, separators=(",", ":")))
