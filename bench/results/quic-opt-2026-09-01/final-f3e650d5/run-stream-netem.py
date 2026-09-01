#!/usr/bin/env python3
import json
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path.cwd()
ARMS = {
    "baseline": ROOT / "stream-baseline",
    "candidate": ROOT / "stream-candidate",
}
SCENARIOS = (
    ("healthy", "2ms", "1gbit", None, 64 << 20, 1, 8),
    ("bdp200", "100ms", "500mbit", None, 64 << 20, 1, 8),
    ("bdp200_parallel3", "100ms", "500mbit", None, 32 << 20, 3, 8),
    ("loss1", "40ms", "500mbit", "1%", 32 << 20, 1, 8),
)
rows = []
try:
    for scenario_index, (name, delay, rate, loss, size, concurrency, samples) in enumerate(SCENARIOS):
        command = ["tc", "qdisc", "replace", "dev", "lo", "root", "netem", "delay", delay, "rate", rate]
        if loss:
            command += ["loss", loss]
        subprocess.run(command, check=True)
        node = "hy2-brutal.txt" if name.startswith("bdp") else "hy2.txt"
        order = ("baseline", "candidate") if scenario_index % 2 == 0 else ("candidate", "baseline")
        for arm in order:
            started = time.monotonic()
            result = subprocess.run(
                [str(ARMS[arm]), str(ROOT / node), "198.18.0.2:28080", str(size), str(samples), str(concurrency)],
                text=True,
                capture_output=True,
                timeout=900,
            )
            values = [int(line) for line in result.stdout.splitlines() if line.isdigit()]
            warm = values[2:]
            median_ns = statistics.median(warm) if warm else None
            rows.append({
                "scenario": name,
                "arm": arm,
                "returncode": result.returncode,
                "completed": len(values),
                "median_ns": median_ns,
                "median_mbps": (size * concurrency * 8_000 / median_ns) if median_ns else None,
                "raw_ns": values,
                "elapsed_s": time.monotonic() - started,
                "stderr": result.stderr,
            })
finally:
    subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print(json.dumps(rows, separators=(",", ":")))
