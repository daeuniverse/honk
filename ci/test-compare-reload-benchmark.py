#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("compare-reload-benchmark.py")


class ReloadComparisonTests(unittest.TestCase):
    def compare(self, **changes):
        baseline = dict(
            samples=10, wall_ns=20_000_000, cpu_ns=20_000_000,
            allocations=11, bytes_allocated=501,
            flag_writes=0, dns_publications=0, slow_paths=0, ebpf_writes=0,
        )
        candidate = baseline | changes
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for name, metrics in (("main", baseline), ("candidate", candidate)):
                (directory / name).write_text(
                    "RELOAD_METRICS " + " ".join(f"{key}={value}" for key, value in metrics.items()) + "\n"
                )
            report = directory / "reload.json"
            summary = directory / "summary.md"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(directory / "main"),
                 str(directory / "candidate"), "--json", str(report)],
                env=os.environ | {"GITHUB_STEP_SUMMARY": str(summary)},
                text=True, capture_output=True,
            )
            payload = json.loads(report.read_text()) if report.exists() else None
            if summary.exists():
                self.assertEqual(summary.read_text(), result.stdout)
            return result, payload

    def test_timing_noise_is_advisory(self):
        for wall_ns, cpu_ns in ((27_000_000, 27_000_000), (999_000_000, 999_000_000)):
            with self.subTest(wall_ns=wall_ns):
                result, payload = self.compare(wall_ns=wall_ns, cpu_ns=cpu_ns)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                metrics = payload["values"]["reload_benchmark"]["value"]
                self.assertEqual(metrics["wall_ratio"], wall_ns / 20_000_000)
                self.assertEqual(metrics["cpu_ratio"], cpu_ns / 20_000_000)
                self.assertTrue(metrics["gate_passed"])
                self.assertIsNone(payload["failure"])

    def test_deterministic_regressions_still_fail(self):
        for field, value in dict(allocations=14, bytes_allocated=602, flag_writes=1,
                                 dns_publications=1, slow_paths=1, ebpf_writes=1,
                                 wall_ns=1_000_000_000).items():
            with self.subTest(field=field):
                result, payload = self.compare(**{field: value})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse(payload["values"]["reload_benchmark"]["value"]["gate_passed"])
                self.assertTrue(any(field in line for line in payload["failure"]["detail_lines"]))

    def test_allocation_growth_within_existing_tolerance_passes(self):
        result, payload = self.compare(allocations=13, bytes_allocated=601)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(payload["failure"])

    def test_insufficient_samples_still_fail(self):
        result, _ = self.compare(samples=9)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fewer than 10 samples", result.stderr)


if __name__ == "__main__":
    unittest.main()
