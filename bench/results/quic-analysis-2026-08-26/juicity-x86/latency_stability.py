#!/usr/bin/env python3
"""Collect paced HTTP open-stream latency samples and emit a JSON summary."""

from __future__ import annotations

import argparse
import http.client
import io
import json
import math
import socket
import statistics
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import TextIO

SCHEMA_VERSION = 1


def nearest_rank(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def request_once(target: str, port: int, path: str, timeout: float) -> dict[str, object]:
    started_ns = time.perf_counter_ns()
    connection = http.client.HTTPConnection(target, port, timeout=timeout)
    status: int | None = None
    error: str | None = None
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": target, "Connection": "close"},
        )
        response = connection.getresponse()
        status = response.status
        response.read()
        if not 200 <= status < 400:
            error = f"http_status_{status}"
    except Exception as exc:  # The error class is stable evidence; prose is platform-specific.
        error = type(exc).__name__
    finally:
        connection.close()
    elapsed_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
    return {
        "elapsed_ms": elapsed_ms,
        "status": status,
        "ok": error is None,
        "error": error,
    }

def scheduled_request(
    target: str,
    port: int,
    path: str,
    timeout: float,
    anchor: float,
) -> dict[str, object]:
    started_offset_ms = (time.monotonic() - anchor) * 1000
    return {
        "started_offset_ms": started_offset_ms,
        **request_once(target, port, path, timeout),
    }


def collect(
    *,
    target: str,
    port: int,
    path: str,
    samples: int,
    interval_ms: int,
    timeout: float,
    engine: str,
    protocol: str,
    sink: TextIO,
) -> dict[str, object]:
    if samples <= 0:
        raise ValueError("samples must be positive")
    if interval_ms < 0:
        raise ValueError("interval_ms must be non-negative")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    interval = interval_ms / 1000
    anchor = time.monotonic()
    if interval:
        workers = max(4, math.ceil(timeout / interval) + 2)
    else:
        workers = samples
    workers = min(samples, workers, 64)
    pending: list[tuple[int, Future[dict[str, object]]]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index in range(samples):
            deadline = anchor + index * interval
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            pending.append(
                (
                    index,
                    executor.submit(
                        scheduled_request, target, port, path, timeout, anchor
                    ),
                )
            )

        successful_ms: list[float] = []
        schedule_lags_ms: list[float] = []
        failures = 0
        for index, future in pending:
            result = future.result()
            scheduled_offset_ms = index * interval_ms
            schedule_lag_ms = max(
                0.0, float(result["started_offset_ms"]) - scheduled_offset_ms
            )
            schedule_lags_ms.append(schedule_lag_ms)
            row = {
                "schema_version": SCHEMA_VERSION,
                "engine": engine,
                "protocol": protocol,
                "index": index,
                "scheduled_offset_ms": scheduled_offset_ms,
                "schedule_lag_ms": schedule_lag_ms,
                **result,
            }
            sink.write(json.dumps(row, sort_keys=True) + "\n")
            sink.flush()
            if result["ok"]:
                successful_ms.append(float(result["elapsed_ms"]))
            else:
                failures += 1

    duration_s = time.monotonic() - anchor
    p50 = nearest_rank(successful_ms, 0.50)
    p95 = nearest_rank(successful_ms, 0.95)
    p99 = nearest_rank(successful_ms, 0.99)
    maximum = max(successful_ms) if successful_ms else None
    summary = {
        "schema_version": SCHEMA_VERSION,
        "host": socket.gethostname(),
        "engine": engine,
        "protocol": protocol,
        "target": target,
        "port": port,
        "path": path,
        "attempts": samples,
        "successes": len(successful_ms),
        "failures": failures,
        "failure_rate": failures / samples,
        "interval_ms": interval_ms,
        "duration_s": duration_s,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "max_ms": maximum,
        "mean_ms": statistics.fmean(successful_ms) if successful_ms else None,
        "stddev_ms": statistics.pstdev(successful_ms) if successful_ms else None,
        "p99_p50_spread_ms": p99 - p50 if p99 is not None and p50 is not None else None,
        "schedule_lag_p99_ms": nearest_rank(schedule_lags_ms, 0.99),
        "schedule_lag_max_ms": max(schedule_lags_ms),
        "workers": workers,
    }
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as sink:
        summary = collect(
            target=args.target,
            port=args.port,
            path=args.path,
            samples=args.samples,
            interval_ms=args.interval_ms,
            timeout=args.timeout,
            engine=args.engine,
            protocol=args.protocol,
            sink=sink,
        )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
