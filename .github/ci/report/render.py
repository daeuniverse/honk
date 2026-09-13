#!/usr/bin/env python3
"""Render trusted metadata and untrusted CI artefacts into one bounded comment."""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_JSON_BYTES = 256 * 1024
MAX_REPORTS = 64
MAX_BODY_BYTES = 60_000
MAX_FAILURE_LINES = 20
MAX_FAILURE_LINE_BYTES = 300
MARKER = "<!-- ci-report -->"
SHA_RE = re.compile(r"[0-9a-fA-F]{7,64}\Z")

METRIC_UNITS = {
    "test_inventory": "test-names",
    "ignored_tests": "tests",
    "slowest_test": "seconds",
    "dns_smoke": "queries-and-names",
    "smoke_memory": "MiB",
    "smoke_cpu": "seconds",
    "reload_benchmark": "ratios",
    "toolchain": "rustc-cache",
    "vm_environment": "kernel-accelerator",
    # The agreed ordinary layout fixture predates stage 1. No stage-1 producer emits this.
    "ebpf_instructions": "instructions",
}

SIGNAL_KINDS = {
    "new_warn_lines",
    "shared_layout_changed",
    "workflow_changed",
    "rules_not_updated",
    "docs_language_mismatch",
}

SELECTION_JOBS = {
    "lint": "fmt + clippy",
    "test": "cargo nextest (workspace)",
    "ebpf-check": "eBPF feature compile guard",
    "ebpf": "eBPF object + real VM kernel tests",
    "ebpf-recent": "eBPF real VM tests (recent kernel)",
    "aarch64": "cargo nextest (aarch64)",
    "features": "Independent feature sets",
    "cross-musl": "x86_64 musl release path",
    "review-bot": "mechanical PR review",
}

REPORT_JOBS = {
    **{lane: job for lane, job in SELECTION_JOBS.items() if lane != "review-bot"},
    "review": "mechanical PR review",
    "reload": "compare-main",
}

POLICY_GROUPS = (
    ({"lint", "test", "ebpf-check"}, "code lanes not run: `ci:full`"),
    ({"ebpf"}, "eBPF VM not run: `ci:ebpf`"),
    (
        {"ebpf-recent", "aarch64", "features", "cross-musl"},
        "full lanes not run: `ci:full`",
    ),
)


class InvalidInput(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidInput(message)


def require_string(value: Any, field: str, max_bytes: int = 4096) -> str:
    require(isinstance(value, str), f"{field} must be a string")
    encoded = value.encode("utf-8")
    require(len(encoded) <= max_bytes, f"{field} is too large")
    return value


def require_sha(value: Any, field: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = require_string(value, field, 64)
    require(SHA_RE.fullmatch(text) is not None, f"{field} must be a commit SHA")
    return text


def require_number(value: Any, field: str) -> float:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{field} must be numeric",
    )
    result = float(value)
    require(math.isfinite(result) and 0 <= result <= 10**15, f"{field} is out of range")
    return result


def require_integer(value: Any, field: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer")
    require(0 <= value <= 10**15, f"{field} is out of range")
    return value


def load_json(path: Path) -> Any:
    require(path.is_file(), f"missing {path.name}")
    require(path.stat().st_size <= MAX_JSON_BYTES, f"{path.name} exceeds 256 KiB")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise InvalidInput(f"cannot read {path.name}: {error}") from error


def validate_strings(value: Any, field: str, depth: int = 0) -> None:
    require(depth <= 20, f"{field} is nested too deeply")
    if isinstance(value, str):
        require_string(value, field, 12_000)
    elif isinstance(value, list):
        require(len(value) <= 10_000, f"{field} has too many entries")
        for index, item in enumerate(value):
            validate_strings(item, f"{field}[{index}]", depth + 1)
    elif isinstance(value, dict):
        require(len(value) <= 200, f"{field} has too many entries")
        for key, item in value.items():
            require_string(key, f"{field} key", 100)
            validate_strings(item, f"{field}.{key}", depth + 1)


def validate_report(raw: Any, source: Path) -> dict[str, Any]:
    required = {
        "schema_version", "run_id", "run_attempt", "lane", "matrix",
        "measured_sha", "baseline_sha", "units", "values", "signals", "failure",
    }
    require(isinstance(raw, dict) and set(raw) == required, f"{source.name} has an invalid schema")
    require(raw["schema_version"] == SCHEMA_VERSION, f"{source.name} has an unsupported schema")
    require_integer(raw["run_id"], "run_id")
    require(raw["run_id"] > 0, "run_id must be positive")
    require_integer(raw["run_attempt"], "run_attempt")
    require(raw["run_attempt"] > 0, "run_attempt must be positive")
    lane = require_string(raw["lane"], "lane", 100)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", lane) is not None, "invalid lane")
    require(source.stem == lane, f"lane {lane!r} does not match {source.name}")
    require_sha(raw["measured_sha"], "measured_sha")
    require_sha(raw["baseline_sha"], "baseline_sha", nullable=True)

    matrix = raw["matrix"]
    require(isinstance(matrix, dict) and len(matrix) <= 20, "matrix must be a small object")
    for key, value in matrix.items():
        require_string(key, "matrix key", 100)
        require_string(value, f"matrix.{key}", 300)

    units = raw["units"]
    values = raw["values"]
    require(isinstance(units, dict) and isinstance(values, dict), "units and values must be objects")
    require(set(units) == set(values), "units must name every metric exactly once")
    for name, item in values.items():
        require(name in METRIC_UNITS, f"unknown metric {name!r}")
        require(units[name] == METRIC_UNITS[name], f"units.{name} is not canonical")
        require(
            isinstance(item, dict)
            and {"value", "unit", "available"} <= set(item)
            and set(item) <= {"value", "unit", "available", "reason"},
            f"values.{name} is invalid",
        )
        require(item["unit"] == units[name], f"values.{name}.unit disagrees with units")
        require(isinstance(item["available"], bool), f"values.{name}.available must be boolean")
        validate_strings(item["value"], f"values.{name}.value")
        if "reason" in item:
            require_string(item["reason"], f"values.{name}.reason", 1000)

    signals = raw["signals"]
    require(isinstance(signals, list) and len(signals) <= 100, "signals must be a small array")
    for index, signal in enumerate(signals):
        require(
            isinstance(signal, dict) and set(signal) == {"kind", "detail"},
            f"signals[{index}] is invalid",
        )
        kind = require_string(signal["kind"], f"signals[{index}].kind", 100)
        require(kind in SIGNAL_KINDS, f"unknown signal {kind!r}")
        detail = require_string(signal["detail"], f"signals[{index}].detail", 12_000)
        if signal["kind"] == "new_warn_lines":
            require("```" not in detail, "new WARN detail contains a Markdown fence")

    failure = raw["failure"]
    if failure is not None:
        require(
            isinstance(failure, dict) and set(failure) == {"summary", "detail_lines"},
            "failure is invalid",
        )
        require_string(failure["summary"], "failure.summary", 1200)
        lines = failure["detail_lines"]
        require(isinstance(lines, list) and len(lines) <= MAX_FAILURE_LINES, "failure has too many lines")
        for index, line in enumerate(lines):
            detail = require_string(line, f"failure.detail_lines[{index}]", MAX_FAILURE_LINE_BYTES)
            require("```" not in detail, "failure detail contains a Markdown fence")
    return raw


def source_provenance(jobs: dict[str, Any], baseline: bool = False) -> set[tuple[int, int, str]]:
    if baseline:
        item = jobs.get("baseline")
        if not isinstance(item, dict) or "sha" not in item:
            return set()
        items = [item]
    else:
        items = jobs.get("source_runs")
        require(isinstance(items, list) and items, "jobs.source_runs must be a nonempty array")
    result: set[tuple[int, int, str]] = set()
    for index, item in enumerate(items):
        require(isinstance(item, dict), f"source run {index} must be an object")
        run_id = require_integer(item.get("run_id"), f"source run {index}.run_id")
        attempt = require_integer(item.get("run_attempt"), f"source run {index}.run_attempt")
        sha = require_sha(item.get("sha"), f"source run {index}.sha")
        require(run_id > 0 and attempt > 0, "source run identifiers must be positive")
        result.update((run_id, selected_attempt, sha) for selected_attempt in range(1, attempt + 1))
    return result


def load_reports(directory: Path, provenance: set[tuple[int, int, str]]) -> tuple[dict[str, Any], list[str]]:
    if not directory.is_dir():
        return {}, [f"missing report directory {directory}"]
    paths = sorted(directory.glob("*.json"))
    if len(paths) > MAX_REPORTS:
        return {}, [f"more than {MAX_REPORTS} report files"]
    reports: dict[str, Any] = {}
    errors: list[str] = []
    for path in paths:
        try:
            report = validate_report(load_json(path), path)
            require(
                (report["run_id"], report["run_attempt"], report["measured_sha"]) in provenance,
                f"{path.name} is not from a selected run attempt",
            )
            require(report["lane"] not in reports, f"duplicate lane {report['lane']}")
            reports[report["lane"]] = report
        except (InvalidInput, UnicodeEncodeError) as error:
            errors.append(str(error))
    return reports, errors


def validate_selection(raw: Any, provenance: set[tuple[int, int, str]], head_sha: str) -> dict[str, Any]:
    required = {
        "event", "inputs", "labels", "filters", "filter_outcome",
        "intended_lanes", "run_id", "run_attempt",
    }
    require(isinstance(raw, dict) and set(raw) == required, "selection.json has an invalid schema")
    require_string(raw["event"], "selection.event", 40)
    require(isinstance(raw["inputs"], dict), "selection.inputs must be an object")
    require(
        isinstance(raw["labels"], list) and all(isinstance(label, str) for label in raw["labels"]),
        "selection.labels must be a string array",
    )
    require(
        isinstance(raw["filters"], dict) and set(raw["filters"]) == {"code", "docs", "ebpf"},
        "selection.filters must contain the three path filters",
    )
    require_string(raw["filter_outcome"], "selection.filter_outcome", 40)
    lanes = raw["intended_lanes"]
    require(isinstance(lanes, list) and all(isinstance(lane, str) for lane in lanes), "invalid intended lanes")
    run_id = require_integer(raw["run_id"], "selection.run_id")
    attempt = require_integer(raw["run_attempt"], "selection.run_attempt")
    require((run_id, attempt, head_sha) in provenance, "selection is not from a selected CI run attempt")
    return raw


def escape(value: Any) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("@", "@\u200b").replace("#", "#\u200b")
    escaped = html.escape(text, quote=True)
    for character, entity in {
        "\\": "&#92;", "|": "&#124;", "`": "&#96;", "*": "&#42;",
        "[": "&#91;", "]": "&#93;",
    }.items():
        escaped = escaped.replace(character, entity)
    return escaped.replace("\n", "<br>")


def decimal(value: float, digits: int = 2) -> str:
    rendered = f"{value:.{digits}f}"
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def signed(value: float, unit: str, digits: int = 2) -> str:
    prefix = "+" if value > 0 else ""
    return f"{prefix}{decimal(value, digits)} {unit}"


def metric(report: dict[str, Any] | None, name: str) -> Any | None:
    if report is None:
        return None
    item = report["values"].get(name)
    if not isinstance(item, dict) or not item.get("available"):
        return None
    return item["value"]


def unavailable_measurements(reports: dict[str, Any]) -> list[str]:
    """Measurements a producer declared but could not take; each is shown, never dropped."""
    notes: list[str] = []
    for lane in sorted(reports):
        values = reports[lane].get("values")
        if not isinstance(values, dict):
            continue
        for name in sorted(values):
            item = values[name]
            if isinstance(item, dict) and not item.get("available"):
                reason = item.get("reason") or "no reason given"
                notes.append(f"- **{escape(lane)} / {escape(name)}:** not measured ({escape(reason)})")
    return notes


def matching_baseline(report: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any] | None:
    candidate = baseline.get(report["lane"])
    if candidate is None or candidate["matrix"] != report["matrix"]:
        return None
    return candidate


def tests_section(report: dict[str, Any] | None, old_report: dict[str, Any] | None) -> list[str]:
    current = metric(report, "test_inventory")
    if not isinstance(current, dict):
        return []
    names = current.get("names")
    require(isinstance(names, list) and all(isinstance(name, str) for name in names), "invalid test names")
    total = current.get("total", len(names))
    require_integer(total, "test count")
    require(total == len(names), "test count does not match test names")
    ignored = metric(report, "ignored_tests")
    ignored_count = require_integer(ignored, "ignored tests") if ignored is not None else None
    old = metric(old_report, "test_inventory")
    old_names = old.get("names") if isinstance(old, dict) else None
    if old_names is None:
        summary = f"{total} tests"
        if ignored_count is not None:
            summary += f", {ignored_count} ignored"
        return ["**Tests**", f"<details><summary>{summary}, no baseline</summary>", "", "</details>"]

    require(isinstance(old_names, list), "invalid baseline test names")
    old_set = set(old_names)
    current_set = set(names)
    added = [name for name in names if name not in old_set]
    removed = [name for name in old_names if name not in current_set]
    old_ignored = metric(old_report, "ignored_tests")
    ignored_changed = ignored is not None and ignored != old_ignored
    if not added and not removed and not ignored_changed:
        return []
    summary = f"{len(added)} added, {len(removed)} removed"
    if ignored_count is not None:
        summary += f", {ignored_count} ignored"
    lines = ["**Tests**", f"<details><summary>{summary}</summary>", ""]
    for name in added:
        lines.append(f"- `{escape(name)}`")
    for name in removed:
        lines.append(f"- removed: `{escape(name)}`")
    if ignored_changed and not added and not removed:
        lines.append(f"- ignored tests: {ignored}")
    lines.extend(["", "</details>"])
    return lines


def logs_section(reports: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for report in reports.values():
        for signal in report["signals"]:
            if signal["kind"] == "new_warn_lines":
                lines.extend(signal["detail"].splitlines())
    if not lines:
        return []
    return [
        "**Logs**", f"<details><summary>{len(lines)} new WARN lines in passing tests</summary>",
        "", "```", *lines, "```", "", "</details>",
    ]


def limit_for(old: float | None, cap: float | None) -> float | None:
    relative = old * 1.2 if old is not None else None
    candidates = [item for item in (relative, cap) if item is not None]
    return min(candidates) if candidates else None


def measurement_rows(reports: dict[str, Any], baseline: dict[str, Any]) -> tuple[list[list[str]], list[str]]:
    rows: list[list[str]] = []
    exceeded: list[str] = []
    test = reports.get("test")
    old_test = matching_baseline(test, baseline) if test is not None else None

    memory = metric(test, "smoke_memory")
    old_memory = metric(old_test, "smoke_memory")
    if memory is not None:
        current = require_number(memory, "smoke memory")
        old = require_number(old_memory, "baseline smoke memory") if old_memory is not None else None
        limit = limit_for(old, 100.0)
        over = limit is not None and current > limit
        shown = f"{decimal(current, 1)} MB"
        baseline_cell = f"{decimal(old, 1)} MB" if old is not None else "no baseline"
        change = signed(current - old, "MB", 1) if old is not None else "—"
        limit_cell = f"{decimal(limit, 1)} MB" if limit is not None else "—"
        rows.append(["`honk-core` peak memory in the smoke", f"**{shown}**" if over else shown, baseline_cell, change, limit_cell])
        if over:
            old_note = f" (`main` {decimal(old, 1)} MB)" if old is not None else ""
            exceeded.append(f"- **`honk-core` peak memory in the smoke {shown}**, limit {limit_cell}{old_note}")

    slowest = metric(test, "slowest_test")
    old_slowest = metric(old_test, "slowest_test")
    if isinstance(slowest, dict):
        seconds = require_number(slowest.get("seconds"), "slowest test seconds")
        name = require_string(slowest.get("name"), "slowest test name", 1000)
        old_seconds = None
        if isinstance(old_slowest, dict):
            old_seconds = require_number(old_slowest.get("seconds"), "baseline slowest test seconds")
        limit = limit_for(old_seconds, 60.0)
        over = limit is not None and seconds > limit
        shown = f"{decimal(seconds, 1)} s"
        baseline_cell = f"{decimal(old_seconds, 1)} s" if old_seconds is not None else "no baseline"
        change = signed(seconds - old_seconds, "s", 1) if old_seconds is not None else "—"
        limit_cell = f"{decimal(limit, 1)} s" if limit is not None else "—"
        rows.append(["Slowest test", f"**{shown}**" if over else shown, baseline_cell, change, limit_cell])
        if over:
            old_note = f", `main` {decimal(old_seconds, 1)} s" if old_seconds is not None else ""
            exceeded.append(f"- **slowest test {shown}**, limit {limit_cell} (`{escape(name)}`{old_note})")

    cpu = metric(test, "smoke_cpu")
    old_cpu = metric(old_test, "smoke_cpu")
    if cpu is not None:
        current = require_number(cpu, "smoke CPU")
        old = require_number(old_cpu, "baseline smoke CPU") if old_cpu is not None else None
        limit = limit_for(old, None)
        rows.append([
            "`honk-core` CPU in the smoke", f"{current:.2f} s",
            f"{old:.2f} s" if old is not None else "no baseline",
            signed(current - old, "s") if old is not None else "—",
            f"{limit:.2f} s" if limit is not None else "—",
        ])

    reload = reports.get("reload")
    reload_value = metric(reload, "reload_benchmark")
    if isinstance(reload_value, dict):
        ratio_fields = (
            ("wall_ratio", "Reload wall (vs base, same job)"),
            ("cpu_ratio", "Reload CPU"),
            ("allocations_ratio", "Reload allocations"),
            ("bytes_ratio", "Reload bytes"),
        )
        for field, title in ratio_fields:
            if field not in reload_value:
                continue
            ratio = require_number(reload_value[field], f"reload {field}")
            if field == "allocations_ratio" and "allocations" in reload_value and "baseline_allocations" in reload_value:
                # Same gate as ci/compare-reload-benchmark.py: the ratio against the
                # PR's base commit, measured in the same job, may not exceed 1.20x.
                new_count = require_integer(reload_value["allocations"], "reload allocations")
                old_count = require_integer(reload_value["baseline_allocations"], "baseline reload allocations")
                over = ratio > 1.2
                allocation_delta = new_count - old_count
                rows.append([
                    "Reload allocations (vs base, same job)",
                    f"**{new_count:,}**" if over else f"{new_count:,}",
                    "—",
                    f"{allocation_delta:+,}" if allocation_delta else "0",
                    "1.20×",
                ])
                if over:
                    exceeded.append(
                        f"- **reload allocations {new_count:,}** ({ratio:.2f}× of base {old_count:,}), limit 1.20× (vs base, same job)"
                    )
            else:
                over = ratio > 1.2
                shown = f"{ratio:.2f}×"
                rows.append([title, f"**{shown}**" if over else shown, "—", "—", "1.20×"])
                if over:
                    exceeded.append(f"- **{title.lower()} {shown}**, limit 1.20× (vs base, same job)")

    instruction_reports = [report for report in reports.values() if metric(report, "ebpf_instructions") is not None]
    for report in instruction_reports:
        value = require_integer(metric(report, "ebpf_instructions"), "eBPF instructions")
        old_report = matching_baseline(report, baseline)
        old_value = metric(old_report, "ebpf_instructions")
        old = require_integer(old_value, "baseline eBPF instructions") if old_value is not None else None
        limit = min(4096, math.floor(old * 1.1)) if old is not None else 4096
        over = value > limit
        instruction_delta = value - old if old is not None else None
        rows.append([
            "eBPF object instructions", f"**{value:,}**" if over else f"{value:,}",
            f"{old:,}" if old is not None else "no baseline",
            (f"{instruction_delta:+,}" if instruction_delta else "0")
            if instruction_delta is not None else "—",
            f"{limit:,}",
        ])

    dns = metric(test, "dns_smoke")
    if isinstance(dns, dict):
        queries = require_integer(dns.get("queries"), "DNS query count")
        names = dns.get("upstream_names")
        require(isinstance(names, list) and all(isinstance(name, str) for name in names), "invalid DNS names")
        rows.append(["DNS smoke", f"{queries} queries, {len(names)} expected names", "pass", "—", "pass"])

    toolchain_reports = [report for report in reports.values() if metric(report, "toolchain") is not None]
    # One row per distinct rustc: the lanes normally share the pinned compiler.
    seen_rustc: set[tuple[str, Any]] = set()
    for report in sorted(toolchain_reports, key=lambda item: item["lane"]):
        value_probe = metric(report, "toolchain")
        if isinstance(value_probe, dict):
            key = (str(value_probe.get("rustc")), value_probe.get("cache_hit"))
            if key in seen_rustc:
                continue
            seen_rustc.add(key)
        value = metric(report, "toolchain")
        require(isinstance(value, dict), "invalid toolchain metric")
        rustc = require_string(value.get("rustc"), "rustc", 300)
        cache_hit = value.get("cache_hit")
        require(cache_hit is None or isinstance(cache_hit, bool), "cache_hit must be boolean or null")
        old_report = matching_baseline(report, baseline)
        old = metric(old_report, "toolchain")
        old_rustc = old.get("rustc") if isinstance(old, dict) else None
        title = "rustc" if len(toolchain_reports) == 1 or len(seen_rustc) == 1 else f"rustc ({escape(report['lane'])})"
        cache = ", cache hit" if cache_hit is True else ", cache miss" if cache_hit is False else ""
        rows.append([title, f"{escape(rustc)} (pinned){cache}", escape(old_rustc) if old_rustc else "no baseline", "—", "—"])

    vm_reports = [report for report in reports.values() if metric(report, "vm_environment") is not None]
    for report in sorted(vm_reports, key=lambda item: item["lane"]):
        value = metric(report, "vm_environment")
        require(isinstance(value, dict), "invalid VM metric")
        kernel = require_string(value.get("kernel"), "guest kernel", 300)
        accelerator = require_string(value.get("accelerator"), "VM accelerator", 20)
        rows.append([f"VM ({escape(report['lane'])})", f"{escape(kernel)} ({escape(accelerator)})", "—", "—", "—"])
    return rows, exceeded


def failure_lines(reports: dict[str, Any], jobs: dict[str, Any]) -> tuple[list[str], bool]:
    lines: list[str] = []
    raw_jobs = jobs.get("jobs")
    require(isinstance(raw_jobs, list), "jobs.jobs must be an array")
    failed_names = {
        item.get("name") for item in raw_jobs
        if isinstance(item, dict) and item.get("conclusion") not in (None, "success", "skipped", "neutral")
    }
    for report in sorted(reports.values(), key=lambda item: item["lane"]):
        failure = report["failure"]
        if failure is None and REPORT_JOBS.get(report["lane"]) not in failed_names:
            continue
        summary = failure["summary"] if failure is not None else "lane did not complete successfully"
        detail = failure["detail_lines"] if failure is not None else []
        lines.append(f"- **{escape(report['lane'])} failed:** {escape(summary)}")
        if detail and len(detail) <= 10:
            lines.extend(["", "```", *detail, "```"])
        elif detail:
            lines.extend([
                "", f"<details><summary>{len(detail)} decisive lines</summary>", "",
                "```", *detail, "```", "", "</details>",
            ])
    for name in sorted(item for item in failed_names if isinstance(item, str)):
        if any(REPORT_JOBS.get(report["lane"]) == name for report in reports.values()):
            continue
        lines.append(f"- **{escape(name)} failed:** producer report missing")
    return lines, bool(lines)


def policy_notes(selection: dict[str, Any]) -> list[str]:
    intended = set(selection["intended_lanes"])
    return [note for lanes, note in POLICY_GROUPS if lanes.isdisjoint(intended)]


def incomplete_and_pending(
    reports: dict[str, Any], selection: dict[str, Any], jobs: dict[str, Any]
) -> tuple[list[str], bool]:
    job_names = {item.get("name") for item in jobs["jobs"] if isinstance(item, dict)}
    notes: list[str] = []
    incomplete = False
    intended = set(selection["intended_lanes"])
    for selected_lane, job_name in SELECTION_JOBS.items():
        report_lane = "review" if selected_lane == "review-bot" else selected_lane
        if selected_lane not in intended or report_lane in reports:
            continue
        if job_name in job_names:
            notes.append(f"- **{escape(selected_lane)}:** report incomplete (producer artefact missing)")
        else:
            # Intended by the selection but neither a job nor an artefact exists:
            # the run did not get that far. Never treat absence as success.
            notes.append(f"- **{escape(selected_lane)}:** report incomplete (job never ran)")
        incomplete = True
    reload_sources = [
        run for run in jobs["source_runs"]
        if isinstance(run, dict) and run.get("workflow") == "Reload benchmark"
    ]
    if "reload" not in reports:
        if reload_sources:
            notes.append("- **Reload benchmark:** report incomplete (producer artefact missing)")
            incomplete = True
        else:
            notes.append("- **Reload benchmark:** not run yet")
    return notes, incomplete


def review_notes(reports: dict[str, Any]) -> list[str]:
    labels = {
        "shared_layout_changed": "shared kernel/userspace layout changed",
        "workflow_changed": "workflow files changed",
        "rules_not_updated": "code changed without AGENTS.md or .agents/rules/",
        "docs_language_mismatch": "documentation language pair is incomplete",
    }
    lines: list[str] = []
    for report in reports.values():
        for signal in report["signals"]:
            if signal["kind"] in labels:
                # The review bot's own wording uses backticks decoratively; drop them
                # rather than rendering entities, the rest stays escaped as untrusted.
                detail = str(signal["detail"]).replace("`", "")
                lines.append(f"- **Mechanical review — {labels[signal['kind']]}:** {escape(detail)}")
    return lines


def cap_body(lines: list[str]) -> str:
    body = "\n".join(lines).rstrip() + "\n"
    if len((body + MARKER + "\n").encode("utf-8")) <= MAX_BODY_BYTES:
        return body + MARKER + "\n"
    note = "\n_Report truncated to the 60,000-byte comment limit._\n"
    allowance = MAX_BODY_BYTES - len((note + MARKER + "\n").encode("utf-8"))
    shortened = body.encode("utf-8")[:allowance]
    while True:
        try:
            text = shortened.decode("utf-8")
            break
        except UnicodeDecodeError as error:
            shortened = shortened[: error.start]
    text = text.rsplit("\n", 1)[0]
    return text.rstrip() + note + MARKER + "\n"


def render(candidate_dir: Path, baseline_dir: Path, selection_path: Path, jobs_path: Path) -> str:
    jobs = load_json(jobs_path)
    require(isinstance(jobs, dict), "jobs file must contain an object")
    head_sha = require_sha(jobs.get("head_sha"), "jobs.head_sha")
    candidate_provenance = source_provenance(jobs)
    baseline_provenance = source_provenance(jobs, baseline=True)
    reports, report_errors = load_reports(candidate_dir, candidate_provenance)
    baseline, baseline_errors = (
        load_reports(baseline_dir, baseline_provenance)
        if baseline_provenance and baseline_dir.is_dir()
        else ({}, [])
    )

    selection_errors: list[str] = []
    try:
        selection = validate_selection(load_json(selection_path), candidate_provenance, head_sha)
    except (InvalidInput, UnicodeEncodeError) as error:
        selection_errors.append(str(error))
        selection = {"intended_lanes": [], "labels": []}

    baseline_meta = jobs.get("baseline")
    baseline_sha = None
    if isinstance(baseline_meta, dict) and baseline_meta.get("sha") is not None:
        baseline_sha = require_sha(baseline_meta["sha"], "jobs.baseline.sha")

    render_errors: list[str] = []
    try:
        rows, exceeded = measurement_rows(reports, baseline)
    except (InvalidInput, OverflowError, TypeError, ValueError, ZeroDivisionError) as error:
        rows, exceeded = [], []
        render_errors.append(f"metric data: {error}")
    failures, lane_failed = failure_lines(reports, jobs)
    missing, missing_producer = incomplete_and_pending(reports, selection, jobs)
    unavailable = unavailable_measurements(reports)
    if unavailable:
        # A declared-but-unmeasured value makes the measurement result qualified.
        missing = missing + unavailable
        missing_producer = True
    errors = report_errors + baseline_errors + selection_errors + render_errors
    tests = []
    if "test" in reports:
        try:
            tests = tests_section(reports["test"], matching_baseline(reports["test"], baseline))
        except (InvalidInput, TypeError, ValueError) as error:
            errors.append(f"test inventory: {error}")
    incomplete = missing_producer or bool(errors)
    notes = policy_notes(selection)

    baseline_label = f"`main` {baseline_sha[:8]}" if baseline_sha else "`main` (no baseline)"
    limit_phrase = f"{len(exceeded)} limits exceeded" if exceeded else "no limits exceeded"
    if lane_failed:
        state = "❌"
        status = "a lane failed" + (f", {limit_phrase}" if exceeded else "")
    elif incomplete:
        state = "❌"
        status = "report incomplete" + (f", {limit_phrase}" if exceeded else "")
    elif exceeded:
        state = "⚠️"
        status = limit_phrase
    else:
        state = "✅"
        status = limit_phrase
    policy = f" ({'; '.join(notes)})" if notes else ""
    header = f"{state} **CI report** {head_sha[:8]} vs {baseline_label}: {status}{policy}"

    logs = logs_section(reports)
    reviews = review_notes(reports)
    visible = failures + exceeded + missing + reviews + tests + logs
    if not visible and not rows and not notes and not errors:
        return cap_body([f"✅ **CI report** {head_sha[:8]} vs {baseline_label}: nothing hidden"])

    lines = [header]
    for group in (failures, exceeded, missing, reviews):
        if group:
            lines.extend(["", *group])
    if errors:
        lines.extend(["", f"- **Report validation:** {escape('; '.join(errors))}"])
    for section in (tests, logs):
        if section:
            lines.extend(["", *section])
    if rows:
        lines.extend([
            "", "**Measurements**", f"<details><summary>{len(rows)} metrics, {len(exceeded)} over limit</summary>", "",
            "| | This PR | `main` | Change | Limit |", "|---|---|---|---|---|",
        ])
        lines.extend("| " + " | ".join(row) + " |" for row in rows)
        lines.extend(["", "</details>"])
    return cap_body(lines)


def self_test() -> int:
    root = Path(__file__).resolve().parent / "fixtures"
    cases = (
        "ordinary", "limits-exceeded", "lane-failed", "reload-not-run-yet",
        "no-baseline", "missing-producer", "prose-only-policy-skips", "empty",
    )
    failures: list[str] = []
    for case in cases:
        case_dir = root / case
        expected_path = root / "ordinary.md" if case == "ordinary" else case_dir / "expected.md"
        try:
            actual = render(
                case_dir / "candidate", case_dir / "baseline",
                case_dir / "selection.json", case_dir / "jobs.json",
            )
            expected = expected_path.read_text(encoding="utf-8")
        except (InvalidInput, OSError, UnicodeError) as error:
            failures.append(f"{case}: {error}")
            continue
        if actual != expected:
            failures.append(f"{case}: rendered output differs from {expected_path.name}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("8 report fixtures passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    required = (args.candidate, args.baseline, args.selection, args.jobs, args.out)
    if any(item is None for item in required):
        parser.error("--candidate, --baseline, --selection, --jobs, and --out are required")
    try:
        body = render(args.candidate, args.baseline, args.selection, args.jobs)
        args.out.write_text(body, encoding="utf-8")
    except (InvalidInput, OSError, UnicodeError) as error:
        print(f"report input is invalid: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
