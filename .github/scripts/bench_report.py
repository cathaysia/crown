#!/usr/bin/env python3
"""Render a markdown benchmark report from `critcmp --export` JSON dumps.

Every input file is the JSON document produced by `critcmp --export <baseline>`
and holds the measurements of one criterion baseline. Two baselines are
compared: the baseline (usually `no-asm`) and the candidate (usually `asm`).
Files covering different benchmark targets can be passed together; benchmarks
are matched by their criterion `full_id`.

    critcmp --export no-asm > data/no-asm.json
    critcmp --export asm > data/asm.json
    bench_report.py data/*.json --baseline no-asm --candidate asm
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import dataclass
from pathlib import Path

DURATION_SCALES = (
    ("s", 1_000_000_000.0),
    ("ms", 1_000_000.0),
    ("µs", 1_000.0),
    ("ns", 1.0),
)

RATE_SCALES = (
    ("GiB/s", 1 << 30),
    ("MiB/s", 1 << 20),
    ("KiB/s", 1 << 10),
    ("B/s", 1.0),
)

ELEMENT_SCALES = (
    ("Gelem/s", 1_000_000_000.0),
    ("Melem/s", 1_000_000.0),
    ("kelem/s", 1_000.0),
    ("elem/s", 1.0),
)


@dataclass
class Measurement:
    """One criterion benchmark measured under one baseline."""

    name: str
    group: str
    mean_ns: float | None
    ci_low_ns: float | None
    ci_high_ns: float | None
    bytes: int | None
    elements: int | None

    @property
    def throughput(self) -> tuple[float, tuple[tuple[str, float], ...]] | None:
        """Throughput per second and the scale table to format it with."""
        if self.mean_ns is None or self.mean_ns <= 0:
            return None
        per_second = 1_000_000_000.0 / self.mean_ns
        if self.bytes:
            return self.bytes * per_second, RATE_SCALES
        if self.elements:
            return self.elements * per_second, ELEMENT_SCALES
        return None

    def is_significantly_faster_than(self, other: Measurement) -> bool | None:
        """Whether `self` beats `other` outside the two mean confidence intervals."""
        if None in (self.ci_low_ns, self.ci_high_ns, other.ci_low_ns, other.ci_high_ns):
            return None
        return self.ci_high_ns < other.ci_low_ns

    def is_significantly_slower_than(self, other: Measurement) -> bool | None:
        if None in (self.ci_low_ns, self.ci_high_ns, other.ci_low_ns, other.ci_high_ns):
            return None
        return self.ci_low_ns > other.ci_high_ns


def format_duration(ns: float | None) -> str:
    if ns is None:
        return "n/a"
    for unit, scale in DURATION_SCALES:
        if ns >= scale or unit == "ns":
            if unit == "ns":
                return f"{ns:.2f} ns"
            return f"{ns / scale:.3f} {unit}"
    raise AssertionError("unreachable")


def format_rate(value: float, scales: tuple[tuple[str, float], ...]) -> str:
    for unit, scale in scales:
        if value >= scale:
            return f"{value / scale:.2f} {unit}"
    unit, scale = scales[-1]
    return f"{value / scale:.2f} {unit}"


def load_export(path: Path) -> tuple[str, dict[str, Measurement]]:
    """Return the baseline name and the benchmarks stored in one export file."""
    document = json.loads(path.read_text())
    baseline = document.get("name") or path.stem
    measurements: dict[str, Measurement] = {}
    for key, benchmark in document.get("benchmarks", {}).items():
        info = benchmark.get("criterion_benchmark_v1") or {}
        mean = (benchmark.get("criterion_estimates_v1") or {}).get("mean") or {}
        interval = mean.get("confidence_interval") or {}
        throughput = info.get("throughput") or {}
        measurements[key] = Measurement(
            name=info.get("full_id") or key,
            group=info.get("group_id") or key.split("/")[0],
            mean_ns=mean.get("point_estimate"),
            ci_low_ns=interval.get("lower_bound"),
            ci_high_ns=interval.get("upper_bound"),
            bytes=throughput.get("Bytes"),
            elements=throughput.get("Elements"),
        )
    return baseline, measurements


# A change smaller than this is reported as noise even when the two mean
# confidence intervals do not overlap: on shared CI runners, two consecutive
# runs of the same benchmark routinely differ by a fraction of a percent with
# tight, non-overlapping intervals.
MIN_CHANGE = 0.02


def classify(before: Measurement | None, after: Measurement | None) -> str:
    """Return `faster`, `slower`, `noise` or `partial` for one benchmark."""
    if before is None or after is None or not before.mean_ns or not after.mean_ns:
        return "partial"
    ratio = after.mean_ns / before.mean_ns
    if abs(ratio - 1.0) < MIN_CHANGE:
        return "noise"
    if after.is_significantly_faster_than(before):
        return "faster"
    if after.is_significantly_slower_than(before):
        return "slower"
    return "noise"


def format_row(
    name: str,
    before: Measurement | None,
    after: Measurement | None,
    verdict: str,
) -> str:
    cells = [f"`{name}`"]
    if before is None or after is None:
        cells += [format_duration(m.mean_ns if m else None) for m in (before, after)]
        cells += ["n/a", "n/a"]
        return "| " + " | ".join(cells) + " |"

    speedup = before.mean_ns / after.mean_ns if before.mean_ns and after.mean_ns else None
    marker = {"faster": " ✅", "slower": " ⚠️"}.get(verdict, "")
    delta = f"{speedup:.2f}×{marker}" if speedup is not None else "n/a"

    before_rate = before.throughput
    after_rate = after.throughput
    before_text = format_rate(*before_rate) if before_rate else "n/a"
    after_text = format_rate(*after_rate) if after_rate else "n/a"

    return (
        f"| `{name}` | {format_duration(before.mean_ns)} | {format_duration(after.mean_ns)} "
        f"| {delta} | {before_text} | {after_text} |"
    )


def render_table(rows: list[str], baseline_name: str, candidate_name: str) -> list[str]:
    return [
        f"| Benchmark | `{baseline_name}` | `{candidate_name}` | speedup | `{baseline_name}` rate | `{candidate_name}` rate |",
        "|---|---:|---:|---:|---:|---:|",
        *rows,
    ]


def build_report(
    baseline_name: str,
    candidate_name: str,
    baseline: dict[str, Measurement],
    candidate: dict[str, Measurement],
    notes: list[str],
    empty_files: list[str] | None = None,
) -> str:
    names = sorted(set(baseline) | set(candidate))
    verdicts = {name: classify(baseline.get(name), candidate.get(name)) for name in names}
    faster = [name for name in names if verdicts[name] == "faster"]
    slower = [name for name in names if verdicts[name] == "slower"]
    unchanged = [name for name in names if verdicts[name] == "noise"]
    partial = [name for name in names if verdicts[name] == "partial"]

    def sort_key(names: list[str], reverse: bool = False) -> list[str]:
        def ratio(name: str) -> float:
            before, after = baseline[name], candidate[name]
            if not before.mean_ns or not after.mean_ns:
                return 1.0
            return before.mean_ns / after.mean_ns

        return sorted(names, key=lambda n: (ratio(n), n), reverse=reverse)

    lines = [
        f"# Benchmark report: `{candidate_name}` vs `{baseline_name}`",
        "",
        *[f"- {note}" for note in notes],
        "",
        "## Summary",
        "",
        f"- Benchmarks compared: **{len(names) - len(partial)}**"
        f" ({len(faster)} faster with `{candidate_name}`,"
        f" {len(slower)} slower, {len(unchanged)} within noise)",
        f"- Compared groups: {len({m.group for m in baseline.values()} | {m.group for m in candidate.values()})}",
    ]
    if partial:
        lines.append(
            f"- Measured on only one side ({len(partial)}): "
            + ", ".join(f"`{name}`" for name in partial[:10])
            + (" …" if len(partial) > 10 else "")
        )
    if empty_files:
        lines.append(
            f"- Input files without any measurement ({len(empty_files)}): "
            + ", ".join(f"`{name}`" for name in sorted(empty_files))
        )
    lines.append("")

    if faster:
        lines += ["### Largest speedups", ""]
        lines += render_table(
            [
                format_row(name, baseline[name], candidate[name], verdicts[name])
                for name in sort_key(faster, reverse=True)[:10]
            ],
            baseline_name,
            candidate_name,
        )
        lines.append("")
    if slower:
        lines += ["### Regressions", ""]
        lines += render_table(
            [
                format_row(name, baseline[name], candidate[name], verdicts[name])
                for name in sort_key(slower)[:20]
            ],
            baseline_name,
            candidate_name,
        )
        if len(slower) > 20:
            lines += [f"…and {len(slower) - 20} more; see the full table below.", ""]
        lines.append("")

    lines += [
        "## All benchmarks",
        "",
        "A ✅ marks a change that is significant at the 95% level (the mean confidence"
        f" intervals of the two runs do not overlap) and at least {MIN_CHANGE:.0%}, ⚠️ such"
        f" a slowdown of `{candidate_name}`; every other row is within run-to-run noise."
        " Speedup > 1× means the candidate is faster.",
        "",
    ]

    groups: dict[str, list[str]] = {}
    for name in names:
        measurement = candidate.get(name) or baseline[name]
        groups.setdefault(measurement.group, []).append(name)
    for group in sorted(groups):
        lines += [f"### `{group}`", ""]
        lines += render_table(
            [
                format_row(name, baseline.get(name), candidate.get(name), verdicts[name])
                for name in sorted(groups[group])
            ],
            baseline_name,
            candidate_name,
        )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, help="critcmp --export JSON files")
    parser.add_argument("--baseline", default="no-asm", help="baseline name to compare against")
    parser.add_argument("--candidate", default="asm", help="candidate baseline name")
    parser.add_argument("--note", action="append", default=[], help="metadata line for the report header")
    parser.add_argument("--output", type=Path, help="write the report here instead of stdout")
    args = parser.parse_args()

    baselines: dict[str, dict[str, Measurement]] = {}
    empty_files: list[str] = []
    for path in args.files:
        name, measurements = load_export(path)
        if not measurements:
            empty_files.append(path.name)
        baselines.setdefault(name, {}).update(measurements)

    missing = [name for name in (args.baseline, args.candidate) if name not in baselines]
    if missing:
        print(f"error: no data for baseline(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    notes = list(args.note)
    if not notes:
        notes = [f"Generated: {datetime.datetime.now(datetime.UTC):%Y-%m-%d %H:%M UTC}"]
    report = build_report(
        args.baseline,
        args.candidate,
        baselines[args.baseline],
        baselines[args.candidate],
        notes,
        empty_files,
    )
    if args.output:
        args.output.write_text(report)
        print(f"wrote {args.output} ({len(report.splitlines())} lines)", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
