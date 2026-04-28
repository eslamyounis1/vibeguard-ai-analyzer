"""
VibeGuard benchmark runner.

Usage:
    python -m benchmarks.runner              # run all samples, print table
    python -m benchmarks.runner --json       # machine-readable output
    python -m benchmarks.runner --ids S01 S04  # run specific samples

Metrics computed per sample:
    TP  true positives  — expected rules that were detected
    FN  false negatives — expected rules that were NOT detected
    FP  false positives — unexpected rules that were fired
    Precision = TP / (TP + FP)
    Recall    = TP / (TP + FN)
    F1        = 2 * P * R / (P + R)

Aggregate metrics are macro-averaged across all samples.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# Allow running as both `python -m benchmarks.runner` and `python benchmarks/runner.py`
try:
    from benchmarks.dataset import SAMPLES, SAMPLES_BY_ID, Sample
    from sandbox.static_analyzer import analyze
except ImportError:
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from benchmarks.dataset import SAMPLES, SAMPLES_BY_ID, Sample
    from sandbox.static_analyzer import analyze


# ─── Per-sample result ────────────────────────────────────────────────────────

@dataclass
class SampleResult:
    sample_id: str
    label: str
    source: str
    tags: list[str]

    detected_rules: set[str] = field(default_factory=set)
    expected_rules: set[str] = field(default_factory=set)
    forbidden_rules: set[str] = field(default_factory=set)

    analyzer_ok: bool = True
    analyzer_error: Optional[str] = None
    elapsed_ms: float = 0.0

    @property
    def tp(self) -> set[str]:
        return self.expected_rules & self.detected_rules

    @property
    def fn(self) -> set[str]:
        return self.expected_rules - self.detected_rules

    @property
    def fp(self) -> set[str]:
        return (self.detected_rules - self.expected_rules) & self.forbidden_rules

    @property
    def precision(self) -> float:
        denom = len(self.tp) + len(self.fp)
        return len(self.tp) / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = len(self.tp) + len(self.fn)
        return len(self.tp) / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "label": self.label,
            "source": self.source,
            "tags": self.tags,
            "analyzer_ok": self.analyzer_ok,
            "analyzer_error": self.analyzer_error,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "detected_rules": sorted(self.detected_rules),
            "expected_rules": sorted(self.expected_rules),
            "tp": sorted(self.tp),
            "fn": sorted(self.fn),
            "fp": sorted(self.fp),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


# ─── Aggregate ────────────────────────────────────────────────────────────────

@dataclass
class BenchmarkReport:
    results: list[SampleResult]
    total_samples: int
    total_elapsed_ms: float

    @property
    def macro_precision(self) -> float:
        vals = [r.precision for r in self.results]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_recall(self) -> float:
        vals = [r.recall for r in self.results]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def macro_f1(self) -> float:
        vals = [r.f1 for r in self.results]
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def total_tp(self) -> int:
        return sum(len(r.tp) for r in self.results)

    @property
    def total_fn(self) -> int:
        return sum(len(r.fn) for r in self.results)

    @property
    def total_fp(self) -> int:
        return sum(len(r.fp) for r in self.results)

    def to_dict(self) -> dict:
        return {
            "total_samples": self.total_samples,
            "total_elapsed_ms": round(self.total_elapsed_ms, 2),
            "aggregate": {
                "macro_precision": round(self.macro_precision, 4),
                "macro_recall": round(self.macro_recall, 4),
                "macro_f1": round(self.macro_f1, 4),
                "total_tp": self.total_tp,
                "total_fn": self.total_fn,
                "total_fp": self.total_fp,
            },
            "results": [r.to_dict() for r in self.results],
        }


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_sample(sample: Sample) -> SampleResult:
    result = SampleResult(
        sample_id=sample.id,
        label=sample.label,
        source=sample.source,
        tags=sample.tags,
        expected_rules=set(sample.expected_rules),
        forbidden_rules=set(sample.forbidden_rules),
    )
    t0 = time.perf_counter()
    try:
        analysis = analyze(sample.code)
        result.analyzer_ok = analysis.ok
        result.analyzer_error = analysis.error
        result.detected_rules = {f.rule_id for f in analysis.findings}
    except Exception as exc:  # noqa: BLE001
        result.analyzer_ok = False
        result.analyzer_error = str(exc)
    finally:
        result.elapsed_ms = (time.perf_counter() - t0) * 1000
    return result


def run_benchmark(sample_ids: Optional[list[str]] = None) -> BenchmarkReport:
    samples = (
        [SAMPLES_BY_ID[sid] for sid in sample_ids if sid in SAMPLES_BY_ID]
        if sample_ids
        else SAMPLES
    )
    t0 = time.perf_counter()
    results = [run_sample(s) for s in samples]
    elapsed = (time.perf_counter() - t0) * 1000
    return BenchmarkReport(results=results, total_samples=len(results), total_elapsed_ms=elapsed)


# ─── CLI output ───────────────────────────────────────────────────────────────

def _col(text: str, width: int) -> str:
    return str(text)[:width].ljust(width)


def print_table(report: BenchmarkReport) -> None:
    sep = "-" * 96
    header = (
        f"{'ID':<6} {'Label':<42} {'Src':<6} "
        f"{'P':>6} {'R':>6} {'F1':>6} "
        f"{'TP':>4} {'FN':>4} {'FP':>4} {'ms':>6}"
    )
    print("\nVibeGuard Static Analysis Benchmark")
    print(sep)
    print(header)
    print(sep)
    for r in report.results:
        status = "" if r.analyzer_ok else " [ERR]"
        label = r.label[:40] + status
        print(
            f"{r.sample_id:<6} {_col(label, 42)} {r.source[:5]:<6} "
            f"{r.precision:6.3f} {r.recall:6.3f} {r.f1:6.3f} "
            f"{len(r.tp):4d} {len(r.fn):4d} {len(r.fp):4d} {r.elapsed_ms:6.1f}"
        )
        if r.fn:
            print(f"       Missed rules : {', '.join(sorted(r.fn))}")
        if r.fp:
            print(f"       False alarms : {', '.join(sorted(r.fp))}")
    print(sep)
    print(
        f"{'MACRO':>6} {'(macro-averaged across all samples)':42} {'':6} "
        f"{report.macro_precision:6.3f} {report.macro_recall:6.3f} {report.macro_f1:6.3f} "
        f"{report.total_tp:4d} {report.total_fn:4d} {report.total_fp:4d} "
        f"{report.total_elapsed_ms:6.1f}"
    )
    print(sep)
    print(f"Samples: {report.total_samples}  |  Total time: {report.total_elapsed_ms:.1f} ms\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeGuard static-analysis benchmark runner")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--ids", nargs="+", metavar="ID", help="Run specific sample IDs only")
    args = parser.parse_args()

    report = run_benchmark(sample_ids=args.ids)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_table(report)

    # Exit with non-zero if any expected rule was missed (useful for CI)
    if report.total_fn > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
