"""Dedicated energy/runtime study runner (RQ3).

Measures the runtime cost of each corpus sample in the sandbox, repeated with
warm-ups discarded, and tests whether VibeGuard's static *performance* smells
coincide with higher measured energy/time.

Intended corpus: EvalPlus (HumanEval+ / MBPP+), whose tasks are small, pure
Python functions that produce a usable energy signal — unlike CWEval's
security-focused tasks. Build it first with:

    python -m corpus.build --datasets evalplus --out data/corpus/evalplus.jsonl

Then run, e.g.:

    python -m experiments.run_energy \
        --corpus data/corpus/evalplus.jsonl \
        --out-dir results/energy \
        --runs 20 --warmup 3 --energy-backend auto --max-samples 50

Outputs (under ``--out-dir``):
    rq3_energy.csv        Per-sample energy/time/memory stats (mean + 95% CI).
    rq3_correlation.csv   Perf-smell vs no-smell group comparison (per metric).
    summary.json          Environment, backend, counts, errors.
    METHODS.md            Protocol + threats note.

Energy backend caveat: on machines without RAPL (e.g. macOS) the "auto" backend
falls back to a CPU-time linear proxy. Re-run on Linux with
``--energy-backend rapl`` for hardware-counter energy.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional

from corpus.schema import CorpusSample, read_corpus
from experiments.measure import (
    Comparison,
    compare_metric,
    environment_metadata,
    measure_repeated,
)
from sandbox.profiler import measure_code
from security.core.scanner import Scanner
from security.models.finding import Category

# Metrics carried through to the per-sample CSV (must exist in measure._METRICS).
_REPORT_METRICS = (
    "energy_joules_estimate",
    "wall_time_seconds",
    "cpu_time_seconds",
    "memory_peak_bytes",
)

# Metrics compared between perf-smell and no-smell groups for the RQ3 hypothesis.
_CORRELATION_METRICS = ("energy_joules_estimate", "wall_time_seconds")


def _write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def runnable_code(sample: CorpusSample, with_tests: bool) -> str:
    """Build the snippet to execute.

    EvalPlus ``code`` is typically just function definitions, so executing it
    alone does no work. Appending ``tests`` (which call the entry point) makes
    the measurement reflect the function actually running.
    """
    if with_tests and sample.tests:
        return f"{sample.code}\n\n{sample.tests}\n"
    return sample.code


def has_perf_finding(code: str) -> bool:
    result = Scanner().scan_source(code)
    return any(f.category == Category.PERFORMANCE for f in result.findings)


def measure_corpus(
    samples: List[CorpusSample],
    runs: int,
    warmup: int,
    energy_backend: str,
    max_samples: Optional[int],
    with_tests: bool,
) -> tuple[List[dict], Dict[str, List[float]], List[str]]:
    """Measure each sample; return per-sample rows, grouped energy/time samples,
    and a list of skip/error notes."""
    rows: List[dict] = []
    # group key -> metric -> list of per-sample means
    grouped: Dict[str, List[float]] = {}
    notes: List[str] = []
    measured = 0

    for s in samples:
        if max_samples is not None and measured >= max_samples:
            break
        code = runnable_code(s, with_tests)

        probe = measure_code(code, energy_backend=energy_backend)
        if not probe.get("ok"):
            notes.append(
                f"skip {s.id}: {probe.get('error_type') or 'error'}: "
                f"{(probe.get('error_message') or '').strip()[:160]}"
            )
            continue

        result = measure_repeated(
            code, runs=runs, warmup=warmup, energy_backend=energy_backend
        )
        if not result.stats:
            notes.append(f"skip {s.id}: no successful measured runs")
            continue
        measured += 1

        perf = has_perf_finding(s.code)
        row: dict = {
            "id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "subset": (s.metadata or {}).get("subset"),
            "ran_with_tests": bool(with_tests and s.tests),
            "has_perf_finding": perf,
            "backend": result.backend,
            "n_runs": result.runs,
        }
        for metric in _REPORT_METRICS:
            st = result.stats.get(metric)
            row[f"{metric}_mean"] = st.mean if st else None
            row[f"{metric}_median"] = st.median if st else None
            row[f"{metric}_ci95_low"] = st.ci95_low if st else None
            row[f"{metric}_ci95_high"] = st.ci95_high if st else None
        rows.append(row)

        # Collect group means for the correlation step.
        group = "perf" if perf else "no_perf"
        for metric in _CORRELATION_METRICS:
            st = result.stats.get(metric)
            if st is not None:
                grouped.setdefault(f"{group}::{metric}", []).append(st.mean)

    return rows, grouped, notes


def correlation_rows(grouped: Dict[str, List[float]]) -> List[dict]:
    """Compare perf-smell vs no-smell groups per metric (Mann-Whitney + Cliff's delta)."""
    out: List[dict] = []
    for metric in _CORRELATION_METRICS:
        with_perf = grouped.get(f"perf::{metric}", [])
        without_perf = grouped.get(f"no_perf::{metric}", [])
        # Baseline = no smell, candidate = smell, so improvement_pct < 0 means
        # the smell group costs MORE (the expected direction for RQ3).
        cmp: Comparison = compare_metric(metric, without_perf, with_perf)
        out.append({
            "metric": metric,
            "n_with_perf_finding": len(with_perf),
            "n_without_perf_finding": len(without_perf),
            "mean_with_perf": cmp.candidate.mean if with_perf else None,
            "mean_without_perf": cmp.baseline.mean if without_perf else None,
            "pct_higher_with_perf": (-cmp.improvement_pct) if cmp.improvement_pct is not None else None,
            "cliffs_delta": cmp.cliffs_delta,
            "effect_size": cmp.effect_size,
            "mannwhitney_u": cmp.mannwhitney_u,
            "p_value": cmp.p_value,
            "significant": cmp.significant,
        })
    return out


def _write_methods(out_dir: Path, env: dict, n_measured: int, runs: int, warmup: int, backend: Optional[str], with_tests: bool) -> None:
    text = f"""# RQ3 Energy Study — Methods and Threats

## Environment
- Platform: {env.get('platform')}
- Processor: {env.get('processor')}
- Python: {env.get('python_version')}
- CPU count: {env.get('cpu_count')}
- taskset available: {env.get('taskset_available')}

## Measurement protocol
- Samples measured: {n_measured}
- Repetitions per sample: {runs} (plus {warmup} warm-up run(s) discarded)
- Executed code: sample {'code + tests' if with_tests else 'code only'}
- Energy backend used: {backend}
- Statistics: mean with 95% CI (normal approx). Perf-smell vs no-smell groups
  compared with Mann-Whitney U + Cliff's delta (see experiments/measure.py).

## RQ3 hypothesis
Static performance smells (VibeGuard `Category.PERFORMANCE`) should coincide
with higher measured energy/time. `rq3_correlation.csv` reports the per-metric
group comparison; `pct_higher_with_perf` > 0 and a positive Cliff's delta
support the hypothesis.

## Threats to validity
- Energy backend: `{backend}` may be a CPU-time proxy rather than RAPL on this
  machine. Re-run on Linux with `--energy-backend rapl` for hardware energy.
- EvalPlus `code` alone often only defines functions; we execute `code + tests`
  so the function actually runs. Test harness overhead is included in the cost.
- Profiler overhead excluded by using sandbox "measure" mode (no sys.setprofile).
- Single language (Python) and small tasks limit generalizability; absolute
  energy values are proxies, trends/relative comparisons are the signal.
"""
    (out_dir / "METHODS.md").write_text(text, encoding="utf-8")


def run_energy(
    corpus: str,
    out_dir: str,
    runs: int = 20,
    warmup: int = 3,
    energy_backend: str = "auto",
    max_samples: Optional[int] = None,
    limit: Optional[int] = None,
    with_tests: bool = True,
) -> dict:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    samples = read_corpus(corpus)
    if limit is not None:
        samples = samples[:limit]

    rows, grouped, notes = measure_corpus(
        samples, runs, warmup, energy_backend, max_samples, with_tests
    )
    corr = correlation_rows(grouped)

    _write_csv(out_path / "rq3_energy.csv", rows)
    _write_csv(out_path / "rq3_correlation.csv", corr)

    env = environment_metadata()
    backend = rows[0]["backend"] if rows else None
    _write_methods(out_path, env, len(rows), runs, warmup, backend, with_tests)

    summary = {
        "corpus": corpus,
        "n_corpus": len(samples),
        "n_measured": len(rows),
        "n_skipped": len(notes),
        "runs": runs,
        "warmup": warmup,
        "energy_backend_requested": energy_backend,
        "energy_backend_used": backend,
        "with_tests": with_tests,
        "environment": env,
        "correlation": corr,
        "notes": notes[:50],
    }
    (out_path / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ3 energy/runtime study runner.")
    parser.add_argument("--corpus", required=True, help="Corpus JSONL (e.g. data/corpus/evalplus.jsonl).")
    parser.add_argument("--out-dir", default="results/energy", help="Output directory.")
    parser.add_argument("--runs", type=int, default=20, help="Measured repetitions per sample.")
    parser.add_argument("--warmup", type=int, default=3, help="Warm-up runs discarded per sample.")
    parser.add_argument("--energy-backend", default="auto", help="auto, rapl, codecarbon, powermetrics, linear_proxy.")
    parser.add_argument("--max-samples", type=int, default=None, help="Cap successfully measured samples.")
    parser.add_argument("--limit", type=int, default=None, help="Only consider first N corpus rows.")
    parser.add_argument(
        "--no-tests",
        dest="with_tests",
        action="store_false",
        help="Measure sample.code only (do not append tests).",
    )
    parser.set_defaults(with_tests=True)
    args = parser.parse_args()

    summary = run_energy(
        corpus=args.corpus,
        out_dir=args.out_dir,
        runs=args.runs,
        warmup=args.warmup,
        energy_backend=args.energy_backend,
        max_samples=args.max_samples,
        limit=args.limit,
        with_tests=args.with_tests,
    )
    print(
        f"Measured {summary['n_measured']}/{summary['n_corpus']} samples "
        f"(backend={summary['energy_backend_used']}, skipped={summary['n_skipped']}). "
        f"Wrote outputs to {args.out_dir}"
    )


if __name__ == "__main__":
    main()
