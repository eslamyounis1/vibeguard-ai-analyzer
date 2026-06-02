"""End-to-end study runner: produces RQ1-RQ5 artifacts for the paper.

RQ1  Prevalence of issues in (AI-generated) code, by source and category.
RQ2  AI-vs-human issue rates on matched tasks.
RQ3  Measured runtime/energy cost, and whether static perf smells coincide
     with higher measured cost.
RQ4  Auto-fix effectiveness: findings removed, behavior preserved (tests),
     and before/after energy.
RQ5  Detection precision/recall vs baseline tools in CWE space.

Outputs CSV files (stdlib csv, no pandas needed) plus a methods/threats note,
and optional matplotlib plots when the library is installed.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from corpus.loaders import load_cweval, load_humaneval, load_security_benchmark
from corpus.schema import CorpusSample, read_corpus, write_corpus
from experiments.baselines import evaluate_corpus
from experiments.cwe_scoping import supported_cwes
from experiments.measure import environment_metadata, measure_repeated
from orchestrator.pipeline import compare_fix
from sandbox.profiler import measure_code
from security.core.scanner import Scanner
from security.models.finding import Category


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


def _is_human(sample: CorpusSample) -> bool:
    return sample.source == "human" or sample.source.startswith("human")


def _category_counts(sample: CorpusSample) -> Dict[str, int]:
    result = Scanner().scan_source(sample.code)
    counts = {"security": 0, "code_smell": 0, "performance": 0}
    for finding in result.findings:
        if finding.category == Category.SECURITY:
            counts["security"] += 1
        elif finding.category == Category.CODE_SMELL:
            counts["code_smell"] += 1
        elif finding.category == Category.PERFORMANCE:
            counts["performance"] += 1
    counts["total"] = sum(counts.values())
    return counts


def rq1_prevalence(samples: List[CorpusSample], out_dir: Path) -> List[dict]:
    rows = []
    for s in samples:
        counts = _category_counts(s)
        meta = s.metadata or {}
        rows.append({
            "id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "cwe": meta.get("cwe", ""),
            "security": counts["security"],
            "code_smell": counts["code_smell"],
            "performance": counts["performance"],
            "total": counts["total"],
        })
    _write_csv(out_dir / "rq1_prevalence.csv", rows)

    by_source: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_source[row["source"]].append(row)
    agg = []
    for source, group in sorted(by_source.items()):
        n = len(group)
        agg.append({
            "source": source,
            "samples": n,
            "mean_security": round(sum(r["security"] for r in group) / n, 3),
            "mean_code_smell": round(sum(r["code_smell"] for r in group) / n, 3),
            "mean_performance": round(sum(r["performance"] for r in group) / n, 3),
            "mean_total": round(sum(r["total"] for r in group) / n, 3),
            "pct_with_any": round(100 * sum(1 for r in group if r["total"] > 0) / n, 1),
        })
    _write_csv(out_dir / "rq1_by_source.csv", agg)
    return agg


def rq2_ai_vs_human(samples: List[CorpusSample], out_dir: Path) -> List[dict]:
    """Aggregate by human vs AI group, plus matched task_id comparisons."""
    by_source: Dict[str, List[CorpusSample]] = defaultdict(list)
    for s in samples:
        by_source[s.source].append(s)

    agg_rows = []
    for source, group in sorted(by_source.items()):
        n = len(group)
        totals = [_category_counts(s)["total"] for s in group]
        agg_rows.append({
            "source": source,
            "group": "human" if _is_human(group[0]) else "ai",
            "samples": n,
            "mean_total": round(statistics.fmean(totals), 3) if totals else 0.0,
            "pct_with_any": round(100 * sum(1 for t in totals if t > 0) / n, 1) if n else 0.0,
        })
    _write_csv(out_dir / "rq2_by_source.csv", agg_rows)

    by_task: Dict[str, List[CorpusSample]] = defaultdict(list)
    for s in samples:
        by_task[s.task_id].append(s)

    matched = []
    for task_id, group in sorted(by_task.items()):
        humans = [s for s in group if _is_human(s)]
        ais = [s for s in group if not _is_human(s)]
        if not humans or not ais:
            continue
        h_counts = _category_counts(humans[0])
        ai_mean = statistics.fmean(_category_counts(s)["total"] for s in ais)
        matched.append({
            "task_id": task_id,
            "cwe": (humans[0].metadata or {}).get("cwe", ""),
            "human_total": h_counts["total"],
            "ai_samples": len(ais),
            "ai_mean_total": round(ai_mean, 3),
            "ai_minus_human": round(ai_mean - h_counts["total"], 3),
        })
    _write_csv(out_dir / "rq2_matched_tasks.csv", matched)

    summary: Dict[str, dict] = {}
    for row in agg_rows:
        g = row["group"]
        bucket = summary.setdefault(g, {"group": g, "sources": 0, "mean_total": 0.0})
        bucket["sources"] += 1
        bucket["mean_total"] += row["mean_total"]
    out = []
    for g, bucket in summary.items():
        bucket["mean_total"] = round(bucket["mean_total"] / bucket["sources"], 3) if bucket["sources"] else 0.0
        out.append(bucket)
    _write_csv(out_dir / "rq2_ai_vs_human.csv", out)
    return out


def rq3_energy(
    samples: List[CorpusSample],
    out_dir: Path,
    runs: int,
    max_dynamic: Optional[int],
    energy_backend: str,
) -> List[dict]:
    rows = []
    measured = 0
    for s in samples:
        if max_dynamic is not None and measured >= max_dynamic:
            break
        probe = measure_code(s.code, energy_backend=energy_backend)
        if not probe.get("ok"):
            continue
        result = measure_repeated(s.code, runs=runs, warmup=1, energy_backend=energy_backend)
        measured += 1
        scan = Scanner().scan_source(s.code)
        has_perf = any(f.category == Category.PERFORMANCE for f in scan.findings)
        energy = result.stats.get("energy_joules_estimate")
        wall = result.stats.get("wall_time_seconds")
        rows.append({
            "id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "has_perf_finding": has_perf,
            "backend": result.backend,
            "energy_mean": energy.mean if energy else None,
            "energy_ci95_low": energy.ci95_low if energy else None,
            "energy_ci95_high": energy.ci95_high if energy else None,
            "wall_mean": wall.mean if wall else None,
        })
    _write_csv(out_dir / "rq3_energy.csv", rows)

    with_perf = [r["energy_mean"] for r in rows if r["has_perf_finding"] and r["energy_mean"] is not None]
    without_perf = [r["energy_mean"] for r in rows if not r["has_perf_finding"] and r["energy_mean"] is not None]
    corr = {
        "n_with_perf_finding": len(with_perf),
        "n_without_perf_finding": len(without_perf),
        "mean_energy_with_perf": round(statistics.fmean(with_perf), 6) if with_perf else None,
        "mean_energy_without_perf": round(statistics.fmean(without_perf), 6) if without_perf else None,
    }
    _write_csv(out_dir / "rq3_correlation.csv", [corr])
    return rows


def _compare_sample(s: CorpusSample, run_dynamic: bool, energy_backend: str) -> dict:
    meta = s.metadata or {}
    kwargs = {
        "run_dynamic": run_dynamic,
        "energy_backend": energy_backend,
    }
    if meta.get("test_path") and meta.get("task_stem"):
        kwargs["cweval_task_stem"] = meta["task_stem"]
        kwargs["cweval_test_path"] = meta["test_path"]
    elif s.tests:
        kwargs["tests"] = s.tests
    return compare_fix(s.code, **kwargs)


def rq4_repair(
    samples: List[CorpusSample],
    out_dir: Path,
    energy_backend: str,
    run_dynamic: bool,
    ai_only: bool,
) -> List[dict]:
    rows = []
    for s in samples:
        if ai_only and _is_human(s):
            continue
        report = _compare_sample(s, run_dynamic, energy_backend)
        fix = report["fix"]
        perf = report.get("performance") or {}
        energy_delta = None
        if isinstance(perf, dict) and isinstance(perf.get("energy_joules_estimate"), dict):
            energy_delta = perf["energy_joules_estimate"].get("pct_change")
        tests_block = report.get("tests") or {}
        meta = s.metadata or {}
        rows.append({
            "id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "cwe": meta.get("cwe", ""),
            "changed": fix["changed"],
            "findings_before": fix["findings_before"],
            "findings_after": fix["findings_after"],
            "findings_removed": report["security"]["findings_removed"],
            "n_fixes": len(fix["applied"]),
            "behavior_preserved_stdout": report.get("behavior_preserved"),
            "cweval_functional_before": tests_block.get("cweval_functional_before"),
            "cweval_secure_before": tests_block.get("cweval_secure_before"),
            "cweval_functional_after": tests_block.get("cweval_functional_after"),
            "cweval_secure_after": tests_block.get("cweval_secure_after"),
            "behavior_verified": tests_block.get("behavior_verified"),
            "energy_pct_change": energy_delta,
        })
    _write_csv(out_dir / "rq4_repair.csv", rows)
    return rows


def rq5_baselines(
    samples: List[CorpusSample],
    out_dir: Path,
    ai_only: bool,
    scope_cwes: bool,
) -> List[dict]:
    per_sample, aggregate, _pr = evaluate_corpus(
        samples, ai_only=ai_only, scope_cwes=scope_cwes
    )
    _write_csv(out_dir / "rq5_per_sample.csv", per_sample)
    _write_csv(out_dir / "rq5_baselines.csv", aggregate)

    from experiments.run_baselines import rq5_outcomes

    outcomes = rq5_outcomes(samples, ai_only=ai_only)
    _write_csv(out_dir / "rq5_static_vs_oracle.csv", outcomes)
    return aggregate


def _maybe_plot(out_dir: Path, rq1_by_source: List[dict], rq4_rows: List[dict]) -> bool:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return False

    plots = out_dir / "plots"
    plots.mkdir(parents=True, exist_ok=True)

    if rq1_by_source:
        sources = [r["source"] for r in rq1_by_source]
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(sources, [r["mean_total"] for r in rq1_by_source])
        ax.set_ylabel("Mean findings per sample")
        ax.set_title("RQ1: Mean issues by source")
        plt.xticks(rotation=30, ha="right")
        fig.tight_layout()
        fig.savefig(plots / "rq1_by_source.png", dpi=120)
        plt.close(fig)

    removed = [r["findings_removed"] for r in rq4_rows if r.get("findings_removed") is not None]
    if removed:
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(removed, bins=range(0, max(removed) + 2))
        ax.set_xlabel("Findings removed by auto-fix")
        ax.set_ylabel("Samples")
        ax.set_title("RQ4: Repair effectiveness")
        fig.tight_layout()
        fig.savefig(plots / "rq4_repair.png", dpi=120)
        plt.close(fig)
    return True


def _write_methods(
    out_dir: Path,
    env: dict,
    n_samples: int,
    runs: int,
    tools: List[str],
    scope_cwes: bool,
) -> None:
    scoped = sorted(supported_cwes()) if scope_cwes else []
    text = f"""# Methods and Threats to Validity

## Environment
- Platform: {env.get('platform')}
- Processor: {env.get('processor')}
- Python: {env.get('python_version')}
- CPU count: {env.get('cpu_count')}

## Measurement protocol
- Corpus size: {n_samples} samples
- Energy/time repetitions per sample: {runs} (plus warm-up runs discarded)
- Statistics: mean with 95% CI; variant comparisons use Mann-Whitney U with
  Cliff's delta effect size (see experiments/measure.py).
- Baseline tools available this run: {', '.join(tools)}
- CWE-scoped metrics: {scope_cwes}
- Scoped CWE set ({len(scoped)}): {', '.join(scoped)}

## Threats to validity
- Energy backend: results use the most credible available backend; on this
  machine that may be a CPU-time proxy rather than RAPL. Re-run on Linux with
  `--energy-backend rapl` for hardware-counter energy.
- Profiler overhead is excluded from energy numbers by using the sandbox
  "measure" mode (no sys.setprofile).
- Single language (Python) and bounded task suites limit generalizability.
- LLM-generated samples depend on model/version and prompt phrasing.
- CWEval includes CWE classes outside VibeGuard rule coverage; RQ5 uses scoped
  CWE intersection for fair static-tool comparison.
"""
    (out_dir / "METHODS.md").write_text(text, encoding="utf-8")


def load_study_corpus(corpus_path: Optional[str], limit: Optional[int]) -> List[CorpusSample]:
    if corpus_path:
        return read_corpus(corpus_path)
    return load_security_benchmark() + load_humaneval(limit=limit or 3)


def build_default_cweval_study_corpus(out_path: Path, limit: Optional[int] = None) -> Path:
    """Merge human references + synthetic insecure AI samples for offline study."""
    refs = load_cweval(limit=limit)
    from corpus.loaders.cweval_synthetic import load_cweval_synthetic_insecure

    synth = load_cweval_synthetic_insecure(limit=limit)
    ref_by_task = {s.task_id: s for s in refs}
    for s in synth:
        ref = ref_by_task.get(s.task_id)
        if ref:
            s.prompt = ref.prompt
    write_corpus(refs + synth, out_path)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VibeGuard empirical study (RQ1-RQ5).")
    parser.add_argument("--corpus", default=None, help="Corpus JSONL (default: offline built-in).")
    parser.add_argument(
        "--cweval-study",
        action="store_true",
        help="Build CWEval ref + synthetic insecure corpus and run study on it.",
    )
    parser.add_argument("--out-dir", default="results", help="Output directory.")
    parser.add_argument("--runs", type=int, default=5, help="Energy repetitions per sample (RQ3).")
    parser.add_argument("--max-dynamic", type=int, default=8, help="Max samples to profile for energy.")
    parser.add_argument("--energy-backend", default="auto")
    parser.add_argument("--no-dynamic", action="store_true", help="Skip energy/profiling phases.")
    parser.add_argument(
        "--skip-energy",
        action="store_true",
        help="Run repair and CWEval tests but skip RQ3 energy measurements.",
    )
    parser.add_argument("--include-references", action="store_true", help="Include human refs in RQ4/RQ5.")
    parser.add_argument("--no-scope", action="store_true", help="Disable CWE scoping in RQ5.")
    parser.add_argument("--limit", type=int, default=None, help="Limit task datasets in offline default.")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    ai_only = not args.include_references
    scope_cwes = not args.no_scope

    if args.cweval_study:
        corpus_path = out_dir / "cweval_study_corpus.jsonl"
        build_default_cweval_study_corpus(corpus_path, limit=args.limit)
        samples = read_corpus(corpus_path)
    else:
        samples = load_study_corpus(args.corpus, args.limit)

    run_dynamic = not args.no_dynamic
    repair_dynamic = run_dynamic or args.skip_energy
    measure_energy = run_dynamic and not args.skip_energy
    from experiments.baselines import available_tools

    rq1 = rq1_prevalence(samples, out_dir)
    rq2 = rq2_ai_vs_human(samples, out_dir)
    rq3 = (
        rq3_energy(samples, out_dir, args.runs, args.max_dynamic, args.energy_backend)
        if measure_energy
        else []
    )
    rq4 = rq4_repair(samples, out_dir, args.energy_backend, repair_dynamic, ai_only=ai_only)
    rq5 = rq5_baselines(samples, out_dir, ai_only=ai_only, scope_cwes=scope_cwes)

    plotted = _maybe_plot(out_dir, rq1, rq4)
    env = environment_metadata()
    _write_methods(out_dir, env, len(samples), args.runs, available_tools(), scope_cwes)

    summary = {
        "samples": len(samples),
        "ai_only_rq4_rq5": ai_only,
        "scoped_cwes": scope_cwes,
        "rq1_by_source": rq1,
        "rq2_ai_vs_human": rq2,
        "rq3_energy_rows": len(rq3),
        "rq4_repaired": sum(1 for r in rq4 if r["changed"]),
        "rq5_baselines": rq5,
        "plots_written": plotted,
        "environment": env,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Study complete. Artifacts written to {out_dir}/")
    print(f"  samples={len(samples)} repaired={summary['rq4_repaired']} plots={'yes' if plotted else 'no'}")


if __name__ == "__main__":
    main()
