"""Run baseline tool comparison over a study corpus (RQ5).

Examples:
    python -m experiments.run_baselines --corpus data/corpus/cweval_ai.jsonl
    python -m experiments.run_baselines --corpus data/corpus/cweval_ref.jsonl \\
        --include-references --out-dir results/baselines_ref
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

from corpus.schema import read_corpus
from experiments.baselines import available_tools, evaluate_corpus
from experiments.cwe_scoping import supported_cwes
from experiments.cweval_runner import run_cweval_tests
from experiments.measure import environment_metadata


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


def rq5_outcomes(samples, ai_only: bool = True) -> List[dict]:
    """Compare static CWE detection vs CWEval security-test outcomes."""
    rows = []
    for s in samples:
        if ai_only and s.source == "human":
            continue
        meta = s.metadata or {}
        test_path = meta.get("test_path")
        task_stem = meta.get("task_stem")
        if not test_path or not task_stem:
            continue
        from experiments.baselines import run_vibeguard, labels_to_cwes
        from experiments.cwe_scoping import in_scope_cwe

        vg = run_vibeguard(s.code)
        detected = vg.cwes
        gt = labels_to_cwes(s.expected_security_labels)
        oracle = run_cweval_tests(s.code, task_stem, test_path)
        scoped_gt = {c for c in gt if in_scope_cwe(c)}
        scoped_detected = detected & supported_cwes()
        rows.append({
            "sample_id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "expected_cwe": meta.get("cwe") or (sorted(gt)[0] if gt else ""),
            "in_scope": bool(scoped_gt),
            "static_detected_cwes": ";".join(sorted(scoped_detected)),
            "cweval_functional": oracle.functional,
            "cweval_secure": oracle.secure,
            "static_tp": bool(scoped_detected & scoped_gt),
            "static_fp": bool(scoped_detected - scoped_gt),
            "static_fn": bool(scoped_gt - scoped_detected),
            "outcome_secure": oracle.secure,
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run baseline comparison (RQ5).")
    parser.add_argument("--corpus", required=True, help="Corpus JSONL path.")
    parser.add_argument("--out-dir", default="results/baselines", help="Output directory.")
    parser.add_argument(
        "--include-references",
        action="store_true",
        help="Include human reference samples (default: AI/synthetic only).",
    )
    parser.add_argument(
        "--no-scope",
        action="store_true",
        help="Do not restrict metrics to VibeGuard-supported CWEs.",
    )
    parser.add_argument("--tools", nargs="*", default=None, help="Tools to run (default: all available).")
    args = parser.parse_args()

    samples = read_corpus(args.corpus)
    ai_only = not args.include_references
    tools = args.tools or available_tools()

    out_dir = Path(args.out_dir)
    per_sample, aggregate, _pr = evaluate_corpus(
        samples,
        tools=tools,
        ai_only=ai_only,
        scope_cwes=not args.no_scope,
    )
    outcomes = rq5_outcomes(samples, ai_only=ai_only)

    _write_csv(out_dir / "rq5_per_sample.csv", per_sample)
    _write_csv(out_dir / "rq5_baselines.csv", aggregate)
    _write_csv(out_dir / "rq5_static_vs_oracle.csv", outcomes)

    summary = {
        "corpus": args.corpus,
        "n_samples_evaluated": len({r["sample_id"] for r in per_sample}) if per_sample else 0,
        "tools": tools,
        "ai_only": ai_only,
        "scoped_cwes": not args.no_scope,
        "supported_cwes": sorted(supported_cwes()),
        "aggregate": aggregate,
        "n_outcome_rows": len(outcomes),
        "environment": environment_metadata(),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Baselines written to {out_dir}/")
    print(f"  samples={summary['n_samples_evaluated']} tools={tools}")
    for row in aggregate:
        print(f"  {row['tool']}: P={row['precision']} R={row['recall']} F1={row['f1']}")


if __name__ == "__main__":
    main()
