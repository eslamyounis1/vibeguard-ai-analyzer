"""EvalPlus Finding Prevalence Study.

Runs VibeGuard over HumanEval+ canonical solutions (164 problems) and
reports mean findings per sample by category — an RQ1-style analysis on
general-purpose LLM-generated code (no security labels).

Usage:
    python -m experiments.run_evalplus_prevalence [--out-dir results/evalplus_prevalence]
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from security.core.scanner import Scanner


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="results/evalplus_prevalence")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from evalplus.data import get_human_eval_plus
    problems = get_human_eval_plus()
    print(f"HumanEval+: {len(problems)} problems")

    scanner = Scanner()
    per_sample_rows = []
    totals: dict[str, list] = defaultdict(list)

    for task_id, prob in problems.items():
        code = prob["prompt"] + prob["canonical_solution"]
        result = scanner.scan_source(code)

        n_sec = sum(1 for f in result.findings if f.category.value == "SECURITY")
        n_smell = sum(1 for f in result.findings if f.category.value == "CODE_SMELL")
        n_perf = sum(1 for f in result.findings if f.category.value == "PERFORMANCE")
        n_total = len(result.findings)

        per_sample_rows.append({
            "task_id": task_id,
            "n_security": n_sec,
            "n_smell": n_smell,
            "n_performance": n_perf,
            "n_total": n_total,
            "has_any": int(n_total > 0),
            "rules_fired": ";".join(sorted({f.rule_id for f in result.findings})),
        })
        totals["security"].append(n_sec)
        totals["smell"].append(n_smell)
        totals["performance"].append(n_perf)
        totals["total"].append(n_total)

    n = len(per_sample_rows)
    mean_sec = sum(totals["security"]) / n
    mean_smell = sum(totals["smell"]) / n
    mean_perf = sum(totals["performance"]) / n
    mean_total = sum(totals["total"]) / n
    pct_any = 100 * sum(r["has_any"] for r in per_sample_rows) / n

    # Rule frequency
    from collections import Counter
    rule_freq: Counter = Counter()
    for r in per_sample_rows:
        for rule in r["rules_fired"].split(";"):
            if rule:
                rule_freq[rule] += 1

    # ── Write artifacts ───────────────────────────────────────────────────────
    per_sample_path = out_dir / "per_sample.csv"
    with per_sample_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(per_sample_rows[0].keys()))
        writer.writeheader()
        writer.writerows(per_sample_rows)

    summary = {
        "dataset": "HumanEval+",
        "n_problems": n,
        "source": "canonical_solution",
        "mean_security": round(mean_sec, 3),
        "mean_code_smell": round(mean_smell, 3),
        "mean_performance": round(mean_perf, 3),
        "mean_total": round(mean_total, 3),
        "pct_with_any_finding": round(pct_any, 1),
        "top_rules": rule_freq.most_common(10),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    rule_rows = [{"rule_id": r, "n_samples": c, "pct": round(100*c/n, 1)}
                 for r, c in rule_freq.most_common()]
    rule_path = out_dir / "rule_freq.csv"
    if rule_rows:
        with rule_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["rule_id", "n_samples", "pct"])
            writer.writeheader()
            writer.writerows(rule_rows)

    # ── Print ─────────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"EvalPlus (HumanEval+) Finding Prevalence — {n} problems")
    print(f"{'='*60}")
    print(f"  Mean security findings/sample : {mean_sec:.3f}")
    print(f"  Mean code smell findings/sample: {mean_smell:.3f}")
    print(f"  Mean performance findings/sample: {mean_perf:.3f}")
    print(f"  Mean total findings/sample    : {mean_total:.3f}")
    print(f"  % samples with any finding    : {pct_any:.1f}%")
    print(f"\nTop rules fired:")
    for rule, count in rule_freq.most_common(10):
        print(f"  {rule:<40} {count:>4} samples ({100*count/n:.1f}%)")
    print(f"\nArtifacts written to {out_dir}/")


if __name__ == "__main__":
    main()
