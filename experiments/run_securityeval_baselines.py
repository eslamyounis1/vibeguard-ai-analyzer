"""RQ-SecurityEval: Full precision/recall/F1 study on the SecurityEval dataset.

Loads SecurityEval (121 known-insecure Python samples, 69 CWE classes) from
HuggingFace, runs VibeGuard and Bandit in CWE space, writes results to
results/securityeval_baselines/.

Usage:
    python -m experiments.run_securityeval_baselines [--out-dir results/securityeval_baselines]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def _cwe_from_id(sample_id: str) -> Optional[str]:
    m = _CWE_RE.search(sample_id)
    if not m:
        return None
    # normalise: strip leading zeros in number part
    raw = m.group(1)
    num = int(raw.split("-")[1])
    return f"CWE-{num}"


@dataclass
class SEvalSample:
    id: str
    task_id: str
    source: str
    code: str
    expected_security_labels: List[str]


def load_securityeval() -> List[SEvalSample]:
    import datasets
    ds = datasets.load_dataset("s2e-lab/SecurityEval", split="train")
    samples = []
    for r in ds:
        cwe = _cwe_from_id(r["ID"])
        samples.append(SEvalSample(
            id=r["ID"],
            task_id=r["ID"],
            source="securityeval",
            code=r["Insecure_code"],
            expected_security_labels=[cwe] if cwe else [],
        ))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="results/securityeval_baselines")
    parser.add_argument("--no-scope", action="store_true",
                        help="Evaluate across all CWEs, not just VibeGuard-covered ones")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from experiments.baselines import (
        available_tools, evaluate_sample, security_precision_recall,
        labels_to_cwes, SECURITY_TOOLS,
    )
    from experiments.cwe_scoping import supported_cwes

    samples = load_securityeval()
    print(f"Loaded {len(samples)} SecurityEval samples")

    scope = None if args.no_scope else supported_cwes()
    scope_label = "all CWEs" if scope is None else f"{len(scope)} VibeGuard-covered CWEs"
    print(f"Scope: {scope_label}")

    tools = available_tools()
    sec_tools = tuple(t for t in SECURITY_TOOLS if t in tools)
    print(f"Tools: {tools}")

    per_sample_rows: list[dict] = []
    all_gts: list[Set[str]] = []
    all_runs: list[dict] = []

    for i, s in enumerate(samples):
        if (i + 1) % 30 == 0:
            print(f"  [{i+1}/{len(samples)}] {s.id}")
        rows, runs = evaluate_sample(
            s.id, s.task_id, s.source, s.code, s.expected_security_labels,
            tools=tools, scope_to=scope,
        )
        per_sample_rows.extend(rows)
        gt = labels_to_cwes(s.expected_security_labels)
        if scope:
            gt = gt & scope
        all_gts.append(gt)
        all_runs.append({t: runs[t] for t in sec_tools if t in runs})

    # Aggregate P/R/F1
    pr = security_precision_recall(all_gts, all_runs, tools=sec_tools, scope_to=scope)

    # ── Per-sample CSV ────────────────────────────────────────────────────────
    per_sample_path = out_dir / "per_sample.csv"
    if per_sample_rows:
        with per_sample_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(per_sample_rows[0].keys()))
            writer.writeheader()
            writer.writerows(per_sample_rows)

    # ── Baselines CSV ─────────────────────────────────────────────────────────
    aggregate = []
    for m in pr.values():
        row = m.to_dict()
        row["dataset"] = "securityeval"
        row["n_samples"] = len(samples)
        row["scoped_to_vibeguard_cwes"] = scope is not None
        row["n_scoped_cwes"] = len(scope) if scope else "all"
        aggregate.append(row)

    baselines_path = out_dir / "baselines.csv"
    with baselines_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(aggregate[0].keys()))
        writer.writeheader()
        writer.writerows(aggregate)

    # ── Per-CWE breakdown ─────────────────────────────────────────────────────
    cwe_stats: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))
    for gt, runs in zip(all_gts, all_runs):
        if not gt:
            continue
        for tool in sec_tools:
            run = runs.get(tool)
            detected = run.cwes if (run and run.ok) else set()
            if scope:
                detected = detected & scope
            for cwe in gt:
                if cwe in detected:
                    cwe_stats[cwe][tool]["tp"] += 1
                else:
                    cwe_stats[cwe][tool]["fn"] += 1
            for cwe in detected - gt:
                cwe_stats[cwe][tool]["fp"] += 1

    per_cwe_rows = []
    for cwe in sorted(cwe_stats):
        for tool in sec_tools:
            s = cwe_stats[cwe][tool]
            tp, fp, fn = s["tp"], s["fp"], s["fn"]
            p = tp / (tp + fp) if (tp + fp) else 0.0
            r = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * p * r / (p + r) if (p + r) else 0.0
            per_cwe_rows.append({
                "cwe": cwe, "tool": tool,
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(p, 3),
                "recall": round(r, 3),
                "f1": round(f1, 3),
            })

    per_cwe_path = out_dir / "per_cwe.csv"
    if per_cwe_rows:
        with per_cwe_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(per_cwe_rows[0].keys()))
            writer.writeheader()
            writer.writerows(per_cwe_rows)

    # ── Summary JSON ──────────────────────────────────────────────────────────
    summary = {
        "dataset": "securityeval",
        "n_samples": len(samples),
        "scope": scope_label,
        "results": aggregate,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── Print results ─────────────────────────────────────────────────────────
    in_scope = sum(1 for g in all_gts if g)
    print(f"\n{'='*60}")
    print(f"SecurityEval Baseline Results ({scope_label})")
    print(f"{'='*60}")
    print(f"{'Tool':<15} {'TP':>5} {'FP':>5} {'FN':>5} {'P':>7} {'R':>7} {'F1':>7}")
    print("-" * 60)
    for row in aggregate:
        print(f"{row['tool']:<15} {row['tp']:>5} {row['fp']:>5} {row['fn']:>5} "
              f"{row['precision']:>7.3f} {row['recall']:>7.3f} {row['f1']:>7.3f}")

    print(f"\nSamples with in-scope CWE label: {in_scope}/{len(samples)}")
    vg_pr = pr.get("vibeguard")
    if vg_pr:
        detected = sum(1 for g, r in zip(all_gts, all_runs)
                       if g and r.get("vibeguard") and r["vibeguard"].cwes & g)
        print(f"VibeGuard detected at least one CWE: {detected}/{len(samples)}")

    print(f"\nTop VibeGuard per-CWE results:")
    vg_cwe = [r for r in per_cwe_rows if r["tool"] == "vibeguard"
              and (r["tp"] + r["fp"] + r["fn"]) > 0]
    vg_cwe.sort(key=lambda r: (-r["tp"], r["cwe"]))
    print(f"  {'CWE':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'F1':>6}")
    for r in vg_cwe[:15]:
        print(f"  {r['cwe']:<12} {r['tp']:>4} {r['fp']:>4} {r['fn']:>4} {r['f1']:>6.2f}")

    print(f"\nArtifacts written to {out_dir}/")


if __name__ == "__main__":
    main()
