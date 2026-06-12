"""RQ-SALLM: Full precision/recall/F1 study on the SALLM dataset.

Loads dataset/sallm/dataset.jsonl (100 known-insecure Python samples),
runs VibeGuard and Bandit in CWE space, and writes results to
results/sallm_baselines/.

Usage:
    python -m experiments.run_sallm_baselines [--out-dir results/sallm_baselines]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

# ── helpers ──────────────────────────────────────────────────────────────────

_CWE_RE = re.compile(r"cwe[-_]?(\d+)", re.IGNORECASE)


def _cwe_from_id(sample_id: str) -> Optional[str]:
    m = _CWE_RE.search(sample_id)
    return f"CWE-{int(m.group(1))}" if m else None


@dataclass
class SallmSample:
    id: str
    task_id: str
    source: str
    code: str
    expected_security_labels: List[str]

    @property
    def cwe(self) -> Optional[str]:
        return _cwe_from_id(self.id)


def load_sallm(path: Path) -> List[SallmSample]:
    samples = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cwe = _cwe_from_id(r["id"])
        samples.append(SallmSample(
            id=r["id"],
            task_id=r["id"],
            source=r.get("source", "sallm"),
            code=r["insecure_code"],
            expected_security_labels=[cwe] if cwe else [],
        ))
    return samples


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sallm-path", default="dataset/sallm/dataset.jsonl")
    parser.add_argument("--out-dir", default="results/sallm_baselines")
    parser.add_argument("--no-scope", action="store_true",
                        help="Evaluate across all CWEs, not just VibeGuard-covered ones")
    args = parser.parse_args()

    sallm_path = Path(args.sallm_path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not sallm_path.exists():
        print(f"ERROR: SALLM dataset not found at {sallm_path}", file=sys.stderr)
        sys.exit(1)

    from experiments.baselines import (
        available_tools, evaluate_sample, security_precision_recall,
        labels_to_cwes, SECURITY_TOOLS,
    )
    from experiments.cwe_scoping import supported_cwes

    samples = load_sallm(sallm_path)
    print(f"Loaded {len(samples)} SALLM samples")

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
        if (i + 1) % 20 == 0:
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
        fieldnames = list(per_sample_rows[0].keys())
        with per_sample_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(per_sample_rows)

    # ── Baselines CSV ─────────────────────────────────────────────────────────
    aggregate = []
    for m in pr.values():
        row = m.to_dict()
        row["dataset"] = "sallm"
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
    from collections import defaultdict
    cwe_stats: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))
    for s, gt, runs in zip(samples, all_gts, all_runs):
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
        "dataset": "sallm",
        "n_samples": len(samples),
        "scope": scope_label,
        "results": aggregate,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── Print results ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"SALLM Baseline Results ({scope_label})")
    print(f"{'='*60}")
    print(f"{'Tool':<15} {'TP':>5} {'FP':>5} {'FN':>5} {'P':>7} {'R':>7} {'F1':>7}")
    print("-" * 60)
    for row in aggregate:
        print(f"{row['tool']:<15} {row['tp']:>5} {row['fp']:>5} {row['fn']:>5} "
              f"{row['precision']:>7.3f} {row['recall']:>7.3f} {row['f1']:>7.3f}")

    print(f"\nDetection rate: {sum(1 for g in all_gts if g) } samples with scoped CWE labels")
    vg_pr = pr.get("vibeguard")
    if vg_pr:
        detected = sum(1 for g, r in zip(all_gts, all_runs)
                      if g and r.get("vibeguard") and r["vibeguard"].cwes & g)
        print(f"VibeGuard detected at least one CWE: {detected}/{len(samples)}")

    print(f"\nArtifacts written to {out_dir}/")
    print(f"  {per_sample_path.name}  — per-sample tool runs")
    print(f"  {baselines_path.name}   — aggregate P/R/F1")
    print(f"  {per_cwe_path.name}     — per-CWE breakdown")
    print(f"  summary.json")


if __name__ == "__main__":
    main()
