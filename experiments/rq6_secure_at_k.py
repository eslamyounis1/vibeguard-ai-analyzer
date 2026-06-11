"""RQ6: Secure@k and Vulnerable@k evaluation.

Compares:
- VibeGuard-detected vulnerable@k  (static finding present)
- CWEval oracle vulnerable@k       (oracle security test fails)
- secure@k                          (functional + no finding)
- fix_rate@k                        (LLM fixer resolved finding)

Outputs:
  rq6_secure_at_k.csv     — per-model metrics table
  rq6_per_sample.csv      — per-sample detail

Usage:
    python -m experiments.rq6_secure_at_k \\
        --corpus data/corpus/cweval_multi_openai.jsonl \\
        --out results/study_openai/rq6_secure_at_k.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from corpus.schema import read_corpus, CorpusSample
from experiments.metrics import compute_metrics_per_model
from security.core.scanner import Scanner
from security.models.finding import Category


def _has_security_finding(sample: CorpusSample) -> bool:
    result = Scanner().scan_source(sample.code)
    return any(f.category == Category.SECURITY for f in result.findings)


def _is_oracle_secure(sample: CorpusSample) -> bool:
    meta = sample.metadata or {}
    # cweval_secure_before is True when the oracle's security tests pass
    secure = meta.get("cweval_secure_before")
    if secure is not None:
        return bool(secure)
    return not _has_security_finding(sample)


def _is_functional(sample: CorpusSample) -> bool:
    meta = sample.metadata or {}
    functional = meta.get("cweval_functional_before")
    if functional is not None:
        return bool(functional)
    return True  # Unknown → assume functional


def _load_llm_repair_results(repair_dir: Optional[Path]) -> Dict[str, bool]:
    """Load per-sample LLM fix result from rq4_llm_repair.csv if available."""
    if repair_dir is None:
        return {}
    csv_path = repair_dir / "rq4_llm_repair.csv"
    if not csv_path.exists():
        return {}
    fixed: Dict[str, bool] = {}
    with csv_path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            sample_id = row.get("id", "")
            # A sample is "fixed" if findings_after < findings_before and oracle_secure_after is True
            findings_before = int(row.get("findings_before", 0) or 0)
            findings_after = int(row.get("findings_after", 0) or 0)
            oracle_after = row.get("cweval_secure_after", "")
            fixed[sample_id] = findings_after < findings_before or oracle_after == "True"
    return fixed


def _write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run_rq6(
    corpus_path: str,
    out_dir: Path,
    repair_dir: Optional[Path] = None,
    k_values: tuple = (1, 5, 10),
) -> List[dict]:
    samples = read_corpus(corpus_path)
    # Filter to AI-generated only (exclude human references)
    ai_samples = [s for s in samples if s.source != "human" and not s.source.startswith("human")]

    llm_fixed = _load_llm_repair_results(repair_dir)

    per_sample_rows = []
    for s in ai_samples:
        has_finding = _has_security_finding(s)
        functional = _is_functional(s)
        oracle_secure = _is_oracle_secure(s)
        is_secure = functional and not has_finding
        is_fixed = llm_fixed.get(s.id, False)

        meta = s.metadata or {}
        per_sample_rows.append({
            "id": s.id,
            "task_id": s.task_id,
            "source": s.source,
            "cwe": meta.get("cwe", ""),
            "has_finding": has_finding,
            "functional": functional,
            "oracle_secure": oracle_secure,
            "is_secure": is_secure,
            "llm_fixed": is_fixed,
        })

    _write_csv(out_dir / "rq6_per_sample.csv", per_sample_rows)

    # Compute per-model aggregate metrics
    agg = compute_metrics_per_model(
        per_sample_rows,
        model_key="source",
        k_values=k_values,
        vuln_key="has_finding",
        secure_key="is_secure",
        fixed_key="llm_fixed" if llm_fixed else None,
    )
    _write_csv(out_dir / "rq6_secure_at_k.csv", agg)

    # Also compute oracle-based vulnerable@k for comparison
    oracle_rows = compute_metrics_per_model(
        per_sample_rows,
        model_key="source",
        k_values=k_values,
        vuln_key="has_finding",
        secure_key="oracle_secure",
    )
    _write_csv(out_dir / "rq6_oracle_comparison.csv", oracle_rows)

    print(f"\nRQ6 — Secure@k / Vulnerable@k")
    print(f"{'Model':<20} {'n':>4} {'vuln@1':>7} {'vuln@5':>7} {'secure@1':>9} {'secure@5':>9}")
    print("-" * 60)
    for row in agg:
        model = row.get("source", "?")
        print(
            f"{model:<20} {row.get('n', 0):>4} "
            f"{row.get('vulnerable@1', 0):>7.3f} {row.get('vulnerable@5', 0):>7.3f} "
            f"{row.get('secure@1', 0):>9.3f} {row.get('secure@5', 0):>9.3f}"
        )
    return agg


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ6: secure@k and vulnerable@k metrics")
    parser.add_argument("--corpus", required=True, help="Corpus JSONL path")
    parser.add_argument("--out", default="results/study_openai", help="Output directory")
    parser.add_argument("--repair-dir", default=None, help="Directory with rq4_llm_repair.csv")
    parser.add_argument("--k", nargs="+", type=int, default=[1, 5, 10], help="k values")
    args = parser.parse_args()

    out_dir = Path(args.out)
    repair_dir = Path(args.repair_dir) if args.repair_dir else None
    run_rq6(args.corpus, out_dir, repair_dir=repair_dir, k_values=tuple(args.k))
    print(f"\nResults written to {out_dir}/rq6_*.csv")


if __name__ == "__main__":
    main()
