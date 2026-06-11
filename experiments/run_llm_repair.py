"""RQ4-LLM: Deterministic vs LLM-powered auto-fix on the CWEval AI corpus.

For each AI-generated sample in the corpus this script:
  1. Runs the deterministic fixer  (fixers.engine.fix_source)
  2. Runs the LLM fixer             (fixers.llm_fixer.llm_fix_source)
  3. Executes the CWEval functional and security oracles on every fixed version
  4. Writes per-sample and aggregate comparison CSVs

Usage
-----
    python -m experiments.run_llm_repair \\
        --corpus data/corpus/cweval_multi_openai.jsonl \\
        --out-dir results/llm_repair \\
        --model gpt-4o-mini

The LLM calls are cached under data/cache/llm_fix/ so re-running is free.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional

from corpus.schema import CorpusSample, read_corpus
from experiments.cweval_runner import run_cweval_tests
from fixers.engine import fix_source
from fixers.llm_fixer import llm_fix_source
from security.core.scanner import Scanner


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_human(s: CorpusSample) -> bool:
    return s.source == "human" or s.source.startswith("human")


def _security_finding_count(code: str) -> int:
    result = Scanner().scan_source(code)
    return sum(1 for f in result.findings if getattr(f, "cwe", None) is not None)


def _run_oracle(code: str, meta: dict) -> dict:
    test_path = meta.get("test_path")
    task_stem = meta.get("task_stem")
    if not test_path or not task_stem:
        return {"functional": None, "secure": None, "available": False}
    r = run_cweval_tests(code, task_stem, test_path)
    return {"functional": r.functional, "secure": r.secure, "available": True}


def _write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# per-sample repair
# ---------------------------------------------------------------------------

def _process_sample(
    s: CorpusSample,
    model: str,
    cache_dir: str,
    use_cache: bool,
    run_oracle_tests: bool,
) -> dict:
    meta = s.metadata or {}
    code = s.code

    findings_before = _security_finding_count(code)

    # Oracle on original code
    orig_oracle = _run_oracle(code, meta) if run_oracle_tests else {"functional": None, "secure": None, "available": False}

    # --- Deterministic fixer ---
    det = fix_source(code)
    det_findings_after = _security_finding_count(det.fixed_code) if det.changed else findings_before
    if run_oracle_tests and det.changed:
        det_oracle = _run_oracle(det.fixed_code, meta)
    else:
        det_oracle = {"functional": orig_oracle.get("functional"), "secure": orig_oracle.get("secure"), "available": orig_oracle.get("available", False)}

    # --- LLM fixer ---
    llm = llm_fix_source(
        code,
        filename=s.id or "<sample>",
        model=model,
        cache_dir=cache_dir,
        use_cache=use_cache,
    )
    llm_findings_after = _security_finding_count(llm.fixed_code) if llm.changed else findings_before
    if run_oracle_tests and llm.changed and llm.safe:
        llm_oracle = _run_oracle(llm.fixed_code, meta)
    else:
        llm_oracle = {"functional": orig_oracle.get("functional"), "secure": orig_oracle.get("secure"), "available": orig_oracle.get("available", False)}

    return {
        "id": s.id,
        "task_id": s.task_id,
        "source": s.source,
        "cwe": meta.get("cwe", ""),
        # --- baseline ---
        "security_findings_before": findings_before,
        "oracle_functional_before": orig_oracle["functional"],
        "oracle_secure_before": orig_oracle["secure"],
        # --- deterministic fixer ---
        "det_changed": det.changed,
        "det_safe": det.safe,
        "det_findings_after": det_findings_after,
        "det_findings_removed": max(0, findings_before - det_findings_after),
        "det_oracle_functional": det_oracle["functional"],
        "det_oracle_secure": det_oracle["secure"],
        # --- LLM fixer ---
        "llm_changed": llm.changed,
        "llm_safe": llm.safe,
        "llm_note": llm.note or "",
        "llm_findings_after": llm_findings_after,
        "llm_findings_removed": max(0, findings_before - llm_findings_after),
        "llm_oracle_functional": llm_oracle["functional"],
        "llm_oracle_secure": llm_oracle["secure"],
    }


# ---------------------------------------------------------------------------
# aggregate summary
# ---------------------------------------------------------------------------

def _summarise(rows: List[dict]) -> dict:
    n = len(rows)
    if n == 0:
        return {}

    def _count(key, val=True):
        return sum(1 for r in rows if r.get(key) == val)

    def _mean(key):
        vals = [r[key] for r in rows if r.get(key) is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    # Security oracle improvements: secure_before=False → secure_after=True
    det_improved = sum(
        1 for r in rows
        if r["oracle_secure_before"] is False and r["det_oracle_secure"] is True
    )
    llm_improved = sum(
        1 for r in rows
        if r["oracle_secure_before"] is False and r["llm_oracle_secure"] is True
    )

    # Samples that were already secure (oracle_secure_before=True) — unchanged by either fixer
    already_secure = _count("oracle_secure_before", True)
    insecure_baseline = sum(1 for r in rows if r["oracle_secure_before"] is False)

    return {
        "n_samples": n,
        "n_with_security_findings": sum(1 for r in rows if r["security_findings_before"] > 0),
        "mean_findings_before": _mean("security_findings_before"),
        # Deterministic
        "det_n_changed": _count("det_changed", True),
        "det_pct_changed": round(100 * _count("det_changed", True) / n, 1),
        "det_mean_findings_removed": _mean("det_findings_removed"),
        "det_n_oracle_secure_improved": det_improved,
        "det_pct_oracle_improved": round(100 * det_improved / max(insecure_baseline, 1), 1),
        # LLM
        "llm_n_changed": _count("llm_changed", True),
        "llm_pct_changed": round(100 * _count("llm_changed", True) / n, 1),
        "llm_n_safe_changes": sum(1 for r in rows if r["llm_changed"] and r["llm_safe"]),
        "llm_mean_findings_removed": _mean("llm_findings_removed"),
        "llm_n_oracle_secure_improved": llm_improved,
        "llm_pct_oracle_improved": round(100 * llm_improved / max(insecure_baseline, 1), 1),
        # Context
        "n_already_secure_before": already_secure,
        "n_insecure_before": insecure_baseline,
        "model": rows[0].get("_model", ""),
    }


def _per_cwe_summary(rows: List[dict]) -> List[dict]:
    by_cwe: Dict[str, List[dict]] = {}
    for r in rows:
        cwe = r.get("cwe") or "(none)"
        by_cwe.setdefault(cwe, []).append(r)

    out = []
    for cwe, group in sorted(by_cwe.items()):
        n = len(group)
        det_imp = sum(1 for r in group if r["oracle_secure_before"] is False and r["det_oracle_secure"] is True)
        llm_imp = sum(1 for r in group if r["oracle_secure_before"] is False and r["llm_oracle_secure"] is True)
        insecure = sum(1 for r in group if r["oracle_secure_before"] is False)
        out.append({
            "cwe": cwe,
            "n_samples": n,
            "n_insecure_before": insecure,
            "det_changed": sum(1 for r in group if r["det_changed"]),
            "det_findings_removed_total": sum(r["det_findings_removed"] for r in group),
            "det_oracle_improved": det_imp,
            "llm_changed": sum(1 for r in group if r["llm_changed"]),
            "llm_safe_changes": sum(1 for r in group if r["llm_changed"] and r["llm_safe"]),
            "llm_findings_removed_total": sum(r["llm_findings_removed"] for r in group),
            "llm_oracle_improved": llm_imp,
        })
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare deterministic vs LLM auto-fix on the CWEval AI corpus."
    )
    parser.add_argument(
        "--corpus",
        default="data/corpus/cweval_multi_openai.jsonl",
        help="Path to corpus JSONL.",
    )
    parser.add_argument(
        "--out-dir",
        default="results/llm_repair",
        help="Output directory for CSV and JSON artifacts.",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model to use for LLM fixes (default: gpt-4o-mini).",
    )
    parser.add_argument(
        "--cache-dir",
        default="data/cache",
        help="Cache directory for LLM responses.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass cache and always call the API.",
    )
    parser.add_argument(
        "--skip-oracle",
        action="store_true",
        help="Skip CWEval oracle tests (faster, no pytest subprocess).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit to first N AI samples (for quick testing).",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    use_cache = not args.no_cache
    run_oracle = not args.skip_oracle

    # Fail fast if the API key is missing before processing all samples
    import os
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY is not set. Export it before running:")
        print("  export OPENAI_API_KEY='sk-...'")
        raise SystemExit(1)

    samples = [s for s in read_corpus(args.corpus) if not _is_human(s)]
    if args.limit:
        samples = samples[: args.limit]

    print(f"Processing {len(samples)} AI samples with model={args.model} …")

    rows: List[dict] = []
    for i, s in enumerate(samples, 1):
        print(f"  [{i:3d}/{len(samples)}] {s.id}", end=" ", flush=True)
        row = _process_sample(s, args.model, args.cache_dir, use_cache, run_oracle)
        row["_model"] = args.model
        rows.append(row)
        tag = ""
        if row["llm_changed"] and row["llm_safe"]:
            removed = row["llm_findings_removed"]
            improved = row["llm_oracle_secure"] is True and row["oracle_secure_before"] is False
            tag = f"✓ -{removed} findings" + (" +oracle" if improved else "")
        elif row["llm_changed"] and not row["llm_safe"]:
            tag = f"⚠ unsafe ({row['llm_note'][:60]})"
        elif not row["llm_changed"] and row["llm_note"]:
            tag = f"— {row['llm_note'][:60]}"
        else:
            tag = "— no change"
        print(tag)

    # Strip internal _model column before writing per-sample CSV
    csv_rows = [{k: v for k, v in r.items() if k != "_model"} for r in rows]
    _write_csv(out_dir / "per_sample.csv", csv_rows)

    summary = _summarise(rows)
    _write_csv(out_dir / "summary.csv", [summary])

    per_cwe = _per_cwe_summary(rows)
    _write_csv(out_dir / "per_cwe.csv", per_cwe)

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    print(f"\nResults written to {out_dir}/")
    print(f"\n{'='*60}")
    print(f"{'Metric':<40} {'Deterministic':>14} {'LLM (' + args.model + ')':>16}")
    print(f"{'='*60}")
    print(f"{'Samples processed':<40} {summary['n_samples']:>14}")
    print(f"{'Samples with security findings':<40} {summary['n_with_security_findings']:>14}")
    print(f"{'Changed (triggered)':<40} {summary['det_n_changed']:>14} {summary['llm_n_changed']:>16}")
    print(f"{'Trigger rate':<40} {summary['det_pct_changed']:>13}% {summary['llm_pct_changed']:>15}%")
    print(f"{'Mean findings removed':<40} {summary['det_mean_findings_removed'] or 0:>14} {summary['llm_mean_findings_removed'] or 0:>16}")
    print(f"{'Oracle security improved':<40} {summary['det_n_oracle_secure_improved']:>14} {summary['llm_n_oracle_secure_improved']:>16}")
    if summary.get("n_insecure_before", 0) > 0:
        print(f"{'  % of insecure samples fixed':<40} {summary['det_pct_oracle_improved']:>13}% {summary['llm_pct_oracle_improved']:>15}%")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
