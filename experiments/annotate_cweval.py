"""Annotate a CWEval corpus with sample-level behavioral oracle outcomes."""

from __future__ import annotations

import argparse
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from corpus.schema import CorpusSample, read_corpus, write_corpus
from experiments.cweval_runner import run_cweval_tests


def _evaluate(sample: CorpusSample, timeout_seconds: int) -> tuple[str, dict]:
    metadata = sample.metadata or {}
    task_stem = metadata.get("task_stem")
    test_path = metadata.get("test_path")
    if not task_stem or not test_path:
        return sample.id, {
            "available": False,
            "functional": None,
            "secure": None,
            "both": None,
            "error": "missing task_stem or test_path",
        }
    result = run_cweval_tests(
        sample.code,
        task_stem,
        test_path,
        timeout_seconds=timeout_seconds,
    )
    return sample.id, {
        "available": True,
        "functional": result.functional,
        "secure": result.secure,
        "both": result.functional is True and result.secure is True,
        "error": result.error,
    }


def annotate_corpus(
    corpus_path: str | Path,
    out_path: str | Path,
    *,
    workers: int = 4,
    timeout_seconds: int = 30,
) -> dict:
    samples = read_corpus(corpus_path)
    outcomes: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(_evaluate, sample, timeout_seconds): sample.id
            for sample in samples
        }
        for index, future in enumerate(as_completed(futures), 1):
            sample_id, outcome = future.result()
            outcomes[sample_id] = outcome
            print(f"[{index:4d}/{len(samples)}] {sample_id}: {outcome}", flush=True)

    rows = []
    for sample in samples:
        outcome = outcomes[sample.id]
        sample.metadata = dict(sample.metadata or {})
        sample.metadata["oracle"] = outcome
        rows.append({
            "id": sample.id,
            "task_id": sample.task_id,
            "source": sample.source,
            "sample_index": sample.metadata.get("sample_index"),
            "cwe": sample.metadata.get("cwe"),
            **outcome,
        })

    out_path = Path(out_path)
    write_corpus(samples, out_path)
    csv_path = out_path.with_suffix(".oracle.csv")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "samples": len(rows),
        "available": sum(row["available"] is True for row in rows),
        "security_available": sum(isinstance(row["secure"], bool) for row in rows),
        "security_unavailable": sum(row["secure"] is None for row in rows),
        "functional_pass": sum(row["functional"] is True for row in rows),
        "security_pass": sum(row["secure"] is True for row in rows),
        "both_pass": sum(row["both"] is True for row in rows),
        "errors": sum(bool(row["error"]) for row in rows),
    }
    out_path.with_suffix(".oracle.summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    summary = annotate_corpus(
        args.corpus,
        args.out,
        workers=args.workers,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
