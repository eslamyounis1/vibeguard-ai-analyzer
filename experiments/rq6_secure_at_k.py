"""Compute task-level functional@k, secure@k, and vulnerable@k on CWEval."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from corpus.schema import read_corpus
from experiments.metrics import compute_task_level_at_k


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_rq6(
    corpus_path: str,
    out_dir: Path,
    k_values: tuple[int, ...] = (1, 3, 5),
) -> list[dict]:
    """Use repeated samples and behavioral oracles; never pool unrelated tasks."""
    by_source: dict[str, list[dict]] = defaultdict(list)
    detail = []
    for sample in read_corpus(corpus_path):
        if sample.source == "human" or sample.source.startswith("human"):
            continue
        oracle = (sample.metadata or {}).get("oracle") or {}
        if not isinstance(oracle.get("secure"), bool):
            raise ValueError(
                "Corpus must be annotated with experiments.annotate_cweval first"
            )
        row = {
            "id": sample.id,
            "task_id": sample.task_id,
            "source": sample.source,
            "functional": oracle.get("functional") is True,
            "secure": (
                oracle.get("functional") is True and oracle.get("secure") is True
            ),
            "vulnerable": (
                oracle.get("functional") is True and oracle.get("secure") is False
            ),
        }
        detail.append(row)
        by_source[sample.source].append(row)

    results = []
    for source, rows in sorted(by_source.items()):
        result = {"source": source}
        for endpoint in ("functional", "secure", "vulnerable"):
            metrics = compute_task_level_at_k(
                rows,
                success_key=endpoint,
                k_values=k_values,
            )
            result.update({
                key: value for key, value in metrics.items()
                if key not in {"tasks", "min_samples_per_task", "max_samples_per_task"}
            })
        result["tasks"] = len({row["task_id"] for row in rows})
        result["min_samples_per_task"] = min(
            sum(item["task_id"] == task for item in rows)
            for task in {row["task_id"] for row in rows}
        )
        results.append(result)

    _write_csv(out_dir / "rq6_per_sample.csv", detail)
    _write_csv(out_dir / "rq6_secure_at_k.csv", results)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", default="results/research_v4")
    parser.add_argument("--k", nargs="+", type=int, default=[1, 3, 5])
    args = parser.parse_args()
    rows = run_rq6(args.corpus, Path(args.out), tuple(args.k))
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
