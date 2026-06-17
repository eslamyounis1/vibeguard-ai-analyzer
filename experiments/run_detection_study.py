"""Cross-dataset target-recall and security-alert incidence evaluation.

SALLM and SecurityEval provide one target CWE per known-insecure sample. That
supports exact-CWE recall, relaxed family recall, and any-alert incidence, but
not precision: an additional finding cannot be called a false positive without
complete multi-label ground truth. EvalPlus is unlabeled for security and is
therefore reported only as alert incidence on benign algorithmic references.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from corpus.loaders import load_evalplus, load_sallm, load_securityeval
from experiments.batch_tools import (
    run_bandit_batch,
    run_semgrep_batch,
    run_vibeguard_batch,
)
from experiments.run_research_evaluation import _cross_dataset_rows, _write_csv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="results/detection_study")
    parser.add_argument("--sallm-path", default="dataset/sallm/dataset.jsonl")
    parser.add_argument(
        "--securityeval-path", default="dataset/securityeval/dataset.jsonl"
    )
    parser.add_argument("--evalplus-path", default="dataset/evalplus")
    args = parser.parse_args()

    rows, _ = _cross_dataset_rows(
        {
            "sallm": load_sallm(args.sallm_path),
            "securityeval": load_securityeval(args.securityeval_path),
            "evalplus": load_evalplus(
                args.evalplus_path, subsets=("humanevalplus",)
            ),
        },
        {
            "vibeguard": lambda data: run_vibeguard_batch(data, enable_taint=True),
            "bandit": run_bandit_batch,
            "semgrep": run_semgrep_batch,
        },
    )
    out_dir = Path(args.out_dir)
    _write_csv(out_dir / "detection_study.csv", rows)
    (out_dir / "summary.json").write_text(
        json.dumps({"results": rows}, indent=2), encoding="utf-8"
    )
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
