"""Merge per-model corpora into one study JSONL.

Human references come from a single ref file (all rows with ``source=human``).
AI rows are taken from one or more inputs, skipping embedded human duplicates,
deduped by ``(task_id, source)``.

Example::

    python -m corpus.merge \\
        --human-from data/corpus/cweval_ref.jsonl \\
        --inputs data/corpus/cweval_ai.jsonl data/corpus/cweval_gemma.jsonl \\
        --out data/corpus/cweval_multi.jsonl
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from corpus.schema import CorpusSample, read_corpus, write_corpus


def merge_corpora(
    inputs: Sequence[str | Path],
    out: str | Path,
    *,
    human_from: Optional[str | Path] = None,
) -> int:
    """Merge corpora; humans only from ``human_from`` when set, else union from inputs."""
    humans: List[CorpusSample] = []
    if human_from is not None:
        humans = [s for s in read_corpus(human_from) if s.source == "human"]
        if not humans:
            raise ValueError(f"No human samples in {human_from}")

    ai: List[CorpusSample] = []
    seen_ai: set[Tuple[str, str]] = set()
    for path in inputs:
        for sample in read_corpus(path):
            if sample.source == "human":
                if human_from is None:
                    key = ("human", sample.task_id)
                    if key in seen_ai:
                        continue
                    seen_ai.add(key)
                    humans.append(sample)
                continue
            key = (sample.task_id, sample.source)
            if key in seen_ai:
                continue
            seen_ai.add(key)
            ai.append(sample)

    if human_from is None and not humans:
        raise ValueError("No human samples; pass --human-from or include human rows in inputs")

    return write_corpus(humans + ai, out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge corpus JSONL files for multi-model studies.")
    parser.add_argument(
        "--human-from",
        default=None,
        help="JSONL with human/reference rows (e.g. data/corpus/cweval_ref.jsonl). Recommended.",
    )
    parser.add_argument(
        "--inputs", nargs="+", required=True,
        help="Per-model corpus files (human rows inside are ignored if --human-from is set).",
    )
    parser.add_argument("--out", required=True, help="Merged output JSONL path.")
    args = parser.parse_args()

    count = merge_corpora(args.inputs, args.out, human_from=args.human_from)
    print(f"Wrote {count} sample(s) to {args.out}")


if __name__ == "__main__":
    main()
