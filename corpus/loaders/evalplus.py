"""EvalPlus loader: HumanEval+ and MBPP+ tasks for the energy study (RQ3).

Reads the locally downloaded parquet files under ``dataset/evalplus/`` and
normalizes each problem into a :class:`CorpusSample`. Reference solutions are
tagged ``source="human"`` so they can serve as the human baseline, and the
dataset's own (extended) tests are attached for behavior validation.

EvalPlus tasks are small, pure-Python functions, which makes them a good signal
for measured energy/runtime, unlike CWEval's security-focused tasks.

Two subsets differ in how their tests invoke the solution:

* **HumanEval+** — the ``test`` defines ``def check(candidate): ...``; we append
  ``check(<entry_point>)`` so the test runs inline (same convention as the
  legacy ``humaneval`` loader).
* **MBPP+** — the ``test`` is top-level code that calls the entry point by name
  directly, so it runs as-is once the solution is in scope. There is no
  ``entry_point`` column, so we parse it from the reference ``code``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Sequence

from corpus.schema import CorpusSample

DEFAULT_EVALPLUS_ROOT = Path("dataset/evalplus")
DEFAULT_SUBSETS = ("humanevalplus", "mbppplus")

_DEF_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)


def _read_parquet(subset_dir: Path):
    files = sorted(subset_dir.glob("data/*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found under {subset_dir / 'data'}")
    try:
        import pandas as pd
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(
            "EvalPlus loader requires pandas (and a parquet engine). "
            "Install with: pip install -e \".[experiments]\""
        ) from exc

    frames = [pd.read_parquet(f) for f in files]
    return pd.concat(frames, ignore_index=True) if len(frames) > 1 else frames[0]


def _entry_point_from_code(code: str) -> Optional[str]:
    match = _DEF_RE.search(code or "")
    return match.group(1) if match else None


def _humaneval_sample(row: dict) -> CorpusSample:
    task_id = str(row.get("task_id", "HumanEval/?"))
    prompt = row.get("prompt", "") or ""
    solution = prompt + (row.get("canonical_solution", "") or "")
    entry_point = row.get("entry_point")
    test_code = row.get("test", "") or ""
    tests = (
        f"{test_code}\n\ncheck({entry_point})\n"
        if entry_point and test_code
        else (test_code or None)
    )
    return CorpusSample(
        id=f"evalplus::human::{task_id}",
        task_id=task_id,
        source="human",
        prompt=prompt,
        code=solution,
        reference_solution=solution,
        tests=tests,
        entry_point=entry_point,
        tags=["evalplus", "humanevalplus", "reference"],
        metadata={"dataset": "evalplus", "subset": "humanevalplus"},
    )


def _mbpp_sample(row: dict) -> CorpusSample:
    task_id = f"MbppPlus/{row.get('task_id', '?')}"
    prompt = row.get("prompt", "") or ""
    solution = (row.get("code", "") or "").strip()
    test_code = row.get("test", "") or ""
    # MBPP+ tests call the entry point by name at top level; no check() wrapper.
    tests = test_code or None
    return CorpusSample(
        id=f"evalplus::human::{task_id}",
        task_id=task_id,
        source="human",
        prompt=prompt,
        code=solution,
        reference_solution=solution,
        tests=tests,
        entry_point=_entry_point_from_code(solution),
        tags=["evalplus", "mbppplus", "reference"],
        metadata={
            "dataset": "evalplus",
            "subset": "mbppplus",
            "source_file": row.get("source_file"),
        },
    )


def load_evalplus(
    root: str | Path = DEFAULT_EVALPLUS_ROOT,
    subsets: Sequence[str] = DEFAULT_SUBSETS,
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Load EvalPlus reference solutions as :class:`CorpusSample` records.

    Args:
        root: Directory containing ``humanevalplus/`` and ``mbppplus/`` subdirs.
        subsets: Which subsets to load (defaults to both).
        limit: If set, cap the number of samples *per subset*.
    """
    root = Path(root)
    builders = {"humanevalplus": _humaneval_sample, "mbppplus": _mbpp_sample}

    samples: List[CorpusSample] = []
    for subset in subsets:
        if subset not in builders:
            raise ValueError(
                f"Unknown EvalPlus subset {subset!r}; expected one of {sorted(builders)}"
            )
        subset_dir = root / subset
        if not subset_dir.is_dir():
            raise FileNotFoundError(f"EvalPlus subset not found at {subset_dir}")

        frame = _read_parquet(subset_dir)
        rows = frame.to_dict("records")
        if limit is not None:
            rows = rows[:limit]
        builder = builders[subset]
        samples.extend(builder(row) for row in rows)

    return samples
