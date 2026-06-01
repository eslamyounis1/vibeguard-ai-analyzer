"""MBPP loader: short Python tasks with asserts as tests.

Like the HumanEval loader, reference solutions are tagged ``source="human"``
and the dataset asserts are attached as tests. Falls back to a small built-in
set offline.
"""

from __future__ import annotations

from typing import List, Optional

from corpus.schema import CorpusSample

_FALLBACK = [
    {
        "task_id": 1,
        "text": "Write a function to find the shared elements from two lists.",
        "code": (
            "def similar_elements(a, b):\n"
            "    return tuple(set(a) & set(b))\n"
        ),
        "test_list": [
            "assert set(similar_elements((3,4,5,6),(5,7,4,10))) == {4,5}",
        ],
    },
]


def _to_sample(problem: dict) -> CorpusSample:
    task_id = str(problem.get("task_id", "?"))
    code = problem.get("code", "")
    tests = "\n".join(problem.get("test_list", []) or []) or None
    return CorpusSample(
        id=f"mbpp::human::{task_id}",
        task_id=f"MBPP/{task_id}",
        source="human",
        prompt=problem.get("text", ""),
        code=code,
        reference_solution=code,
        tests=tests,
        tags=["mbpp", "reference"],
        metadata={"dataset": "mbpp"},
    )


def load_mbpp(limit: Optional[int] = None) -> List[CorpusSample]:
    problems: List[dict] = []
    try:
        from datasets import load_dataset

        ds = load_dataset("mbpp", split="test")
        problems = list(ds)
    except Exception:
        problems = _FALLBACK

    if limit is not None:
        problems = problems[:limit]
    return [_to_sample(p) for p in problems]
