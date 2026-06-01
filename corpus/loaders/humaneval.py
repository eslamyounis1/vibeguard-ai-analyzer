"""HumanEval loader: tasks with reference solutions and unit tests.

Reference solutions are tagged ``source="human"`` so they can serve as the
human baseline in AI-vs-human comparisons, and the dataset's own ``check()``
tests are attached for behavior validation. Falls back to a tiny built-in set
when the ``datasets`` package or network is unavailable, so the pipeline is
testable offline.
"""

from __future__ import annotations

from typing import List, Optional

from corpus.schema import CorpusSample

_FALLBACK = [
    {
        "task_id": "HumanEval/0",
        "entry_point": "has_close_elements",
        "prompt": (
            "from typing import List\n\n\n"
            "def has_close_elements(numbers: List[float], threshold: float) -> bool:\n"
            "    \"\"\"Return True if any two numbers are closer than threshold.\"\"\"\n"
        ),
        "canonical_solution": (
            "    for i in range(len(numbers)):\n"
            "        for j in range(len(numbers)):\n"
            "            if i != j and abs(numbers[i] - numbers[j]) < threshold:\n"
            "                return True\n"
            "    return False\n"
        ),
        "test": (
            "def check(candidate):\n"
            "    assert candidate([1.0, 2.0, 3.0], 0.5) is False\n"
            "    assert candidate([1.0, 2.8, 3.0], 0.3) is True\n"
        ),
    },
]


def _to_sample(problem: dict) -> CorpusSample:
    entry_point = problem.get("entry_point")
    prompt = problem.get("prompt", "")
    solution = prompt + problem.get("canonical_solution", "")
    test_code = problem.get("test", "")
    tests = f"{test_code}\n\ncheck({entry_point})\n" if entry_point and test_code else test_code or None
    task_id = problem.get("task_id", "HumanEval/?")
    return CorpusSample(
        id=f"humaneval::human::{task_id}",
        task_id=task_id,
        source="human",
        prompt=prompt,
        code=solution,
        reference_solution=solution,
        tests=tests,
        entry_point=entry_point,
        tags=["humaneval", "reference"],
        metadata={"dataset": "openai_humaneval"},
    )


def load_humaneval(limit: Optional[int] = None) -> List[CorpusSample]:
    problems: List[dict] = []
    try:
        from datasets import load_dataset

        ds = load_dataset("openai_humaneval", split="test")
        problems = list(ds)
    except Exception:
        problems = _FALLBACK

    if limit is not None:
        problems = problems[:limit]
    return [_to_sample(p) for p in problems]
