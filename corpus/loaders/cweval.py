"""CWEval loader: security-critical Python tasks with pytest oracles.

Reads ``dataset/cweval/benchmark/core/py/*_task.py`` and normalizes each task
into :class:`CorpusSample`. The prompt is extracted at ``# BEGIN SOLUTION``;
the full file is stored as the human reference baseline.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from corpus.cweval_prompt import (
    entry_point_from_prompt,
    extract_prompt,
    parse_task_filename,
)
from corpus.schema import CorpusSample

DEFAULT_CWEVAL_PY_ROOT = Path("dataset/cweval/benchmark/core/py")


def _test_path_for(task_path: Path) -> Path:
    return task_path.with_name(task_path.name.replace("_task.py", "_test.py"))


def load_cweval(
    root: str | Path = DEFAULT_CWEVAL_PY_ROOT,
    include_references: bool = True,
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Load CWEval Python tasks as :class:`CorpusSample` records.

    Each sample uses ``source="human"`` for the secure reference implementation.
    Ground-truth labels are CWE IDs parsed from filenames (e.g. ``CWE-502``).
    Pytest oracle paths are stored in ``metadata["test_path"]`` because CWEval
    tests import the task module by name and cannot run inline in the sandbox.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"CWEval Python tasks not found at {root}")

    task_paths = sorted(root.glob("cwe_*_task.py"))
    if limit is not None:
        task_paths = task_paths[:limit]

    samples: List[CorpusSample] = []
    for task_path in task_paths:
        task_text = task_path.read_text(encoding="utf-8")
        stem, cwe, variant = parse_task_filename(task_path)
        prompt = extract_prompt(task_text)
        test_path = _test_path_for(task_path)
        entry_point = entry_point_from_prompt(prompt)

        if include_references:
            samples.append(
                CorpusSample(
                    id=f"cweval::human::{stem}",
                    task_id=stem,
                    source="human",
                    prompt=prompt,
                    code=task_text.strip(),
                    reference_solution=task_text.strip(),
                    tests=None,
                    entry_point=entry_point,
                    expected_security_labels=[cwe],
                    tags=["cweval", "reference", "security-ground-truth"],
                    metadata={
                        "dataset": "cweval",
                        "cwe": cwe,
                        "variant": variant,
                        "task_stem": stem,
                        "task_path": str(task_path),
                        "test_path": str(test_path) if test_path.exists() else None,
                    },
                )
            )
    return samples
