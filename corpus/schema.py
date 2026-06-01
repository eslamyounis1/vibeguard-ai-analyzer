"""Unified corpus schema and JSONL storage.

A :class:`CorpusSample` is one piece of code under study, tagged with where it
came from (a specific LLM, a human reference, or a public dataset), the task it
solves, optional reference solution and tests (for behavior validation), and
optional security ground-truth labels.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass
class CorpusSample:
    id: str
    task_id: str
    source: str  # model name (e.g. "gpt-4o"), "human", or dataset name
    prompt: str
    code: str
    reference_solution: Optional[str] = None
    tests: Optional[str] = None  # executable Python (asserts or a check() call)
    entry_point: Optional[str] = None
    expected_security_labels: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CorpusSample":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def write_corpus(samples: Iterable[CorpusSample], path: str | Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_corpus(path: str | Path) -> List[CorpusSample]:
    path = Path(path)
    samples: List[CorpusSample] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                samples.append(CorpusSample.from_dict(json.loads(line)))
    return samples
