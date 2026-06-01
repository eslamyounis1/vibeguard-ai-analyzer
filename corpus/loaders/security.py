"""Security ground-truth loaders.

Two sources:
- ``load_security_benchmark`` converts the in-repo labeled samples in
  ``benchmarks/dataset.py`` into the corpus schema, giving an offline security
  ground-truth set immediately.
- ``load_security_jsonl`` reads an external labeled set (e.g. SecurityEval /
  LLMSecEval exported to JSONL with ``code`` and ``labels`` fields).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from corpus.schema import CorpusSample


def load_security_benchmark() -> List[CorpusSample]:
    from benchmarks.dataset import SAMPLES

    samples: List[CorpusSample] = []
    for s in SAMPLES:
        samples.append(
            CorpusSample(
                id=f"benchmark::{s.source}::{s.id}",
                task_id=s.id,
                source=f"benchmark:{s.source}",
                prompt=s.description,
                code=s.code,
                expected_security_labels=sorted(s.expected_rules),
                tags=list(s.tags) + ["security-ground-truth"],
                metadata={"label": s.label, "forbidden_rules": sorted(s.forbidden_rules)},
            )
        )
    return samples


def load_security_jsonl(path: str | Path, limit: Optional[int] = None) -> List[CorpusSample]:
    path = Path(path)
    samples: List[CorpusSample] = []
    with path.open("r", encoding="utf-8") as handle:
        for i, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            if limit is not None and len(samples) >= limit:
                break
            row = json.loads(line)
            task_id = str(row.get("id", row.get("task_id", i)))
            samples.append(
                CorpusSample(
                    id=f"securityeval::{task_id}",
                    task_id=task_id,
                    source=row.get("source", "securityeval"),
                    prompt=row.get("prompt", ""),
                    code=row.get("code", ""),
                    expected_security_labels=list(row.get("labels", row.get("cwes", []))),
                    tags=["security-ground-truth", "external"],
                    metadata={k: v for k, v in row.items() if k not in {"code", "prompt"}},
                )
            )
    return samples
