"""SALLM loader: security-focused prompts with known-insecure completions.

SALLM (`s2e-lab/sallm`) ships 100 Python prompts (signature + docstring) paired
with a reference *insecure* completion that exhibits a specific CWE. The CWE is
encoded in each record ``id`` (e.g. ``Matching_Author_A_cwe502_0.py`` → CWE-502).

Each record becomes a :class:`CorpusSample` where:

* ``prompt`` — the function stub sent to an LLM,
* ``code`` / ``reference_solution`` — SALLM's bundled *insecure* completion,
* ``expected_security_labels`` — the CWE parsed from the id,
* ``source`` — ``"sallm"`` (the bundled code is a known-bad reference, not a
  human-secure baseline, so it is *not* tagged ``source="human"``).

There are no executable oracles, so ``tests`` is left ``None``; SALLM is a
security-detection smoke set, not a behavior benchmark.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from corpus.schema import CorpusSample

DEFAULT_SALLM_PATH = Path("dataset/sallm/dataset.jsonl")

_CWE_RE = re.compile(r"cwe(\d+)", re.IGNORECASE)


def _cwe_from_id(record_id: str) -> Optional[str]:
    match = _CWE_RE.search(record_id or "")
    return f"CWE-{match.group(1)}" if match else None


def _to_sample(record: dict) -> CorpusSample:
    record_id = record.get("id", "unknown")
    task_id = record_id[:-3] if record_id.endswith(".py") else record_id
    prompt = record.get("prompt", "") or ""
    code = record.get("insecure_code", "") or ""
    cwe = _cwe_from_id(record_id)
    return CorpusSample(
        id=f"sallm::{task_id}",
        task_id=task_id,
        source="sallm",
        prompt=prompt,
        code=code,
        reference_solution=code,
        tests=None,
        entry_point=None,
        expected_security_labels=[cwe] if cwe else [],
        tags=["sallm", "security-ground-truth", "insecure-reference"],
        metadata={
            "dataset": "sallm",
            "cwe": cwe,
            "technique": record.get("technique"),
            "origin": record.get("source"),
        },
    )


def load_sallm(
    path: str | Path = DEFAULT_SALLM_PATH,
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Load SALLM prompts + insecure completions as :class:`CorpusSample` records."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"SALLM dataset not found at {path}")

    samples: List[CorpusSample] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            samples.append(_to_sample(json.loads(line)))
            if limit is not None and len(samples) >= limit:
                break
    return samples
