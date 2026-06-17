"""SecurityEval loader for known-insecure Python snippets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from corpus.schema import CorpusSample

DEFAULT_SECURITYEVAL_PATH = Path("dataset/securityeval/dataset.jsonl")
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _cwe_from_id(record_id: str) -> Optional[str]:
    match = _CWE_RE.search(record_id or "")
    return f"CWE-{int(match.group(1))}" if match else None


def load_securityeval(
    path: str | Path = DEFAULT_SECURITYEVAL_PATH,
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Load SecurityEval's labeled insecure implementations."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"SecurityEval dataset not found at {path}")

    samples: List[CorpusSample] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            record_id = str(record.get("ID", "unknown"))
            cwe = _cwe_from_id(record_id)
            code = record.get("Insecure_code", "") or ""
            samples.append(
                CorpusSample(
                    id=f"securityeval::{record_id}",
                    task_id=record_id.removesuffix(".py"),
                    source="securityeval",
                    prompt=record.get("Prompt", "") or "",
                    code=code,
                    reference_solution=code,
                    expected_security_labels=[cwe] if cwe else [],
                    tags=["securityeval", "security-ground-truth", "insecure-reference"],
                    metadata={"dataset": "securityeval", "cwe": cwe},
                )
            )
            if limit is not None and len(samples) >= limit:
                break
    return samples
