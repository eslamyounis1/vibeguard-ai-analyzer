"""SeCodePLT loader: vulnerable/patched code pairs at scale.

SeCodePLT (`UCSB-SURFI/SeCodePLT`) provides, per language split, records with a
prompt, a ``vulnerable_code_reference`` (insecure), a ``patched_code_reference``
(secure), and a ``CWE_ID``. We treat the vulnerable reference as the study
subject (``code``) and the patched reference as the secure ``reference_solution``.

Because the published parquet splits mix languages (some ``python_*`` files in a
given snapshot actually contain C/C++ "arvo" CVE rows with empty prompts/CWEs),
this loader filters to a target ``language`` and skips rows lacking a usable
prompt + CWE. If a split contains no matching rows it returns an empty list —
re-download the dataset if you expected Python rows (see plan.md).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence

from corpus.schema import CorpusSample

DEFAULT_SECODEPLT_ROOT = Path("dataset/secodeplt")
DEFAULT_SPLITS = (
    "python_secure_coding",
    "python_vulnerability_detection",
    "python_patch_generation",
)


def _normalize_cwe(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    digits = raw.upper().replace("CWE-", "").replace("CWE_", "").strip()
    return f"CWE-{int(digits)}" if digits.isdigit() else None


def _to_sample(record: dict, split: str) -> CorpusSample:
    record_id = str(record.get("id", "unknown"))
    cwe = _normalize_cwe(record.get("CWE_ID"))
    vulnerable = (record.get("vulnerable_code_reference") or "").strip()
    patched = (record.get("patched_code_reference") or "").strip()
    return CorpusSample(
        id=f"secodeplt::{split}::{record_id}",
        task_id=record_id,
        source="secodeplt",
        prompt=record.get("input_prompt", "") or "",
        code=vulnerable,
        reference_solution=patched or None,
        tests=None,
        entry_point=None,
        expected_security_labels=[cwe] if cwe else [],
        tags=["secodeplt", "security-ground-truth", "insecure-reference"],
        metadata={
            "dataset": "secodeplt",
            "split": split,
            "cwe": cwe,
            "language": record.get("language"),
            "context": record.get("context"),
        },
    )


def _read_split(root: Path, split: str):
    files = sorted((root / "data").glob(f"{split}-*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet found for split {split!r} under {root / 'data'}")
    try:
        import pandas as pd
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(
            "SeCodePLT loader requires pandas (and a parquet engine). "
            "Install with: pip install -e \".[experiments]\""
        ) from exc

    frames = [pd.read_parquet(f) for f in files]
    return pd.concat(frames, ignore_index=True) if len(frames) > 1 else frames[0]


def load_secodeplt(
    root: str | Path = DEFAULT_SECODEPLT_ROOT,
    splits: Sequence[str] = DEFAULT_SPLITS,
    language: str = "Python",
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Load SeCodePLT vulnerable/patched pairs as :class:`CorpusSample` records.

    Args:
        root: SeCodePLT root containing ``data/*.parquet``.
        splits: Which splits to read (defaults to the three Python splits).
        language: Keep only rows whose ``language`` matches (case-insensitive).
        limit: If set, cap the number of *kept* samples per split.
    """
    root = Path(root)
    if not (root / "data").is_dir():
        raise FileNotFoundError(f"SeCodePLT data directory not found at {root / 'data'}")

    lang = language.lower()
    samples: List[CorpusSample] = []
    for split in splits:
        frame = _read_split(root, split)
        kept = 0
        for record in frame.to_dict("records"):
            row_lang = str(record.get("language") or "").lower()
            if lang and lang not in row_lang:
                continue
            if not (record.get("input_prompt") or "").strip():
                continue
            samples.append(_to_sample(record, split))
            kept += 1
            if limit is not None and kept >= limit:
                break
    return samples
