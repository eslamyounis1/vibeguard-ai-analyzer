"""Synthetic CWEval AI corpus from embedded unsafe reference functions.

CWEval test files define ``*_unsafe*`` functions illustrating vulnerable
patterns models often produce. This loader extracts them so baseline and study
pipelines can run end-to-end without LLM API keys.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Optional

from corpus.cweval_prompt import parse_task_filename
from corpus.loaders.cweval import DEFAULT_CWEVAL_PY_ROOT, _test_path_for
from corpus.schema import CorpusSample

_UNSAFE_RE = re.compile(r"_unsafe")


def _module_preamble(task_text: str) -> str:
    """Imports and top-level statements before the first function in the task file."""
    try:
        tree = ast.parse(task_text)
    except SyntaxError:
        return ""
    if not tree.body:
        return ""
    first = tree.body[0]
    if isinstance(first, ast.FunctionDef):
        return ""
    lines = task_text.splitlines()
    end_line = first.end_lineno or first.lineno
    return "\n".join(lines[:end_line]).strip()


def _extract_unsafe_functions(test_text: str) -> List[tuple[str, str]]:
    """Return (name, source) for each top-level function containing ``_unsafe``."""
    try:
        tree = ast.parse(test_text)
    except SyntaxError:
        return []
    lines = test_text.splitlines()
    out: List[tuple[str, str]] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if not _UNSAFE_RE.search(node.name):
            continue
        segment = ast.get_source_segment(test_text, node)
        if segment:
            out.append((node.name, segment))
    return out


def load_cweval_synthetic_insecure(
    root: str | Path = DEFAULT_CWEVAL_PY_ROOT,
    limit: Optional[int] = None,
) -> List[CorpusSample]:
    """Build AI-like samples from CWEval ``*_unsafe*`` functions in test files."""
    root = Path(root)
    task_paths = sorted(root.glob("cwe_*_task.py"))
    if limit is not None:
        task_paths = task_paths[:limit]

    samples: List[CorpusSample] = []
    for task_path in task_paths:
        task_text = task_path.read_text(encoding="utf-8")
        stem, cwe, variant = parse_task_filename(task_path)
        test_path = _test_path_for(task_path)
        if not test_path.exists():
            continue
        test_text = test_path.read_text(encoding="utf-8")
        preamble = _module_preamble(task_text)
        unsafe_funcs = _extract_unsafe_functions(test_text)
        if not unsafe_funcs:
            continue

        for func_name, func_src in unsafe_funcs:
            parts = [preamble, func_src] if preamble else [func_src]
            code = "\n\n".join(p for p in parts if p).strip() + "\n"
            samples.append(
                CorpusSample(
                    id=f"cweval::synthetic:{stem}::{func_name}",
                    task_id=stem,
                    source="synthetic:insecure",
                    prompt="",  # filled from reference loader if needed
                    code=code,
                    reference_solution=task_text.strip(),
                    tests=None,
                    entry_point=func_name.split("_unsafe")[0] if "_unsafe" in func_name else func_name,
                    expected_security_labels=[cwe],
                    tags=["cweval", "ai-generated", "synthetic"],
                    metadata={
                        "dataset": "cweval",
                        "cwe": cwe,
                        "variant": variant,
                        "task_stem": stem,
                        "task_path": str(task_path),
                        "test_path": str(test_path),
                        "unsafe_function": func_name,
                        "synthetic": True,
                    },
                )
            )
    return samples
