from __future__ import annotations

import ast
from typing import List, Optional

from security.fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_WEAK_HASHES = {"md5", "sha1", "sha"}


class WeakHashFixer(Fixer):
    """Rewrite ``hashlib.md5(...)`` / ``sha1`` / ``sha`` to ``hashlib.sha256(...)``."""

    rule_id = "weak_hash_algorithm"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and node.lineno == finding.line
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _WEAK_HASHES
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
            ):
                span = node_span(line_offsets, node.func)
                value_span = node_span(line_offsets, node.func.value)
                if span is None or value_span is None:
                    return None
                value_text = source[value_span[0] : value_span[1]]
                return Edit(
                    start=span[0],
                    end=span[1],
                    replacement=f"{value_text}.sha256",
                    description=f"hashlib.{node.func.attr}() -> hashlib.sha256()",
                )
        return None
