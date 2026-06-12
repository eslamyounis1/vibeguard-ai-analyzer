"""Fixer: replace tempfile.mktemp() with tempfile.mkstemp()."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class InsecureTmpFileFixer(Fixer):
    """Rewrite tempfile.mktemp() -> tempfile.mkstemp()."""

    rule_id = "insecure_tmpfile"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno != finding.line:
                continue
            func = node.func
            is_mktemp = (
                (isinstance(func, ast.Attribute) and func.attr == "mktemp") or
                (isinstance(func, ast.Name) and func.id == "mktemp")
            )
            if not is_mktemp:
                continue
            # Replace the function name only
            if isinstance(func, ast.Attribute):
                span = node_span(line_offsets, func)
                if span is None:
                    return None
                obj_end = span[0] + len(source[span[0]:span[1]].split(".")[0]) + 1  # after "tempfile."
                attr_start = obj_end
                attr_end = span[1]
                return Edit(
                    start=attr_start,
                    end=attr_end,
                    replacement="mkstemp",
                    description="tempfile.mktemp() -> tempfile.mkstemp()",
                )
            if isinstance(func, ast.Name):
                span = node_span(line_offsets, func)
                if span is None:
                    return None
                return Edit(
                    start=span[0],
                    end=span[1],
                    replacement="mkstemp",
                    description="mktemp() -> mkstemp()",
                )
        return None
