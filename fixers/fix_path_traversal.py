"""Fixer: wrap path arguments with os.path.normpath and a basedir check."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, compute_line_offsets, node_span
from security.models.finding import Finding


class PathTraversalFixer(Fixer):
    """Wrap open(user_path) -> open(os.path.normpath(os.path.join(BASE_DIR, user_path)))."""

    rule_id = "path_traversal"

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
            is_open = (isinstance(func, ast.Name) and func.id == "open") or (
                isinstance(func, ast.Attribute) and func.attr == "open"
            )
            if not is_open or not node.args:
                continue

            path_arg = node.args[0]
            if isinstance(path_arg, ast.Constant):
                return None  # Constant path — not traversal

            path_src = ast.unparse(path_arg)
            path_span = node_span(line_offsets, path_arg)
            if path_span is None:
                return None

            return Edit(
                start=path_span[0],
                end=path_span[1],
                replacement=f"os.path.normpath(os.path.join(BASE_DIR, {path_src}))",
                description="path_traversal: wrapped path with normpath+join for basedir confinement",
            )
        return None
