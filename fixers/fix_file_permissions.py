"""Fixer: replace world-writable chmod modes with restrictive 0o640."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_WORLD_WRITABLE = {0o777, 0o666, 0o776, 0o767, 0o677, 0o775, 0o757, 0o577}
_SAFE_REPLACEMENT = "0o640"
_SAFE_EXEC_REPLACEMENT = "0o750"


class FilePermissionsFixer(Fixer):
    """Replace world-writable file permission modes with 0o640."""

    rule_id = "incorrect_file_permissions"

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
            is_chmod = (
                (isinstance(func, ast.Attribute) and func.attr == "chmod") or
                (isinstance(func, ast.Name) and func.id == "chmod")
            )
            if not is_chmod:
                continue

            # Find the mode argument
            mode_node = None
            mode_value = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode_node = node.args[1]
                mode_value = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode_node = kw.value
                    mode_value = kw.value.value

            if mode_node is None or not isinstance(mode_value, int):
                return None
            if mode_value not in _WORLD_WRITABLE and not (mode_value & 0o002):
                return None

            span = node_span(line_offsets, mode_node)
            if span is None:
                return None
            safe = _SAFE_EXEC_REPLACEMENT if (mode_value & 0o100) else _SAFE_REPLACEMENT
            return Edit(
                start=span[0],
                end=span[1],
                replacement=safe,
                description=f"chmod {oct(mode_value)} -> {safe} (remove world-writable bits)",
            )
        return None
