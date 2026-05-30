from __future__ import annotations

import ast
from typing import List, Optional

from security.fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class YamlLoadFixer(Fixer):
    """Rewrite ``yaml.load(x)`` to ``yaml.safe_load(x)``.

    Only the attribute form (``yaml.load``) is auto-fixed. The bare
    ``from yaml import load`` form is left untouched because ``safe_load`` may
    not be imported, so a safe edit cannot be guaranteed.
    """

    rule_id = "unsafe_yaml_load"

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
                and node.func.attr == "load"
                and isinstance(node.func.value, ast.Name)
            ):
                span = node_span(line_offsets, node.func)
                value_span = node_span(line_offsets, node.func.value)
                if span is None or value_span is None:
                    return None
                value_text = source[value_span[0] : value_span[1]]
                return Edit(
                    start=span[0],
                    end=span[1],
                    replacement=f"{value_text}.safe_load",
                    description=f"{value_text}.load() -> {value_text}.safe_load()",
                )
        return None
