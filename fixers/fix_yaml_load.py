from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class YamlLoadFixer(Fixer):
    """Rewrite a compatible ``yaml.load`` call to ``yaml.safe_load``.

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
            if not (
                isinstance(node, ast.Call)
                and node.lineno == finding.line
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "load"
                and isinstance(node.func.value, ast.Name)
            ):
                continue
            if len(node.args) != 1 or any(kw.arg != "Loader" for kw in node.keywords):
                return None

            call_span = node_span(line_offsets, node)
            value_span = node_span(line_offsets, node.func.value)
            arg_span = node_span(line_offsets, node.args[0])
            if call_span is None or value_span is None or arg_span is None:
                return None
            value_text = source[value_span[0] : value_span[1]]
            arg_text = source[arg_span[0] : arg_span[1]]
            return Edit(
                start=call_span[0],
                end=call_span[1],
                replacement=f"{value_text}.safe_load({arg_text})",
                description=f"{value_text}.load() -> {value_text}.safe_load()",
            )
        return None
