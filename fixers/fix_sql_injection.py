"""Fixer: convert string-interpolated SQL to parameterized queries."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


def _extract_dynamic_parts(node: ast.AST) -> list[str]:
    """Return variable names embedded in f-string / % / .format SQL."""
    vars_found = []
    for child in ast.walk(node):
        if isinstance(child, ast.FormattedValue) and isinstance(child.value, ast.Name):
            vars_found.append(child.value.id)
        if isinstance(child, ast.Name) and not isinstance(ast.walk(child), type(None)):
            pass
    return vars_found


class SqlInjectionFixer(Fixer):
    """Rewrite cursor.execute(f'SELECT ... {var}') -> cursor.execute('SELECT ... ?', [var])."""

    rule_id = "sql_query_construction"

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
            if not isinstance(func, ast.Attribute) or func.attr not in {"execute", "executemany"}:
                continue
            if not node.args or not isinstance(node.args[0], ast.JoinedStr):
                continue

            fstr_node = node.args[0]
            # Collect the literal and dynamic parts
            literal_parts = []
            dynamic_parts = []
            for part in fstr_node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    literal_parts.append(part.value)
                elif isinstance(part, ast.FormattedValue):
                    literal_parts.append("?")
                    dynamic_parts.append(ast.unparse(part.value))

            if not dynamic_parts:
                return None

            safe_query = "".join(literal_parts)
            params_list = "[" + ", ".join(dynamic_parts) + "]"

            # Replace the f-string argument with a safe parameterized form
            fstr_span = node_span(line_offsets, fstr_node)
            if fstr_span is None:
                return None

            return Edit(
                start=fstr_span[0],
                end=fstr_span[1],
                replacement=f'"{safe_query}", {params_list}',
                description=f"SQL parameterized: replaced f-string with static query + params",
            )
        return None
