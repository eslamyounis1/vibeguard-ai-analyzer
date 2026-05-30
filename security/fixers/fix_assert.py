from __future__ import annotations

import ast
from typing import List, Optional

from security.fixers.base import Edit, Fixer, line_indent, node_span
from security.models.finding import Finding


class AssertFixer(Fixer):
    """Rewrite ``assert cond, msg`` into an explicit ``if/raise`` that survives ``-O``.

    ``assert cond`` becomes ``if not (cond): raise AssertionError`` and
    ``assert cond, msg`` becomes ``if not (cond): raise AssertionError(msg)``.
    """

    rule_id = "assert_used_for_validation"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assert) or node.lineno != finding.line:
                continue
            span = node_span(line_offsets, node)
            if span is None:
                return None

            indent = line_indent(source, line_offsets, node.lineno)
            condition = ast.unparse(node.test)
            if node.msg is not None:
                raise_stmt = f"raise AssertionError({ast.unparse(node.msg)})"
            else:
                raise_stmt = "raise AssertionError"

            replacement = f"if not ({condition}):\n{indent}    {raise_stmt}"
            return Edit(
                start=span[0],
                end=span[1],
                replacement=replacement,
                description="assert -> explicit if/raise (survives python -O)",
            )
        return None
