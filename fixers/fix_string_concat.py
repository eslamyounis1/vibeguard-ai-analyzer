from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, line_indent, node_span
from security.models.finding import Finding


class StringConcatFixer(Fixer):
    """Rewrite an accumulate-by-`+=` loop into list-append + ``"".join``.

    Only the safe, recognizable shape is handled: a ``for`` loop whose body is a
    single ``acc += expr`` statement. The loop is replaced with::

        _vg_parts = []
        for <t> in <it>:
            _vg_parts.append(<expr>)
        acc += "".join(_vg_parts)

    Anything more complex returns None and is left untouched. The orchestrator's
    test-based validation guards correctness before this is reported as safe.
    """

    rule_id = "string_concat_in_loop"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.For) or len(node.body) != 1:
                continue
            stmt = node.body[0]
            if (
                not isinstance(stmt, ast.AugAssign)
                or not isinstance(stmt.op, ast.Add)
                or stmt.lineno != finding.line
            ):
                continue

            span = node_span(line_offsets, node)
            if span is None:
                return None

            indent = line_indent(source, line_offsets, node.lineno)
            target = ast.unparse(node.target)
            iterable = ast.unparse(node.iter)
            acc = ast.unparse(stmt.target)
            expr = ast.unparse(stmt.value)

            replacement = (
                "_vg_parts = []\n"
                f"{indent}for {target} in {iterable}:\n"
                f"{indent}    _vg_parts.append({expr})\n"
                f'{indent}{acc} += "".join(_vg_parts)'
            )
            return Edit(
                start=span[0],
                end=span[1],
                replacement=replacement,
                description='string += in loop -> list append + "".join',
            )
        return None
