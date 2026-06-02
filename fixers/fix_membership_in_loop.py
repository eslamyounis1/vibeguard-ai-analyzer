from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class MembershipInLoopFixer(Fixer):
    """Rewrite a list/tuple membership literal to a set literal: ``x in [a, b]`` -> ``x in {a, b}``.

    Set membership is O(1) and semantically identical to list/tuple membership
    for the ``in`` operator, so this is a safe, local energy/perf win.
    """

    rule_id = "membership_in_loop"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Compare)
                and node.lineno == finding.line
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and isinstance(node.comparators[0], (ast.List, ast.Tuple))
                and node.comparators[0].elts
            ):
                literal = node.comparators[0]
                span = node_span(line_offsets, literal)
                if span is None:
                    return None
                inner = source[span[0] + 1 : span[1] - 1].strip().rstrip(",")
                return Edit(
                    start=span[0],
                    end=span[1],
                    replacement="{" + inner + "}",
                    description="list/tuple membership -> set literal (O(1) lookups)",
                )
        return None
