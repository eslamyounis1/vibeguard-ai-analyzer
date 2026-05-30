from __future__ import annotations

import ast
from typing import List, Optional

from security.fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class TlsVerifyFixer(Fixer):
    """Rewrite ``verify=False`` to ``verify=True`` on the flagged call.

    Restoring certificate validation is the secure default and removes the
    finding without altering the call's structure.
    """

    rule_id = "tls_verification_disabled"

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
            for keyword in node.keywords:
                if (
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    span = node_span(line_offsets, keyword.value)
                    if span is None:
                        return None
                    return Edit(
                        start=span[0],
                        end=span[1],
                        replacement="True",
                        description="verify=False -> verify=True (restore TLS verification)",
                    )
        return None
