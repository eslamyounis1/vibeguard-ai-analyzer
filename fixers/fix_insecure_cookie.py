"""Fixer: add secure=True, httponly=True to set_cookie() calls."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding


class InsecureCookieFixer(Fixer):
    """Add secure=True and httponly=True to set_cookie() calls missing them."""

    rule_id = "insecure_cookie"

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
            if not isinstance(func, ast.Attribute) or func.attr not in {"set_cookie", "set_signed_cookie"}:
                continue

            existing_kw_names = {kw.arg for kw in node.keywords}
            additions = []
            if "secure" not in existing_kw_names:
                additions.append("secure=True")
            if "httponly" not in existing_kw_names:
                additions.append("httponly=True")

            if not additions:
                return None

            # Insert additions just before the closing paren
            # Find the end of the call node
            call_span = node_span(line_offsets, node)
            if call_span is None:
                return None

            # We insert ', secure=True, httponly=True' before the closing paren
            end_of_call = call_span[1]
            # The source at end_of_call - 1 should be ')'
            insert_pos = end_of_call - 1
            addition_str = ", ".join(additions)
            # Insert before closing paren
            original_close = source[insert_pos:end_of_call]
            if ")" not in original_close:
                return None
            return Edit(
                start=insert_pos,
                end=insert_pos,
                replacement=f", {addition_str}",
                description=f"set_cookie: added {addition_str}",
            )
        return None
