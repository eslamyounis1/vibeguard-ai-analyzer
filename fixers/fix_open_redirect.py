"""Fixer: guard redirect() calls against external URLs to prevent open redirect."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_REDIRECT_FUNCS = frozenset({"redirect", "HttpResponseRedirect", "RedirectResponse"})


class OpenRedirectFixer(Fixer):
    """Replace redirect(url) with redirect(url if url.startswith('/') else '/').

    This prevents redirects to external (attacker-controlled) URLs by falling
    back to the site root when the target URL is not relative.
    """

    rule_id = "open_redirect"

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

            func_name = self._func_name(node)
            if func_name not in _REDIRECT_FUNCS:
                continue

            if not node.args:
                continue

            url_arg = node.args[0]
            if isinstance(url_arg, ast.Constant):
                continue

            arg_span = node_span(line_offsets, url_arg)
            if arg_span is None:
                continue

            url_src = source[arg_span[0]:arg_span[1]]
            safe_expr = f"({url_src}) if isinstance({url_src}, str) and ({url_src}).startswith('/') else '/'"
            return Edit(
                start=arg_span[0],
                end=arg_span[1],
                replacement=safe_expr,
                description="open_redirect: restrict redirect target to relative URLs only",
            )

        return None

    def _func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
