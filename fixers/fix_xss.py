"""Fixer: wrap HTML-emitting arguments with html.escape() to prevent XSS."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_RESPONSE_FUNCS = frozenset({"make_response", "Response", "HttpResponse"})
_UNSAFE_MARKUP = frozenset({"Markup", "mark_safe"})


class XssFixer(Fixer):
    """Wrap unescaped user content in HTML-emitting calls with html.escape().

    Handles:
    - make_response(user_data) -> make_response(html.escape(str(user_data)))
    - Response(user_data) -> Response(html.escape(str(user_data)))
    - Markup(user_data) -> html.escape(str(user_data))
    """

    rule_id = "unsafe_html_output"

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
            if func_name is None:
                continue

            # Pattern 1: Markup(user_data) -> html.escape(str(user_data))
            if func_name in _UNSAFE_MARKUP and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    continue
                call_span = node_span(line_offsets, node)
                arg_span = node_span(line_offsets, arg)
                if call_span is None or arg_span is None:
                    continue
                arg_src = source[arg_span[0]:arg_span[1]]
                return Edit(
                    start=call_span[0],
                    end=call_span[1],
                    replacement=f"html.escape(str({arg_src}))",
                    description=f"XSS: {func_name}(user_data) -> html.escape(str(user_data))",
                )

            # Pattern 2: Response/make_response/HttpResponse(user_data, ...) ->
            #             Response(html.escape(str(user_data)), ...)
            if func_name in _RESPONSE_FUNCS and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    continue
                arg_span = node_span(line_offsets, arg)
                if arg_span is None:
                    continue
                arg_src = source[arg_span[0]:arg_span[1]]
                return Edit(
                    start=arg_span[0],
                    end=arg_span[1],
                    replacement=f"html.escape(str({arg_src}))",
                    description=f"XSS: wrap {func_name} first arg with html.escape()",
                )

        return None

    def _func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
