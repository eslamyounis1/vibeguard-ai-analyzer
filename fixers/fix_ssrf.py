"""Fixer: add scheme validation to HTTP requests to mitigate SSRF."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "request"})
_HTTP_MODULES = frozenset({"requests", "httpx"})


class SsrfFixer(Fixer):
    """Wrap the URL argument of HTTP client calls with a scheme/host guard.

    Changes:
        requests.get(url)
    to:
        requests.get(url if str(url).startswith(('https://', 'http://')) else '')

    This prevents SSRF via non-http schemes (file://, ftp://, gopher://, etc.)
    and forces callers to supply a fully-qualified URL. An empty string causes
    a connection error rather than a successful exploit.

    Note: proper SSRF prevention also requires host allow-listing; use the LLM
    fixer for that level of repair.
    """

    rule_id = "ssrf_unvalidated_url"

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

            if not self._is_http_call(node):
                continue

            url_arg = self._url_arg(node)
            if url_arg is None or isinstance(url_arg, ast.Constant):
                continue

            arg_span = node_span(line_offsets, url_arg)
            if arg_span is None:
                continue

            url_src = source[arg_span[0]:arg_span[1]]
            safe_expr = (
                f"({url_src}) if str({url_src}).startswith(('https://', 'http://')) else ''"
            )
            return Edit(
                start=arg_span[0],
                end=arg_span[1],
                replacement=safe_expr,
                description="ssrf: restrict URL to http(s) schemes; add host allow-listing for full protection",
            )

        return None

    def _is_http_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _HTTP_METHODS:
            if isinstance(func.value, ast.Name) and func.value.id in _HTTP_MODULES:
                return True
            if isinstance(func.value, ast.Name) and func.value.id in {"session", "client", "s"}:
                return True
        return False

    def _url_arg(self, node: ast.Call) -> Optional[ast.AST]:
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value
        return None
