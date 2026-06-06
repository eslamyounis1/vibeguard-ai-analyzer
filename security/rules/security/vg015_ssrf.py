import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import first_arg, full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "request"})
_HTTP_MODULES = frozenset({"requests", "httpx", "aiohttp"})


class SsrfRule(SecurityRule):
    rule_id = "ssrf_unvalidated_url"
    title = "Server-Side Request Forgery (SSRF)"
    description = "HTTP client calls with attacker-controlled URLs can reach internal services."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            if not self._is_http_client_call(node):
                continue
            url_arg = first_arg(node) or self._url_keyword(node)
            if url_arg is None or not is_non_constant(url_arg):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="HTTP request URL is not a constant and may enable SSRF.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Allow-list outbound hosts/schemes, block private IP ranges, and never pass raw user input as the URL.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _is_http_client_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "urlopen" and full_attr_name(func).endswith("urlopen"):
                return True
            if func.attr in _HTTP_METHODS and isinstance(func.value, ast.Name):
                return func.value.id in _HTTP_MODULES
        if isinstance(func, ast.Name) and func.id == "urlopen":
            return True
        return False

    def _url_keyword(self, node: ast.Call) -> ast.AST | None:
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value
        return None
