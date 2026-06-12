import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ROUTE_DECORATORS = frozenset({"route", "post", "put", "patch", "delete"})


class CsrfRule(SecurityRule):
    rule_id = "csrf_missing_protection"
    title = "Missing CSRF Protection (CWE-352)"
    description = "State-changing routes without CSRF token validation are vulnerable to cross-site request forgery."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        # Check for Flask/Django routes that accept POST/PUT/DELETE without csrf_token
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if self._is_mutating_route(node) and not self._has_csrf_check(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Route accepts mutating HTTP methods without apparent CSRF token validation.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use Flask-WTF CSRFProtect or Django's {% csrf_token %} / CsrfViewMiddleware.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_mutating_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in node.decorator_list:
            if self._decorator_has_mutating_method(decorator):
                return True
        return False

    def _decorator_has_mutating_method(self, decorator: ast.AST) -> bool:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute) and func.attr in _ROUTE_DECORATORS:
                # Check methods= keyword
                for kw in decorator.keywords:
                    if kw.arg == "methods":
                        methods_node = kw.value
                        if isinstance(methods_node, (ast.List, ast.Tuple)):
                            for elt in methods_node.elts:
                                if isinstance(elt, ast.Constant) and elt.value in _MUTATING_METHODS:
                                    return True
            # @app.post / @app.put etc.
            if isinstance(func, ast.Attribute) and func.attr in {"post", "put", "patch", "delete"}:
                return True
        return False

    def _has_csrf_check(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        src = ast.unparse(node)
        csrf_markers = ["csrf_token", "csrf_protect", "CSRFProtect", "X-CSRFToken", "x_csrf", "validate_csrf"]
        return any(m in src for m in csrf_markers)
