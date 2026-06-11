import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class InsecureCookieRule(SecurityRule):
    rule_id = "insecure_cookie"
    title = "Insecure Cookie (Missing Secure Flag, CWE-614)"
    description = "Cookies set without the Secure flag can be transmitted over HTTP."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_set_cookie(node):
                continue
            if not self._has_secure_flag(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Cookie set without secure=True; may be sent over insecure HTTP connections.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Add secure=True, httponly=True, and samesite='Strict' to set_cookie() calls.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_set_cookie(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in {"set_cookie", "set_signed_cookie"}
        return False

    def _has_secure_flag(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "secure":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False
