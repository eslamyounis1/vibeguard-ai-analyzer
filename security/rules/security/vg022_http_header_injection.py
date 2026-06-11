import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_HEADER_METHODS = frozenset({"add_header", "set_header", "headers"})


class HttpHeaderInjectionRule(SecurityRule):
    rule_id = "http_header_injection"
    title = "HTTP Header Injection (CWE-113)"
    description = "User-controlled data in HTTP response headers can allow header splitting attacks."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_header_assignment(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="HTTP header value built from user-controlled input may contain newline injection.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Strip or reject header values containing '\\r' or '\\n' characters before setting headers.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_header_assignment(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr not in _HEADER_METHODS:
            return False
        # Check if value argument is dynamic
        if len(node.args) >= 2 and is_non_constant(node.args[1]):
            return True
        for kw in node.keywords:
            if kw.arg == "value" and is_non_constant(kw.value):
                return True
        return False
