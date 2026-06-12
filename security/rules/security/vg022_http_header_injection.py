"""VG022 — HTTP Header Injection / CRLF Injection (CWE-113).

Detects non-constant values being set in HTTP response headers via:
- Subscript assignment: response.headers['X-Custom'] = user_value
- Method calls: response.add_header('X-Custom', user_value)

An attacker who controls a header value can inject CRLF sequences
(``\\r\\n``) to terminate the current header and append arbitrary new
headers or split the HTTP response.
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_HEADER_METHODS = frozenset({"add_header", "set_header"})


class HttpHeaderInjectionRule(SecurityRule):
    rule_id = "http_header_injection"
    title = "HTTP Header Injection"
    description = (
        "Assigning unsanitised user input to HTTP response headers enables "
        "CRLF injection and HTTP response splitting."
    )
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        suggestion = (
            "Strip \\r and \\n from any user-controlled header value: "
            "value.replace('\\r', '').replace('\\n', '')."
        )
        for node in ast.walk(tree):
            # Pattern 1: response.headers['X-Header'] = user_value (ast.Assign)
            if isinstance(node, ast.Assign):
                value = node.value
                if is_non_constant(value):
                    for target in node.targets:
                        if self._is_header_subscript(target):
                            findings.append(Finding(
                                rule_id=self.rule_id, title=self.title,
                                message=(
                                    "Non-constant value assigned to an HTTP response header. "
                                    "Unsanitised input may allow CRLF injection."
                                ),
                                severity=self.severity, file=file_path,
                                line=node.lineno, suggestion=suggestion,
                                snippet=self._snippet(source_lines, node.lineno),
                            ))
            # Pattern 2: response.add_header('X-Header', user_value) (ast.Call)
            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr in _HEADER_METHODS
                    and len(node.args) >= 2
                    and is_non_constant(node.args[1])
                ):
                    findings.append(Finding(
                        rule_id=self.rule_id, title=self.title,
                        message=(
                            f"HTTP header value built from user-controlled input via "
                            f"{func.attr}() may contain newline injection."
                        ),
                        severity=self.severity, file=file_path,
                        line=node.lineno, suggestion=suggestion,
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    def _is_header_subscript(self, target: ast.AST) -> bool:
        """Return True for response.headers['key'] or headers['key'] assignment targets."""
        if not isinstance(target, ast.Subscript):
            return False
        container = target.value
        # response.headers[key]
        if isinstance(container, ast.Attribute) and container.attr == "headers":
            return True
        # headers[key] where variable is named *header*
        if isinstance(container, ast.Name) and "header" in container.id.lower():
            return True
        return False
