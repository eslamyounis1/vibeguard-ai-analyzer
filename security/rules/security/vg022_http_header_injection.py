"""VG022 — HTTP Header Injection / CRLF Injection (CWE-113).

Detects non-constant values being assigned into HTTP response headers via
attribute or subscript access on objects with a ``headers`` attribute
(e.g. Flask ``response.headers['X-Custom'] = user_value``).

An attacker who controls a header value can inject CRLF sequences
(``\\r\\n``) to terminate the current header and append arbitrary new
headers or split the HTTP response.
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule


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
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not is_non_constant(value):
                continue
            for target in node.targets:
                if self._is_header_subscript(target):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=(
                                "Non-constant value assigned to an HTTP response header. "
                                "Unsanitised input may allow CRLF injection."
                            ),
                            severity=self.severity,
                            file=file_path,
                            line=node.lineno,
                            suggestion=(
                                "Strip \\r and \\n from any user-controlled header value: "
                                "value.replace('\\r', '').replace('\\n', '')."
                            ),
                            snippet=self._snippet(source_lines, node.lineno),
                        )
                    )
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
