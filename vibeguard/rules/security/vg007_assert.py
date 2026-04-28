import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule

_SECURITY_KEYWORDS = frozenset({
    "auth", "admin", "permission", "password", "user", "role",
    "access", "secret", "token", "login", "authenticated", "authorized",
    "privilege", "credential",
})


class SecurityAssertRule(SecurityRule):
    rule_id = "VG007"
    title = "Assert Used for Security Check"
    description = (
        "Assertions are disabled when Python runs with the -O flag. "
        "Never rely on assert for security-critical validation."
    )
    severity = Severity.MEDIUM

    def _looks_security_related(self, node: ast.Assert) -> bool:
        src = ast.unparse(node.test).lower()
        return any(kw in src for kw in _SECURITY_KEYWORDS)

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and self._looks_security_related(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        "Security-related assert statement can be silently disabled with Python's -O flag. "
                        "Use an explicit if/raise pattern for security validation."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
