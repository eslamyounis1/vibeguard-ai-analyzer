import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule


class SecurityAssertRule(SecurityRule):
    rule_id = "assert_used_for_validation"
    title = "assert Used for Validation"
    description = (
        "Assertions are disabled when Python runs with the -O flag. "
        "Never rely on assert for runtime validation."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        "assert statements are stripped with Python -O and must not be used for validation. "
                        "Use an explicit if/raise pattern instead."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Replace with explicit if/raise or use pydantic/cerberus validation.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
