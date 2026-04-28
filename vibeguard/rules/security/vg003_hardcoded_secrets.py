import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule

_SENSITIVE = frozenset({
    "password", "passwd", "secret", "api_key", "token",
    "private_key", "auth_token", "access_token",
})


class HardcodedSecretsRule(SecurityRule):
    rule_id = "hardcoded_secret"
    title = "Hardcoded Secret"
    description = (
        "Assigning a non-empty string literal to a variable with a sensitive name "
        "may expose credentials in source code."
    )
    severity = Severity.HIGH

    def _is_sensitive(self, name: str) -> bool:
        name_lower = name.lower()
        return any(s in name_lower for s in _SENSITIVE)

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and self._is_sensitive(target.id):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"Variable '{target.id}' appears to contain a hardcoded secret. "
                            "Move credentials to environment variables or a secrets manager."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings
