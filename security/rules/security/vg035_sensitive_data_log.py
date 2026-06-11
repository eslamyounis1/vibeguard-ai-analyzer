import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception", "log"})
_SENSITIVE_NAMES = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "private_key", "credentials", "ssn", "credit_card", "cvv",
    "access_token", "refresh_token",
})


class SensitiveDataLogRule(SecurityRule):
    rule_id = "sensitive_data_in_log"
    title = "Sensitive Data Exposure in Logs (CWE-200)"
    description = "Logging sensitive fields like passwords or tokens exposes them in log files."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_log_call(node):
                continue
            sensitive = self._find_sensitive_args(node)
            if sensitive:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Sensitive variable(s) [{', '.join(sensitive)}] passed to logging call.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Redact or mask sensitive fields before logging (e.g., log only last 4 chars of token).",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_log_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS:
            return True
        return False

    def _find_sensitive_args(self, node: ast.Call) -> List[str]:
        found = []
        all_args = list(node.args) + [kw.value for kw in node.keywords if kw.arg]
        for arg in all_args:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Name):
                    if any(s in sub.id.lower() for s in _SENSITIVE_NAMES):
                        found.append(sub.id)
        return list(dict.fromkeys(found))  # dedupe preserving order
