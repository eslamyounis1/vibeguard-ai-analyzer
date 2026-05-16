import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_REQUESTS_METHODS = frozenset({
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
})


class DisabledTlsVerificationRule(SecurityRule):
    rule_id = "tls_verification_disabled"
    title = "TLS Verification Disabled"
    description = "Passing verify=False to requests disables certificate validation."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        requests_aliases: set[str] = set()
        direct_methods: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "requests":
                        requests_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "requests":
                for alias in node.names:
                    if alias.name in _REQUESTS_METHODS:
                        direct_methods.add(alias.asname or alias.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not self._has_verify_false(node):
                continue
            if not self._is_requests_call(node, requests_aliases, direct_methods):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="requests call disables TLS certificate verification with verify=False.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Remove verify=False or configure a trusted CA bundle.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _has_verify_false(self, node: ast.Call) -> bool:
        return any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )

    def _is_requests_call(
        self,
        node: ast.Call,
        requests_aliases: set[str],
        direct_methods: set[str],
    ) -> bool:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _REQUESTS_METHODS
            and isinstance(func.value, ast.Name)
            and func.value.id in requests_aliases
        ):
            return True
        return isinstance(func, ast.Name) and func.id in direct_methods
