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

_SSL_UNVERIFIED_FUNCS = frozenset({
    "_create_unverified_context",
    "create_default_context",
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
            if isinstance(node, ast.Call):
                if self._has_verify_false(node) and self._is_requests_call(node, requests_aliases, direct_methods):
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
                elif self._is_ssl_unverified_context(node):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="ssl._create_unverified_context() disables certificate verification entirely.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Use ssl.create_default_context() without disabling hostname/cert checking.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
            elif isinstance(node, ast.Assign):
                finding = self._check_ssl_ctx_assignment(node, file_path, source_lines)
                if finding:
                    findings.append(finding)

        return findings

    def _has_verify_false(self, node: ast.Call) -> bool:
        return any(
            keyword.arg == "verify"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )

    def _is_ssl_unverified_context(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "_create_unverified_context":
            return True
        return False

    def _check_ssl_ctx_assignment(self, node: ast.Assign, file_path: str, source_lines: List[str]):
        """Detect ctx.check_hostname = False and ctx.verify_mode = ssl.CERT_NONE."""
        for target in node.targets:
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr == "check_hostname":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    return Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="SSL context has check_hostname disabled, removing hostname verification.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Keep check_hostname=True to prevent MITM attacks.",
                        snippet=self._snippet(source_lines, node.lineno),
                    )
            elif target.attr == "verify_mode":
                # ssl.CERT_NONE is an Attribute node
                val = node.value
                if (isinstance(val, ast.Attribute) and val.attr == "CERT_NONE") or (
                    isinstance(val, ast.Constant) and val.value == 0
                ):
                    return Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="SSL context verify_mode set to CERT_NONE, disabling certificate verification.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Use ssl.CERT_REQUIRED (the default) to enforce certificate validation.",
                        snippet=self._snippet(source_lines, node.lineno),
                    )
        return None

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
