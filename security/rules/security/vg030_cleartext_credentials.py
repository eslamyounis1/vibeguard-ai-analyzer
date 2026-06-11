import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_CREDENTIAL_NAMES = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth_token", "access_token", "private_key", "credential",
})
_WRITE_METHODS = frozenset({"write", "execute", "set", "insert", "add"})
_STORAGE_FUNCS = frozenset({"open", "write"})


class CleartextCredentialsRule(SecurityRule):
    rule_id = "cleartext_credentials"
    title = "Cleartext Storage of Credentials (CWE-312)"
    description = "Credentials written to storage without hashing or encryption."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_cleartext_write(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Credential-named variable written to storage without apparent hashing.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Hash passwords with bcrypt/argon2 before storage. Encrypt secrets with proper key management.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_cleartext_write(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr not in _WRITE_METHODS:
            return False
        # Check if any arg is a credential-named variable
        all_args = list(node.args) + [kw.value for kw in node.keywords if kw.arg]
        for arg in all_args:
            if isinstance(arg, ast.Name) and any(name in arg.id.lower() for name in _CREDENTIAL_NAMES):
                return True
        return False
