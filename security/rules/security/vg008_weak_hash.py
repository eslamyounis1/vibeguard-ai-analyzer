import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_WEAK_HASHES = {"md5", "sha1", "sha"}


class WeakHashRule(SecurityRule):
    rule_id = "weak_hash_algorithm"
    title = "Weak Hash Algorithm"
    description = "MD5/SHA-1 are cryptographically broken and must not be used for security purposes."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in _WEAK_HASHES
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"hashlib.{node.func.attr}() uses a weak/broken hash algorithm.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use hashlib.sha256() or better. For passwords, use bcrypt/argon2.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
