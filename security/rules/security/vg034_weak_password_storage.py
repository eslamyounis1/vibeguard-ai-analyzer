import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_WEAK_HASHES = frozenset({"md5", "sha1", "sha"})
_PASSWORD_NAMES = frozenset({
    "password", "passwd", "pwd", "pass_",
    "user_password", "raw_password", "plain_password",
})


class WeakPasswordStorageRule(SecurityRule):
    rule_id = "weak_password_storage"
    title = "Insufficiently Protected Credentials (CWE-522)"
    description = "Passwords stored using MD5/SHA1 are easily cracked without a proper password hash."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_weak_hash(node):
                continue
            if self._hashes_password(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Password hashed with a weak algorithm (MD5/SHA1); use bcrypt, argon2, or scrypt.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use bcrypt.hashpw(), argon2-cffi, or Django's make_password() for password storage.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_weak_hash(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in _WEAK_HASHES
        if isinstance(func, ast.Name):
            return func.id in _WEAK_HASHES
        return False

    def _hashes_password(self, node: ast.Call) -> bool:
        all_args = list(node.args) + [kw.value for kw in node.keywords if kw.arg]
        for arg in all_args:
            if isinstance(arg, ast.Name):
                name_lower = arg.id.lower()
                if any(pw in name_lower for pw in _PASSWORD_NAMES):
                    return True
        return False
