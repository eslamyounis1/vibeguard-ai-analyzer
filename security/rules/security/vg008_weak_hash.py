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
        # Collect names imported directly from hashlib (e.g. `from hashlib import md5`)
        direct_imports: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "hashlib":
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    if alias.name in _WEAK_HASHES:
                        direct_imports.add(name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Pattern 1: hashlib.md5(...) / hashlib.sha1(...)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in _WEAK_HASHES
            ):
                algo = node.func.attr
                findings.append(self._make_finding(
                    f"hashlib.{algo}() uses a weak/broken hash algorithm.",
                    file_path, node.lineno, source_lines,
                ))
                continue

            # Pattern 2: direct call after from-import — md5(data)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in direct_imports
            ):
                findings.append(self._make_finding(
                    f"{node.func.id}() uses a weak/broken hash algorithm.",
                    file_path, node.lineno, source_lines,
                ))
                continue

            # Pattern 3: hashlib.new('md5', ...) — dynamic algorithm selection
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr == "new"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.lower() in _WEAK_HASHES
            ):
                algo = node.args[0].value
                findings.append(self._make_finding(
                    f"hashlib.new('{algo}', ...) uses a weak/broken hash algorithm.",
                    file_path, node.lineno, source_lines,
                ))

        return findings

    def _make_finding(self, message: str, file_path: str, lineno: int, source_lines: List[str]) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=self.severity,
            file=file_path,
            line=lineno,
            suggestion="Use hashlib.sha256() or better. For passwords, use bcrypt/argon2.",
            snippet=self._snippet(source_lines, lineno),
        )
