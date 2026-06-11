import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

# NIST SP 800-57 post-2030: minimum 3072 bits for RSA/DSA
_MIN_KEY_BITS = 3072
_WEAK_KEY_FUNCS = frozenset({"generate_private_key", "generate", "generate_parameters"})


class WeakCryptoKeyRule(SecurityRule):
    rule_id = "weak_crypto_key"
    title = "Weak Cryptographic Key Size"
    description = "RSA/DSA keys smaller than 3072 bits are below NIST SP 800-57 post-2030 recommendations."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            key_size = self._extract_key_size(node)
            if key_size is not None and key_size < _MIN_KEY_BITS:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Key size {key_size} bits is below the 3072-bit minimum (NIST SP 800-57).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use at least 3072-bit RSA/DSA keys, or prefer ECC (P-256 or higher).",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _extract_key_size(self, node: ast.Call) -> int | None:
        func = node.func
        func_name = ""
        if isinstance(func, ast.Attribute):
            func_name = func.attr
        elif isinstance(func, ast.Name):
            func_name = func.id

        if func_name not in _WEAK_KEY_FUNCS:
            return None

        # generate_private_key(public_exponent, key_size, backend) — RSA
        # rsa.generate_private_key(public_exponent=65537, key_size=2048, ...)
        for kw in node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                return int(kw.value.value)

        # Positional: rsa.generate_private_key(65537, 2048, backend)
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            return int(node.args[1].value)

        # dsa.generate_parameters(key_size=1024) or dsa.generate_parameters(1024)
        if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
            v = node.args[0].value
            if isinstance(v, int) and v <= 8192:
                return v

        return None
