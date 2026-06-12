"""VG020 — Weak Cryptographic Key Size (CWE-326).

Detects:
- RSA/DSA/ElGamal key generation with key size < 3072 bits (NIST SP 800-57).
- Use of broken symmetric ciphers: DES, DES3, ARC4/RC4.

Supports both APIs:
- PyCryptodome: RSA.generate(2048), DSA.generate(1024)
- cryptography lib: rsa.generate_private_key(key_size=2048), dsa.generate_parameters(key_size=1024)
"""

import ast
from typing import List, Optional

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_ASYMMETRIC_CLASSES = frozenset({"RSA", "DSA", "ElGamal"})
_BROKEN_CIPHERS = frozenset({"DES", "DES3", "ARC4", "RC4", "Blowfish"})
# PyCryptodome module names (lowercase) that wrap asymmetric key gen
_ASYMMETRIC_MODULES = frozenset({"rsa", "dsa", "elgamal"})
_KEYGEN_FUNCS = frozenset({"generate_private_key", "generate_parameters", "generate"})
_MIN_KEY_BITS = 3072


class WeakCryptoKeyRule(SecurityRule):
    rule_id = "weak_crypto_key"
    title = "Weak Cryptographic Key Size"
    description = (
        "RSA/DSA keys below 3072 bits and broken ciphers (DES, RC4) are "
        "cryptographically weak. NIST SP 800-57 recommends 3072+ bits for "
        "keys intended for use beyond 2030."
    )
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            obj_name = func.value.id if isinstance(func.value, ast.Name) else ""

            # PyCryptodome: RSA.generate(bits) / DSA.generate(bits)
            if func.attr == "generate" and obj_name in _ASYMMETRIC_CLASSES:
                key_size = self._key_size_positional(node)
                if key_size is not None and key_size < _MIN_KEY_BITS:
                    findings.append(self._finding(
                        node, file_path, source_lines,
                        f"{obj_name}.generate({key_size}) uses a key size below "
                        f"{_MIN_KEY_BITS} bits (NIST SP 800-57).",
                        f"Use {obj_name}.generate({_MIN_KEY_BITS}) or larger.",
                    ))

            # cryptography lib: rsa.generate_private_key / dsa.generate_parameters
            if func.attr in _KEYGEN_FUNCS and obj_name in _ASYMMETRIC_MODULES:
                key_size = self._key_size_kwarg(node)
                if key_size is not None and key_size < _MIN_KEY_BITS:
                    findings.append(self._finding(
                        node, file_path, source_lines,
                        f"{obj_name}.{func.attr}(key_size={key_size}) uses a key size below "
                        f"{_MIN_KEY_BITS} bits (NIST SP 800-57).",
                        f"Use key_size={_MIN_KEY_BITS} or larger.",
                    ))

            # DES.new() / ARC4.new() etc.
            if func.attr == "new" and obj_name in _BROKEN_CIPHERS:
                findings.append(self._finding(
                    node, file_path, source_lines,
                    f"{obj_name} is a broken or weak symmetric cipher.",
                    "Replace with AES.new() (mode GCM or CBC) with a 128-bit or 256-bit key.",
                ))

        return findings

    def _key_size_positional(self, node: ast.Call) -> Optional[int]:
        """Return the key size from the first positional int argument."""
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
            return node.args[0].value
        for kw in node.keywords:
            if kw.arg == "bits" and isinstance(kw.value, ast.Constant):
                return int(kw.value.value)
        return None

    def _key_size_kwarg(self, node: ast.Call) -> Optional[int]:
        """Return the key_size from keyword arg or second positional argument."""
        for kw in node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                return int(kw.value.value)
        # dsa.generate_parameters(key_size=1024) may also pass positionally
        if node.args and len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
            v = node.args[0].value
            if isinstance(v, int) and v <= 16384:
                return v
        if node.args and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            v = node.args[1].value
            if isinstance(v, int) and v <= 16384:
                return v
        return None

    def _finding(self, node: ast.AST, file_path: str, source_lines: List[str],
                 message: str, suggestion: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion=suggestion,
            snippet=self._snippet(source_lines, node.lineno),
        )
