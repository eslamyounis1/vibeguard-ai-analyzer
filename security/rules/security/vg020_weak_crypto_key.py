"""VG020 — Weak Cryptographic Key Size (CWE-326).

Detects:
- RSA/DSA/ElGamal key generation with key size < 2048 bits.
- Use of broken symmetric ciphers: DES, DES3, ARC4/RC4.
"""

import ast
from typing import List, Optional

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_ASYMMETRIC_CLASSES = frozenset({"RSA", "DSA", "ElGamal"})
_BROKEN_CIPHERS = frozenset({"DES", "DES3", "ARC4", "RC4", "Blowfish"})
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

            # RSA.generate(bits) / DSA.generate(bits)
            if (
                func.attr == "generate"
                and isinstance(func.value, ast.Name)
                and func.value.id in _ASYMMETRIC_CLASSES
            ):
                key_size = self._key_size(node)
                if key_size is not None and key_size < _MIN_KEY_BITS:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=(
                                f"{func.value.id}.generate({key_size}) uses a key size below "
                                f"{_MIN_KEY_BITS} bits, which is insufficient for post-2030 security "
                                "(NIST SP 800-57)."
                            ),
                            severity=self.severity,
                            file=file_path,
                            line=node.lineno,
                            suggestion=f"Use {func.value.id}.generate({_MIN_KEY_BITS}) or larger.",
                            snippet=self._snippet(source_lines, node.lineno),
                        )
                    )

            # DES.new() / ARC4.new() etc.
            if (
                func.attr == "new"
                and isinstance(func.value, ast.Name)
                and func.value.id in _BROKEN_CIPHERS
            ):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"{func.value.id} is a broken or weak symmetric cipher; "
                            "it must not be used for security-sensitive operations."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Replace with AES.new() (mode GCM or CBC) with a 128-bit or 256-bit key.",
                        snippet=self._snippet(source_lines, node.lineno),
                    )
                )

        return findings

    def _key_size(self, node: ast.Call) -> Optional[int]:
        """Return the key size constant from RSA.generate(bits) / DSA.generate(bits)."""
        # First positional argument
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
            return node.args[0].value
        # 'bits' keyword argument
        for kw in node.keywords:
            if kw.arg == "bits" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return kw.value.value
        return None
