"""VG025 — URL Domain Validation Bypass (CWE-20).

Detects the suffix-bypass pattern where netloc/hostname from a parsed URL is
checked with ``endswith(domain)`` instead of a proper domain equality check.

The flaw: ``"evil-example.com".endswith("example.com")`` is ``True``, so any
attacker-controlled subdomain-prefix can pass the guard.

Example of vulnerable code:
    parsed = urlparse(target)
    if parsed.netloc.endswith(allowed_domain):   # bypass: evil-example.com
        return redirect(target)

Safe alternatives:
    - parsed.netloc == allowed_domain
    - parsed.netloc.endswith("." + allowed_domain) and parsed.netloc != allowed_domain
    - use an allow-list of complete origins
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_URL_ATTRS = frozenset({"netloc", "hostname", "host"})


class UrlValidationBypassRule(SecurityRule):
    rule_id = "url_validation_bypass"
    title = "URL Domain Validation Bypass"
    description = (
        "Using endswith() on a parsed URL netloc/hostname does not correctly validate "
        "the domain: 'evil-example.com'.endswith('example.com') is True, allowing bypass."
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
            if func.attr != "endswith":
                continue
            # The receiver of .endswith() must be a .netloc / .hostname / .host attribute
            receiver = func.value
            if not (isinstance(receiver, ast.Attribute) and receiver.attr in _URL_ATTRS):
                continue
            # Flag regardless of whether the argument is constant or variable —
            # even endswith('example.com') is bypassable with 'evil-example.com'
            if not node.args:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"endswith() on URL {receiver.attr} does not validate the domain "
                        "correctly: a prefix like 'evil-example.com' matches 'example.com'."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion=(
                        "Use exact equality (parsed.netloc == allowed_domain) or check "
                        "parsed.netloc.endswith('.' + allowed_domain) to prevent prefix bypass."
                    ),
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings
