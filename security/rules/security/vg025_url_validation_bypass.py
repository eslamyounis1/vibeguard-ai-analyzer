import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class UrlValidationBypassRule(SecurityRule):
    rule_id = "url_validation_bypass"
    title = "URL Domain Validation Bypass (CWE-20)"
    description = "Using str.endswith() to validate URL domains is bypassable via suffix attacks."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_endswith_on_netloc(node):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Domain validation with .endswith() is vulnerable to suffix attacks (e.g. 'evil.trusted.com').",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Use exact match: parsed.netloc == 'trusted.com' or parsed.netloc.endswith('.trusted.com').",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _is_endswith_on_netloc(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr != "endswith":
            return False
        # Check if called on netloc attribute
        obj = func.value
        if isinstance(obj, ast.Attribute) and obj.attr == "netloc":
            return True
        # Or on a variable named netloc / host / domain
        if isinstance(obj, ast.Name) and obj.id in {"netloc", "host", "domain", "hostname"}:
            return True
        return False
