import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class InsecureTmpFileRule(SecurityRule):
    rule_id = "insecure_tmpfile"
    title = "Insecure Temporary File (CWE-377)"
    description = "tempfile.mktemp() is deprecated and has a race condition between name generation and use."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_mktemp = (
                (isinstance(func, ast.Attribute) and func.attr == "mktemp") or
                (isinstance(func, ast.Name) and func.id == "mktemp")
            )
            if is_mktemp:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="tempfile.mktemp() creates a race condition; use tempfile.mkstemp() or NamedTemporaryFile instead.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Replace mktemp() with tempfile.mkstemp() or tempfile.NamedTemporaryFile(delete=False).",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
