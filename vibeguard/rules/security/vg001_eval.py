import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule


class EvalUsageRule(SecurityRule):
    rule_id = "VG001"
    title = "Use of eval()"
    description = "Calling eval() executes arbitrary code and is a critical security risk."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "eval"
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Use of eval() is insecure and may allow arbitrary code execution.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
