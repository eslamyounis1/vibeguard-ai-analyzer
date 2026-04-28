import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class ExecUsageRule(SecurityRule):
    rule_id = "eval_exec_usage"
    title = "Use of exec()"
    description = "Calling exec() executes arbitrary code and is a critical security risk."
    severity = Severity.CRITICAL

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "exec"
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Use of exec() is insecure and may allow arbitrary code execution.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
