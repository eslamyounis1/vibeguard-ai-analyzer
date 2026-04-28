import ast
from typing import List

from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.rules.smells.base import SmellRule

MAX_LINES = 50


class LongFunctionRule(SmellRule):
    rule_id = "long_function"
    title = "Long Function"
    description = f"Functions exceeding {MAX_LINES} lines are hard to understand and test."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            lines = (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno + 1
            if lines > MAX_LINES:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Function '{node.name}' spans {lines} lines (limit {MAX_LINES}).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion="Break it into smaller, single-responsibility functions.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
