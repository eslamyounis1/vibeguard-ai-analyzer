import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.performance.base import PerformanceRule


class NestedLoopRule(PerformanceRule):
    rule_id = "nested_loop"
    title = "Nested Loop"
    description = "Nested loops can produce O(n²) or worse complexity."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue
            for child in ast.walk(node):
                if child is node:
                    continue
                if isinstance(child, (ast.For, ast.While)):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="Nested loop detected — potential O(n²) or worse complexity.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        category=self.category,
                        suggestion="Consider vectorisation (numpy), dict/set lookups, or algorithmic restructuring.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
                    break
        return findings
