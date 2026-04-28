import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.performance.base import PerformanceRule


class StringConcatInLoopRule(PerformanceRule):
    rule_id = "string_concat_in_loop"
    title = "String Concatenation in Loop"
    description = "Using += on strings inside a loop creates O(n²) copies."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="String concatenation with '+=' inside a loop creates O(n²) copies.",
                        severity=self.severity,
                        file=file_path,
                        line=child.lineno,
                        category=self.category,
                        suggestion="Collect parts in a list and join at the end: ''.join(parts).",
                        snippet=self._snippet(source_lines, child.lineno),
                    ))
                    break
        return findings
