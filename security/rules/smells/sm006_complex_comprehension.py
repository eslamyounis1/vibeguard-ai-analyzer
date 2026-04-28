import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.smells.base import SmellRule


class ComplexComprehensionRule(SmellRule):
    rule_id = "complex_comprehension"
    title = "Complex Comprehension"
    description = "List comprehensions with more than 2 generators are hard to read."
    severity = Severity.LOW

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ListComp) and len(node.generators) > 2:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"List comprehension has {len(node.generators)} generators — hard to read.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion="Replace with an explicit for-loop with named variables.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
