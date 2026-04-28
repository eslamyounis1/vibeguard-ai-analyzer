import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule


class _UsageCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.assigned: dict[str, int] = {}  # name → first assignment line
        self.used: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id not in self.assigned:
                self.assigned[target.id] = node.lineno
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.used.add(node.id)
        self.generic_visit(node)


class UnusedVariableRule(SmellRule):
    rule_id = "unused_variable"
    title = "Unused Variable"
    description = "Variables assigned but never read add noise and may indicate a bug."
    severity = Severity.LOW

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        collector = _UsageCollector()
        collector.visit(tree)
        findings = []
        for name, lineno in collector.assigned.items():
            if name not in collector.used and not name.startswith("_") and name not in ("self", "cls"):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Variable '{name}' is assigned but never read.",
                    severity=self.severity,
                    file=file_path,
                    line=lineno,
                    category=self.category,
                    suggestion="Remove the assignment or prefix with '_' if intentionally unused.",
                    snippet=self._snippet(source_lines, lineno),
                ))
        return findings
