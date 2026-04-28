import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule


class MissingReturnAnnotationRule(SmellRule):
    rule_id = "missing_return_annotation"
    title = "Missing Return Annotation"
    description = "Functions without return type annotations reduce readability and tooling support."
    severity = Severity.INFO

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.returns is None and node.name != "__init__":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Function '{node.name}' is missing a return type annotation.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion=f"Add a return type: def {node.name}(...) -> ReturnType:",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
