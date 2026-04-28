import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.smells.base import SmellRule

MAX_COMPLEXITY = 15
_BRANCH_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                 ast.ExceptHandler, ast.With, ast.AsyncWith, ast.comprehension)


def _cognitive_complexity(node: ast.AST) -> int:
    total = [0]

    def walk(n: ast.AST, depth: int) -> None:
        if isinstance(n, _BRANCH_NODES):
            total[0] += 1 + depth
            depth += 1
        elif isinstance(n, ast.BoolOp):
            total[0] += len(n.values) - 1
        for child in ast.iter_child_nodes(n):
            walk(child, depth)

    walk(node, 0)
    return total[0]


class HighComplexityRule(SmellRule):
    rule_id = "high_complexity"
    title = "High Cognitive Complexity"
    description = f"Functions with cognitive complexity above {MAX_COMPLEXITY} are error-prone."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cc = _cognitive_complexity(node)
            if cc > MAX_COMPLEXITY:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Function '{node.name}' has cognitive complexity {cc} (limit {MAX_COMPLEXITY}).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion="Decompose into smaller functions; reduce branching depth.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
