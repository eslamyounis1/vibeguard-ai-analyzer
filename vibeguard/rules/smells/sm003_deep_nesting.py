import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule

MAX_DEPTH = 4
_NESTING_NODES = (ast.For, ast.AsyncFor, ast.While, ast.If, ast.With, ast.AsyncWith, ast.Try, ast.ExceptHandler)


def _nesting_depth(node: ast.AST) -> int:
    max_depth = [0]

    def walk(n: ast.AST, depth: int) -> None:
        if isinstance(n, _NESTING_NODES):
            depth += 1
            max_depth[0] = max(max_depth[0], depth)
        for child in ast.iter_child_nodes(n):
            walk(child, depth)

    walk(node, 0)
    return max_depth[0]


class DeepNestingRule(SmellRule):
    rule_id = "deep_nesting"
    title = "Deep Nesting"
    description = f"Control flow nested more than {MAX_DEPTH} levels deep is hard to follow."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            depth = _nesting_depth(node)
            if depth > MAX_DEPTH:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Function '{node.name}' has nesting depth {depth} (limit {MAX_DEPTH}).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion="Use early returns/guard clauses or extract inner blocks into helpers.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
