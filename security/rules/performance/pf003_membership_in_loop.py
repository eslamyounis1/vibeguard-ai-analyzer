import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.performance.base import PerformanceRule


class MembershipInLoopRule(PerformanceRule):
    rule_id = "membership_in_loop"
    title = "Membership Test Against Literal Collection in Loop"
    description = "Repeated 'x in [..]' inside a loop is O(n); a set gives O(1) lookups."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        loops = [n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))]
        matches: dict[int, ast.Compare] = {}
        for loop in loops:
            for node in ast.walk(loop):
                if self._is_list_membership(node):
                    matches[id(node)] = node  # dedupe across nested loops

        findings = []
        for node in sorted(matches.values(), key=lambda n: (n.lineno, n.col_offset)):
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Membership test against a list/tuple literal inside a loop is O(n) per check.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                category=self.category,
                suggestion="Use a set literal {..} for O(1) membership lookups.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _is_list_membership(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and isinstance(node.comparators[0], (ast.List, ast.Tuple))
            and bool(node.comparators[0].elts)
        )
