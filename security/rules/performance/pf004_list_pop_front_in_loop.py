"""PF004 — list.pop(0) inside a loop.

``list.pop(0)`` (or ``list.pop(i)`` for any non-negative literal index) shifts
every remaining element one position, making the loop O(n²). This pattern was
observed in gpt-4o's implementation of ``strange_sort_list`` (HumanEval/70),
where it caused a 12.6× slowdown at n=50 000 compared to a two-pointer approach.

Fix: use ``collections.deque`` with ``popleft()``, or restructure with index
pointers so no shifting is required.
"""
import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.performance.base import PerformanceRule


class ListPopFrontInLoopRule(PerformanceRule):
    rule_id = "list_pop_front_in_loop"
    title = "list.pop(0) Inside a Loop"
    description = (
        "Calling list.pop(0) (or any non-negative index) inside a loop is O(n) "
        "per call, making the loop O(n²) overall."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set[int] = set()  # deduplicate by node id across nested loops

        for loop in ast.walk(tree):
            if not isinstance(loop, (ast.For, ast.While)):
                continue
            for node in ast.walk(loop):
                if id(node) in seen:
                    continue
                if self._is_pop_front(node):
                    seen.add(id(node))
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            "list.pop(0) inside a loop shifts all remaining elements "
                            "on every iteration, making the loop O(n²)."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        category=self.category,
                        suggestion=(
                            "Use collections.deque with popleft() for O(1) front removal, "
                            "or restructure with integer index pointers to avoid shifting."
                        ),
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    @staticmethod
    def _is_pop_front(node: ast.AST) -> bool:
        """Return True if node is a call to .pop(<non-negative integer literal>)."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "pop"):
            return False
        # .pop() with no args removes the last element — not a front-removal issue
        if len(node.args) != 1:
            return False
        arg = node.args[0]
        # Support both Python 3.8+ ast.Constant and older ast.Num
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value >= 0:
            return True
        if isinstance(arg, ast.UnaryOp) and isinstance(arg.op, ast.USub):
            return False  # negative index is a back-removal — fine
        return False
