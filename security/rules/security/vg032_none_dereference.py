import ast
from typing import List, Set

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_NONE_RETURNING_FUNCS = frozenset({
    "find", "get", "first", "one_or_none", "scalar_one_or_none",
    "fetchone", "pop",
})


class NoneDereferenceRule(SecurityRule):
    rule_id = "none_dereference"
    title = "Potential None Dereference (CWE-476)"
    description = "Return value of a function that may return None is used without a None check."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        # Find assignments like: x = obj.find(...) or x = dict.get(...)
        # then check if x is used without None check
        assigned_maybe_none: dict[str, int] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if (
                    len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Call)
                    and self._is_none_returning(node.value)
                ):
                    assigned_maybe_none[node.targets[0].id] = node.lineno

        # Look for attribute accesses on those variables without None guard
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in assigned_maybe_none
            ):
                assign_line = assigned_maybe_none[node.value.id]
                if node.lineno > assign_line:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=f"Variable '{node.value.id}' may be None; accessing .{node.attr} without a None check.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion=f"Check 'if {node.value.id} is not None:' before accessing its attributes.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    def _is_none_returning(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in _NONE_RETURNING_FUNCS
        return False
