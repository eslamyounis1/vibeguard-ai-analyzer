import ast
from typing import List, Set

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_INPUT_SOURCES = frozenset({
    "request.args", "request.form", "request.values",
    "request.json", "request.GET", "request.POST",
})
_NUMERIC_CONVERT = frozenset({"int", "float", "Decimal"})


class DivideByZeroRule(SecurityRule):
    rule_id = "divide_by_zero"
    title = "Unguarded Division by User-Controlled Value (CWE-369)"
    description = "Dividing by a value derived from user input without zero-check can cause crashes."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        # Track variables assigned from user input or numeric conversion of user input
        user_vars: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if self._is_user_input_conversion(node.value):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            user_vars.add(tgt.id)

        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                if self._is_user_controlled(node.right, user_vars):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="Division by a user-controlled value without zero check may cause ZeroDivisionError.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Check that the divisor is non-zero before dividing, or use try/except ZeroDivisionError.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    def _is_user_input_conversion(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        func_name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        if func_name not in _NUMERIC_CONVERT:
            return False
        # Check if the argument ultimately comes from request or input()
        for arg in node.args:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "input":
                    return True
                if isinstance(sub, ast.Attribute) and f"{sub.value.id if isinstance(sub.value, ast.Name) else ''}.{sub.attr}" in {
                    "request.args", "request.form", "request.values", "request.json",
                    "request.GET", "request.POST",
                }:
                    return True
        return False

    def _is_user_controlled(self, node: ast.AST, user_vars: Set[str]) -> bool:
        if isinstance(node, ast.Name) and node.id in user_vars:
            return True
        return False
