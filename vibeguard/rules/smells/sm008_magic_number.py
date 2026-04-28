import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule

_ALLOWED = frozenset({0, 1, -1, 2, 0.0, 1.0, -1.0, 100, 10, 1000})


class _MagicNumberVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings_data: list[tuple[int, int, object]] = []  # (line, col, value)
        self._in_range = False
        self._in_slice = False

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id == "range":
            old, self._in_range = self._in_range, True
            self.generic_visit(node)
            self._in_range = old
        else:
            self.generic_visit(node)

    def visit_Slice(self, node: ast.Slice) -> None:
        old, self._in_slice = self._in_slice, True
        self.generic_visit(node)
        self._in_slice = old

    def visit_Constant(self, node: ast.Constant) -> None:
        if not self._in_range and not self._in_slice:
            if isinstance(node.value, (int, float)) and node.value not in _ALLOWED:
                self.findings_data.append((node.lineno, node.col_offset, node.value))
        self.generic_visit(node)


class MagicNumberRule(SmellRule):
    rule_id = "magic_number"
    title = "Magic Number"
    description = "Unexplained numeric literals make code hard to understand and maintain."
    severity = Severity.INFO

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        visitor = _MagicNumberVisitor()
        visitor.visit(tree)
        findings = []
        for lineno, col, value in visitor.findings_data:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message=f"Magic number {value!r} found in expression.",
                severity=self.severity,
                file=file_path,
                line=lineno,
                col=col,
                category=self.category,
                suggestion="Extract into a named constant: MAX_RETRIES = 5.",
                snippet=self._snippet(source_lines, lineno),
            ))
        return findings
