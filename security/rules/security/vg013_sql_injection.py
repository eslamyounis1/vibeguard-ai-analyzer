import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_SQL_METHODS = frozenset({"execute", "executemany"})
_SQL_STARTERS = (
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "replace",
)


class SqlInjectionRule(SecurityRule):
    rule_id = "sql_query_construction"
    title = "Dynamic SQL Query Construction"
    description = "Constructing SQL queries with string interpolation can allow injection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not self._is_execute_call(node):
                continue
            if not node.args or not self._is_dynamic_sql(node.args[0]):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="SQL query is built with string interpolation or concatenation before execution.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Use parameterized queries and pass user values separately from the SQL string.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _is_execute_call(self, node: ast.Call) -> bool:
        func = node.func
        return isinstance(func, ast.Attribute) and func.attr in _SQL_METHODS

    def _is_dynamic_sql(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return self._joined_str_starts_with_sql(node)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Mod, ast.Add)) and self._contains_sql_literal(node):
                return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and self._contains_sql_literal(node.func.value)
        ):
            return True
        return False

    def _joined_str_starts_with_sql(self, node: ast.JoinedStr) -> bool:
        literal = "".join(
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        )
        return self._looks_like_sql(literal)

    def _contains_sql_literal(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and self._looks_like_sql(child.value)
            ):
                return True
        return False

    def _looks_like_sql(self, value: str) -> bool:
        return value.strip().lower().startswith(_SQL_STARTERS)
