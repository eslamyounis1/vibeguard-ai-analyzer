import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import first_arg, full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_PATH_READ_ATTRS = frozenset({"read_text", "read_bytes", "write_text", "write_bytes", "open"})


class PathTraversalRule(SecurityRule):
    rule_id = "path_traversal"
    title = "Path Traversal via Dynamic File Path"
    description = "User-influenced paths passed to file operations can escape intended directories."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            target = self._sensitive_path_arg(node)
            if target is None or not is_non_constant(target):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="File path is built from non-constant data and may allow directory traversal.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Validate paths against an allow-list, use pathlib.Path.resolve(), and reject '..' segments.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _sensitive_path_arg(self, node: ast.Call) -> ast.AST | None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            return first_arg(node)
        if isinstance(func, ast.Attribute):
            attr = full_attr_name(func)
            if attr == "Path" or (func.attr == "open" and isinstance(func.value, ast.Name)):
                return first_arg(node)
            if func.attr in _PATH_READ_ATTRS and isinstance(func.value, ast.Call):
                inner = func.value
                if isinstance(inner.func, ast.Name) and inner.func.id == "Path":
                    return first_arg(inner)
        return None
