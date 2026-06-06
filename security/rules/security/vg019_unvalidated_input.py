import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_REQUEST_SOURCES = frozenset(
    {
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.data",
        "request.GET",
        "request.POST",
        "request.query_params",
        "request.path_params",
    }
)
_SENSITIVE_SINK_ATTRS = frozenset(
    {
        "open",
        "system",
        "popen",
        "execute",
        "executemany",
        "get",
        "post",
        "urlopen",
        "redirect",
        "xpath",
        "loads",
        "load",
    }
)


class UnvalidatedInputRule(SecurityRule):
    rule_id = "unvalidated_user_input"
    title = "Unvalidated User Input to Sensitive Sink"
    description = "Raw request or stdin input passed directly to a security-sensitive operation."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            if not self._call_uses_unvalidated_input(node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="User-controlled input flows directly into a sensitive function without validation.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Validate, normalize, and allow-list user input before using it in file, network, or query operations.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _call_uses_unvalidated_input(self, node: ast.Call) -> bool:
        if not self._is_sensitive_sink(node):
            return False
        for arg in list(node.args) + [kw.value for kw in node.keywords if kw.arg]:
            if self._contains_unvalidated_source(arg):
                return True
        return False

    def _is_sensitive_sink(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id in {"open", "eval", "exec", "redirect"}
        if isinstance(func, ast.Attribute):
            return func.attr in _SENSITIVE_SINK_ATTRS
        return False

    def _contains_unvalidated_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        if isinstance(node, ast.Attribute):
            name = full_attr_name(node)
            if name in _REQUEST_SOURCES:
                return True
            if isinstance(node.value, ast.Name) and node.value.id == "request" and node.attr in {
                "args",
                "form",
                "values",
                "json",
                "data",
                "GET",
                "POST",
                "query_params",
                "path_params",
            }:
                return True
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            base = full_attr_name(node.value)
            if base in _REQUEST_SOURCES or (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "request"
                and node.value.attr in {"args", "form", "values", "GET", "POST"}
            ):
                return True
        for child in ast.iter_child_nodes(node):
            if self._contains_unvalidated_source(child):
                return True
        return False
