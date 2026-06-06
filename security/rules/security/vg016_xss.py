import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import call_matches, first_arg, full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_UNSAFE_MARKUP = frozenset(
    {
        "markupsafe.Markup",
        "Markup",
        "mark_safe",
        "django.utils.safestring.mark_safe",
    }
)
_TEMPLATE_FUNCS = frozenset({"render_template_string", "Template"})


class UnsafeHtmlOutputRule(SecurityRule):
    rule_id = "unsafe_html_output"
    title = "Unsafe HTML / XSS Output"
    description = "Rendering unescaped user content in HTML enables cross-site scripting."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            if self._is_unsafe_markup(node):
                arg = first_arg(node)
                if arg and is_non_constant(arg):
                    findings.append(self._finding(node, file_path, source_lines, "User content is marked safe for HTML without escaping."))
                continue
            if self._is_render_template_string(node):
                arg = first_arg(node)
                if arg and is_non_constant(arg):
                    findings.append(
                        self._finding(
                            node,
                            file_path,
                            source_lines,
                            "Template string includes non-constant data and may allow XSS.",
                        )
                    )
        return findings

    def _is_unsafe_markup(self, node: ast.Call) -> bool:
        name = full_attr_name(node.func) if isinstance(node.func, ast.Attribute) else ""
        if isinstance(node.func, ast.Name) and node.func.id in {"Markup", "mark_safe"}:
            return True
        return name in _UNSAFE_MARKUP or call_matches(node, _UNSAFE_MARKUP)

    def _is_render_template_string(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute) and node.func.attr in _TEMPLATE_FUNCS:
            return True
        if isinstance(node.func, ast.Name) and node.func.id in _TEMPLATE_FUNCS:
            return True
        return False

    def _finding(self, node: ast.Call, file_path: str, source_lines: List[str], message: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Escape output (html.escape / Jinja autoescape) and never mark untrusted input as safe.",
            snippet=self._snippet(source_lines, node.lineno),
        )
