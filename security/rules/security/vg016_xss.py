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
_RESPONSE_FUNCS = frozenset({"make_response", "Response", "HttpResponse"})


class UnsafeHtmlOutputRule(SecurityRule):
    rule_id = "unsafe_html_output"
    title = "Unsafe HTML / XSS Output"
    description = "Rendering unescaped user content in HTML enables cross-site scripting."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        primary_lines: set[int] = set()
        for node in iter_calls(tree):
            if self._is_unsafe_markup(node):
                arg = first_arg(node)
                if arg and is_non_constant(arg):
                    primary_lines.add(node.lineno)
                    findings.append(self._finding(node, file_path, source_lines, "User content is marked safe for HTML without escaping."))
                continue
            if self._is_render_template_string(node):
                arg = first_arg(node)
                if arg and is_non_constant(arg):
                    primary_lines.add(node.lineno)
                    findings.append(
                        self._finding(
                            node,
                            file_path,
                            source_lines,
                            "Template string includes non-constant data and may allow XSS.",
                        )
                    )
                continue
            if self._is_response_func(node):
                arg = first_arg(node)
                if arg and self._contains_user_data(arg):
                    findings.append(
                        self._finding(
                            node,
                            file_path,
                            source_lines,
                            "Response body built from non-constant data may include unescaped user input, enabling XSS.",
                        )
                    )
        # Check for f-string returns in functions whose docstring mentions HTML
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._has_html_docstring(node):
                    for ret in ast.walk(node):
                        if isinstance(ret, ast.Return) and ret.value is not None:
                            if isinstance(ret.value, ast.JoinedStr) and is_non_constant(ret.value):
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        title=self.title,
                                        message=(
                                            f"Function '{node.name}' returns an f-string with non-constant "
                                            "content in an HTML context (docstring mentions 'html'). "
                                            "This may expose unescaped user data as XSS."
                                        ),
                                        severity=self.severity,
                                        file=file_path,
                                        line=ret.lineno,
                                        suggestion="Escape output with html.escape() before returning HTML content.",
                                        snippet=self._snippet(source_lines, ret.lineno),
                                    )
                                )
        # Secondary taint-lite check — catches XSS paths via intermediate variables
        try:
            from security.taint.tracer import trace_taint
            taint_paths = trace_taint("\n".join(source_lines), sink_categories=["xss"])
            for path in taint_paths:
                if path.sink_lineno not in primary_lines:
                    primary_lines.add(path.sink_lineno)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"Taint-lite: parameter '{path.source_param}' flows to "
                            f"'{path.sink_call}' via {' -> '.join(path.path_nodes) or 'direct'}."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=path.sink_lineno,
                        suggestion="Escape output (html.escape / Jinja autoescape) and never mark untrusted input as safe.",
                        snippet=self._snippet(source_lines, path.sink_lineno),
                    ))
        except Exception:
            pass  # taint analysis is best-effort

        return findings

    def _has_html_docstring(self, func_node: ast.FunctionDef) -> bool:
        """Return True if the function's docstring contains 'html' (case-insensitive)."""
        if not func_node.body:
            return False
        first = func_node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            return "html" in first.value.value.lower()
        return False

    def _is_unsafe_markup(self, node: ast.Call) -> bool:
        name = full_attr_name(node.func) if isinstance(node.func, ast.Attribute) else ""
        if isinstance(node.func, ast.Name) and node.func.id in {"Markup", "mark_safe"}:
            return True
        return name in _UNSAFE_MARKUP or call_matches(node, _UNSAFE_MARKUP)

    def _is_response_func(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name) and node.func.id in _RESPONSE_FUNCS:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _RESPONSE_FUNCS:
            return True
        return False

    def _contains_user_data(self, node: ast.AST) -> bool:
        """True if node is a BinOp(+) or JoinedStr with non-constant parts, or a bare Name/Subscript."""
        if isinstance(node, ast.JoinedStr):
            return is_non_constant(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return is_non_constant(node.left) or is_non_constant(node.right)
        if isinstance(node, (ast.Name, ast.Subscript, ast.Attribute)):
            return True
        return False

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
