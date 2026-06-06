import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import first_arg, full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_REDIRECT_FUNCS = frozenset({"redirect", "RedirectResponse", "HttpResponseRedirect", "redirect_to"})


class OpenRedirectRule(SecurityRule):
    rule_id = "open_redirect"
    title = "Open Redirect"
    description = "Redirects to user-controlled URLs can be abused for phishing."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            func = node.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name not in _REDIRECT_FUNCS:
                continue
            target = first_arg(node)
            if target is None:
                for kw in node.keywords:
                    if kw.arg in {"url", "location", "to"}:
                        target = kw.value
                        break
            if target is None or not is_non_constant(target):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Redirect target in '{full_attr_name(func) if isinstance(func, ast.Attribute) else name}' is not constant.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Allow-list redirect destinations or use relative paths validated against the application base URL.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings
