import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import first_arg, full_attr_name, is_non_constant, iter_calls
from security.rules.security.base import SecurityRule

_XPATH_ATTRS = frozenset({"xpath", "XPath", "find", "findall", "findtext", "iterfind"})


class XPathInjectionRule(SecurityRule):
    rule_id = "xpath_injection"
    title = "XPath Injection"
    description = "Dynamic XPath expressions built from user input can alter query logic."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in iter_calls(tree):
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in _XPATH_ATTRS:
                continue
            expr = first_arg(node)
            if expr is None:
                for kw in node.keywords:
                    if kw.arg in {"path", "xpath", "expr", "element_path"}:
                        expr = kw.value
                        break
            if expr is None or not is_non_constant(expr):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"XPath expression passed to '{full_attr_name(func)}' is not constant.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use parameterized XPath APIs or validate input against a strict allow-list.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings
