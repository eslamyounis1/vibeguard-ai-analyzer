import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_RESPONSE_FUNCS = frozenset({"Response", "make_response", "HttpResponse", "StreamingHttpResponse"})


class ImproperOutputEncodingRule(SecurityRule):
    rule_id = "improper_output_encoding"
    title = "Improper Output Encoding (CWE-116)"
    description = "Raw bytes or strings written to HTTP response without proper encoding/escaping."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_response_construction(node):
                continue
            if node.args and is_non_constant(node.args[0]):
                arg = node.args[0]
                # Flag if it's raw bytes concatenation or dynamic content
                if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Name)):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="HTTP response constructed with dynamic content without explicit encoding.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Encode output with the appropriate content type. Use render_template for HTML.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    def _is_response_construction(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id in _RESPONSE_FUNCS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _RESPONSE_FUNCS:
            return True
        return False
