import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_XML_BUILD_METHODS = frozenset({"tostring", "SubElement", "Element"})


class XmlInjectionRule(SecurityRule):
    rule_id = "xml_injection"
    title = "XML Injection (CWE-091)"
    description = "User input interpolated into XML strings can break XML structure or inject elements."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.JoinedStr, ast.BinOp)):
                if self._is_xml_construction(node) and self._contains_dynamic(node):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="XML content built from dynamic values via string interpolation.",
                        severity=self.severity,
                        file=file_path,
                        line=getattr(node, "lineno", None),
                        suggestion="Use xml.etree.ElementTree API to build XML, or escape values with xml.sax.saxutils.escape().",
                        snippet=self._snippet(source_lines, getattr(node, "lineno", None)),
                    ))
        return findings

    def _is_xml_construction(self, node: ast.AST) -> bool:
        # Check if the literal parts contain XML tags
        literals = []
        if isinstance(node, ast.JoinedStr):
            literals = [v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        elif isinstance(node, ast.BinOp):
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    literals.append(child.value)
        combined = "".join(literals)
        return "<" in combined and ">" in combined

    def _contains_dynamic(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp):
            return is_non_constant(node)
        return False
