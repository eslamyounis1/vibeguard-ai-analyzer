import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_XXE_PARSE_FUNCS = frozenset({"parse", "fromstring", "XML", "iterparse"})
_XXE_SAFE_IMPORTS = frozenset({"defusedxml"})


class XxeRule(SecurityRule):
    rule_id = "xxe_vulnerability"
    title = "XML External Entity Injection (CWE-611)"
    description = "Parsing XML without disabling external entities allows XXE attacks."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        # If defusedxml is imported, skip — it's safe by default
        uses_defusedxml = self._uses_defusedxml(tree)
        if uses_defusedxml:
            return []

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_unsafe_xml_parse(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="XML parsed with stdlib ET/lxml without disabling external entities.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use defusedxml.ElementTree or configure lxml parser with resolve_entities=False.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _uses_defusedxml(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("defusedxml"):
                        return True
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("defusedxml"):
                    return True
        return False

    def _is_unsafe_xml_parse(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _XXE_PARSE_FUNCS:
                if isinstance(func.value, ast.Attribute):
                    # e.g. ET.parse or etree.parse
                    parent = func.value.attr if isinstance(func.value.attr, str) else ""
                    if parent in {"ElementTree", "etree", "ET"}:
                        return True
                if isinstance(func.value, ast.Name):
                    mod = func.value.id
                    if mod in {"ET", "etree", "ElementTree"}:
                        return True
        if isinstance(func, ast.Name) and func.id in _XXE_PARSE_FUNCS:
            return True
        return False
