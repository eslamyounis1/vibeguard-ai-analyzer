import ast
import re
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

# Patterns indicative of catastrophic backtracking
_REDOS_PATTERNS = [
    re.compile(r'\([^)]*[+*][^)]*\)[+*]'),           # (a+)+ or (a*)* etc.
    re.compile(r'\([^)]*[+*]\)[+*]'),                 # (a+)* style
    re.compile(r'\([^)]*\|[^)]*\)[+*{]'),             # (a|b)+ alternation
    re.compile(r'(\.\*){2,}'),                         # .*.* repeated
    re.compile(r'\([^)]+\)\{[0-9]+,[0-9]*\}[+*]'),    # (a){n,m}+
]


class ReDoSRule(SecurityRule):
    rule_id = "redos_vulnerability"
    title = "Regular Expression Denial of Service (CWE-400)"
    description = "Complex regex patterns with nested quantifiers may cause catastrophic backtracking."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            pattern_str = self._extract_regex_pattern(node)
            if pattern_str and self._is_vulnerable_pattern(pattern_str):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Regex pattern '{pattern_str[:80]}' has nested quantifiers that may cause ReDoS.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Rewrite the pattern to avoid nested quantifiers, or use re.timeout / limit input length.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _extract_regex_pattern(self, node: ast.Call) -> str | None:
        func = node.func
        re_methods = frozenset({"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"})
        if isinstance(func, ast.Attribute) and func.attr in re_methods:
            if isinstance(func.value, ast.Name) and func.value.id == "re":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    return node.args[0].value
        return None

    def _is_vulnerable_pattern(self, pattern: str) -> bool:
        for p in _REDOS_PATTERNS:
            if p.search(pattern):
                return True
        return False
