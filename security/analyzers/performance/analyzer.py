import ast
from typing import List

from security.models.finding import Finding
from security.rules.performance.base import PerformanceRule
from security.rules.performance.pf001_nested_loop import NestedLoopRule
from security.rules.performance.pf002_string_concat_loop import StringConcatInLoopRule

_DEFAULT_RULES: List[PerformanceRule] = [
    NestedLoopRule(),
    StringConcatInLoopRule(),
]


class PerformanceAnalyzer:
    def __init__(self, rules: List[PerformanceRule] | None = None) -> None:
        self.rules = rules if rules is not None else _DEFAULT_RULES

    def analyze(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, file_path, source_lines))
        return findings
