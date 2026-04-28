import ast
from typing import List

from vibeguard.models.finding import Finding
from vibeguard.rules.smells.base import SmellRule
from vibeguard.rules.smells.sm001_long_function import LongFunctionRule
from vibeguard.rules.smells.sm002_too_many_params import TooManyParamsRule
from vibeguard.rules.smells.sm003_deep_nesting import DeepNestingRule
from vibeguard.rules.smells.sm004_high_complexity import HighComplexityRule
from vibeguard.rules.smells.sm005_missing_annotation import MissingReturnAnnotationRule
from vibeguard.rules.smells.sm006_complex_comprehension import ComplexComprehensionRule
from vibeguard.rules.smells.sm007_unused_variable import UnusedVariableRule
from vibeguard.rules.smells.sm008_magic_number import MagicNumberRule
from vibeguard.rules.smells.sm009_duplicate_block import DuplicateCodeBlockRule

_DEFAULT_RULES: List[SmellRule] = [
    LongFunctionRule(),
    TooManyParamsRule(),
    DeepNestingRule(),
    HighComplexityRule(),
    MissingReturnAnnotationRule(),
    ComplexComprehensionRule(),
    UnusedVariableRule(),
    MagicNumberRule(),
    DuplicateCodeBlockRule(),
]


class SmellAnalyzer:
    def __init__(self, rules: List[SmellRule] | None = None) -> None:
        self.rules = rules if rules is not None else _DEFAULT_RULES

    def analyze(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, file_path, source_lines))
        return findings
