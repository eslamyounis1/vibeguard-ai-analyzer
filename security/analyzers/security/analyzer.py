import ast
from typing import List

from security.models.finding import Finding
from security.rules.security.base import SecurityRule
from security.rules.security.vg001_eval import EvalUsageRule
from security.rules.security.vg002_exec import ExecUsageRule
from security.rules.security.vg003_hardcoded_secrets import HardcodedSecretsRule
from security.rules.security.vg004_insecure_random import InsecureRandomRule
from security.rules.security.vg005_subprocess import SubprocessShellRule
from security.rules.security.vg006_pickle import PickleRule
from security.rules.security.vg007_assert import SecurityAssertRule
from security.rules.security.vg008_weak_hash import WeakHashRule
from security.rules.security.vg009_os_shell import OsShellRule

_DEFAULT_RULES: List[SecurityRule] = [
    EvalUsageRule(),
    ExecUsageRule(),
    HardcodedSecretsRule(),
    InsecureRandomRule(),
    SubprocessShellRule(),
    PickleRule(),
    SecurityAssertRule(),
    WeakHashRule(),
    OsShellRule(),
]


class SecurityAnalyzer:
    def __init__(self, rules: List[SecurityRule] | None = None) -> None:
        self.rules = rules if rules is not None else _DEFAULT_RULES

    def analyze(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(tree, file_path, source_lines))
        return findings
