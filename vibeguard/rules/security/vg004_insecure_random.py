import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule

_RANDOM_FUNCTIONS = frozenset({
    "random", "randint", "randrange", "choice", "choices",
    "uniform", "shuffle", "sample", "getrandbits",
})


class InsecureRandomRule(SecurityRule):
    rule_id = "insecure_random"
    title = "Insecure Randomness"
    description = (
        "The random module uses a pseudo-random generator not suitable for "
        "cryptographic or security-sensitive use. Prefer the secrets module."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        has_random_import = False
        direct_aliases: dict[str, str] = {}  # alias → original function name

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "random":
                        has_random_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module == "random":
                    for alias in node.names:
                        if alias.name in _RANDOM_FUNCTIONS:
                            key = alias.asname if alias.asname else alias.name
                            direct_aliases[key] = alias.name

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            func_name = None

            if (
                has_random_import
                and isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "random"
                and func.attr in _RANDOM_FUNCTIONS
            ):
                func_name = f"random.{func.attr}"
            elif isinstance(func, ast.Name) and func.id in direct_aliases:
                func_name = f"random.{direct_aliases[func.id]}"

            if func_name:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"{func_name}() is not cryptographically secure. "
                        "Use the 'secrets' module for security-sensitive randomness."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
