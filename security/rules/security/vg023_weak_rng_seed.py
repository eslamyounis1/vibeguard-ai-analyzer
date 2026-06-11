import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_WEAK_SEED_SOURCES = frozenset({
    "time", "time.time", "time.localtime", "time.gmtime",
    "os.getpid", "os.getppid",
})


class WeakRngSeedRule(SecurityRule):
    rule_id = "weak_rng_seed"
    title = "Weak RNG Seed (CWE-329)"
    description = "Seeding a PRNG with predictable values (time, PID) makes outputs guessable."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_seed_call(node):
                continue
            if node.args and self._is_weak_seed(node.args[0]):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="PRNG seeded with a predictable value; outputs may be guessable.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use os.urandom() or secrets module instead of random with a predictable seed.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_seed_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "seed":
            return True
        if isinstance(func, ast.Name) and func.id == "seed":
            return True
        return False

    def _is_weak_seed(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                name = f"{func.value.id if isinstance(func.value, ast.Name) else ''}.{func.attr}"
                return name in _WEAK_SEED_SOURCES or func.attr in {"time", "getpid", "getppid"}
            if isinstance(func, ast.Name):
                return func.id in _WEAK_SEED_SOURCES
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return True  # Hardcoded constant seed
        return False
