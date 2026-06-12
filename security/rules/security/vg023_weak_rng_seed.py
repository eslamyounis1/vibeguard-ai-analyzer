"""VG023 — Weak Random Number Generator Seed (CWE-329).

Detects calls to ``random.seed()`` with predictable or absent entropy:
- No argument at all (relies on system time in older Python).
- A constant literal (e.g. ``random.seed(42)``).
- A time-based value (e.g. ``random.seed(int(time.time()))``).

A guessable seed lets an attacker reproduce the entire random sequence,
breaking tokens, nonces, or any security decision that depends on ``random``.
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_TIME_ATTRS = frozenset({"time", "clock", "monotonic", "perf_counter", "process_time"})


class WeakRngSeedRule(SecurityRule):
    rule_id = "weak_rng_seed"
    title = "Weak Random Number Seed"
    description = (
        "random.seed() with a predictable or absent value makes the entire "
        "random sequence guessable by an attacker."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "seed"
                and isinstance(func.value, ast.Name)
                and func.value.id == "random"
            ):
                continue

            # No argument — flag only when `import random` is explicit (avoids FP on bare seed())
            if not node.args and not node.keywords:
                if self._imports_random(tree):
                    findings.append(self._finding(
                        node, file_path, source_lines,
                        "random.seed() called without arguments; in older Python this seeds from "
                        "system time, producing a predictable sequence.",
                    ))
                continue

            seed_arg = node.args[0] if node.args else None
            if seed_arg is None:
                continue

            # Constant literal
            if isinstance(seed_arg, ast.Constant):
                findings.append(self._finding(
                    node, file_path, source_lines,
                    f"random.seed({seed_arg.value!r}) uses a constant seed — "
                    "the sequence is fully predictable and reproducible by anyone.",
                ))
                continue

            # Time-based seed
            if self._is_time_based(seed_arg):
                findings.append(self._finding(
                    node, file_path, source_lines,
                    "random.seed() uses a time-based value which is guessable "
                    "within a narrow window and not suitable for security use.",
                ))

        return findings

    def _imports_random(self, tree: ast.AST) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "random" for alias in node.names):
                    return True
        return False

    def _is_time_based(self, node: ast.AST) -> bool:
        """Return True if node is a time.* call, or wraps one (e.g. int(time.time()))."""
        if isinstance(node, ast.Call):
            func = node.func
            # time.time() / time.clock() etc.
            if isinstance(func, ast.Attribute) and func.attr in _TIME_ATTRS:
                return True
            # Bare time() (from import time)
            if isinstance(func, ast.Name) and func.id in _TIME_ATTRS:
                return True
            # int(time.time()) / float(time.time())
            if isinstance(func, ast.Name) and func.id in {"int", "float", "round"}:
                if node.args:
                    return self._is_time_based(node.args[0])
        return False

    def _finding(self, node: ast.AST, file_path: str, source_lines: List[str], msg: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=msg,
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion=(
                "Use os.urandom(16) or secrets.token_bytes() as the seed, "
                "or switch entirely to the 'secrets' module for security-sensitive randomness."
            ),
            snippet=self._snippet(source_lines, node.lineno),
        )
