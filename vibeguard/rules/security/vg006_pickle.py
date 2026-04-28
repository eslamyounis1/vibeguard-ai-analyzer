import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule

_PICKLE_MODULES = frozenset({"pickle", "cPickle"})
_LOAD_FUNCS = frozenset({"load", "loads"})


class PickleRule(SecurityRule):
    rule_id = "VG006"
    title = "Pickle Deserialization"
    description = (
        "pickle.load() and pickle.loads() can execute arbitrary code when "
        "deserializing untrusted data."
    )
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        # Track functions directly imported from pickle
        direct_aliases: dict[str, str] = {}  # alias → "load" or "loads"

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in _PICKLE_MODULES:
                for alias in node.names:
                    if alias.name in _LOAD_FUNCS:
                        key = alias.asname if alias.asname else alias.name
                        direct_aliases[key] = alias.name

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            func_name = None

            if (
                isinstance(func, ast.Attribute)
                and func.attr in _LOAD_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id in _PICKLE_MODULES
            ):
                func_name = f"{func.value.id}.{func.attr}"
            elif isinstance(func, ast.Name) and func.id in direct_aliases:
                func_name = f"pickle.{direct_aliases[func.id]}"

            if func_name:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"{func_name}() deserializes untrusted data and can execute arbitrary code. "
                        "Use a safe format such as JSON for untrusted input."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
