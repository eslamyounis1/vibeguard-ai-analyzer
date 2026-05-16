import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class DebugModeRule(SecurityRule):
    rule_id = "debug_mode_enabled"
    title = "Debug Mode Enabled"
    description = "Production web servers must not run with debug mode enabled."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._has_debug_true(node):
                continue
            if not self._looks_like_web_app_call(node):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Debug mode exposes detailed errors and interactive tooling that should not run in production.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Disable debug=True outside local development and control it through environment config.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _has_debug_true(self, node: ast.Call) -> bool:
        return any(
            keyword.arg == "debug"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    def _looks_like_web_app_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "run":
            return True
        return isinstance(func, ast.Name) and func.id in {"run", "FastAPI", "Flask"}
