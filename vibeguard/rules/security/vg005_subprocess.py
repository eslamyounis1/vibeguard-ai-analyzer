import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.security.base import SecurityRule

_SUBPROCESS_FUNCS = frozenset({
    "run", "call", "Popen", "check_call", "check_output",
    "getoutput", "getstatusoutput",
})


class SubprocessShellRule(SecurityRule):
    rule_id = "VG005"
    title = "Dangerous Subprocess Usage"
    description = "Using shell=True in subprocess calls exposes the command to shell injection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        imported_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _SUBPROCESS_FUNCS:
                        imported_aliases.add(alias.asname if alias.asname else alias.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            has_shell_true = any(
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if not has_shell_true:
                continue

            func = node.func
            is_subprocess_call = (
                (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                    and func.attr in _SUBPROCESS_FUNCS
                )
                or (isinstance(func, ast.Name) and func.id in imported_aliases)
            )

            if is_subprocess_call:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        "subprocess called with shell=True, which passes the command through "
                        "a shell and may allow command injection. Pass a list of arguments instead."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
