import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_OS_SHELL_FUNCS = {"os.system", "os.popen", "os.execv", "os.execve"}
_OS_SHELL_BARE = {"system", "popen", "execv", "execve"}


def _full_attr(node: ast.Attribute) -> str:
    parts = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


class OsShellRule(SecurityRule):
    rule_id = "os_shell_execution"
    title = "os Shell Execution"
    description = "os.system/popen can execute arbitrary shell commands."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        # Collect bare names imported from os (e.g. `from os import system`)
        bare_imports: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    imported_name = alias.name
                    local_name = alias.asname if alias.asname else alias.name
                    if imported_name in _OS_SHELL_BARE:
                        bare_imports.add(local_name)

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Pattern 1: os.system(...) / os.popen(...) etc.
            if isinstance(node.func, ast.Attribute) and _full_attr(node.func) in _OS_SHELL_FUNCS:
                name = _full_attr(node.func)
                findings.append(self._make_finding(name, file_path, node.lineno, source_lines))
                continue

            # Pattern 2: bare call after `from os import system`
            if isinstance(node.func, ast.Name) and node.func.id in bare_imports:
                findings.append(self._make_finding(node.func.id, file_path, node.lineno, source_lines))

        return findings

    def _make_finding(self, name: str, file_path: str, lineno: int, source_lines: List[str]) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=f"Call to '{name}()' can execute arbitrary shell commands.",
            severity=self.severity,
            file=file_path,
            line=lineno,
            suggestion="Use subprocess with a list argument (not shell=True) and validate inputs.",
            snippet=self._snippet(source_lines, lineno),
        )
