import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_OS_SHELL_FUNCS = {"os.system", "os.popen", "os.execv", "os.execve"}


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
        findings = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and _full_attr(node.func) in _OS_SHELL_FUNCS
            ):
                name = _full_attr(node.func)
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Call to '{name}()' can execute arbitrary shell commands.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use subprocess with a list argument (not shell=True) and validate inputs.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
