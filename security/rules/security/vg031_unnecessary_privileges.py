import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class UnnecessaryPrivilegesRule(SecurityRule):
    rule_id = "unnecessary_privileges"
    title = "Unnecessary Privileges (CWE-250)"
    description = "Code running as root or using sudo grants excessive permissions."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_setuid_root(node) or self._is_sudo_subprocess(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Code escalates to root privileges; apply principle of least privilege.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Drop privileges as early as possible. Avoid setuid(0) and running sudo from code.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_setuid_root(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"setuid", "seteuid"}:
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0:
                return True
        return False

    def _is_sudo_subprocess(self, node: ast.Call) -> bool:
        func = node.func
        is_subprocess = (
            isinstance(func, ast.Attribute) and func.attr in {"run", "call", "Popen", "check_call", "check_output"}
        ) or (
            isinstance(func, ast.Name) and func.id in {"system", "popen"}
        )
        if not is_subprocess:
            return False
        # Check if first arg contains 'sudo'
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "sudo" in arg.value:
                return True
            if isinstance(arg, (ast.List, ast.Tuple)):
                for elt in arg.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value.strip() == "sudo":
                        return True
        return False
