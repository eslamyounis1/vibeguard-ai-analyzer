import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

# World-writable or world-executable modes
_WORLD_WRITABLE_MODES = {0o777, 0o666, 0o776, 0o767, 0o677, 0o775, 0o757, 0o577}


class InsecureFilePermissionsRule(SecurityRule):
    rule_id = "incorrect_file_permissions"
    title = "Incorrect File Permissions (CWE-732)"
    description = "World-writable file permissions allow any user to modify or execute the file."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_chmod(node):
                continue
            mode = self._extract_mode(node)
            if mode is not None and self._is_world_writable(mode):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"File permission {oct(mode)} is world-writable; use restrictive permissions like 0o640.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use os.chmod(path, 0o640) or 0o750 for executables; avoid world-writable bits.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_chmod(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "chmod":
            return True
        if isinstance(func, ast.Name) and func.id == "chmod":
            return True
        return False

    def _extract_mode(self, node: ast.Call) -> int | None:
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            v = node.args[1].value
            if isinstance(v, int):
                return v
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                v = kw.value.value
                if isinstance(v, int):
                    return v
        return None

    def _is_world_writable(self, mode: int) -> bool:
        # Check world-write bit (bit 1 of "other" permissions)
        return bool(mode & 0o002) or mode in _WORLD_WRITABLE_MODES
