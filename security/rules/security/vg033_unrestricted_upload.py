import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_SAVE_METHODS = frozenset({"save", "write"})
_UPLOAD_SOURCES = frozenset({
    "filename", "file", "upload", "attachment", "files",
})


class UnrestrictedUploadRule(SecurityRule):
    rule_id = "unrestricted_file_upload"
    title = "Unrestricted File Upload (CWE-434)"
    description = "File upload saved without extension or MIME type validation."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_unsafe_file_save(node):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="File saved from upload without apparent extension or MIME type validation.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Validate file extension against an allow-list and check MIME type before saving.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings

    def _is_unsafe_file_save(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        if func.attr not in _SAVE_METHODS:
            return False
        # Check if the object being saved comes from request.files or has an upload-like name
        obj = func.value
        if isinstance(obj, ast.Attribute) and obj.attr in _UPLOAD_SOURCES:
            return True
        if isinstance(obj, ast.Name) and any(s in obj.id.lower() for s in _UPLOAD_SOURCES):
            return True
        # Check if the path argument contains a filename from request
        for arg in node.args:
            if isinstance(arg, ast.Name) and any(s in arg.id.lower() for s in _UPLOAD_SOURCES):
                return True
        return False
