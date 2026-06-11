import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import full_attr_name, is_non_constant
from security.rules.security.base import SecurityRule

_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception", "log"})
_LOG_MODULES = frozenset({"logging", "logger", "log", "LOGGER", "LOG"})
_LOG_NAME_PARTS = frozenset({"log", "audit", "record", "event"})


class LogInjectionRule(SecurityRule):
    rule_id = "log_injection"
    title = "Log Injection (CWE-117)"
    description = "User-controlled data in log messages may allow log forging or injection attacks."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._is_log_call(node):
                if node.args and is_non_constant(node.args[0]):
                    # Check if the first arg is an f-string or concat (tainted)
                    arg = node.args[0]
                    if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Log message built with string interpolation may contain unescaped newlines or control characters.",
                            severity=self.severity,
                            file=file_path,
                            line=node.lineno,
                            suggestion="Use logging's % formatting (logger.info('%s', user_input)) or sanitize input by removing newlines.",
                            snippet=self._snippet(source_lines, node.lineno),
                        ))
        return findings

    def _is_log_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr not in _LOG_METHODS:
                return False
            obj_name = ""
            if isinstance(func.value, ast.Name):
                obj_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                obj_name = func.value.attr
            if obj_name in _LOG_MODULES:
                return True
            # logger-like variable names
            obj_lower = obj_name.lower()
            return any(part in obj_lower for part in _LOG_NAME_PARTS)
        return False
