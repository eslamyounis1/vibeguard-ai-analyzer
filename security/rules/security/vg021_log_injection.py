"""VG021 — Log Injection (CWE-117).

Detects unsanitised non-constant data passed directly as the first argument to
standard Python logging calls (logging.info, logger.warning, etc.).

Attackers who control logged values can forge log entries, inject newlines to
simulate legitimate entries, or pollute log analysis tools.
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "critical", "exception", "log",
    "fatal", "notice",
})
_LOG_FUNC_KEYWORDS = ("log", "record", "audit", "event")


class LogInjectionRule(SecurityRule):
    rule_id = "log_injection"
    title = "Log Injection"
    description = (
        "Unsanitised user input in log messages enables log forging and injection "
        "of fake log entries via embedded newlines."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match *.debug(), *.info(), *.warning(), etc.
            if not (isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS):
                continue
            if not node.args:
                continue
            msg = node.args[0]
            if is_non_constant(msg):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"Log call {func.attr}() receives a non-constant message. "
                            "Unsanitised user input can inject newlines and forge log entries."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Strip newline characters before logging: "
                            "value.replace('\\n', ' ').replace('\\r', ' '), "
                            "or use structured logging with separate fields."
                        ),
                        snippet=self._snippet(source_lines, node.lineno),
                    )
                )
        # Check for log-builder functions that return unsanitised f-strings
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_name = node.name.lower()
            if not any(kw in func_name for kw in _LOG_FUNC_KEYWORDS):
                continue
            # Collect parameter names so we can check the returned value uses them
            param_names = {
                arg.arg for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs
            }
            for ret in ast.walk(node):
                if not isinstance(ret, ast.Return) or ret.value is None:
                    continue
                val = ret.value
                if self._is_unsanitised_log_string(val, param_names):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=(
                                f"Function '{node.name}' returns an unsanitised log string "
                                "containing non-constant data. Callers may forward this to a "
                                "logger, enabling log injection via embedded newlines."
                            ),
                            severity=self.severity,
                            file=file_path,
                            line=ret.lineno,
                            suggestion=(
                                "Sanitise values before building log strings: "
                                "value.replace('\\n', ' ').replace('\\r', ' ')."
                            ),
                            snippet=self._snippet(source_lines, ret.lineno),
                        )
                    )
        return findings

    def _is_unsanitised_log_string(self, node: ast.AST, param_names: set) -> bool:
        """Return True when node is an f-string or BinOp(+) containing a function parameter."""
        if isinstance(node, ast.JoinedStr):
            return self._fstring_uses_params(node, param_names)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._uses_params(node.left, param_names) or self._uses_params(node.right, param_names)
        return False

    def _fstring_uses_params(self, node: ast.JoinedStr, param_names: set) -> bool:
        for part in node.values:
            if isinstance(part, ast.FormattedValue) and self._uses_params(part.value, param_names):
                return True
        return False

    def _uses_params(self, node: ast.AST, param_names: set) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in param_names:
                return True
        return False
