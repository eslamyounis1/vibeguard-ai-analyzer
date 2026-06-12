"""VG024 — Regular Expression Denial of Service (ReDoS) (CWE-400).

Detects calls to the ``re`` module where the **pattern** argument is
non-constant (i.e. derived from a variable, parameter, or user input).

User-supplied regular expressions containing nested quantifiers or
alternation can trigger catastrophic backtracking, causing the process to
hang and enabling a denial-of-service attack.
"""

import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_utils import is_non_constant
from security.rules.security.base import SecurityRule

_RE_FUNCS = frozenset({
    "compile", "search", "match", "fullmatch",
    "findall", "finditer", "sub", "subn", "split",
})


class RegexDosRule(SecurityRule):
    rule_id = "regex_dos"
    title = "Regular Expression Denial of Service (ReDoS)"
    description = (
        "User-controlled regular expression patterns can cause catastrophic "
        "backtracking, making the process unresponsive."
    )
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        re_aliases = self._collect_re_aliases(tree)
        if not re_aliases:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in _RE_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id in re_aliases
            ):
                continue
            if not node.args:
                continue
            pattern = node.args[0]
            if is_non_constant(pattern):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"re.{func.attr}() is called with a non-constant pattern. "
                            "User-supplied patterns can trigger catastrophic backtracking (ReDoS)."
                        ),
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Use only constant (literal) patterns. If user-supplied patterns are "
                            "required, use the 're2' library (linear-time guarantees) or enforce "
                            "a timeout with 'signal.alarm' or 'timeout_decorator'."
                        ),
                        snippet=self._snippet(source_lines, node.lineno),
                    )
                )
        return findings

    def _collect_re_aliases(self, tree: ast.AST) -> set:
        """Return the set of local names bound to the 're' module."""
        aliases: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "re":
                        aliases.add(alias.asname or "re")
        return aliases
