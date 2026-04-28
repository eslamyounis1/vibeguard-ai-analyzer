import ast
from abc import ABC, abstractmethod
from typing import List

from vibeguard.models.finding import Finding, Severity


class SecurityRule(ABC):
    rule_id: str
    title: str
    description: str
    severity: Severity

    @abstractmethod
    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        ...

    def _snippet(self, source_lines: List[str], lineno: int) -> str | None:
        if 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()
        return None
