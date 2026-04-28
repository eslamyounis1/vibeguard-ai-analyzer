import ast
from abc import ABC, abstractmethod
from typing import List, Optional

from security.models.finding import Category, Finding, Severity


class PerformanceRule(ABC):
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category = Category.PERFORMANCE

    @abstractmethod
    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        ...

    def _snippet(self, source_lines: List[str], lineno: Optional[int]) -> Optional[str]:
        if lineno and 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()
        return None
