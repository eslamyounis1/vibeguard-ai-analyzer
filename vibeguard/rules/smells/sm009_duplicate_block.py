import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule

MIN_LINES = 6


class DuplicateCodeBlockRule(SmellRule):
    rule_id = "duplicate_code_block"
    title = "Duplicate Code Block"
    description = f"Blocks of {MIN_LINES}+ consecutive lines that appear more than once should be extracted."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        non_trivial = [
            (i + 1, ln.strip())
            for i, ln in enumerate(source_lines)
            if ln.strip() and not ln.strip().startswith("#")
        ]
        seen: dict[tuple, int] = {}
        for start in range(len(non_trivial) - MIN_LINES + 1):
            window = tuple(ln for _, ln in non_trivial[start: start + MIN_LINES])
            line_no = non_trivial[start][0]
            if window in seen:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"Code block at line {line_no} duplicates a block near line {seen[window]}."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=line_no,
                    category=self.category,
                    suggestion="Extract the repeated logic into a shared function.",
                    snippet=self._snippet(source_lines, line_no),
                ))
            else:
                seen[window] = line_no
        return findings
