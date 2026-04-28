import ast
from typing import List

from vibeguard.models.finding import Finding, Severity
from vibeguard.rules.smells.base import SmellRule

MAX_PARAMS = 5


class TooManyParamsRule(SmellRule):
    rule_id = "too_many_params"
    title = "Too Many Parameters"
    description = f"Functions with more than {MAX_PARAMS} parameters are hard to call and test."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = (
                len(node.args.args)
                + len(node.args.posonlyargs)
                + len(node.args.kwonlyargs)
            )
            if params > MAX_PARAMS:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"Function '{node.name}' has {params} parameters (limit {MAX_PARAMS}).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    category=self.category,
                    suggestion="Group related parameters into a dataclass or config object.",
                    snippet=self._snippet(source_lines, node.lineno),
                ))
        return findings
