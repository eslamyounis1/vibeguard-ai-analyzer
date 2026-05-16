import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule


class UnsafeYamlLoadRule(SecurityRule):
    rule_id = "unsafe_yaml_load"
    title = "Unsafe YAML Deserialization"
    description = "yaml.load() can construct arbitrary Python objects when used without a safe loader."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        yaml_aliases: set[str] = set()
        load_aliases: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "yaml":
                        yaml_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "yaml":
                for alias in node.names:
                    if alias.name == "load":
                        load_aliases.add(alias.asname or alias.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_yaml_load_call(node, yaml_aliases, load_aliases):
                continue
            if self._has_safe_loader(node):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="yaml.load() without SafeLoader can deserialize arbitrary Python objects.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _is_yaml_load_call(
        self,
        node: ast.Call,
        yaml_aliases: set[str],
        load_aliases: set[str],
    ) -> bool:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "load"
            and isinstance(func.value, ast.Name)
            and func.value.id in yaml_aliases
        ):
            return True
        return isinstance(func, ast.Name) and func.id in load_aliases

    def _has_safe_loader(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg != "Loader":
                continue
            value = keyword.value
            if isinstance(value, ast.Name) and value.id in {"SafeLoader", "CSafeLoader"}:
                return True
            if (
                isinstance(value, ast.Attribute)
                and value.attr in {"SafeLoader", "CSafeLoader"}
                and isinstance(value.value, ast.Name)
            ):
                return True
        return False
