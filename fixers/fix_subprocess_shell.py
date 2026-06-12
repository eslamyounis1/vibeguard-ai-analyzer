"""Fixer: replace subprocess(..., shell=True) with the list-form without shell."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, compute_line_offsets, node_span
from security.models.finding import Finding


class SubprocessShellFixer(Fixer):
    """Rewrite subprocess.run('cmd arg', shell=True) -> subprocess.run(['cmd', 'arg'])."""

    rule_id = "subprocess_shell_true"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno != finding.line:
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in {"run", "call", "check_call", "check_output", "Popen"}:
                continue

            # Find shell=True keyword
            shell_kw = None
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_kw = kw
                    break
            if shell_kw is None:
                return None

            # Only handle string literal first-arg case
            if not node.args or not isinstance(node.args[0], ast.Constant):
                return None
            cmd_str = node.args[0].value
            if not isinstance(cmd_str, str):
                return None

            # Rewrite: replace the first arg with a list
            parts = cmd_str.split()
            list_repr = "[" + ", ".join(f'"{p}"' for p in parts) + "]"

            arg_span = node_span(line_offsets, node.args[0])
            shell_span = node_span(line_offsets, shell_kw.value)
            if arg_span is None or shell_span is None:
                return None

            # Replace the string arg with a list
            return Edit(
                start=arg_span[0],
                end=arg_span[1],
                replacement=list_repr,
                description=f"subprocess shell=True: '{cmd_str}' -> {list_repr}",
            )
        return None
