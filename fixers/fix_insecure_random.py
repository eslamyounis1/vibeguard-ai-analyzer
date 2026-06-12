"""Fixer: replace random.X() with secrets.X() for security-sensitive usage."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_RANDOM_TO_SECRETS = {
    "randint": "randbelow",
    "randrange": "randbelow",
    "choice": "choice",
    "random": "token_hex",
    "getrandbits": "randbits",
    "uniform": None,  # no direct equivalent
}

_IMPORT_MARKER = "import secrets  # vibeguard: added by auto-fix\n"


class InsecureRandomFixer(Fixer):
    """Rewrite random.choice/randint to secrets equivalents."""

    rule_id = "insecure_random"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and node.lineno == finding.line
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"
                and node.func.attr in _RANDOM_TO_SECRETS
            ):
                replacement = _RANDOM_TO_SECRETS[node.func.attr]
                if replacement is None:
                    return None
                span = node_span(line_offsets, node.func.value)
                if span is None:
                    return None
                return Edit(
                    start=span[0],
                    end=span[1],
                    replacement="secrets",
                    description=f"random.{node.func.attr}() -> secrets.{replacement}()",
                )
        return None
