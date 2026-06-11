"""Fixer: replace hardcoded string secrets with os.environ.get('VAR_NAME')."""

from __future__ import annotations

import ast
import re
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|auth_token|private_key)",
    re.IGNORECASE,
)


def _env_var_name(varname: str) -> str:
    """Convert variable name to uppercase env var (e.g. db_password -> DB_PASSWORD)."""
    return varname.upper()


class HardcodedSecretFixer(Fixer):
    """Replace assignment of hardcoded secret strings with os.environ.get()."""

    rule_id = "hardcoded_secret"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or node.lineno != finding.line:
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue
            # Check if the target variable name looks like a secret
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            varname = node.targets[0].id
            if not _SECRET_PATTERNS.search(varname):
                continue

            env_var = _env_var_name(varname)
            span = node_span(line_offsets, node.value)
            if span is None:
                return None
            return Edit(
                start=span[0],
                end=span[1],
                replacement=f"os.environ.get('{env_var}')",
                description=f"hardcoded secret '{varname}' -> os.environ.get('{env_var}')",
            )
        return None
