"""Fixer: replace unsafe xml.etree.ElementTree imports with defusedxml."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, compute_line_offsets, offset_of
from security.models.finding import Finding


class XxeFixer(Fixer):
    """Rewrite 'import xml.etree.ElementTree as ET' to use defusedxml."""

    rule_id = "xxe_vulnerability"

    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        # Look for the import statement for xml.etree.ElementTree
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"xml.etree.ElementTree", "xml.etree", "lxml.etree"}:
                        start = offset_of(line_offsets, node.lineno, node.col_offset)
                        # End of the import line
                        end_lineno = getattr(node, "end_lineno", node.lineno)
                        end_col = getattr(node, "end_col_offset", len(source.splitlines()[node.lineno - 1]))
                        end = offset_of(line_offsets, end_lineno, end_col)
                        asname = alias.asname or "ET"
                        return Edit(
                            start=start,
                            end=end,
                            replacement=f"import defusedxml.ElementTree as {asname}",
                            description=f"XXE: replaced {alias.name} with defusedxml.ElementTree",
                        )
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("xml.etree"):
                    start = offset_of(line_offsets, node.lineno, node.col_offset)
                    end_lineno = getattr(node, "end_lineno", node.lineno)
                    end_col = getattr(node, "end_col_offset", len(source.splitlines()[node.lineno - 1]))
                    end = offset_of(line_offsets, end_lineno, end_col)
                    names_str = ", ".join(
                        alias.name + (f" as {alias.asname}" if alias.asname else "")
                        for alias in node.names
                    )
                    return Edit(
                        start=start,
                        end=end,
                        replacement=f"from defusedxml.ElementTree import {names_str}",
                        description="XXE: replaced xml.etree with defusedxml.ElementTree",
                    )
        return None
