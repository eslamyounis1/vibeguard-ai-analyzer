"""Fixer: convert dynamic XPath f-string expressions to lxml parameterized form."""

from __future__ import annotations

import ast
from typing import List, Optional

from fixers.base import Edit, Fixer, node_span
from security.models.finding import Finding

_XPATH_METHODS = frozenset({"xpath", "XPath", "find", "findall", "findtext"})


class XPathInjectionFixer(Fixer):
    """Convert f-string XPath expressions to lxml parameterized XPath.

    Handles the common pattern:
        element.xpath(f"//user[@name='{name}']")
    →
        element.xpath("//user[@name=$name]", name=name)

    This works when the f-string contains exactly one substitution that maps
    to a simple variable name. More complex expressions (multiple vars, method
    calls inside the expression) are left for the LLM fixer.
    """

    rule_id = "xpath_injection"

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
            if not isinstance(func, ast.Attribute) or func.attr not in _XPATH_METHODS:
                continue

            if not node.args:
                continue

            expr_arg = node.args[0]
            if not isinstance(expr_arg, ast.JoinedStr):
                continue

            # Try to extract a single simple variable substitution
            param = self._extract_single_name(expr_arg)
            if param is None:
                continue

            # Build the parameterized string by replacing the f-string interpolation
            static_expr = self._fstring_to_param(expr_arg, param)
            if static_expr is None:
                continue

            call_span = node_span(line_offsets, node)
            func_span = node_span(line_offsets, func)
            if call_span is None or func_span is None:
                continue

            # Replace the entire first argument with a static string + keyword arg
            arg_span = node_span(line_offsets, expr_arg)
            if arg_span is None:
                continue

            # Build replacement: "static_expr", varname=varname
            rest_src = source[arg_span[1]:call_span[1] - 1].rstrip()
            replacement_args = f'"{static_expr}", {param}={param}{rest_src}'
            return Edit(
                start=arg_span[0],
                end=call_span[1] - 1,
                replacement=replacement_args,
                description=f"xpath_injection: parameterized XPath, variable '{param}' as keyword arg",
            )

        return None

    def _extract_single_name(self, fstring: ast.JoinedStr) -> Optional[str]:
        """Return the single variable name if the f-string has exactly one Name substitution."""
        names: List[str] = []
        for part in fstring.values:
            if isinstance(part, ast.FormattedValue):
                if isinstance(part.value, ast.Name):
                    names.append(part.value.id)
                else:
                    return None  # non-Name expression — too complex
        return names[0] if len(names) == 1 else None

    def _fstring_to_param(self, fstring: ast.JoinedStr, param: str) -> Optional[str]:
        """Build the parameterized XPath string by replacing {varname} with $varname."""
        parts: List[str] = []
        for part in fstring.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
                parts.append(f"${part.value.id}")
            else:
                return None
        return "".join(parts)
