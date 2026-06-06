"""Shared AST helpers for security rules."""

from __future__ import annotations

import ast
from typing import FrozenSet, Iterable, Optional


def full_attr_name(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def is_non_constant(node: ast.AST) -> bool:
    """Return True when ``node`` is not a compile-time constant string/int."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(part, ast.FormattedValue) or is_non_constant(part)
            for part in node.values
            if not (isinstance(part, ast.Constant) and isinstance(part.value, str))
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return is_non_constant(node.left) or is_non_constant(node.right)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return is_non_constant(node.func.value) or any(is_non_constant(a) for a in node.args)
        return True
    if isinstance(node, (ast.Subscript, ast.Attribute, ast.IfExp, ast.List, ast.Tuple, ast.Dict)):
        return True
    return True


def call_matches(node: ast.Call, dotted_names: FrozenSet[str], attr_names: Optional[FrozenSet[str]] = None) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        name = full_attr_name(func)
        if name in dotted_names:
            return True
        if attr_names and func.attr in attr_names:
            return True
    if isinstance(func, ast.Name) and func.id in dotted_names:
        return True
    return False


def first_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in {"url", "path", "filename", "file", "source", "target", "location"}:
            return kw.value
    return None


def iter_calls(tree: ast.AST) -> Iterable[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node
