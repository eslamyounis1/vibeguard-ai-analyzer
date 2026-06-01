"""Base abstractions for the VibeGuard auto-fix (optimization) layer.

A :class:`Fixer` turns a single :class:`Finding` into a textual :class:`Edit`
against the original source. We deliberately produce *text edits* rather than
re-emitting the file with ``ast.unparse`` so that comments, formatting, and
untouched code are preserved exactly.
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from security.models.finding import Finding


@dataclass(frozen=True)
class Edit:
    """A replacement of ``source[start:end]`` with ``replacement``.

    ``start`` and ``end`` are absolute character offsets into the original
    source string (``end`` exclusive).
    """

    start: int
    end: int
    replacement: str
    description: str = ""


def compute_line_offsets(source: str) -> List[int]:
    """Return the absolute char offset at which each 1-indexed line begins."""
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def offset_of(line_offsets: List[int], lineno: int, col: int) -> int:
    """Convert a 1-indexed line / 0-indexed column to an absolute offset."""
    return line_offsets[lineno - 1] + col


def node_span(line_offsets: List[int], node: ast.AST) -> Optional[tuple[int, int]]:
    """Absolute (start, end) offsets for an AST node, or None if unavailable."""
    if (
        getattr(node, "lineno", None) is None
        or getattr(node, "end_lineno", None) is None
        or getattr(node, "col_offset", None) is None
        or getattr(node, "end_col_offset", None) is None
    ):
        return None
    start = offset_of(line_offsets, node.lineno, node.col_offset)
    end = offset_of(line_offsets, node.end_lineno, node.end_col_offset)
    return start, end


def line_indent(source: str, line_offsets: List[int], lineno: int) -> str:
    """Return the leading whitespace of a 1-indexed source line."""
    start = line_offsets[lineno - 1]
    end = line_offsets[lineno] if lineno < len(line_offsets) else len(source)
    line = source[start:end]
    return line[: len(line) - len(line.lstrip())]


class Fixer(ABC):
    """Produces a deterministic, behavior-preserving edit for a rule's finding."""

    rule_id: str

    @abstractmethod
    def fix(
        self,
        tree: ast.AST,
        finding: Finding,
        source: str,
        line_offsets: List[int],
    ) -> Optional[Edit]:
        """Return an :class:`Edit` that remediates ``finding``, or None.

        Returning None means this fixer cannot safely auto-fix this instance
        (for example, an unusual import form). The finding is then left as-is.
        """
        ...


def apply_edits(source: str, edits: List[Edit]) -> str:
    """Apply non-overlapping edits to ``source``.

    Edits are applied from the end of the file backwards so earlier offsets
    stay valid. Overlapping edits are dropped (first one by position wins).
    """
    ordered = sorted(edits, key=lambda e: (e.start, e.end), reverse=True)
    result = source
    prev_start = len(source) + 1
    for edit in ordered:
        if edit.end > prev_start:
            # Overlaps an edit we already applied closer to the end; skip it.
            continue
        result = result[: edit.start] + edit.replacement + result[edit.end :]
        prev_start = edit.start
    return result
