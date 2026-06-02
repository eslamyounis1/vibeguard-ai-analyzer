"""The VibeGuard optimization / auto-fix engine.

Given source code, the engine:
  1. runs the static scanner to obtain findings,
  2. asks the registered fixer for each fixable finding to produce a text edit,
  3. applies all non-overlapping edits, and
  4. re-scans the result and verifies it still parses, so a fix is only
     reported as ``safe`` when it removes findings without adding new ones.
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field
from typing import List, Optional

from security.core.scanner import Scanner
from fixers.base import Edit, apply_edits, compute_line_offsets
from fixers.registry import FIXERS_BY_RULE


@dataclass
class AppliedFix:
    rule_id: str
    line: Optional[int]
    description: str

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "line": self.line, "description": self.description}


@dataclass
class FixResult:
    original_code: str
    fixed_code: str
    applied: List[AppliedFix] = field(default_factory=list)
    findings_before: int = 0
    findings_after: int = 0
    safe: bool = True
    note: Optional[str] = None

    @property
    def changed(self) -> bool:
        return self.fixed_code != self.original_code

    def unified_diff(self, filename: str = "input.py") -> str:
        diff = difflib.unified_diff(
            self.original_code.splitlines(keepends=True),
            self.fixed_code.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)

    def to_dict(self) -> dict:
        return {
            "changed": self.changed,
            "safe": self.safe,
            "note": self.note,
            "findings_before": self.findings_before,
            "findings_after": self.findings_after,
            "applied": [a.to_dict() for a in self.applied],
            "fixed_code": self.fixed_code,
        }


def fix_source(code: str, filename: str = "<code>") -> FixResult:
    scanner = Scanner()
    before = scanner.scan_source(code, filename)

    if not before.ok:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before.findings),
            findings_after=len(before.findings),
            safe=False,
            note="Source did not parse; nothing fixed.",
        )

    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        return FixResult(
            original_code=code,
            fixed_code=code,
            safe=False,
            note="Source did not parse; nothing fixed.",
        )

    line_offsets = compute_line_offsets(code)

    edits: List[Edit] = []
    applied: List[AppliedFix] = []
    for finding in before.findings:
        fixers = FIXERS_BY_RULE.get(finding.rule_id)
        if not fixers:
            continue
        for fixer in fixers:
            edit = fixer.fix(tree, finding, code, line_offsets)
            if edit is not None:
                edits.append(edit)
                applied.append(
                    AppliedFix(rule_id=finding.rule_id, line=finding.line, description=edit.description)
                )
                break

    if not edits:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before.findings),
            findings_after=len(before.findings),
            safe=True,
            note="No auto-fixable findings.",
        )

    fixed_code = apply_edits(code, edits)

    after = scanner.scan_source(fixed_code, filename)
    safe = after.ok and len(after.findings) <= len(before.findings)
    note = None
    if not after.ok:
        note = "Fix produced code that does not parse; reverting."
        fixed_code = code
        applied = []
        safe = False
    elif len(after.findings) > len(before.findings):
        note = "Fix introduced new findings; reverting."
        fixed_code = code
        applied = []
        safe = False

    return FixResult(
        original_code=code,
        fixed_code=fixed_code,
        applied=applied,
        findings_before=len(before.findings),
        findings_after=len(after.findings) if after.ok else len(before.findings),
        safe=safe,
        note=note,
    )
