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
from typing import Dict, List, Optional, Any

from security.core.scanner import Scanner
from fixers.base import Edit, apply_edits, compute_line_offsets
from fixers.registry import FIXERS_BY_RULE
from fixers.safety import format_introduced_findings, introduced_findings


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
    findings_before_list: List[dict] = field(default_factory=list)
    findings_after_list: List[dict] = field(default_factory=list)
    safe: bool = True
    note: Optional[str] = None
    profile_before: Optional[Dict[str, Any]] = None
    profile_after: Optional[Dict[str, Any]] = None

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

    def perf_delta(self) -> Optional[Dict[str, Any]]:
        """Return before/after performance delta, or None if profiling was not run."""
        if not self.profile_before or not self.profile_after:
            return None
        b = self.profile_before
        a = self.profile_after
        if not b.get("ok") or not a.get("ok"):
            return None
        bt, at = b["totals"], a["totals"]

        def _delta(key: str) -> Optional[float]:
            bv, av = bt.get(key), at.get(key)
            if bv is None or av is None:
                return None
            return round(av - bv, 6)

        def _pct(key: str) -> Optional[float]:
            bv = bt.get(key)
            if not bv:
                return None
            dv = _delta(key)
            return round(dv / bv * 100, 1) if dv is not None else None

        return {
            "cpu_time_before": bt.get("cpu_time_seconds"),
            "cpu_time_after": at.get("cpu_time_seconds"),
            "cpu_time_delta": _delta("cpu_time_seconds"),
            "cpu_time_pct": _pct("cpu_time_seconds"),
            "wall_time_before": bt.get("wall_time_seconds"),
            "wall_time_after": at.get("wall_time_seconds"),
            "wall_time_delta": _delta("wall_time_seconds"),
            "wall_time_pct": _pct("wall_time_seconds"),
            "memory_peak_before": bt.get("memory_peak_bytes"),
            "memory_peak_after": at.get("memory_peak_bytes"),
            "memory_peak_delta": _delta("memory_peak_bytes"),
            "energy_before": bt.get("energy_joules_estimate"),
            "energy_after": at.get("energy_joules_estimate"),
            "energy_delta": _delta("energy_joules_estimate"),
            "energy_model": bt.get("energy_model"),
        }

    def to_dict(self) -> dict:
        d = {
            "changed": self.changed,
            "safe": self.safe,
            "note": self.note,
            "findings_before": self.findings_before_list,
            "findings_after": self.findings_after_list,
            "applied": [a.to_dict() for a in self.applied],
            "fixed_code": self.fixed_code,
        }
        delta = self.perf_delta()
        if delta is not None:
            d["perf_delta"] = delta
        return d


def _run_profiler(code: str) -> Optional[Dict[str, Any]]:
    """Run sandbox measure_code; returns result dict or None on import failure."""
    try:
        from sandbox.profiler import measure_code  # noqa: PLC0415
        return measure_code(code)
    except Exception:
        return None


def fix_source(code: str, filename: str = "<code>", with_profile: bool = False) -> FixResult:
    scanner = Scanner()
    before = scanner.scan_source(code, filename)
    profile_before = _run_profiler(code) if with_profile else None

    if not before.ok:
        parse_list = [f.to_dict() for f in before.findings]
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before.findings),
            findings_after=len(before.findings),
            findings_before_list=parse_list,
            findings_after_list=parse_list,
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

    before_list = [f.to_dict() for f in before.findings]

    if not edits:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before.findings),
            findings_after=len(before.findings),
            findings_before_list=before_list,
            findings_after_list=before_list,
            safe=True,
            note="No auto-fixable findings.",
            profile_before=profile_before,
        )

    fixed_code = apply_edits(code, edits)

    after = scanner.scan_source(fixed_code, filename)
    introduced = introduced_findings(before.findings, after.findings) if after.ok else {}
    safe = after.ok and not introduced
    note = None
    if not after.ok:
        note = "Fix produced code that does not parse; reverting."
        fixed_code = code
        applied = []
        safe = False
    elif introduced:
        note = (
            "Fix introduced new findings "
            f"({format_introduced_findings(introduced)}); reverting."
        )
        fixed_code = code
        applied = []
        safe = False

    after_list = [f.to_dict() for f in after.findings] if after.ok else before_list
    profile_after = _run_profiler(fixed_code) if with_profile and fixed_code != code else None

    return FixResult(
        original_code=code,
        fixed_code=fixed_code,
        applied=applied,
        findings_before=len(before.findings),
        findings_after=len(after.findings) if after.ok else len(before.findings),
        findings_before_list=before_list,
        findings_after_list=after_list,
        safe=safe,
        note=note,
        profile_before=profile_before,
        profile_after=profile_after,
    )
