"""Shared acceptance checks for deterministic and LLM-generated fixes."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from security.models.finding import Finding


FindingKey = tuple[str, str]


def _finding_key(finding: Finding) -> FindingKey:
    category = getattr(finding.category, "value", str(finding.category))
    return str(category), finding.rule_id


def introduced_findings(
    before: Iterable[Finding],
    after: Iterable[Finding],
) -> Counter[FindingKey]:
    """Return finding kinds whose multiplicity increased after a proposed fix."""
    before_counts = Counter(_finding_key(finding) for finding in before)
    after_counts = Counter(_finding_key(finding) for finding in after)
    return after_counts - before_counts


def format_introduced_findings(findings: Counter[FindingKey]) -> str:
    return ", ".join(
        f"{category}:{rule_id}" + (f" x{count}" if count > 1 else "")
        for (category, rule_id), count in sorted(findings.items())
    )
