"""Exploitability scoring for VibeGuard findings (W3).

Computes a runtime-confirmed exploitability score that combines static severity
with dynamic probe status. This is novel: no existing LLM-security tool assigns
a runtime-confirmed exploitability score.

Score map:
  confirmed  → 0.9  (probe ran and confirmed the vulnerability)
  dismissed  → 0.05 (probe ran and the code defended against the payload)
  unknown    → 0.3  (probe not run or inconclusive)

Risk score = weighted average of (severity_weight × exploitability) per finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from security.models.finding import Finding

# Exploitability multiplier per dynamic_status
EXPLOITABILITY_MAP: dict[Optional[str], float] = {
    "confirmed": 0.9,
    "dismissed": 0.05,
    "unknown": 0.3,
    None: 0.3,
}

# Base severity weights (0–1 scale)
_SEVERITY_WEIGHT: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.05,
}


def finding_exploitability(finding: "Finding") -> float:
    """Return the exploitability multiplier for a single finding."""
    return EXPLOITABILITY_MAP.get(finding.dynamic_status, 0.3)


def compute_risk_score(findings: List["Finding"]) -> float:
    """Compute an aggregate risk score in [0, 1] for a list of findings.

    Formula: weighted average of (severity_weight × exploitability) across all
    security findings. Returns 0.0 when there are no findings.
    """
    from security.models.finding import Category

    security_findings = [f for f in findings if f.category == Category.SECURITY]
    if not security_findings:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0
    for f in security_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        w = _SEVERITY_WEIGHT.get(sev, 0.3)
        exp = finding_exploitability(f)
        weighted_sum += w * exp
        total_weight += w

    if total_weight == 0.0:
        return 0.0
    return round(weighted_sum / total_weight, 4)
