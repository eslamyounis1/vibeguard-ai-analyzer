"""Backwards-compatibility shim — scoring logic lives in security.models.scoring."""
from security.models.scoring import (  # noqa: F401
    EXPLOITABILITY_MAP,
    compute_risk_score,
    finding_exploitability,
)
