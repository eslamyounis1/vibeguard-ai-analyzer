"""Base abstractions for dynamic security probes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from security.models.finding import Finding


class ProbeStatus(str, Enum):
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    status: ProbeStatus
    rule_id: str
    line: Optional[int]
    evidence: str = ""
    error: Optional[str] = None

    @property
    def confirmed(self) -> bool:
        return self.status == ProbeStatus.CONFIRMED

    @property
    def dismissed(self) -> bool:
        return self.status == ProbeStatus.DISMISSED


class SecurityProbe(ABC):
    """Runs a dynamic probe to confirm or dismiss a static finding."""

    rule_id: str

    @abstractmethod
    def probe(self, source: str, finding: Finding) -> ProbeResult:
        """Execute a dynamic test against the code and return the probe result."""
        ...

    def _unknown(self, finding: Finding, reason: str = "") -> ProbeResult:
        return ProbeResult(
            status=ProbeStatus.UNKNOWN,
            rule_id=finding.rule_id,
            line=finding.line,
            evidence=reason,
        )

    def _confirmed(self, finding: Finding, evidence: str = "") -> ProbeResult:
        return ProbeResult(
            status=ProbeStatus.CONFIRMED,
            rule_id=finding.rule_id,
            line=finding.line,
            evidence=evidence,
        )

    def _dismissed(self, finding: Finding, evidence: str = "") -> ProbeResult:
        return ProbeResult(
            status=ProbeStatus.DISMISSED,
            rule_id=finding.rule_id,
            line=finding.line,
            evidence=evidence,
        )
