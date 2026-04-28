from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


def severity_gte(a: "Severity", b: "Severity") -> bool:
    return _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b]


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    file: str
    line: int
    snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass
class ParseError:
    file: str
    message: str

    def to_dict(self) -> dict:
        return {"file": self.file, "message": self.message}


@dataclass
class ScanResult:
    scanned_files: int = 0
    findings: List[Finding] = field(default_factory=list)
    parse_errors: List[ParseError] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        for f in self.findings:
            counts[f.severity] += 1
        return {s.value: c for s, c in counts.items()}

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "findings": [f.to_dict() for f in self.findings],
            "parse_errors": [e.to_dict() for e in self.parse_errors],
            "summary": self.summary(),
        }
