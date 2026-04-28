from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Category(str, Enum):
    SECURITY = "SECURITY"
    CODE_SMELL = "CODE_SMELL"
    PERFORMANCE = "PERFORMANCE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_gte(a: "Severity", b: "Severity") -> bool:
    return _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b]


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    file: str
    line: Optional[int]
    category: Category = Category.SECURITY
    col: Optional[int] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "suggestion": self.suggestion,
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

    @property
    def ok(self) -> bool:
        return len(self.parse_errors) == 0

    @property
    def error(self) -> Optional[str]:
        return self.parse_errors[0].message if self.parse_errors else None

    def summary(self) -> dict:
        by_severity = {s.value: 0 for s in Severity}
        by_category = {c.value: 0 for c in Category}
        for f in self.findings:
            by_severity[f.severity.value] += 1
            by_category[f.category.value] += 1
        return {"by_severity": by_severity, "by_category": by_category}

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "findings": [f.to_dict() for f in self.findings],
            "parse_errors": [e.to_dict() for e in self.parse_errors],
            "summary": self.summary(),
        }
