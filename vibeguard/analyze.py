from vibeguard.core.scanner import Scanner
from vibeguard.models.finding import ScanResult


def analyze(source: str) -> ScanResult:
    """Analyze a Python source string and return a ScanResult.

    ScanResult.ok is False if the source could not be parsed.
    ScanResult.findings contains all detected issues with .rule_id for each.
    """
    return Scanner().scan_source(source)
