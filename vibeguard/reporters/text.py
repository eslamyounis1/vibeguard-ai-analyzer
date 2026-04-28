import sys
from vibeguard.models.finding import ScanResult, Severity

_COLORS = {
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class TextReporter:
    def __init__(self, use_color: bool | None = None) -> None:
        if use_color is None:
            use_color = sys.stdout.isatty()
        self.use_color = use_color

    def _sev(self, severity: Severity) -> str:
        if self.use_color:
            return f"{_COLORS[severity]}[{severity.value}]{_RESET}"
        return f"[{severity.value}]"

    def report(self, result: ScanResult) -> str:
        lines: list[str] = []

        if result.findings:
            for finding in result.findings:
                lines.append(f"{self._sev(finding.severity)} {finding.rule_id} {finding.title}")
                lines.append(f"  File: {finding.file}:{finding.line}")
                if finding.snippet:
                    lines.append(f"  Code: {finding.snippet}")
                lines.append(f"  Message: {finding.message}")
                lines.append("")
        else:
            lines.append("No security issues found.")
            lines.append("")

        if result.parse_errors:
            lines.append("Parse errors (files skipped):")
            for err in result.parse_errors:
                lines.append(f"  {err.file}: {err.message}")
            lines.append("")

        summary = result.summary()
        lines.append(
            f"Scanned {result.scanned_files} file(s). "
            f"Found {len(result.findings)} issue(s): "
            f"{summary['HIGH']} high, {summary['MEDIUM']} medium, {summary['LOW']} low."
        )

        return "\n".join(lines)
