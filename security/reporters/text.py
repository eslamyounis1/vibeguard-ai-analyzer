import sys
from security.models.finding import Category, ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[96m",
}
_CAT_LABELS = {
    Category.SECURITY: "SEC",
    Category.CODE_SMELL: "SMELL",
    Category.PERFORMANCE: "PERF",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class TextReporter:
    def __init__(self, use_color: bool | None = None) -> None:
        if use_color is None:
            use_color = sys.stdout.isatty()
        self.use_color = use_color

    def _sev(self, finding) -> str:
        label = f"[{finding.severity.value}]"
        cat = f"[{_CAT_LABELS.get(finding.category, finding.category.value)}]"
        if self.use_color:
            color = _COLORS.get(finding.severity, "")
            return f"{color}{label}{cat}{_RESET}"
        return f"{label}{cat}"

    def report(self, result: ScanResult) -> str:
        lines: list[str] = []

        if result.findings:
            for finding in result.findings:
                lines.append(f"{self._sev(finding)} {finding.rule_id}  {finding.title}")
                lines.append(f"  File: {finding.file}:{finding.line}")
                if finding.snippet:
                    lines.append(f"  Code: {finding.snippet}")
                lines.append(f"  {finding.message}")
                if finding.suggestion:
                    lines.append(f"  Fix:  {finding.suggestion}")
                lines.append("")
        else:
            lines.append("No issues found.")
            lines.append("")

        if result.parse_errors:
            lines.append("Parse errors (files skipped):")
            for err in result.parse_errors:
                lines.append(f"  {err.file}: {err.message}")
            lines.append("")

        summary = result.summary()
        by_sev = summary["by_severity"]
        by_cat = summary["by_category"]
        lines.append(
            f"Scanned {result.scanned_files} file(s). "
            f"Found {len(result.findings)} issue(s): "
            f"{by_sev['CRITICAL']} critical, {by_sev['HIGH']} high, "
            f"{by_sev['MEDIUM']} medium, {by_sev['LOW']} low, {by_sev['INFO']} info  |  "
            f"security={by_cat['SECURITY']}  smell={by_cat['CODE_SMELL']}  perf={by_cat['PERFORMANCE']}"
        )

        return "\n".join(lines)
