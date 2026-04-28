import ast
from pathlib import Path
from typing import Optional, Tuple, List

from security.analyzers.security.analyzer import SecurityAnalyzer
from security.analyzers.smells.analyzer import SmellAnalyzer
from security.analyzers.performance.analyzer import PerformanceAnalyzer
from security.models.finding import Finding, ParseError, ScanResult, Severity, severity_gte
from security.utils.file_utils import collect_python_files


class Scanner:
    def __init__(
        self,
        min_severity: Optional[Severity] = None,
        include_snippet: bool = True,
    ) -> None:
        self.min_severity = min_severity
        self.include_snippet = include_snippet
        self._security = SecurityAnalyzer()
        self._smells = SmellAnalyzer()
        self._performance = PerformanceAnalyzer()

    def scan(self, path: str) -> ScanResult:
        result = ScanResult()
        files = collect_python_files(path)
        result.scanned_files = len(files)

        for file_path in files:
            findings, error = self._scan_file(file_path)
            if error:
                result.parse_errors.append(error)
                continue
            for finding in findings:
                if self.min_severity and not severity_gte(finding.severity, self.min_severity):
                    continue
                if not self.include_snippet:
                    finding.snippet = None
                result.findings.append(finding)

        return result

    def scan_source(self, code: str, filename: str = "<code>") -> ScanResult:
        result = ScanResult()
        result.scanned_files = 1
        findings, error = self._scan_source_str(code, filename)
        if error:
            result.parse_errors.append(error)
        else:
            for finding in findings:
                if self.min_severity and not severity_gte(finding.severity, self.min_severity):
                    continue
                if not self.include_snippet:
                    finding.snippet = None
                result.findings.append(finding)
        return result

    def _scan_source_str(self, code: str, file_path: str) -> Tuple[List[Finding], Optional[ParseError]]:
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as exc:
            return [], ParseError(file=file_path, message=f"SyntaxError: {exc}")
        source_lines = code.splitlines()
        findings = self._run_all(tree, file_path, source_lines)
        return findings, None

    def _scan_file(self, file_path: str) -> Tuple[List[Finding], Optional[ParseError]]:
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [], ParseError(file=file_path, message=str(exc))

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as exc:
            return [], ParseError(file=file_path, message=f"SyntaxError: {exc}")

        source_lines = source.splitlines()
        findings = self._run_all(tree, file_path, source_lines)
        return findings, None

    def _run_all(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._security.analyze(tree, file_path, source_lines))
        findings.extend(self._smells.analyze(tree, file_path, source_lines))
        findings.extend(self._performance.analyze(tree, file_path, source_lines))
        return findings
