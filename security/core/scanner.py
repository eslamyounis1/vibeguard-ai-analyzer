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
        dynamic_verify: bool = False,
    ) -> None:
        self.min_severity = min_severity
        self.include_snippet = include_snippet
        self.dynamic_verify = dynamic_verify
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

        from security.models.scoring import compute_risk_score
        result.exploitability_score = compute_risk_score(result.findings)
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
        if self.dynamic_verify:
            self._run_dynamic_verification(result, code)
        from security.models.scoring import compute_risk_score
        result.exploitability_score = compute_risk_score(result.findings)
        return result

    def _run_dynamic_verification(self, result: ScanResult, source: str) -> None:
        """Run dynamic probes on security findings and annotate with dynamic_status."""
        try:
            from sandbox.probe_registry import get_probe
        except ImportError:
            return
        for finding in result.findings:
            probe = get_probe(finding.rule_id)
            if probe is None:
                continue
            try:
                probe_result = probe.probe(source, finding)
                # Annotate finding with dynamic verification status
                finding.dynamic_status = probe_result.status.value
                finding.dynamic_evidence = probe_result.evidence
            except Exception:
                finding.dynamic_status = "unknown"

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
        return [finding for finding in findings if not self._is_ignored(finding, source_lines)]

    def _is_ignored(self, finding: Finding, source_lines: List[str]) -> bool:
        if finding.line is None:
            return False
        comments = []
        for line_no in (finding.line - 1, finding.line):
            if 1 <= line_no <= len(source_lines):
                comments.append(source_lines[line_no - 1])
        return any(self._ignore_comment_matches(comment, finding.rule_id) for comment in comments)

    def _ignore_comment_matches(self, line: str, rule_id: str) -> bool:
        marker = "# vibeguard: ignore"
        if marker not in line:
            return False
        ignored = line.split(marker, 1)[1].strip()
        if not ignored:
            return True
        ignored_rules = {part.strip() for part in ignored.replace(",", " ").split()}
        return "all" in ignored_rules or rule_id in ignored_rules
