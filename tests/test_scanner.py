import os
import tempfile

import pytest

from security.core.scanner import Scanner
from security.models.finding import Severity


def _write_tmp(code: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(code)
    return path


class TestScannerSingleFile:
    def test_finding_detected(self):
        path = _write_tmp("eval(user_input)\n")
        try:
            result = Scanner().scan(path)
            assert result.scanned_files == 1
            assert any(f.rule_id == "eval_exec_usage" for f in result.findings)
        finally:
            os.unlink(path)

    def test_clean_file_no_findings(self):
        path = _write_tmp("x = 1 + 2\nprint(x)\n")
        try:
            result = Scanner().scan(path)
            assert result.scanned_files == 1
            assert result.findings == []
            assert result.parse_errors == []
        finally:
            os.unlink(path)

    def test_syntax_error_recorded(self):
        path = _write_tmp("def broken(:\n")
        try:
            result = Scanner().scan(path)
            assert result.scanned_files == 1
            assert len(result.parse_errors) == 1
            assert result.findings == []
        finally:
            os.unlink(path)

    def test_non_py_file_ignored(self):
        path = _write_tmp("eval(x)\n", suffix=".txt")
        try:
            result = Scanner().scan(path)
            assert result.scanned_files == 0
        finally:
            os.unlink(path)


class TestScannerDirectory:
    def test_scans_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "a.py"), "w") as fh:
                fh.write("eval(x)\n")
            with open(os.path.join(tmpdir, "b.py"), "w") as fh:
                fh.write("x = 1\n")
            result = Scanner().scan(tmpdir)
            assert result.scanned_files == 2
            assert len(result.findings) >= 1

    def test_ignores_non_py_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "notes.txt"), "w") as fh:
                fh.write("eval(x)\n")
            result = Scanner().scan(tmpdir)
            assert result.scanned_files == 0

    def test_recursive_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "sub")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "deep.py"), "w") as fh:
                fh.write("eval(x)\n")
            result = Scanner().scan(tmpdir)
            assert result.scanned_files == 1
            assert len(result.findings) == 1

    def test_continues_after_parse_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.py"), "w") as fh:
                fh.write("def (\n")
            with open(os.path.join(tmpdir, "good.py"), "w") as fh:
                fh.write("eval(x)\n")
            result = Scanner().scan(tmpdir)
            assert result.scanned_files == 2
            assert len(result.parse_errors) == 1
            assert len(result.findings) == 1


class TestSeverityFilter:
    def test_filters_below_minimum(self):
        code = "import random\nx = random.randint(0, 10)\n"
        path = _write_tmp(code)
        try:
            result = Scanner(min_severity=Severity.HIGH).scan(path)
            # insecure_random is MEDIUM, so it must not survive a HIGH filter
            random_findings = [f for f in result.findings if f.rule_id == "insecure_random"]
            assert random_findings == []
        finally:
            os.unlink(path)

    def test_high_filter_passes_high(self):
        path = _write_tmp("eval(x)\n")
        try:
            result = Scanner(min_severity=Severity.HIGH).scan(path)
            assert any(f.rule_id == "eval_exec_usage" for f in result.findings)
        finally:
            os.unlink(path)


class TestSnippetControl:
    def test_snippet_included_by_default(self):
        path = _write_tmp("eval(user_input)\n")
        try:
            result = Scanner(include_snippet=True).scan(path)
            assert result.findings[0].snippet is not None
        finally:
            os.unlink(path)

    def test_snippet_excluded(self):
        path = _write_tmp("eval(user_input)\n")
        try:
            result = Scanner(include_snippet=False).scan(path)
            assert result.findings[0].snippet is None
        finally:
            os.unlink(path)


class TestSecurityMetadata:
    def test_security_finding_includes_professional_metadata(self):
        result = Scanner().scan_source("eval(user_input)\n")
        finding = result.findings[0]
        assert finding.cwe == "CWE-95"
        assert finding.owasp == "A03:2021 Injection"
        assert finding.confidence.value == "HIGH"
        assert finding.risk_score == 95
        assert finding.impact

    def test_summary_includes_security_risk_score(self):
        result = Scanner().scan_source("eval(user_input)\n")
        risk = result.summary()["risk"]
        assert risk["security_score"] == 5
        assert risk["max_risk_score"] == 95
        assert risk["average_risk_score"] == 95
        assert risk["high_confidence_count"] == 1


class TestIgnoreComments:
    def test_inline_ignore_suppresses_matching_rule(self):
        code = "eval(user_input)  # vibeguard: ignore eval_exec_usage\n"
        result = Scanner().scan_source(code)
        assert result.findings == []

    def test_previous_line_ignore_suppresses_matching_rule(self):
        code = "import yaml\n# vibeguard: ignore unsafe_yaml_load\nyaml.load(raw)\n"
        result = Scanner().scan_source(code)
        assert [finding.rule_id for finding in result.findings] == []

    def test_ignore_all_suppresses_any_rule(self):
        code = "# vibeguard: ignore all\neval(user_input)\n"
        result = Scanner().scan_source(code)
        assert result.findings == []

    def test_ignore_does_not_suppress_other_rules(self):
        code = "eval(user_input)  # vibeguard: ignore hardcoded_secret\n"
        result = Scanner().scan_source(code)
        assert [finding.rule_id for finding in result.findings] == ["eval_exec_usage"]
