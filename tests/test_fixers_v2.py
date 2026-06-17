"""Tests for new deterministic fixers (Pillar 4)."""

import ast
import pytest

from fixers.base import compute_line_offsets, apply_edits
from fixers.fix_subprocess_shell import SubprocessShellFixer
from fixers.fix_insecure_random import InsecureRandomFixer
from fixers.fix_hardcoded_secret import HardcodedSecretFixer
from fixers.fix_insecure_cookie import InsecureCookieFixer
from fixers.fix_insecure_tmpfile import InsecureTmpFileFixer
from fixers.fix_file_permissions import FilePermissionsFixer
from fixers.fix_sql_injection import SqlInjectionFixer
from fixers.fix_path_traversal import PathTraversalFixer
from fixers.fix_xxe import XxeFixer

from security.models.finding import Finding, Severity


def _make_finding(rule_id: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test",
        message="Test finding",
        severity=Severity.HIGH,
        file="test.py",
        line=line,
    )


def _apply_fixer(fixer, code: str, rule_id: str, line: int = 1) -> str:
    """Parse code, run fixer, apply edit, return result."""
    tree = ast.parse(code)
    finding = _make_finding(rule_id, line)
    offsets = compute_line_offsets(code)
    edit = fixer.fix(tree, finding, code, offsets)
    if edit is None:
        return code
    return apply_edits(code, [edit])


class TestSubprocessShellFixer:
    def test_replaces_string_with_list(self):
        code = 'subprocess.run("ls -la", shell=True)'
        result = _apply_fixer(SubprocessShellFixer(), code, "subprocess_shell_true")
        assert '["ls", "-la"]' in result

    def test_no_fix_for_variable_arg(self):
        code = "subprocess.run(cmd, shell=True)"
        result = _apply_fixer(SubprocessShellFixer(), code, "subprocess_shell_true")
        assert result == code  # unchanged


class TestInsecureRandomFixer:
    def test_replaces_random_with_secrets(self):
        code = "import random\nx = random.choice(items)"
        result = _apply_fixer(InsecureRandomFixer(), code, "insecure_random", line=2)
        assert "secrets.choice" in result

    def test_no_fix_for_uniform(self):
        code = "x = random.uniform(0, 1)"
        result = _apply_fixer(InsecureRandomFixer(), code, "insecure_random")
        assert result == code


class TestHardcodedSecretFixer:
    def test_replaces_password_with_env(self):
        code = 'db_password = "super_secret_123"'
        result = _apply_fixer(HardcodedSecretFixer(), code, "hardcoded_secret")
        assert "os.environ.get('DB_PASSWORD')" in result

    def test_no_fix_for_non_secret_name(self):
        code = 'greeting = "hello world"'
        result = _apply_fixer(HardcodedSecretFixer(), code, "hardcoded_secret")
        assert result == code


class TestInsecureCookieFixer:
    def test_adds_secure_httponly(self):
        code = "response.set_cookie('session', val)"
        result = _apply_fixer(InsecureCookieFixer(), code, "insecure_cookie")
        assert "secure=True" in result
        assert "httponly=True" in result

    def test_only_adds_missing_flags(self):
        code = "response.set_cookie('session', val, secure=True)"
        result = _apply_fixer(InsecureCookieFixer(), code, "insecure_cookie")
        assert "httponly=True" in result
        # secure=True should appear exactly once
        assert result.count("secure=True") == 1


class TestInsecureTmpFileFixer:
    def test_replaces_mktemp_with_mkstemp(self):
        code = "import tempfile\nfname = tempfile.mktemp()"
        result = _apply_fixer(InsecureTmpFileFixer(), code, "insecure_tmpfile", line=2)
        assert "mkstemp" in result
        assert "mktemp" not in result


class TestFilePermissionsFixer:
    def test_replaces_0o777(self):
        code = "os.chmod('/tmp/f', 0o777)"
        result = _apply_fixer(FilePermissionsFixer(), code, "incorrect_file_permissions")
        assert "0o640" in result or "0o750" in result
        assert "0o777" not in result

    def test_no_fix_for_safe_permissions(self):
        code = "os.chmod('/tmp/f', 0o640)"
        result = _apply_fixer(FilePermissionsFixer(), code, "incorrect_file_permissions")
        assert result == code


class TestSqlInjectionFixer:
    def test_replaces_fstring_with_params(self):
        code = 'cur.execute(f"SELECT * FROM users WHERE name = \'{username}\'")'
        result = _apply_fixer(SqlInjectionFixer(), code, "sql_query_construction")
        assert "?" in result or result != code  # parameterized form

    def test_no_fix_for_static_query(self):
        code = 'cur.execute("SELECT * FROM users")'
        result = _apply_fixer(SqlInjectionFixer(), code, "sql_query_construction")
        assert result == code


class TestXxeFixer:
    def test_replaces_xml_etree_import(self):
        code = "import xml.etree.ElementTree as ET\ntree = ET.parse('f.xml')"
        result = _apply_fixer(XxeFixer(), code, "xxe_vulnerability")
        assert "defusedxml" in result

    def test_no_fix_for_defusedxml_already(self):
        code = "import defusedxml.ElementTree as ET\ntree = ET.parse('f.xml')"
        result = _apply_fixer(XxeFixer(), code, "xxe_vulnerability")
        # Should not double-wrap
        assert result.count("defusedxml") == 1


class TestPathTraversalFixer:
    def test_declines_variable_path_without_trust_root(self):
        code = "with open(user_path, 'r') as f: pass"
        result = _apply_fixer(PathTraversalFixer(), code, "path_traversal")
        assert result == code

    def test_no_fix_for_constant_path(self):
        code = "with open('/etc/hosts', 'r') as f: pass"
        result = _apply_fixer(PathTraversalFixer(), code, "path_traversal")
        assert result == code
