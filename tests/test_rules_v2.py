"""Tests for VG020-VG040 security rules (Pillar 1 expansion)."""

import ast
import pytest

from security.rules.security.vg020_weak_crypto_key import WeakCryptoKeyRule
from security.rules.security.vg021_log_injection import LogInjectionRule
from security.rules.security.vg022_http_header_injection import HttpHeaderInjectionRule
from security.rules.security.vg023_weak_rng_seed import WeakRngSeedRule
from security.rules.security.vg024_redos import ReDoSRule
from security.rules.security.vg025_url_validation_bypass import UrlValidationBypassRule
from security.rules.security.vg026_xxe import XxeRule
from security.rules.security.vg027_insecure_cookie import InsecureCookieRule
from security.rules.security.vg028_csrf import CsrfRule
from security.rules.security.vg029_insecure_tmpfile import InsecureTmpFileRule
from security.rules.security.vg030_cleartext_credentials import CleartextCredentialsRule
from security.rules.security.vg031_unnecessary_privileges import UnnecessaryPrivilegesRule
from security.rules.security.vg032_none_dereference import NoneDereferenceRule
from security.rules.security.vg033_unrestricted_upload import UnrestrictedUploadRule
from security.rules.security.vg034_weak_password_storage import WeakPasswordStorageRule
from security.rules.security.vg035_sensitive_data_log import SensitiveDataLogRule
from security.rules.security.vg036_xml_injection import XmlInjectionRule
from security.rules.security.vg037_improper_output_encoding import ImproperOutputEncodingRule
from security.rules.security.vg038_jwt_no_verify import JwtNoVerifyRule
from security.rules.security.vg039_insecure_file_permissions import InsecureFilePermissionsRule
from security.rules.security.vg040_divide_by_zero import DivideByZeroRule


def _parse(code: str):
    return ast.parse(code), code.splitlines()


# ---------------------------------------------------------------------------
# VG020 — Weak Crypto Key
# ---------------------------------------------------------------------------

class TestVG020WeakCryptoKey:
    def test_detects_2048_bit_rsa(self):
        code = "rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())"
        tree, lines = _parse(code)
        findings = WeakCryptoKeyRule().check(tree, "t.py", lines)
        assert len(findings) == 1
        assert "2048" in findings[0].message

    def test_no_finding_for_3072(self):
        code = "rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())"
        tree, lines = _parse(code)
        assert WeakCryptoKeyRule().check(tree, "t.py", lines) == []

    def test_no_finding_for_4096(self):
        code = "rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())"
        tree, lines = _parse(code)
        assert WeakCryptoKeyRule().check(tree, "t.py", lines) == []

    def test_detects_1024_bit_dsa(self):
        code = "dsa.generate_parameters(key_size=1024)"
        tree, lines = _parse(code)
        findings = WeakCryptoKeyRule().check(tree, "t.py", lines)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# VG021 — Log Injection
# ---------------------------------------------------------------------------

class TestVG021LogInjection:
    def test_detects_fstring_in_log(self):
        code = 'logger.info(f"User {user_input} logged in")'
        tree, lines = _parse(code)
        findings = LogInjectionRule().check(tree, "t.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "log_injection"

    def test_no_finding_for_static_message(self):
        code = 'logger.info("Static message")'
        tree, lines = _parse(code)
        assert LogInjectionRule().check(tree, "t.py", lines) == []

    def test_detects_concat_in_log(self):
        code = 'logging.error("Error: " + user_data)'
        tree, lines = _parse(code)
        findings = LogInjectionRule().check(tree, "t.py", lines)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# VG022 — HTTP Header Injection
# ---------------------------------------------------------------------------

class TestVG022HttpHeaderInjection:
    def test_detects_dynamic_header_value(self):
        code = "response.add_header('X-Custom', user_value)"
        tree, lines = _parse(code)
        findings = HttpHeaderInjectionRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_static_value(self):
        code = "response.add_header('X-Custom', 'static-value')"
        tree, lines = _parse(code)
        assert HttpHeaderInjectionRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG023 — Weak RNG Seed
# ---------------------------------------------------------------------------

class TestVG023WeakRngSeed:
    def test_detects_time_seed(self):
        code = "import time\nrandom.seed(time.time())"
        tree, lines = _parse(code)
        findings = WeakRngSeedRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_detects_constant_seed(self):
        code = "random.seed(42)"
        tree, lines = _parse(code)
        findings = WeakRngSeedRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_no_arg(self):
        code = "random.seed()"
        tree, lines = _parse(code)
        assert WeakRngSeedRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG024 — ReDoS
# ---------------------------------------------------------------------------

class TestVG024ReDoS:
    def test_detects_nested_quantifier(self):
        code = "import re\nre.compile(r'(a+)+')"
        tree, lines = _parse(code)
        findings = ReDoSRule().check(tree, "t.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "redos_vulnerability"

    def test_detects_alternation_quantifier(self):
        code = "import re\nre.match(r'(a|b)+c', text)"
        tree, lines = _parse(code)
        findings = ReDoSRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_safe_pattern(self):
        code = "import re\nre.compile(r'^[a-z]+$')"
        tree, lines = _parse(code)
        assert ReDoSRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG025 — URL Validation Bypass
# ---------------------------------------------------------------------------

class TestVG025UrlValidationBypass:
    def test_detects_netloc_endswith(self):
        code = "from urllib.parse import urlparse\nparsed = urlparse(url)\nif parsed.netloc.endswith('trusted.com'):\n    pass"
        tree, lines = _parse(code)
        findings = UrlValidationBypassRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_exact_match(self):
        code = "if parsed.netloc == 'trusted.com':\n    pass"
        tree, lines = _parse(code)
        assert UrlValidationBypassRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG026 — XXE
# ---------------------------------------------------------------------------

class TestVG026Xxe:
    def test_detects_et_parse(self):
        code = "import xml.etree.ElementTree as ET\ntree = ET.parse('data.xml')"
        tree, lines = _parse(code)
        findings = XxeRule().check(tree, "t.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "xxe_vulnerability"

    def test_no_finding_when_defusedxml_used(self):
        code = "import defusedxml.ElementTree as ET\ntree = ET.parse('data.xml')"
        tree, lines = _parse(code)
        assert XxeRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG027 — Insecure Cookie
# ---------------------------------------------------------------------------

class TestVG027InsecureCookie:
    def test_detects_missing_secure_flag(self):
        code = "response.set_cookie('session', value)"
        tree, lines = _parse(code)
        findings = InsecureCookieRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_with_secure_true(self):
        code = "response.set_cookie('session', value, secure=True)"
        tree, lines = _parse(code)
        assert InsecureCookieRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG029 — Insecure Tmpfile
# ---------------------------------------------------------------------------

class TestVG029InsecureTmpfile:
    def test_detects_mktemp(self):
        code = "import tempfile\nfname = tempfile.mktemp()"
        tree, lines = _parse(code)
        findings = InsecureTmpFileRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_mkstemp(self):
        code = "import tempfile\nfd, fname = tempfile.mkstemp()"
        tree, lines = _parse(code)
        assert InsecureTmpFileRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG031 — Unnecessary Privileges
# ---------------------------------------------------------------------------

class TestVG031UnnecessaryPrivileges:
    def test_detects_setuid_0(self):
        code = "import os\nos.setuid(0)"
        tree, lines = _parse(code)
        findings = UnnecessaryPrivilegesRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_detects_sudo_subprocess(self):
        code = "import subprocess\nsubprocess.run(['sudo', 'apt', 'install', 'pkg'])"
        tree, lines = _parse(code)
        findings = UnnecessaryPrivilegesRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_normal_uid(self):
        code = "os.setuid(1000)"
        tree, lines = _parse(code)
        assert UnnecessaryPrivilegesRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG034 — Weak Password Storage
# ---------------------------------------------------------------------------

class TestVG034WeakPasswordStorage:
    def test_detects_md5_password(self):
        code = "import hashlib\nhashed = hashlib.md5(password)"
        tree, lines = _parse(code)
        findings = WeakPasswordStorageRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_md5_non_password(self):
        code = "import hashlib\nhash = hashlib.md5(file_content)"
        tree, lines = _parse(code)
        assert WeakPasswordStorageRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG035 — Sensitive Data in Logs
# ---------------------------------------------------------------------------

class TestVG035SensitiveDataLog:
    def test_detects_password_in_log(self):
        code = 'logger.info("Login", password)'
        tree, lines = _parse(code)
        findings = SensitiveDataLogRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_safe_log(self):
        code = 'logger.info("User %s logged in", username)'
        tree, lines = _parse(code)
        assert SensitiveDataLogRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG038 — JWT No Verify
# ---------------------------------------------------------------------------

class TestVG038JwtNoVerify:
    def test_detects_verify_false(self):
        code = "import jwt\ndata = jwt.decode(token, options={'verify_signature': False})"
        tree, lines = _parse(code)
        findings = JwtNoVerifyRule().check(tree, "t.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "jwt_signature_not_verified"

    def test_detects_algorithms_none(self):
        code = "decoded = jwt.decode(token, key, algorithms=['none'])"
        tree, lines = _parse(code)
        findings = JwtNoVerifyRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_proper_verification(self):
        code = "decoded = jwt.decode(token, key, algorithms=['HS256'])"
        tree, lines = _parse(code)
        assert JwtNoVerifyRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG039 — Insecure File Permissions
# ---------------------------------------------------------------------------

class TestVG039InsecureFilePermissions:
    def test_detects_0o777(self):
        code = "import os\nos.chmod('/tmp/f', 0o777)"
        tree, lines = _parse(code)
        findings = InsecureFilePermissionsRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_detects_world_write_bit(self):
        code = "os.chmod('/tmp/f', 0o646)"
        tree, lines = _parse(code)
        findings = InsecureFilePermissionsRule().check(tree, "t.py", lines)
        assert len(findings) == 1  # 0o646 has world-write bit

    def test_no_finding_for_0o640(self):
        code = "os.chmod('/tmp/f', 0o640)"
        tree, lines = _parse(code)
        assert InsecureFilePermissionsRule().check(tree, "t.py", lines) == []


# ---------------------------------------------------------------------------
# VG036 — XML Injection
# ---------------------------------------------------------------------------

class TestVG036XmlInjection:
    def test_detects_xml_fstring(self):
        code = "xml_str = f'<user>{username}</user>'"
        tree, lines = _parse(code)
        findings = XmlInjectionRule().check(tree, "t.py", lines)
        assert len(findings) == 1

    def test_no_finding_for_static_xml(self):
        code = "xml_str = '<user>alice</user>'"
        tree, lines = _parse(code)
        assert XmlInjectionRule().check(tree, "t.py", lines) == []
