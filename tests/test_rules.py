import ast
import pytest

from security.rules.security.vg020_weak_crypto_key import WeakCryptoKeyRule
from security.rules.security.vg021_log_injection import LogInjectionRule
from security.rules.security.vg022_http_header_injection import HttpHeaderInjectionRule
from security.rules.security.vg023_weak_rng_seed import WeakRngSeedRule
from security.rules.security.vg024_regex_dos import RegexDosRule
from security.rules.security.vg025_url_validation_bypass import UrlValidationBypassRule
from security.rules.security.vg001_eval import EvalUsageRule
from security.rules.security.vg002_exec import ExecUsageRule
from security.rules.security.vg003_hardcoded_secrets import HardcodedSecretsRule
from security.rules.security.vg004_insecure_random import InsecureRandomRule
from security.rules.security.vg005_subprocess import SubprocessShellRule
from security.rules.security.vg006_pickle import PickleRule
from security.rules.security.vg007_assert import SecurityAssertRule
from security.rules.security.vg008_weak_hash import WeakHashRule
from security.rules.security.vg009_os_shell import OsShellRule
from security.rules.security.vg010_yaml_load import UnsafeYamlLoadRule
from security.rules.security.vg011_tls_verify import DisabledTlsVerificationRule
from security.rules.security.vg012_debug_mode import DebugModeRule
from security.rules.security.vg013_sql_injection import SqlInjectionRule
from security.rules.security.vg014_path_traversal import PathTraversalRule
from security.rules.security.vg015_ssrf import SsrfRule
from security.rules.security.vg016_xss import UnsafeHtmlOutputRule
from security.rules.security.vg017_xpath_injection import XPathInjectionRule
from security.rules.security.vg018_open_redirect import OpenRedirectRule
from security.rules.security.vg019_unvalidated_input import UnvalidatedInputRule


def _parse(code: str):
    return ast.parse(code), code.splitlines()


class TestVG001Eval:
    def test_detects_eval(self):
        tree, lines = _parse("eval(user_input)")
        findings = EvalUsageRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "eval_exec_usage"
        assert findings[0].line == 1

    def test_snippet_captured(self):
        tree, lines = _parse("result = eval(expr)")
        findings = EvalUsageRule().check(tree, "test.py", lines)
        assert findings[0].snippet == "result = eval(expr)"

    def test_no_false_positive(self):
        tree, lines = _parse("x = 1 + 2\nprint('eval me not')")
        assert EvalUsageRule().check(tree, "test.py", lines) == []

    def test_multiple_evals(self):
        code = "eval(a)\neval(b)"
        tree, lines = _parse(code)
        assert len(EvalUsageRule().check(tree, "test.py", lines)) == 2


class TestVG002Exec:
    def test_detects_exec(self):
        tree, lines = _parse('exec("import os")')
        findings = ExecUsageRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "exec_usage"

    def test_no_false_positive_string(self):
        tree, lines = _parse("x = 'executor string'")
        assert ExecUsageRule().check(tree, "test.py", lines) == []


class TestVG003HardcodedSecrets:
    def test_detects_password(self):
        tree, lines = _parse('password = "super_secret"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "hardcoded_secret"

    def test_detects_api_key(self):
        tree, lines = _parse('api_key = "sk-abc123"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_token(self):
        tree, lines = _parse('auth_token = "tok_xyz"')
        findings = HardcodedSecretsRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_no_flag_empty_string(self):
        tree, lines = _parse('password = ""')
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []

    def test_no_flag_non_string_value(self):
        tree, lines = _parse("password = None")
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []

    def test_no_flag_unrelated_variable(self):
        tree, lines = _parse('greeting = "hello world"')
        assert HardcodedSecretsRule().check(tree, "test.py", lines) == []


class TestVG004InsecureRandom:
    def test_detects_random_randint(self):
        code = "import random\ntoken = random.randint(0, 100)"
        tree, lines = _parse(code)
        findings = InsecureRandomRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "insecure_random"

    def test_detects_random_choice(self):
        code = "import random\nx = random.choice(['a', 'b'])"
        tree, lines = _parse(code)
        assert len(InsecureRandomRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_random_import(self):
        code = "from random import choice\nx = choice(['a', 'b'])"
        tree, lines = _parse(code)
        findings = InsecureRandomRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_no_flag_secrets_module(self):
        code = "import secrets\nx = secrets.token_hex()"
        tree, lines = _parse(code)
        assert InsecureRandomRule().check(tree, "test.py", lines) == []

    def test_no_flag_random_import_without_call(self):
        code = "import random"
        tree, lines = _parse(code)
        assert InsecureRandomRule().check(tree, "test.py", lines) == []


class TestVG005Subprocess:
    def test_detects_subprocess_run_shell_true(self):
        code = "import subprocess\nsubprocess.run(['ls'], shell=True)"
        tree, lines = _parse(code)
        findings = SubprocessShellRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "subprocess_shell_true"

    def test_detects_subprocess_popen_shell_true(self):
        code = "import subprocess\nsubprocess.Popen('ls', shell=True)"
        tree, lines = _parse(code)
        assert len(SubprocessShellRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_subprocess_import(self):
        code = "from subprocess import run\nrun('ls', shell=True)"
        tree, lines = _parse(code)
        assert len(SubprocessShellRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_shell_false(self):
        code = "import subprocess\nsubprocess.run(['ls'], shell=False)"
        tree, lines = _parse(code)
        assert SubprocessShellRule().check(tree, "test.py", lines) == []

    def test_no_flag_no_shell_kwarg(self):
        code = "import subprocess\nsubprocess.run(['ls'])"
        tree, lines = _parse(code)
        assert SubprocessShellRule().check(tree, "test.py", lines) == []


class TestVG006Pickle:
    def test_detects_pickle_load(self):
        code = "import pickle\ndata = pickle.load(f)"
        tree, lines = _parse(code)
        findings = PickleRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_deserialization"

    def test_detects_pickle_loads(self):
        code = "import pickle\ndata = pickle.loads(raw)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1

    def test_detects_from_pickle_import_load(self):
        code = "from pickle import load\ndata = load(f)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1

    def test_detects_cpickle(self):
        code = "import cPickle\ndata = cPickle.loads(raw)"
        tree, lines = _parse(code)
        assert len(PickleRule().check(tree, "test.py", lines)) == 1


class TestVG007Assert:
    def test_detects_auth_assert(self):
        tree, lines = _parse("assert user.is_authenticated")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "assert_used_for_validation"

    def test_detects_admin_assert(self):
        tree, lines = _parse("assert is_admin(user)")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_permission_assert(self):
        tree, lines = _parse("assert user.has_permission('edit')")
        findings = SecurityAssertRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_flags_all_asserts(self):
        # Rule now flags every assert regardless of context
        tree, lines = _parse("assert len(items) > 0")
        assert len(SecurityAssertRule().check(tree, "test.py", lines)) == 1

    def test_flags_math_assert(self):
        tree, lines = _parse("assert result == expected_value")
        assert len(SecurityAssertRule().check(tree, "test.py", lines)) == 1


class TestVG008WeakHash:
    def test_detects_hashlib_md5(self):
        tree, lines = _parse("import hashlib\nhashlib.md5(data)")
        findings = WeakHashRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "weak_hash_algorithm"

    def test_detects_direct_import_md5(self):
        code = "from hashlib import md5\nmd5(data)"
        tree, lines = _parse(code)
        findings = WeakHashRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "weak_hash_algorithm"

    def test_detects_hashlib_new_md5(self):
        code = "import hashlib\nhashlib.new('md5', data)"
        tree, lines = _parse(code)
        findings = WeakHashRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_no_finding_sha256(self):
        code = "import hashlib\nhashlib.sha256(data)"
        tree, lines = _parse(code)
        assert WeakHashRule().check(tree, "test.py", lines) == []

    def test_detects_sha1(self):
        code = "from hashlib import sha1\nsha1(data)"
        tree, lines = _parse(code)
        assert len(WeakHashRule().check(tree, "test.py", lines)) == 1


class TestVG009OsShell:
    def test_detects_os_system(self):
        code = "import os\nos.system(cmd)"
        tree, lines = _parse(code)
        findings = OsShellRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "os_shell_execution"

    def test_detects_bare_system_from_import(self):
        code = "from os import system\nsystem(cmd)"
        tree, lines = _parse(code)
        findings = OsShellRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "os_shell_execution"

    def test_no_finding_subprocess_run(self):
        code = "import subprocess\nsubprocess.run([])"
        tree, lines = _parse(code)
        assert OsShellRule().check(tree, "test.py", lines) == []


class TestVG010YamlLoad:
    def test_detects_yaml_load_without_loader(self):
        code = "import yaml\ndata = yaml.load(raw)"
        tree, lines = _parse(code)
        findings = UnsafeYamlLoadRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_yaml_load"

    def test_detects_direct_yaml_load_import(self):
        code = "from yaml import load\ndata = load(raw)"
        tree, lines = _parse(code)
        assert len(UnsafeYamlLoadRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_safe_load(self):
        code = "import yaml\ndata = yaml.safe_load(raw)"
        tree, lines = _parse(code)
        assert UnsafeYamlLoadRule().check(tree, "test.py", lines) == []

    def test_no_flag_safe_loader(self):
        code = "import yaml\ndata = yaml.load(raw, Loader=yaml.SafeLoader)"
        tree, lines = _parse(code)
        assert UnsafeYamlLoadRule().check(tree, "test.py", lines) == []


class TestVG011TlsVerify:
    def test_detects_requests_verify_false(self):
        code = "import requests\nrequests.get('https://example.com', verify=False)"
        tree, lines = _parse(code)
        findings = DisabledTlsVerificationRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "tls_verification_disabled"

    def test_detects_direct_requests_import(self):
        code = "from requests import post\npost('https://example.com', verify=False)"
        tree, lines = _parse(code)
        assert len(DisabledTlsVerificationRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_verify_true(self):
        code = "import requests\nrequests.get('https://example.com', verify=True)"
        tree, lines = _parse(code)
        assert DisabledTlsVerificationRule().check(tree, "test.py", lines) == []

    def test_detects_ssl_unverified_context(self):
        code = "import ssl\nctx = ssl._create_unverified_context()"
        tree, lines = _parse(code)
        findings = DisabledTlsVerificationRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_check_hostname_false(self):
        code = "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False"
        tree, lines = _parse(code)
        findings = DisabledTlsVerificationRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_detects_verify_mode_cert_none(self):
        code = "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_NONE"
        tree, lines = _parse(code)
        findings = DisabledTlsVerificationRule().check(tree, "test.py", lines)
        assert len(findings) == 1


class TestVG012DebugMode:
    def test_detects_app_run_debug_true(self):
        tree, lines = _parse("app.run(debug=True)")
        findings = DebugModeRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "debug_mode_enabled"

    def test_detects_fastapi_debug_true(self):
        tree, lines = _parse("app = FastAPI(debug=True)")
        assert len(DebugModeRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_debug_false(self):
        tree, lines = _parse("app.run(debug=False)")
        assert DebugModeRule().check(tree, "test.py", lines) == []


class TestVG013SqlInjection:
    def test_detects_f_string_sql_execute(self):
        code = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
        tree, lines = _parse(code)
        findings = SqlInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "sql_query_construction"

    def test_detects_percent_formatted_sql(self):
        code = "cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)"
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "test.py", lines)) == 1

    def test_detects_format_sql(self):
        code = "cursor.execute(\"DELETE FROM users WHERE id = {}\".format(user_id))"
        tree, lines = _parse(code)
        assert len(SqlInjectionRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_parameterized_sql(self):
        code = "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
        tree, lines = _parse(code)
        assert SqlInjectionRule().check(tree, "test.py", lines) == []


class TestVG014PathTraversal:
    def test_detects_dynamic_open(self):
        code = "open(user_path)"
        tree, lines = _parse(code)
        findings = PathTraversalRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "path_traversal"

    def test_detects_f_string_open(self):
        code = 'open(f"/tmp/{name}")'
        tree, lines = _parse(code)
        assert len(PathTraversalRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_constant_path(self):
        code = 'open("/etc/hosts")'
        tree, lines = _parse(code)
        assert PathTraversalRule().check(tree, "test.py", lines) == []


class TestVG015Ssrf:
    def test_detects_requests_get_variable(self):
        code = "import requests\nrequests.get(target_url)"
        tree, lines = _parse(code)
        findings = SsrfRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "ssrf_unvalidated_url"

    def test_no_flag_constant_url(self):
        code = "import requests\nrequests.get('https://example.com')"
        tree, lines = _parse(code)
        assert SsrfRule().check(tree, "test.py", lines) == []


class TestVG016Xss:
    def test_detects_markup(self):
        code = "from markupsafe import Markup\nreturn Markup(user_html)"
        tree, lines = _parse(code)
        findings = UnsafeHtmlOutputRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_html_output"

    def test_detects_render_template_string(self):
        code = "from flask import render_template_string\nreturn render_template_string(template)"
        tree, lines = _parse(code)
        assert len(UnsafeHtmlOutputRule().check(tree, "test.py", lines)) == 1

    def test_detects_make_response_concat(self):
        code = "from flask import make_response\nreturn make_response('<p>' + user_input + '</p>')"
        tree, lines = _parse(code)
        assert len(UnsafeHtmlOutputRule().check(tree, "test.py", lines)) == 1

    def test_detects_response_fstring(self):
        code = "from flask import Response\nreturn Response(f'<b>{name}</b>')"
        tree, lines = _parse(code)
        assert len(UnsafeHtmlOutputRule().check(tree, "test.py", lines)) == 1


class TestVG017XPath:
    def test_detects_dynamic_xpath(self):
        code = "tree.xpath(f\"//user[@name='{username}']\")"
        tree, lines = _parse(code)
        findings = XPathInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "xpath_injection"


class TestVG018OpenRedirect:
    def test_detects_redirect_variable(self):
        code = "from flask import redirect\nreturn redirect(next_url)"
        tree, lines = _parse(code)
        findings = OpenRedirectRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "open_redirect"


class TestVG019UnvalidatedInput:
    def test_detects_request_args_to_open(self):
        code = "from flask import request\nopen(request.args.get('path'))"
        tree, lines = _parse(code)
        findings = UnvalidatedInputRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unvalidated_user_input"
        assert findings[0].owasp is None  # enriched at analyzer level

    def test_enriched_owasp_metadata(self):
        from security.rules.security.metadata import enrich_security_finding
        from security.models.finding import Finding, Severity

        finding = enrich_security_finding(
            Finding(
                rule_id="ssrf_unvalidated_url",
                title="t",
                message="m",
                severity=Severity.HIGH,
                file="f",
                line=1,
            )
        )
        assert finding.owasp == "A10:2021 Server-Side Request Forgery"
        assert finding.cwe == "CWE-918"


class TestVG020WeakCryptoKey:
    def test_detects_rsa_small_key(self):
        code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)"
        tree, lines = _parse(code)
        findings = WeakCryptoKeyRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "weak_crypto_key"

    def test_detects_des_usage(self):
        code = "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)"
        tree, lines = _parse(code)
        findings = WeakCryptoKeyRule().check(tree, "test.py", lines)
        assert len(findings) == 1

    def test_flags_rsa_2048(self):
        # 2048-bit is now below the 3072-bit threshold
        code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)"
        tree, lines = _parse(code)
        findings = WeakCryptoKeyRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert "3072" in findings[0].message

    def test_no_flag_rsa_3072(self):
        code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(3072)"
        tree, lines = _parse(code)
        assert WeakCryptoKeyRule().check(tree, "test.py", lines) == []

    def test_no_flag_rsa_4096(self):
        code = "from Crypto.PublicKey import RSA\nkey = RSA.generate(4096)"
        tree, lines = _parse(code)
        assert WeakCryptoKeyRule().check(tree, "test.py", lines) == []

    def test_detects_arc4(self):
        code = "from Crypto.Cipher import ARC4\ncipher = ARC4.new(key)"
        tree, lines = _parse(code)
        assert len(WeakCryptoKeyRule().check(tree, "test.py", lines)) == 1


class TestVG021LogInjection:
    def test_detects_log_variable(self):
        code = "import logging\nlogging.info(user_input)"
        tree, lines = _parse(code)
        findings = LogInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "log_injection"

    def test_detects_fstring_log(self):
        code = "import logging\nlogging.warning(f'User: {name}')"
        tree, lines = _parse(code)
        assert len(LogInjectionRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_constant_message(self):
        code = "import logging\nlogging.info('Server started')"
        tree, lines = _parse(code)
        assert LogInjectionRule().check(tree, "test.py", lines) == []

    def test_detects_logger_error(self):
        code = "import logging\nlogger = logging.getLogger()\nlogger.error(err_msg)"
        tree, lines = _parse(code)
        assert len(LogInjectionRule().check(tree, "test.py", lines)) == 1


class TestVG022HttpHeaderInjection:
    def test_detects_response_header_assignment(self):
        code = "response.headers['X-Custom'] = user_value"
        tree, lines = _parse(code)
        findings = HttpHeaderInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "http_header_injection"

    def test_detects_headers_variable(self):
        code = "response_headers['Location'] = request_url"
        tree, lines = _parse(code)
        assert len(HttpHeaderInjectionRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_constant_value(self):
        code = "response.headers['Content-Type'] = 'application/json'"
        tree, lines = _parse(code)
        assert HttpHeaderInjectionRule().check(tree, "test.py", lines) == []

    def test_no_flag_non_header_dict(self):
        code = "data['key'] = user_value"
        tree, lines = _parse(code)
        assert HttpHeaderInjectionRule().check(tree, "test.py", lines) == []


class TestVG023WeakRngSeed:
    def test_detects_constant_seed(self):
        code = "import random\nrandom.seed(42)"
        tree, lines = _parse(code)
        findings = WeakRngSeedRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "weak_rng_seed"

    def test_detects_no_args(self):
        code = "import random\nrandom.seed()"
        tree, lines = _parse(code)
        assert len(WeakRngSeedRule().check(tree, "test.py", lines)) == 1

    def test_detects_time_based_seed(self):
        code = "import random\nimport time\nrandom.seed(int(time.time()))"
        tree, lines = _parse(code)
        assert len(WeakRngSeedRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_os_urandom_seed(self):
        code = "import random\nimport os\nrandom.seed(os.urandom(16))"
        tree, lines = _parse(code)
        assert WeakRngSeedRule().check(tree, "test.py", lines) == []

    def test_no_flag_without_import_random(self):
        code = "seed(42)"
        tree, lines = _parse(code)
        assert WeakRngSeedRule().check(tree, "test.py", lines) == []


class TestVG024RegexDos:
    def test_detects_dynamic_compile(self):
        code = "import re\nre.compile(user_pattern)"
        tree, lines = _parse(code)
        findings = RegexDosRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "regex_dos"

    def test_detects_dynamic_search(self):
        code = "import re\nre.search(pattern, text)"
        tree, lines = _parse(code)
        assert len(RegexDosRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_literal_pattern(self):
        code = "import re\nre.compile(r'^[a-z]+$')"
        tree, lines = _parse(code)
        assert RegexDosRule().check(tree, "test.py", lines) == []

    def test_no_flag_without_import_re(self):
        code = "re.compile(user_pattern)"
        tree, lines = _parse(code)
        assert RegexDosRule().check(tree, "test.py", lines) == []


class TestVG025UrlValidationBypass:
    def test_detects_netloc_endswith_variable(self):
        code = (
            "from urllib.parse import urlparse\n"
            "parsed = urlparse(target)\n"
            "if parsed.netloc.endswith(domain): return target"
        )
        tree, lines = _parse(code)
        findings = UrlValidationBypassRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "url_validation_bypass"

    def test_detects_hostname_endswith_variable(self):
        code = (
            "from urllib.parse import urlparse\n"
            "parsed = urlparse(url)\n"
            "if parsed.hostname.endswith(allowed_domain): pass"
        )
        tree, lines = _parse(code)
        assert len(UrlValidationBypassRule().check(tree, "test.py", lines)) == 1

    def test_detects_host_endswith_variable(self):
        code = "if parsed.host.endswith(allowed): redirect(url)"
        tree, lines = _parse(code)
        assert len(UrlValidationBypassRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_static_extension_check(self):
        # Static string arg — not a domain validation, just a file extension check
        code = "if url.endswith('.png'): pass"
        tree, lines = _parse(code)
        assert UrlValidationBypassRule().check(tree, "test.py", lines) == []

    def test_no_flag_netloc_equality(self):
        # Equality check is safe — not flagged by this rule
        code = "if parsed.netloc == allowed_domain: pass"
        tree, lines = _parse(code)
        assert UrlValidationBypassRule().check(tree, "test.py", lines) == []

    def test_no_flag_non_url_endswith(self):
        # endswith on non-netloc attribute should not be flagged
        code = "if filename.endswith(ext): pass"
        tree, lines = _parse(code)
        assert UrlValidationBypassRule().check(tree, "test.py", lines) == []


class TestVG016XssHtmlDocstring:
    def test_detects_html_docstring_fstring_return(self):
        code = (
            'def render_greeting(username):\n'
            '    """Returns HTML rendered in the browser."""\n'
            '    return f"<p>Welcome, {username}!</p>"\n'
        )
        tree, lines = _parse(code)
        findings = UnsafeHtmlOutputRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe_html_output"

    def test_no_flag_non_html_docstring(self):
        code = (
            'def format_message(username):\n'
            '    """Returns a plain text greeting."""\n'
            '    return f"Welcome, {username}!"\n'
        )
        tree, lines = _parse(code)
        assert UnsafeHtmlOutputRule().check(tree, "test.py", lines) == []

    def test_no_flag_constant_fstring_in_html_func(self):
        code = (
            'def render_static():\n'
            '    """Returns HTML content."""\n'
            '    return f"<p>Hello, World!</p>"\n'
        )
        tree, lines = _parse(code)
        assert UnsafeHtmlOutputRule().check(tree, "test.py", lines) == []


class TestVG021LogBuilderFunction:
    def test_detects_log_builder_function(self):
        code = (
            "def generate_receive_log(msg, ts):\n"
            "    return f'[{ts}] Received: {msg}'\n"
        )
        tree, lines = _parse(code)
        findings = LogInjectionRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "log_injection"

    def test_detects_audit_log_function(self):
        code = (
            "def build_audit_entry(user, action):\n"
            "    return f'USER={user} ACTION={action}'\n"
        )
        tree, lines = _parse(code)
        assert len(LogInjectionRule().check(tree, "test.py", lines)) == 1

    def test_no_flag_non_log_function(self):
        code = (
            "def format_greeting(name):\n"
            "    return f'Hello, {name}!'\n"
        )
        tree, lines = _parse(code)
        assert LogInjectionRule().check(tree, "test.py", lines) == []

    def test_no_flag_log_function_with_constant_only(self):
        code = (
            "def get_log_prefix():\n"
            "    return '[INFO] Server started'\n"
        )
        tree, lines = _parse(code)
        assert LogInjectionRule().check(tree, "test.py", lines) == []
