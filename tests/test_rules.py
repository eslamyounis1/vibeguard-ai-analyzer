import ast
import pytest

from security.rules.security.vg001_eval import EvalUsageRule
from security.rules.security.vg002_exec import ExecUsageRule
from security.rules.security.vg003_hardcoded_secrets import HardcodedSecretsRule
from security.rules.security.vg004_insecure_random import InsecureRandomRule
from security.rules.security.vg005_subprocess import SubprocessShellRule
from security.rules.security.vg006_pickle import PickleRule
from security.rules.security.vg007_assert import SecurityAssertRule
from security.rules.security.vg010_yaml_load import UnsafeYamlLoadRule
from security.rules.security.vg011_tls_verify import DisabledTlsVerificationRule
from security.rules.security.vg012_debug_mode import DebugModeRule
from security.rules.security.vg013_sql_injection import SqlInjectionRule


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
        assert findings[0].rule_id == "eval_exec_usage"

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
