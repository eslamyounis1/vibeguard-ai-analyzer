"""Tests for the auto-fix (optimization) engine."""

from fixers.base import Edit, apply_edits, compute_line_offsets, offset_of
from fixers.engine import fix_source
from fixers.registry import fixable_rule_ids


class TestEditApplication:
    def test_apply_single_edit(self):
        src = "abcdef"
        out = apply_edits(src, [Edit(2, 4, "XY")])
        assert out == "abXYef"

    def test_apply_multiple_non_overlapping_bottom_up(self):
        src = "0123456789"
        out = apply_edits(src, [Edit(1, 3, "A"), Edit(6, 8, "B")])
        assert out == "0A345B89"

    def test_overlapping_edits_drop_one(self):
        src = "0123456789"
        # The two edits overlap; applied bottom-up, the later-positioned one
        # wins and the overlapping earlier one is dropped.
        out = apply_edits(src, [Edit(2, 5, "X"), Edit(4, 7, "Y")])
        assert out == "0123Y789"

    def test_offset_of_maps_line_col(self):
        src = "ab\ncd\nef"
        offsets = compute_line_offsets(src)
        assert offset_of(offsets, 1, 0) == 0
        assert offset_of(offsets, 2, 0) == 3
        assert offset_of(offsets, 3, 1) == 7


class TestWeakHashFixer:
    def test_md5_rewritten_to_sha256(self):
        res = fix_source("import hashlib\nx = hashlib.md5(b'a').hexdigest()\n")
        assert "hashlib.sha256(" in res.fixed_code
        assert "hashlib.md5(" not in res.fixed_code
        assert res.changed and res.safe

    def test_sha1_rewritten(self):
        res = fix_source("import hashlib\nhashlib.sha1(b'a')\n")
        assert "hashlib.sha256(" in res.fixed_code


class TestYamlFixer:
    def test_yaml_load_to_safe_load(self):
        res = fix_source("import yaml\nyaml.load(raw)\n")
        assert "yaml.safe_load(raw)" in res.fixed_code

    def test_yaml_loader_keyword_is_removed(self):
        res = fix_source(
            "import yaml\nfrom yaml import Loader\nyaml.load(raw, Loader=Loader)\n"
        )
        assert "yaml.safe_load(raw)" in res.fixed_code
        assert "Loader=Loader" not in res.fixed_code

    def test_safe_load_untouched(self):
        res = fix_source("import yaml\nyaml.safe_load(raw)\n")
        assert not res.changed


class TestTlsFixer:
    def test_verify_false_becomes_true(self):
        res = fix_source("import requests\nrequests.get('https://x', verify=False)\n")
        assert "verify=True" in res.fixed_code
        assert "verify=False" not in res.fixed_code


class TestAssertFixer:
    def test_assert_with_message(self):
        res = fix_source("def f(a):\n    assert a > 0, 'bad'\n    return a\n")
        assert "if not (a > 0):" in res.fixed_code
        assert "raise AssertionError('bad')" in res.fixed_code
        assert "assert" not in res.fixed_code

    def test_assert_without_message(self):
        res = fix_source("def f(a):\n    assert a > 0\n    return a\n")
        assert "raise AssertionError" in res.fixed_code

    def test_fixed_code_is_valid_python(self):
        res = fix_source("def f(a):\n    assert a > 0, 'bad'\n    return a\n")
        compile(res.fixed_code, "<fixed>", "exec")


class TestEngineSafety:
    def test_reports_findings_before_after(self):
        res = fix_source("import hashlib\nhashlib.md5(b'a')\n")
        assert res.findings_before > res.findings_after

    def test_no_fixable_findings_is_noop(self):
        res = fix_source("x = 1 + 2\n")
        assert not res.changed
        assert res.safe

    def test_unparseable_source_is_safe_noop(self):
        res = fix_source("def broken(:\n")
        assert not res.changed
        assert res.safe is False

    def test_registry_exposes_fixable_rules(self):
        ids = fixable_rule_ids()
        assert {"weak_hash_algorithm", "unsafe_yaml_load",
                "tls_verification_disabled", "assert_used_for_validation"} <= ids
        assert "path_traversal" not in ids


# ---------------------------------------------------------------------------
# LLM fixer tests — all LLM calls are mocked so no API key is required
# ---------------------------------------------------------------------------

from unittest.mock import patch
from fixers.llm_fixer import llm_fix_source, _build_prompt


_INSECURE_YAML = "import yaml\ndata = yaml.load(user_input)\n"
_SECURE_YAML   = "import yaml\ndata = yaml.safe_load(user_input)\n"

_INSECURE_HASH = "import hashlib\nhashlib.md5(b'password').hexdigest()\n"
_SECURE_HASH   = "import hashlib\nhashlib.sha256(b'password').hexdigest()\n"


def _mock_llm(fixed_code: str):
    """Return a context manager that makes _call_llm return a fenced response."""
    return patch(
        "fixers.llm_fixer._call_llm",
        return_value=f"```python\n{fixed_code}\n```",
    )


class TestLlmFixerPrompt:
    def test_prompt_contains_rule_id(self):
        prompt = _build_prompt(_INSECURE_YAML, [])
        # Empty findings list edge case
        assert "```python" in prompt

    def test_prompt_lists_all_findings(self):
        from security.models.finding import Finding, Severity
        findings = [
            Finding(rule_id="unsafe_yaml_load", title="Unsafe YAML", message="yaml.load is unsafe",
                    severity=Severity.HIGH, file="t.py", line=2,
                    suggestion="Use yaml.safe_load"),
            Finding(rule_id="weak_hash_algorithm", title="Weak Hash", message="md5 is weak",
                    severity=Severity.MEDIUM, file="t.py", line=3),
        ]
        prompt = _build_prompt("code", findings)
        assert "unsafe_yaml_load" in prompt
        assert "weak_hash_algorithm" in prompt
        assert "line 2" in prompt
        assert "line 3" in prompt
        assert "yaml.safe_load" in prompt   # suggestion included


class TestLlmFixerHappyPath:
    def test_yaml_fixed_by_llm(self):
        with _mock_llm(_SECURE_YAML):
            res = llm_fix_source(_INSECURE_YAML)
        assert res.changed
        assert res.safe
        assert "yaml.safe_load" in res.fixed_code
        assert res.findings_after < res.findings_before

    def test_hash_fixed_by_llm(self):
        with _mock_llm(_SECURE_HASH):
            res = llm_fix_source(_INSECURE_HASH)
        assert res.changed
        assert res.safe
        assert "sha256" in res.fixed_code

    def test_applied_fixes_list_populated(self):
        with _mock_llm(_SECURE_YAML):
            res = llm_fix_source(_INSECURE_YAML)
        assert len(res.applied) >= 1
        assert any(a.rule_id == "unsafe_yaml_load" for a in res.applied)

    def test_diff_available(self):
        with _mock_llm(_SECURE_YAML):
            res = llm_fix_source(_INSECURE_YAML)
        diff = res.unified_diff("test.py")
        assert "yaml.load" in diff
        assert "yaml.safe_load" in diff


class TestLlmFixerSafety:
    def test_invalid_python_from_llm_reverts(self):
        with _mock_llm("def broken(:\n"):
            res = llm_fix_source(_INSECURE_YAML)
        assert not res.changed
        assert not res.safe
        assert "unparseable" in res.note.lower()

    def test_llm_introducing_new_findings_reverts(self):
        # Original has ≤2 findings; bad fix adds eval + md5 + subprocess shell = 3+ new findings
        bad_fix = (
            "import yaml, hashlib, subprocess\n"
            "data = yaml.safe_load(user_input)\n"
            "hashlib.md5(b'x')\n"
            "eval(data)\n"
            "subprocess.run(cmd, shell=True)\n"
        )
        with _mock_llm(bad_fix):
            res = llm_fix_source(_INSECURE_YAML)
        assert not res.changed
        assert not res.safe

    def test_no_security_findings_is_noop(self):
        # No security findings (no CWE-tagged rules fire on constant-only code)
        clean_code = "import hashlib\nresult = hashlib.sha256(b'hello').hexdigest()\n"
        with _mock_llm(clean_code):
            res = llm_fix_source(clean_code)
        assert not res.changed
        assert res.safe
        assert "No security findings" in res.note

    def test_unparseable_source_is_safe_noop(self):
        res = llm_fix_source("def broken(:\n")
        assert not res.changed
        assert not res.safe

    def test_llm_api_error_reverts(self):
        with patch("fixers.llm_fixer._call_llm", side_effect=RuntimeError("network error")):
            res = llm_fix_source(_INSECURE_YAML)
        assert not res.changed
        assert not res.safe
        assert "network error" in res.note

    def test_fixed_code_is_valid_python(self):
        with _mock_llm(_SECURE_YAML):
            res = llm_fix_source(_INSECURE_YAML)
        compile(res.fixed_code, "<fixed>", "exec")  # must not raise
