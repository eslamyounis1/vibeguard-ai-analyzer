"""Tests for the auto-fix (optimization) engine."""

from security.fixers.base import Edit, apply_edits, compute_line_offsets, offset_of
from security.fixers.engine import fix_source
from security.fixers.registry import fixable_rule_ids


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
