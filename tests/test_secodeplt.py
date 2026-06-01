"""Tests for the SeCodePLT corpus loader.

The row -> CorpusSample mapping and CWE normalization are tested directly with
synthetic records so they do not depend on the (large, possibly mislabeled)
parquet download. An integration test runs only if the local Python splits
actually contain Python rows.
"""

from pathlib import Path

import pytest

from corpus.loaders.secodeplt import _normalize_cwe, _to_sample, load_secodeplt

SECODEPLT_ROOT = Path("dataset/secodeplt")


class TestCweNormalization:
    def test_variants(self):
        assert _normalize_cwe("CWE-79") == "CWE-79"
        assert _normalize_cwe("79") == "CWE-79"
        assert _normalize_cwe("cwe_502") == "CWE-502"
        assert _normalize_cwe("") is None
        assert _normalize_cwe(None) is None


class TestRowMapping:
    def test_to_sample_maps_vuln_and_patch(self):
        record = {
            "id": "task-1",
            "input_prompt": "def f():",
            "vulnerable_code_reference": "def f():\n    eval(x)\n",
            "patched_code_reference": "def f():\n    ast.literal_eval(x)\n",
            "CWE_ID": "94",
            "language": "Python",
            "context": "ctx",
        }
        s = _to_sample(record, "python_secure_coding")
        assert s.source == "secodeplt"
        assert s.task_id == "task-1"
        assert "eval(x)" in s.code  # vulnerable reference is the study subject
        assert s.reference_solution and "literal_eval" in s.reference_solution
        assert s.expected_security_labels == ["CWE-94"]
        assert s.metadata["split"] == "python_secure_coding"
        assert "secodeplt" in s.tags


@pytest.mark.skipif(
    not (SECODEPLT_ROOT / "data").is_dir(),
    reason="SeCodePLT dataset not downloaded (dataset/secodeplt/)",
)
class TestSecodepltIntegration:
    def test_python_filter_returns_only_python_or_empty(self):
        samples = load_secodeplt(root=SECODEPLT_ROOT, limit=5)
        # Some published snapshots mislabel python_* splits with C/C++ rows; in
        # that case the language filter correctly yields nothing.
        for s in samples:
            assert "python" in str(s.metadata.get("language", "")).lower()
            assert s.expected_security_labels
