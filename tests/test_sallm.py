"""Tests for the SALLM corpus loader (security smoke set)."""

from pathlib import Path

import pytest

from corpus.build import build_corpus
from corpus.loaders.sallm import _cwe_from_id, load_sallm
from corpus.schema import read_corpus

SALLM_PATH = Path("dataset/sallm/dataset.jsonl")
pytestmark = pytest.mark.skipif(
    not SALLM_PATH.is_file(),
    reason="SALLM dataset not downloaded (dataset/sallm/dataset.jsonl)",
)


class TestCweParsing:
    def test_parses_padded_and_long_cwes(self):
        assert _cwe_from_id("Matching_Author_A_cwe502_0.py") == "CWE-502"
        assert _cwe_from_id("Tainted_CodeQL_T_cwe020_3.py") == "CWE-020"
        assert _cwe_from_id("Assertion_X_cwe1204_0.py") == "CWE-1204"
        assert _cwe_from_id("no_cwe_here.py") is None


class TestSallmLoader:
    def test_loads_all_rows(self):
        samples = load_sallm()
        assert len(samples) == 100

    def test_limit(self):
        assert len(load_sallm(limit=10)) == 10

    def test_sample_fields(self):
        s = load_sallm(limit=1)[0]
        assert s.source == "sallm"
        assert s.expected_security_labels
        assert s.expected_security_labels[0].startswith("CWE-")
        # Bundled completion is the insecure reference and contains the prompt stub.
        assert s.code.startswith(s.prompt)
        assert "sallm" in s.tags
        assert s.tests is None

    def test_build_sallm_jsonl(self, tmp_path):
        out = tmp_path / "sallm.jsonl"
        count = build_corpus(
            datasets=["sallm"],
            generate=[],
            limit=5,
            cache_dir=tmp_path / "cache",
            out=out,
            sallm_path=str(SALLM_PATH),
        )
        assert count == 5
        loaded = read_corpus(out)
        assert all(s.source == "sallm" for s in loaded)
