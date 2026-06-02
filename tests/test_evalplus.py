"""Tests for the EvalPlus corpus loader (HumanEval+ / MBPP+, RQ3 energy)."""

from pathlib import Path

import pytest

from corpus.build import build_corpus
from corpus.loaders.evalplus import load_evalplus
from corpus.schema import read_corpus

EVALPLUS_ROOT = Path("dataset/evalplus")
pytestmark = pytest.mark.skipif(
    not (EVALPLUS_ROOT / "humanevalplus").is_dir(),
    reason="EvalPlus dataset not downloaded (dataset/evalplus/)",
)


class TestEvalPlusLoader:
    def test_loads_both_subsets(self):
        samples = load_evalplus(limit=5)
        assert len(samples) == 10  # 5 per subset
        subsets = {s.metadata["subset"] for s in samples}
        assert subsets == {"humanevalplus", "mbppplus"}

    def test_humaneval_sample_fields(self):
        samples = load_evalplus(subsets=("humanevalplus",), limit=1)
        s = samples[0]
        assert s.source == "human"
        assert s.entry_point
        assert s.entry_point in s.code
        assert s.tests and f"check({s.entry_point})" in s.tests
        assert "evalplus" in s.tags

    def test_mbpp_sample_fields(self):
        samples = load_evalplus(subsets=("mbppplus",), limit=1)
        s = samples[0]
        assert s.source == "human"
        # MBPP+ entry point is parsed from the reference code.
        assert s.entry_point and f"def {s.entry_point}" in s.code
        # MBPP+ tests call the entry point directly (no check() wrapper).
        assert s.tests and s.entry_point in s.tests

    def test_unknown_subset_raises(self):
        with pytest.raises(ValueError):
            load_evalplus(subsets=("bogus",), limit=1)

    def test_build_evalplus_jsonl(self, tmp_path):
        out = tmp_path / "evalplus.jsonl"
        count = build_corpus(
            datasets=["evalplus"],
            generate=[],
            limit=3,
            cache_dir=tmp_path / "cache",
            out=out,
            evalplus_path=str(EVALPLUS_ROOT),
        )
        assert count == 6  # 3 per subset
        loaded = read_corpus(out)
        assert all(s.source == "human" for s in loaded)
