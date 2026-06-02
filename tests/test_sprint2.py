"""Sprint 2: baselines CLI, scoped metrics, study runner on CWEval corpus."""

from pathlib import Path

import pytest

from corpus.build import build_corpus
from corpus.schema import read_corpus
from experiments.baselines import evaluate_corpus
from experiments.run_baselines import rq5_outcomes

CWEVAL_ROOT = Path("dataset/cweval/benchmark/core/py")
pytestmark = pytest.mark.skipif(
    not CWEVAL_ROOT.is_dir(),
    reason="CWEval dataset not downloaded",
)


class TestSyntheticCorpus:
    def test_build_synthetic_corpus(self, tmp_path):
        out = tmp_path / "synthetic.jsonl"
        count = build_corpus(
            datasets=["cweval-synthetic"],
            generate=[],
            limit=5,
            cache_dir=tmp_path / "cache",
            out=out,
            cweval_path=str(CWEVAL_ROOT),
        )
        assert count > 0
        samples = read_corpus(out)
        assert all(s.source == "synthetic:insecure" for s in samples)
        assert all("cweval" in s.tags for s in samples)
        assert samples[0].metadata.get("test_path")


class TestBaselines:
    def test_evaluate_synthetic_corpus(self, tmp_path):
        out = tmp_path / "synthetic.jsonl"
        build_corpus(
            datasets=["cweval-synthetic"],
            generate=[],
            limit=3,
            cache_dir=tmp_path / "cache",
            out=out,
            cweval_path=str(CWEVAL_ROOT),
        )
        samples = read_corpus(out)
        per_sample, aggregate, pr = evaluate_corpus(samples, ai_only=True, scope_cwes=True)
        assert per_sample
        assert aggregate
        assert "vibeguard" in pr
        vg = next(r for r in aggregate if r["tool"] == "vibeguard")
        assert "precision" in vg

    def test_rq5_outcomes_has_rows(self, tmp_path):
        out = tmp_path / "synthetic.jsonl"
        build_corpus(
            datasets=["cweval-synthetic"],
            generate=[],
            limit=2,
            cache_dir=tmp_path / "cache",
            out=out,
            cweval_path=str(CWEVAL_ROOT),
        )
        samples = read_corpus(out)
        outcomes = rq5_outcomes(samples, ai_only=True)
        assert outcomes
        assert "cweval_secure" in outcomes[0]


class TestStudyRunner:
    def test_cweval_study_smoke(self, tmp_path):
        from experiments.run_study import build_default_cweval_study_corpus, main
        import sys

        corpus = tmp_path / "study.jsonl"
        build_default_cweval_study_corpus(corpus, limit=3)
        merged = read_corpus(corpus)
        assert any(s.source == "human" for s in merged)
        assert any(s.source == "synthetic:insecure" for s in merged)

        out = tmp_path / "results"
        sys.argv = [
            "run_study",
            "--corpus",
            str(corpus),
            "--out-dir",
            str(out),
            "--no-dynamic",
        ]
        main()
        assert (out / "rq1_prevalence.csv").exists()
        assert (out / "rq2_matched_tasks.csv").exists()
        assert (out / "rq4_repair.csv").exists()
        assert (out / "rq5_baselines.csv").exists()
        assert (out / "rq5_static_vs_oracle.csv").exists()
        assert (out / "METHODS.md").exists()
