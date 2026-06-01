"""Tests for the RQ3 energy runner (uses the always-available linear_proxy)."""

import json
from pathlib import Path

from corpus.schema import CorpusSample, write_corpus
from experiments.run_energy import (
    correlation_rows,
    has_perf_finding,
    run_energy,
    runnable_code,
)

# A nested loop over a range triggers VibeGuard's performance smell rules.
_PERF_CODE = (
    "def work(n):\n"
    "    total = 0\n"
    "    for i in range(n):\n"
    "        for j in range(n):\n"
    "            total += i * j\n"
    "    return total\n"
)
_CLEAN_CODE = "def add(a, b):\n    return a + b\n"


def _sample(sid: str, code: str, tests: str | None, source: str = "human") -> CorpusSample:
    return CorpusSample(
        id=sid, task_id=sid, source=source, prompt="", code=code, tests=tests,
        metadata={"subset": "test"},
    )


class TestHelpers:
    def test_runnable_code_appends_tests(self):
        s = _sample("a", _CLEAN_CODE, "assert add(1, 2) == 3\n")
        assert "assert add(1, 2) == 3" in runnable_code(s, with_tests=True)
        assert "assert" not in runnable_code(s, with_tests=False)

    def test_runnable_code_without_tests(self):
        s = _sample("a", _CLEAN_CODE, None)
        assert runnable_code(s, with_tests=True) == _CLEAN_CODE

    def test_perf_finding_detection(self):
        assert has_perf_finding(_PERF_CODE) is True
        assert has_perf_finding(_CLEAN_CODE) is False

    def test_correlation_rows_shape(self):
        grouped = {
            "perf::energy_joules_estimate": [0.5, 0.6],
            "no_perf::energy_joules_estimate": [0.1, 0.2],
            "perf::wall_time_seconds": [0.05, 0.06],
            "no_perf::wall_time_seconds": [0.01, 0.02],
        }
        rows = correlation_rows(grouped)
        metrics = {r["metric"] for r in rows}
        assert metrics == {"energy_joules_estimate", "wall_time_seconds"}
        energy = next(r for r in rows if r["metric"] == "energy_joules_estimate")
        assert energy["n_with_perf_finding"] == 2
        # Perf group has higher energy -> positive pct_higher_with_perf.
        assert energy["pct_higher_with_perf"] > 0


class TestRunEnergy:
    def test_end_to_end_linear_proxy(self, tmp_path):
        corpus = tmp_path / "corpus.jsonl"
        write_corpus(
            [
                _sample("perf-1", _PERF_CODE, "work(40)\n"),
                _sample("clean-1", _CLEAN_CODE, "add(1, 2)\n"),
            ],
            corpus,
        )
        out_dir = tmp_path / "out"
        summary = run_energy(
            corpus=str(corpus),
            out_dir=str(out_dir),
            runs=2,
            warmup=1,
            energy_backend="linear_proxy",
        )
        assert summary["n_measured"] == 2
        assert summary["energy_backend_used"] == "linear_proxy"
        assert (out_dir / "rq3_energy.csv").read_text().strip()
        assert (out_dir / "rq3_correlation.csv").exists()
        assert (out_dir / "METHODS.md").exists()
        loaded = json.loads((out_dir / "summary.json").read_text())
        assert loaded["with_tests"] is True
        assert len(loaded["correlation"]) == 2
