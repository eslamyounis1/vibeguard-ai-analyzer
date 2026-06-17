"""Tests for the research harness: energy backends, measure mode, statistics,
corpus, baselines, and the performance fixers.

Experiment dependencies (scipy/pandas/matplotlib/external CLIs) are optional;
these tests only exercise functionality that works without them.
"""

import ast
import sys

import pytest

from corpus.providers.base import Provider, extract_code
from corpus.schema import CorpusSample, read_corpus, write_corpus
from experiments.measure import (
    cliffs_delta,
    compare_metric,
    summarize,
    _mannwhitney_u,
)
from fixers.engine import fix_source
from sandbox.energy import LinearProxyMeter, available_backends, get_meter
from sandbox.profiler import measure_code


# ── Energy backends ─────────────────────────────────────────────────────────

class TestEnergyBackends:
    def test_linear_proxy_always_available(self):
        assert LinearProxyMeter.available() is True
        assert "linear_proxy" in available_backends()

    def test_auto_returns_a_working_meter(self):
        meter = get_meter("auto")
        with meter.measure():
            sum(range(100000))
        sample = meter.result
        assert sample.wall_seconds >= 0.0
        assert sample.backend in available_backends() or sample.backend == "linear_proxy"

    def test_proxy_energy_is_nonnegative(self):
        meter = get_meter("linear_proxy")
        with meter.measure():
            sum(range(50000))
        assert meter.result.energy_joules is not None
        assert meter.result.energy_joules >= 0.0

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError):
            get_meter("does-not-exist")


# ── Measure mode (clean run, no setprofile) ─────────────────────────────────

class TestMeasureMode:
    def test_measure_code_shape(self):
        result = measure_code("print(sum(range(10000)))", energy_backend="linear_proxy")
        assert result["ok"] is True
        assert result["profile"] == []  # no per-function profiling in measure mode
        totals = result["totals"]
        for key in ("cpu_time_seconds", "wall_time_seconds", "energy_joules_estimate", "energy_backend"):
            assert key in totals
        assert totals["energy_backend"] == "linear_proxy"

    def test_measure_reports_runtime_error(self):
        result = measure_code("raise ValueError('boom')", energy_backend="linear_proxy")
        assert result["ok"] is False


# ── Statistics ───────────────────────────────────────────────────────────────

class TestStatistics:
    def test_cliffs_delta_extremes(self):
        delta, label = cliffs_delta([5, 6, 7, 8], [1, 2, 3, 4])
        assert delta == 1.0 and label == "large"
        delta, label = cliffs_delta([1, 2, 3], [1, 2, 3])
        assert delta == 0.0 and label == "negligible"

    def test_mannwhitney_detects_difference(self):
        _, p = _mannwhitney_u([10, 11, 12, 13, 14], [1, 2, 3, 4, 5])
        assert p < 0.05

    def test_summarize_ci(self):
        stats = summarize("metric", [1.0, 1.0, 1.0, 1.0])
        assert stats.mean == 1.0
        assert stats.stdev == 0.0
        assert stats.ci95_low == 1.0 and stats.ci95_high == 1.0

    def test_compare_metric_improvement(self):
        cmp = compare_metric("wall", [10.0] * 5, [5.0] * 5)
        assert cmp.improvement_pct == 50.0


# ── Corpus ───────────────────────────────────────────────────────────────────

class TestCorpus:
    def test_sample_roundtrip(self, tmp_path):
        samples = [
            CorpusSample(id="a", task_id="t1", source="gpt", prompt="p", code="x = 1",
                         expected_security_labels=["weak_hash_algorithm"], tags=["ai"]),
            CorpusSample(id="b", task_id="t2", source="human", prompt="q", code="y = 2"),
        ]
        path = tmp_path / "c.jsonl"
        assert write_corpus(samples, path) == 2
        loaded = read_corpus(path)
        assert [s.id for s in loaded] == ["a", "b"]
        assert loaded[0].expected_security_labels == ["weak_hash_algorithm"]

    def test_security_benchmark_loader(self):
        from corpus.loaders import load_security_benchmark

        samples = load_security_benchmark()
        assert len(samples) > 0
        assert any(s.expected_security_labels for s in samples)

    def test_humaneval_fallback_has_tests(self):
        from corpus.loaders import load_humaneval

        samples = load_humaneval(limit=1)
        assert len(samples) == 1
        assert samples[0].tests and "check(" in samples[0].tests

    def test_extract_code_strips_fences(self):
        assert extract_code("```python\nx = 1\n```") == "x = 1"
        assert extract_code("x = 2") == "x = 2"

    def test_provider_disk_cache(self, tmp_path):
        class DummyProvider(Provider):
            name = "dummy"
            calls = 0

            def _complete(self, prompt: str) -> str:
                type(self).calls += 1
                return "```python\nvalue = 42\n```"

        provider = DummyProvider(model="m", cache_dir=tmp_path)
        first = provider.generate("prompt")
        second = provider.generate("prompt")
        assert first == "value = 42" == second
        assert DummyProvider.calls == 1  # second call served from cache


# ── Baselines ────────────────────────────────────────────────────────────────

class TestBaselines:
    def test_tool_resolution_checks_active_python_environment(
        self, tmp_path, monkeypatch
    ):
        from experiments import baselines

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        python = bin_dir / "python"
        tool = bin_dir / "bandit"
        python.write_text("", encoding="utf-8")
        tool.write_text("#!/bin/sh\n", encoding="utf-8")
        tool.chmod(0o755)
        monkeypatch.setattr(sys, "executable", str(python))
        monkeypatch.setattr(baselines.shutil, "which", lambda name: None)

        assert baselines.tool_executable("bandit") == str(tool)

    def test_vibeguard_adapter_reports_cwe(self):
        from experiments.baselines import run_vibeguard

        run = run_vibeguard("import hashlib\nhashlib.md5(b'x').hexdigest()")
        assert run.ok and run.findings
        assert any(f.cwe for f in run.findings)

    def test_labels_to_cwes(self):
        from experiments.baselines import labels_to_cwes

        cwes = labels_to_cwes(["weak_hash_algorithm", "CWE-89"])
        assert "CWE-89" in cwes

    def test_precision_recall_perfect(self):
        from experiments.baselines import run_vibeguard, security_precision_recall

        code = "import hashlib\nhashlib.md5(b'x')"
        run = run_vibeguard(code)
        gt = {f.cwe for f in run.findings if f.cwe}
        pr = security_precision_recall([gt], [{"vibeguard": run}], tools=("vibeguard",))
        assert pr["vibeguard"].recall == 1.0


# ── Performance fixers (gated behavior elsewhere; here check safety) ─────────

class TestPerfFixers:
    def test_membership_to_set(self):
        code = "def f(xs):\n    out = []\n    for x in xs:\n        if x in [1, 2, 3]:\n            out.append(x)\n    return out\n"
        result = fix_source(code)
        assert result.changed and result.safe
        assert "{1, 2, 3}" in result.fixed_code
        ast.parse(result.fixed_code)

    def test_string_concat_rewrite(self):
        code = "def build(items):\n    s = \"\"\n    for i in items:\n        s += str(i)\n    return s\n"
        result = fix_source(code)
        assert result.changed and result.safe
        assert '"".join(' in result.fixed_code
        ast.parse(result.fixed_code)

    def test_string_concat_behavior_preserved(self):
        code = "def build(items):\n    s = \"\"\n    for i in items:\n        s += str(i)\n    return s\n"
        result = fix_source(code)
        namespace: dict = {}
        exec(result.fixed_code, namespace)  # noqa: S102 - test of generated code
        assert namespace["build"]([1, 2, 3]) == "123"
