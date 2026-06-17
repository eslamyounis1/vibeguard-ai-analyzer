"""Tests for experiments/metrics.py — secure@k / vulnerable@k estimators."""

import math
import pytest

from experiments.metrics import (
    _at_k,
    fix_rate_at_k,
    secure_at_k,
    vulnerable_at_k,
    compute_metrics_for_group,
    compute_metrics_per_model,
    compute_task_level_at_k,
)


class TestAtK:
    def test_zero_successes(self):
        assert _at_k(10, 0, 1) == 0.0

    def test_all_successes(self):
        assert _at_k(10, 10, 5) == 1.0

    def test_half_successes_k1(self):
        assert _at_k(10, 5, 1) == pytest.approx(0.5)

    def test_increases_with_k(self):
        n, c = 10, 3
        prev = 0.0
        for k in range(1, 8):
            v = _at_k(n, c, k)
            assert v >= prev
            prev = v

    def test_n_less_than_k_is_undefined(self):
        with pytest.raises(ValueError):
            _at_k(4, 2, 10)

    def test_k_equals_n(self):
        assert _at_k(5, 3, 5) == 1.0

    def test_successes_exceed_remaining_failures(self):
        assert _at_k(10, 8, 5) == 1.0


class TestVulnerableAtK:
    def test_basic(self):
        assert vulnerable_at_k(10, 5, 1) == pytest.approx(0.5)

    def test_all_vulnerable(self):
        assert vulnerable_at_k(5, 5, 1) == 1.0


class TestSecureAtK:
    def test_basic(self):
        result = secure_at_k(10, 3, 1)
        assert result == pytest.approx(0.3)

    def test_zero_secure(self):
        assert secure_at_k(10, 0, 5) == 0.0


class TestFixRateAtK:
    def test_basic(self):
        result = fix_rate_at_k(5, 2, 3)
        assert 0.0 < result <= 1.0

    def test_all_fixed(self):
        assert fix_rate_at_k(5, 5, 1) == 1.0


class TestComputeMetricsForGroup:
    def _make_samples(self, n_vuln, n_secure, n_total):
        samples = []
        for i in range(n_total):
            samples.append({
                "has_finding": i < n_vuln,
                "is_secure": i >= (n_total - n_secure),
            })
        return samples

    def test_returns_all_k_values(self):
        samples = self._make_samples(6, 2, 10)
        metrics = compute_metrics_for_group(samples, k_values=(1, 5, 10))
        assert "vulnerable@1" in metrics
        assert "vulnerable@5" in metrics
        assert "vulnerable@10" in metrics
        assert "secure@1" in metrics

    def test_counts_correct(self):
        samples = self._make_samples(4, 3, 10)
        metrics = compute_metrics_for_group(samples, k_values=(1,))
        assert metrics["c_vuln"] == 4
        assert metrics["c_secure"] == 3
        assert metrics["n"] == 10

    def test_fix_rate_when_key_provided(self):
        samples = [{"has_finding": True, "is_secure": False, "fixed": i < 3} for i in range(10)]
        metrics = compute_metrics_for_group(samples, k_values=(1,), fixed_key="fixed")
        assert "fix_rate@1" in metrics
        assert metrics["c_fixed"] == 3


class TestComputeMetricsPerModel:
    def test_groups_by_model(self):
        rows = [
            {"source": "gpt-4o", "has_finding": True, "is_secure": False},
            {"source": "gpt-4o", "has_finding": False, "is_secure": True},
            {"source": "gpt-4o-mini", "has_finding": True, "is_secure": False},
        ]
        result = compute_metrics_per_model(rows, k_values=(1,))
        sources = {r["source"] for r in result}
        assert "gpt-4o" in sources
        assert "gpt-4o-mini" in sources
        assert len(result) == 2


class TestTaskLevelAtK:
    def test_macro_averages_repeated_samples_by_task(self):
        rows = [
            {"task_id": "a", "secure": True},
            {"task_id": "a", "secure": False},
            {"task_id": "b", "secure": False},
            {"task_id": "b", "secure": False},
        ]
        result = compute_task_level_at_k(rows, success_key="secure", k_values=(1, 2))
        assert result["secure@1"] == pytest.approx(0.25)
        assert result["secure@2"] == pytest.approx(0.5)

    def test_skips_k_without_enough_repeats(self):
        rows = [{"task_id": "a", "secure": True}]
        result = compute_task_level_at_k(rows, success_key="secure", k_values=(1, 3))
        assert "secure@1" in result
        assert "secure@3" not in result
