"""Tests for sandbox metric correctness and the orchestration pipeline."""

from orchestrator.pipeline import analyze_and_profile, compare_fix
from sandbox.sandbox_runner import run_user_code


class TestSelfTimeAccounting:
    def test_totals_not_double_counted(self):
        # parent() spends all its time inside child(); summing self-times must
        # not exceed the wall clock of a single top-level call meaningfully.
        code = """
def child(n):
    total = 0
    for i in range(n):
        total += i
    return total

def parent(n):
    return child(n) + child(n)

print(parent(20000))
"""
        result = run_user_code(code)
        assert result["ok"], result
        totals = result["totals"]
        # Self CPU of every function summed equals the total; this is only
        # possible if nested time was subtracted from parents.
        per_fn_cpu = sum(f["cpu_time_seconds"] for f in result["profile"])
        assert abs(per_fn_cpu - totals["cpu_time_seconds"]) < 1e-6

    def test_energy_is_cpu_times_power(self):
        code = "print(sum(range(100000)))"
        result = run_user_code(code)
        assert result["ok"]
        totals = result["totals"]
        expected = round(totals["cpu_time_seconds"] * totals["assumed_cpu_power_watts"], 6)
        assert abs(totals["energy_joules_estimate"] - expected) < 1e-3

    def test_execution_error_reported(self):
        result = run_user_code("raise ValueError('boom')")
        assert result["ok"] is False
        assert result["error_type"] == "ExecutionError"


class TestPipeline:
    def test_analyze_and_profile_corroborates_perf(self):
        code = """
def f(items):
    out = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                out.append(items[i])
    return out

print(len(f(list(range(80)))))
"""
        report = analyze_and_profile(code)
        corr = report["performance_corroboration"]
        # performance_corroboration is now an array of per-finding entries
        assert isinstance(corr, list)
        assert len(corr) >= 1
        assert "rule_id" in corr[0]
        assert "confirmed" in corr[0]

    def test_compare_fix_reports_findings_removed(self):
        code = "import hashlib\nprint(hashlib.md5(b'x').hexdigest())\n"
        report = compare_fix(code, run_dynamic=False)
        assert report["security"]["delta"] >= 1
        assert report["fix"]["changed"] is True

    def test_compare_fix_detects_behavior_change(self):
        # md5 -> sha256 changes printed output, so behavior is not preserved.
        code = "import hashlib\nprint(hashlib.md5(b'x').hexdigest())\n"
        report = compare_fix(code, run_dynamic=True)
        assert report["behavior_preserved"] is False
