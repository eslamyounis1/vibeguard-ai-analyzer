"""End-to-end orchestration across VibeGuard's layers.

This module is intentionally *outside* both the ``security`` package (static
security analysis) and the ``sandbox`` package (dynamic runtime metrics). It is
the only layer allowed to depend on both: it combines static findings with
sandbox-measured runtime cost.

Two entry points:

* :func:`analyze_and_profile` runs static analysis *and* dynamic profiling on
  the same code and corroborates static performance findings with measured
  runtime cost (the proposal's "profiling validates static analysis").
* :func:`compare_fix` produces an auto-fixed version and reports before/after
  security, performance, and energy metrics (the proposal's "comparative
  metrics" output), refusing fixes that change observable behavior.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sandbox.profiler import measure_code
from security.core.scanner import Scanner
from fixers.engine import fix_source
from security.models.finding import Category


def _totals(profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return profile.get("totals") if profile.get("ok") else None


def analyze_and_profile(
    code: str, run_dynamic: bool = True, energy_backend: str = "auto"
) -> Dict[str, Any]:
    """Static scan + optional dynamic profile, with performance corroboration."""
    result = Scanner().scan_source(code)
    static = result.to_dict()

    perf_findings = [f for f in result.findings if f.category == Category.PERFORMANCE]

    dynamic: Optional[Dict[str, Any]] = None
    measured_wall_ms: Optional[float] = None

    if run_dynamic:
        dynamic = measure_code(code, energy_backend=energy_backend)
        totals = _totals(dynamic)
        if totals is not None and totals.get("wall_time_seconds") is not None:
            measured_wall_ms = round(totals["wall_time_seconds"] * 1000, 3)

    # Build per-finding corroboration array matching the TypeScript interface:
    # Array<{ rule_id: string; confirmed: boolean; measured_ms?: number }>
    corroboration = [
        {
            "rule_id": f.rule_id,
            "confirmed": measured_wall_ms is not None,
            "measured_ms": measured_wall_ms,
        }
        for f in perf_findings
    ]

    return {
        "static": static,
        "dynamic": dynamic,
        "performance_corroboration": corroboration,
    }


def _metric_delta(before: Optional[float], after: Optional[float]) -> Optional[Dict[str, Any]]:
    if before is None or after is None:
        return None
    delta = round(after - before, 6)
    pct = round((delta / before) * 100, 2) if before else None
    return {"before": before, "after": after, "delta": delta, "pct_change": pct}


def _tests_pass(code: str, tests: str, energy_backend: str) -> bool:
    """True if ``code`` followed by ``tests`` executes without raising."""
    combined = f"{code}\n\n{tests}\n"
    return bool(measure_code(combined, energy_backend=energy_backend).get("ok"))


def compare_fix(
    code: str,
    run_dynamic: bool = True,
    energy_backend: str = "auto",
    tests: Optional[str] = None,
    cweval_task_stem: Optional[str] = None,
    cweval_test_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Auto-fix the code and report before/after comparative metrics.

    When ``tests`` (executable Python that raises on failure) is provided, the
    fix is validated in the sandbox. For CWEval tasks, pass ``cweval_task_stem``
    and ``cweval_test_path`` to run the official pytest oracles instead.
    """
    fix = fix_source(code)

    comparison: Dict[str, Any] = {
        "fix": fix.to_dict(),
        "security": {
            "findings_before": fix.findings_before_list,
            "findings_after": fix.findings_after_list,
            "delta": max(0, fix.findings_before - fix.findings_after),
        },
        "performance": None,
        "behavior_preserved": None,
        "tests": None,
    }

    if run_dynamic and fix.changed:
        if cweval_task_stem and cweval_test_path:
            from experiments.cweval_runner import run_cweval_tests

            before = run_cweval_tests(fix.original_code, cweval_task_stem, cweval_test_path)
            after = run_cweval_tests(fix.fixed_code, cweval_task_stem, cweval_test_path)
            comparison["tests"] = {
                "cweval_functional_before": before.functional,
                "cweval_secure_before": before.secure,
                "cweval_functional_after": after.functional,
                "cweval_secure_after": after.secure,
                "behavior_verified": (
                    before.functional is not False
                    and before.secure is not False
                    and after.functional is not False
                    and after.secure is not False
                ),
            }
        elif tests:
            passed_before = _tests_pass(fix.original_code, tests, energy_backend)
            passed_after = _tests_pass(fix.fixed_code, tests, energy_backend)
            comparison["tests"] = {
                "tests_passed_before": passed_before,
                "tests_passed_after": passed_after,
                "behavior_verified": passed_before and passed_after,
            }

    if not run_dynamic or not fix.changed:
        return comparison

    before = measure_code(fix.original_code, energy_backend=energy_backend)
    after = measure_code(fix.fixed_code, energy_backend=energy_backend)

    before_totals = _totals(before)
    after_totals = _totals(after)

    # Behavior guard: identical stdout on both runs means the fix did not change
    # observable output. If either run failed to execute we can't assert this.
    if before.get("ok") and after.get("ok"):
        comparison["behavior_preserved"] = before.get("stdout") == after.get("stdout")
    else:
        comparison["behavior_preserved"] = None

    if before_totals is not None and after_totals is not None:
        energy_delta_info = _metric_delta(
            before_totals.get("energy_joules_estimate"), after_totals.get("energy_joules_estimate")
        )
        comparison["performance"] = {
            # Flat fields matching the TypeScript CompareResponse.performance interface
            "cpu_before": before_totals.get("cpu_time_seconds"),
            "cpu_after": after_totals.get("cpu_time_seconds"),
            "energy_before": before_totals.get("energy_joules_estimate"),
            "energy_after": after_totals.get("energy_joules_estimate"),
            # Detailed deltas for research pipeline consumers
            "cpu_time_seconds": _metric_delta(
                before_totals.get("cpu_time_seconds"), after_totals.get("cpu_time_seconds")
            ),
            "wall_time_seconds": _metric_delta(
                before_totals.get("wall_time_seconds"), after_totals.get("wall_time_seconds")
            ),
            "energy_joules_estimate": energy_delta_info,
            "memory_peak_bytes": _metric_delta(
                before_totals.get("memory_peak_bytes"), after_totals.get("memory_peak_bytes")
            ),
        }
        # Surfaced at top level for RQ8 aggregation
        comparison["delta_energy_joules"] = (
            energy_delta_info["delta"] if energy_delta_info else None
        )
    else:
        comparison["performance"] = {
            "note": "Could not profile before/after (code not executable in sandbox).",
        }
        comparison["delta_energy_joules"] = None

    return comparison
