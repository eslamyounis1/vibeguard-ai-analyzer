import argparse
import contextlib
import io
import json
import os
import resource
import time
import tracemalloc
import sys
import traceback
from collections import defaultdict
from pathlib import Path


def _clamp_limit(requested: int, hard_limit: int) -> int:
    if hard_limit in (-1, resource.RLIM_INFINITY):
        return requested
    return min(requested, hard_limit)


def _set_soft_limit(resource_name: int, requested: int) -> None:
    soft, hard = resource.getrlimit(resource_name)
    target = _clamp_limit(requested, hard)
    try:
        resource.setrlimit(resource_name, (target, hard))
    except (ValueError, OSError):
        # Some platforms disallow reducing certain limits.
        pass


def apply_limits(cpu_seconds: int, memory_mb: int) -> None:
    memory_bytes = memory_mb * 1024 * 1024

    _set_soft_limit(resource.RLIMIT_CPU, cpu_seconds)
    _set_soft_limit(resource.RLIMIT_AS, memory_bytes)
    # Prevent very large output flooding.
    _set_soft_limit(resource.RLIMIT_FSIZE, 1_000_000)


# Low-fidelity energy proxy: energy(J) = cpu_seconds * CPU_POWER_WATTS.
# This is a coarse linear model (ignores frequency scaling, memory power, and
# profiler overhead) and is reported as an estimate only. For higher fidelity,
# integrate RAPL (pyRAPL) or CodeCarbon on supported hardware.
CPU_POWER_WATTS = 50.0


def _function_name(frame: object) -> str:
    code_obj = frame.f_code
    return f"{code_obj.co_filename}:{code_obj.co_firstlineno}:{code_obj.co_name}"


def _summarize_function_metrics(function_totals: dict[str, dict[str, float]]) -> list[dict]:
    """Return every profiled function sorted by self CPU time (descending).

    Times stored here are *self* times (callee time already subtracted), so the
    list can be summed without double-counting nested calls.
    """
    summary = []
    for function_key, data in function_totals.items():
        cpu_seconds = data["cpu_seconds"]
        summary.append(
            {
                "function": function_key,
                "calls": int(data["calls"]),
                "cpu_time_seconds": round(cpu_seconds, 6),
                "wall_time_seconds": round(data["wall_seconds"], 6),
                "memory_delta_bytes": int(data["memory_delta_bytes"]),
                "energy_joules_estimate": round(cpu_seconds * CPU_POWER_WATTS, 6),
            }
        )

    return sorted(summary, key=lambda item: item["cpu_time_seconds"], reverse=True)


def run_user_code(code: str) -> dict:
    globals_dict = {"__name__": "__main__", "__builtins__": __builtins__}
    user_stdout = io.StringIO()
    user_stderr = io.StringIO()
    call_stack = []
    function_totals: dict[str, dict[str, float]] = defaultdict(
        lambda: {"calls": 0.0, "cpu_seconds": 0.0, "wall_seconds": 0.0, "memory_delta_bytes": 0.0}
    )

    def trace_calls(frame, event, arg):  # noqa: ANN001
        if event == "call":
            memory_now, _ = tracemalloc.get_traced_memory()
            call_stack.append(
                {
                    "function_key": _function_name(frame),
                    "start_cpu": time.process_time(),
                    "start_wall": time.perf_counter(),
                    "start_memory": memory_now,
                    # CPU/wall time consumed by direct + transitive callees of
                    # this frame, used to derive *self* time on return.
                    "children_cpu": 0.0,
                    "children_wall": 0.0,
                }
            )
        elif event in ("return", "exception") and call_stack:
            end_cpu = time.process_time()
            end_wall = time.perf_counter()
            memory_now, _ = tracemalloc.get_traced_memory()
            start = call_stack.pop()

            gross_cpu = max(0.0, end_cpu - start["start_cpu"])
            gross_wall = max(0.0, end_wall - start["start_wall"])
            self_cpu = max(0.0, gross_cpu - start["children_cpu"])
            self_wall = max(0.0, gross_wall - start["children_wall"])

            function_key = start["function_key"]
            totals = function_totals[function_key]
            totals["calls"] += 1
            totals["cpu_seconds"] += self_cpu
            totals["wall_seconds"] += self_wall
            totals["memory_delta_bytes"] += memory_now - start["start_memory"]

            # Attribute this frame's gross time to its parent so the parent's
            # self time excludes time spent inside this call.
            if call_stack:
                parent = call_stack[-1]
                parent["children_cpu"] += gross_cpu
                parent["children_wall"] += gross_wall
        return trace_calls

    try:
        compiled = compile(code, "<user_code>", "exec")
        tracemalloc.start()
        with contextlib.redirect_stdout(user_stdout), contextlib.redirect_stderr(user_stderr):
            sys.setprofile(trace_calls)
            exec(compiled, globals_dict, None)  # noqa: S102 - explicit sandbox subprocess
            sys.setprofile(None)
    except Exception:
        sys.setprofile(None)
        tracemalloc.stop()
        return {
            "ok": False,
            "error_type": "ExecutionError",
            "error_message": traceback.format_exc(limit=10),
            "profile": [],
            "stdout": user_stdout.getvalue(),
            "stderr": user_stderr.getvalue(),
            "totals": None,
        }
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    all_functions = _summarize_function_metrics(function_totals)
    # Totals are computed across ALL functions (self times, no double counting);
    # the returned profile is capped to the heaviest 50 for readability.
    total_cpu = sum(item["cpu_time_seconds"] for item in all_functions)
    total_wall = sum(item["wall_time_seconds"] for item in all_functions)
    total_energy = sum(item["energy_joules_estimate"] for item in all_functions)
    top_functions = all_functions[:50]

    return {
        "ok": True,
        "error_type": None,
        "error_message": None,
        "profile": top_functions,
        "stdout": user_stdout.getvalue(),
        "stderr": user_stderr.getvalue(),
        "text_report": None,
        "totals": {
            "cpu_time_seconds": round(total_cpu, 6),
            "wall_time_seconds": round(total_wall, 6),
            "energy_joules_estimate": round(total_energy, 6),
            "memory_current_bytes": int(current_mem),
            "memory_peak_bytes": int(peak_mem),
            "assumed_cpu_power_watts": CPU_POWER_WATTS,
            "energy_model": "linear_cpu_proxy (estimate only)",
        },
    }


def run_user_code_measure(code: str, energy_backend: str = "auto") -> dict:
    """Clean energy/time measurement run.

    Unlike :func:`run_user_code`, this does NOT install ``sys.setprofile`` (which
    adds large per-call overhead and contaminates energy/time numbers). It wraps
    the whole execution in a single :class:`EnergyMeter` so the reported energy
    reflects the program, not the profiler. Use this for headline metrics; use
    ``run_user_code`` for per-function hotspot attribution.
    """
    # Under ``python3 -I`` the script directory is not on sys.path, so make the
    # sandbox package importable before pulling in the energy backends.
    repo_root = str(Path(__file__).resolve().parents[1])
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from sandbox.energy import get_meter

    meter = get_meter(energy_backend)
    globals_dict = {"__name__": "__main__", "__builtins__": __builtins__}
    user_stdout = io.StringIO()
    user_stderr = io.StringIO()

    try:
        compiled = compile(code, "<user_code>", "exec")
        tracemalloc.start()
        cpu_start = time.process_time()
        with contextlib.redirect_stdout(user_stdout), contextlib.redirect_stderr(user_stderr):
            with meter.measure():
                exec(compiled, globals_dict, None)  # noqa: S102 - explicit sandbox subprocess
        cpu_seconds = max(0.0, time.process_time() - cpu_start)
    except Exception:
        tracemalloc.stop()
        return {
            "ok": False,
            "error_type": "ExecutionError",
            "error_message": traceback.format_exc(limit=10),
            "profile": [],
            "stdout": user_stdout.getvalue(),
            "stderr": user_stderr.getvalue(),
            "totals": None,
        }

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    sample = meter.result

    return {
        "ok": True,
        "error_type": None,
        "error_message": None,
        "profile": [],
        "stdout": user_stdout.getvalue(),
        "stderr": user_stderr.getvalue(),
        "text_report": None,
        "totals": {
            "cpu_time_seconds": round(cpu_seconds, 6),
            "wall_time_seconds": round(sample.wall_seconds, 6),
            "energy_joules_estimate": sample.energy_joules,
            "energy_backend": sample.backend,
            "pkg_joules": sample.pkg_joules,
            "dram_joules": sample.dram_joules,
            "memory_current_bytes": int(current_mem),
            "memory_peak_bytes": int(peak_mem),
            "energy_model": sample.note,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code-path", required=True)
    parser.add_argument("--cpu-seconds", type=int, default=2)
    parser.add_argument("--memory-mb", type=int, default=128)
    parser.add_argument("--mode", choices=["profile", "measure"], default="profile")
    parser.add_argument("--energy-backend", default="auto")
    args = parser.parse_args()

    apply_limits(cpu_seconds=args.cpu_seconds, memory_mb=args.memory_mb)

    with open(args.code_path, "r", encoding="utf-8") as code_file:
        code = code_file.read()

    if args.mode == "measure":
        result = run_user_code_measure(code, energy_backend=args.energy_backend)
    else:
        result = run_user_code(code)
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    # Remove inherited env vars that may leak secrets to untrusted code.
    os.environ.clear()
    main()
