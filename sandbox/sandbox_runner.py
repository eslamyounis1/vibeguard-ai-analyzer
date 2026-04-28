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


CPU_POWER_WATTS = 50.0


def _function_name(frame: object) -> str:
    code_obj = frame.f_code
    return f"{code_obj.co_filename}:{code_obj.co_firstlineno}:{code_obj.co_name}"


def _summarize_function_metrics(function_totals: dict[str, dict[str, float]]) -> list[dict]:
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

    return sorted(summary, key=lambda item: item["cpu_time_seconds"], reverse=True)[:50]


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
                }
            )
        elif event in ("return", "exception") and call_stack:
            end_cpu = time.process_time()
            end_wall = time.perf_counter()
            memory_now, _ = tracemalloc.get_traced_memory()
            start = call_stack.pop()
            function_key = start["function_key"]
            totals = function_totals[function_key]
            totals["calls"] += 1
            totals["cpu_seconds"] += max(0.0, end_cpu - start["start_cpu"])
            totals["wall_seconds"] += max(0.0, end_wall - start["start_wall"])
            totals["memory_delta_bytes"] += memory_now - start["start_memory"]
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
    top_functions = _summarize_function_metrics(function_totals)
    total_cpu = sum(item["cpu_time_seconds"] for item in top_functions)
    total_wall = sum(item["wall_time_seconds"] for item in top_functions)
    total_energy = sum(item["energy_joules_estimate"] for item in top_functions)

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
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code-path", required=True)
    parser.add_argument("--cpu-seconds", type=int, default=2)
    parser.add_argument("--memory-mb", type=int, default=128)
    args = parser.parse_args()

    apply_limits(cpu_seconds=args.cpu_seconds, memory_mb=args.memory_mb)

    with open(args.code_path, "r", encoding="utf-8") as code_file:
        code = code_file.read()

    result = run_user_code(code)
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    # Remove inherited env vars that may leak secrets to untrusted code.
    os.environ.clear()
    main()
