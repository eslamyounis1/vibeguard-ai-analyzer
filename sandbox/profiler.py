"""In-process client for the isolated profiling sandbox.

This invokes ``sandbox/sandbox_runner.py`` in a separate, resource-limited
``python3 -I`` subprocess (the same mechanism the FastAPI sandbox uses) and
returns the parsed profile dictionary. All runtime metrics (CPU, wall time,
memory, estimated energy) are produced inside the sandbox; callers only
receive the measured results.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

_RUNNER_PATH = Path(__file__).resolve().parent / "sandbox_runner.py"

DEFAULT_CPU_SECONDS = 10
DEFAULT_MEMORY_MB = 512
DEFAULT_TIMEOUT_SECONDS = 20


def _error(error_type: str, message: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "error_type": error_type,
        "error_message": message,
        "profile": [],
        "stdout": None,
        "stderr": None,
        "totals": None,
    }


def profile_code(
    code: str,
    cpu_seconds: int = DEFAULT_CPU_SECONDS,
    memory_mb: int = DEFAULT_MEMORY_MB,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    mode: str = "profile",
    energy_backend: str = "auto",
) -> Dict[str, Any]:
    """Run ``code`` in the sandbox and return the runner's result dict.

    ``mode="profile"`` collects per-function self-time hotspots; ``mode="measure"``
    does a clean energy/time run (no profiler overhead) using ``energy_backend``.
    """
    if not _RUNNER_PATH.exists():
        return _error("SandboxMissing", f"Sandbox runner not found at {_RUNNER_PATH}.")

    with tempfile.TemporaryDirectory(prefix="vg_profile_") as tmp_dir:
        code_path = Path(tmp_dir) / "user_code.py"
        code_path.write_text(code, encoding="utf-8")

        cmd = [
            sys.executable or "python3",
            "-I",
            str(_RUNNER_PATH),
            "--code-path",
            str(code_path),
            "--cpu-seconds",
            str(cpu_seconds),
            "--memory-mb",
            str(memory_mb),
            "--mode",
            mode,
            "--energy-backend",
            energy_backend,
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _error("TimeoutError", f"Execution exceeded {timeout_seconds} seconds.")

        if completed.returncode != 0 and not completed.stdout.strip():
            message = completed.stderr.strip() or f"Sandbox exited with code {completed.returncode}."
            return _error("SandboxRuntimeError", message)

        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError:
            return _error("InvalidSandboxResponse", "Sandbox returned non-JSON output.")


def measure_code(
    code: str,
    energy_backend: str = "auto",
    cpu_seconds: int = DEFAULT_CPU_SECONDS,
    memory_mb: int = DEFAULT_MEMORY_MB,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Clean energy/time measurement run (no profiler overhead)."""
    return profile_code(
        code,
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        timeout_seconds=timeout_seconds,
        mode="measure",
        energy_backend=energy_backend,
    )
