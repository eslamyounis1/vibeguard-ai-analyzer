"""Run CWEval pytest oracles against generated code.

CWEval tests import task modules by stem (``from cwe_502_0_task import fn``).
This runner writes candidate code into a temp directory as ``{stem}_task.py``,
copies the official ``*_test.py``, and runs pytest with ``-m functionality``
and ``-m security``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CWEvalTestResult:
    ok: bool
    functional: Optional[bool]
    secure: Optional[bool]
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _run_pytest_marker(work_dir: Path, test_name: str, marker: str) -> Optional[bool]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            test_name,
            "-m",
            marker,
            "-q",
            "--tb=line",
            "-k",
            "not _unsafe",
        ],
        cwd=work_dir,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 5:
        # no tests collected for this marker
        return None
    return proc.returncode == 0


def run_cweval_tests(
    code: str,
    task_stem: str,
    test_path: str | Path,
) -> CWEvalTestResult:
    """Execute CWEval pytest oracle against ``code`` for one task."""
    test_path = Path(test_path)
    if not test_path.exists():
        return CWEvalTestResult(
            ok=False,
            functional=None,
            secure=None,
            error=f"Test file not found: {test_path}",
        )

    with tempfile.TemporaryDirectory(prefix="vg_cweval_") as tmp:
        work = Path(tmp)
        task_file = work / f"{task_stem}_task.py"
        task_file.write_text(code, encoding="utf-8")
        dest_test = work / test_path.name
        shutil.copy(test_path, dest_test)

        try:
            functional = _run_pytest_marker(work, dest_test.name, "functionality")
            secure = _run_pytest_marker(work, dest_test.name, "security")
        except Exception as exc:
            return CWEvalTestResult(
                ok=False,
                functional=None,
                secure=None,
                error=str(exc),
            )

    ok = (functional is not False) and (secure is not False)
    return CWEvalTestResult(ok=ok, functional=functional, secure=secure)
