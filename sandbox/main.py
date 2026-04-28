import json
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
RUNNER_PATH = APP_DIR / "sandbox_runner.py"

MAX_CODE_SIZE = 50_000
EXEC_TIMEOUT_SECONDS = 20
EXEC_CPU_SECONDS = 10
EXEC_MEMORY_MB = 512

app = FastAPI(title="Python Profiling Sandbox", version="0.1.0")
def _describe_termination(return_code: int) -> str:
    if return_code >= 0:
        return "Sandbox process failed."
    signal_num = -return_code
    try:
        signal_name = signal.Signals(signal_num).name
    except ValueError:
        signal_name = f"SIG{signal_num}"
    if signal_name == "SIGXCPU":
        return f"Sandbox terminated by CPU limit ({signal_name})."
    if signal_name == "SIGKILL":
        return "Sandbox terminated by hard resource limit (SIGKILL)."
    return f"Sandbox terminated by signal {signal_name}."




class ProfileResponse(BaseModel):
    ok: bool
    error_type: Optional[str]
    error_message: Optional[str]
    profile: list[dict[str, Any]]
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    text_report: Optional[str] = None
    totals: Optional[dict[str, Any]] = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _extract_code_from_request_body(body: bytes, content_type: str) -> str:
    if not body:
        raise HTTPException(status_code=422, detail="Request body is required.")

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body.") from exc

        if isinstance(parsed, dict):
            code = parsed.get("code")
        elif isinstance(parsed, str):
            code = parsed
        else:
            code = None
    else:
        try:
            code = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="Body must be UTF-8 text.") from exc

    if not isinstance(code, str):
        raise HTTPException(status_code=422, detail="Provide code as JSON {'code': '...'} or raw text body.")
    if not code.strip():
        raise HTTPException(status_code=422, detail="Code cannot be empty.")
    if len(code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=422, detail=f"Code length exceeds {MAX_CODE_SIZE} characters.")
    return code


@app.post("/profile", response_model=ProfileResponse)
async def profile_python_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='def square(x):\n    return x * x\nprint(square(12))',
    ),
) -> Any:
    _ = payload  # Keep explicit body schema so Swagger renders an input box.
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code_from_request_body(body=body, content_type=content_type)

    with tempfile.TemporaryDirectory(prefix="sandbox_") as tmp_dir:
        code_path = Path(tmp_dir) / "user_code.py"
        code_path.write_text(code, encoding="utf-8")

        cmd = [
            "python3",
            "-I",
            str(RUNNER_PATH),
            "--code-path",
            str(code_path),
            "--cpu-seconds",
            str(EXEC_CPU_SECONDS),
            "--memory-mb",
            str(EXEC_MEMORY_MB),
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=EXEC_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(
                status_code=408,
                detail={
                    "ok": False,
                    "error_type": "TimeoutError",
                    "error_message": f"Execution exceeded {EXEC_TIMEOUT_SECONDS} seconds.",
                    "profile": [],
                    "stdout": None,
                    "stderr": None,
                    "text_report": None,
                    "totals": None,
                },
            ) from exc

        if completed.returncode != 0 and not completed.stdout.strip():
            error_message = completed.stderr.strip() or _describe_termination(completed.returncode)
            raise HTTPException(
                status_code=400,
                detail={
                    "ok": False,
                    "error_type": "SandboxRuntimeError",
                    "error_message": error_message,
                    "profile": [],
                    "stdout": None,
                    "stderr": completed.stderr.strip() or None,
                    "text_report": None,
                    "totals": None,
                },
            )

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "ok": False,
                    "error_type": "InvalidSandboxResponse",
                    "error_message": "Sandbox returned non-JSON output.",
                    "profile": [],
                    "stdout": None,
                    "stderr": completed.stderr.strip() or None,
                    "text_report": None,
                    "totals": None,
                },
            ) from exc

        return payload
