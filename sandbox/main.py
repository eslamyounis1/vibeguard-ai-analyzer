import json
import logging
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from sandbox.static_analyzer import analyze as static_analyze

# ─── Logging ──────────────────────────────────────────────────────────────────
# Log metadata only — never log raw submitted code (could contain secrets/PII).
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("vibeguard")

# ─── Config ───────────────────────────────────────────────────────────────────
APP_DIR = Path(__file__).resolve().parent
RUNNER_PATH = APP_DIR / "sandbox_runner.py"

MAX_CODE_SIZE = 50_000
EXEC_TIMEOUT_SECONDS = 20
EXEC_CPU_SECONDS = 10
EXEC_MEMORY_MB = 512

# API key auth — set VIBEGUARD_API_KEY in the environment to enable.
# If the env var is absent the server runs in open (dev/local) mode and warns.
_API_KEY = os.environ.get("VIBEGUARD_API_KEY", "")
_AUTH_REQUIRED = bool(_API_KEY)
if not _AUTH_REQUIRED:
    logger.warning(
        "VIBEGUARD_API_KEY is not set — API is running in unauthenticated mode. "
        "Set this variable before any non-local deployment."
    )

# ─── Rate limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="VibeGuard — AI Code Analyzer", version="0.2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ─── Security headers middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


# ─── Auth dependency ───────────────────────────────────────────────────────────
def _require_api_key(request: Request) -> None:
    if not _AUTH_REQUIRED:
        return
    key = request.headers.get("X-API-Key", "")
    if not key or key != _API_KEY:
        logger.warning("Unauthorized request from %s", request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")


# ─── Helpers ──────────────────────────────────────────────────────────────────
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


# ─── Models ───────────────────────────────────────────────────────────────────
class ProfileResponse(BaseModel):
    ok: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    profile: list[dict[str, Any]] = Field(default_factory=list)
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    text_report: Optional[str] = None
    totals: Optional[dict[str, Any]] = None


class AnalyzeResponse(BaseModel):
    ok: bool
    error: Optional[str] = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class FullAnalysisResponse(BaseModel):
    ok: bool
    error: Optional[str] = None
    static: Optional[dict[str, Any]] = None
    dynamic: Optional[dict[str, Any]] = None


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("30/minute")
async def analyze_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='def work(n):\n    total = 0\n    for i in range(n):\n        for j in range(n):\n            total += i * j\n    return total',
    ),
    _auth: None = Depends(_require_api_key),
) -> Any:
    """
    Static analysis: code smells, security vulnerabilities, and performance anti-patterns.
    Returns structured findings without executing the code.
    """
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code_from_request_body(body=body, content_type=content_type)

    import hashlib
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:12]
    logger.info("Static analysis request: code_hash=%s len=%d", code_hash, len(code))

    result = static_analyze(code)
    response = result.to_dict()

    logger.info(
        "Static analysis complete: code_hash=%s ok=%s total_findings=%d",
        code_hash,
        response["ok"],
        response["summary"].get("total", 0),
    )
    return response


@app.post("/profile", response_model=ProfileResponse)
@limiter.limit("10/minute")
async def profile_python_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='def square(x):\n    return x * x\nprint(square(12))',
    ),
    _auth: None = Depends(_require_api_key),
) -> Any:
    """
    Dynamic profiling: executes code in an isolated subprocess with CPU, memory,
    and wall-time limits, and returns per-function performance metrics.
    """
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code_from_request_body(body=body, content_type=content_type)

    import hashlib
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:12]
    logger.info("Profile request: code_hash=%s len=%d", code_hash, len(code))

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
            logger.warning("Sandbox timeout: code_hash=%s", code_hash)
            raise HTTPException(
                status_code=408,
                detail={
                    "ok": False,
                    "error_type": "TimeoutError",
                    "error_message": f"Execution exceeded {EXEC_TIMEOUT_SECONDS} seconds.",
                    "profile": [],
                },
            ) from exc

        if completed.returncode != 0 and not completed.stdout.strip():
            error_message = completed.stderr.strip() or _describe_termination(completed.returncode)
            logger.warning("Sandbox runtime error: code_hash=%s rc=%d", code_hash, completed.returncode)
            raise HTTPException(
                status_code=400,
                detail={
                    "ok": False,
                    "error_type": "SandboxRuntimeError",
                    "error_message": error_message,
                    "profile": [],
                    "stderr": completed.stderr.strip() or None,
                },
            )

        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            logger.error("Sandbox returned non-JSON output: code_hash=%s", code_hash)
            raise HTTPException(
                status_code=500,
                detail={
                    "ok": False,
                    "error_type": "InvalidSandboxResponse",
                    "error_message": "Sandbox returned non-JSON output.",
                    "profile": [],
                    "stderr": completed.stderr.strip() or None,
                },
            ) from exc

        logger.info(
            "Profile complete: code_hash=%s ok=%s",
            code_hash,
            result.get("ok"),
        )
        return result


@app.post("/full-analysis", response_model=FullAnalysisResponse)
@limiter.limit("5/minute")
async def full_analysis(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='def work(n):\n    total = 0\n    for i in range(n):\n        total += i * i\n    return total\n\nprint(work(200000))',
    ),
    _auth: None = Depends(_require_api_key),
) -> Any:
    """
    Combined endpoint: runs static analysis + dynamic profiling and returns both results.
    """
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code_from_request_body(body=body, content_type=content_type)

    import hashlib
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:12]
    logger.info("Full analysis request: code_hash=%s len=%d", code_hash, len(code))

    # Static analysis (never raises)
    static_result = static_analyze(code).to_dict()

    # Dynamic profiling (isolated subprocess)
    dynamic_result: Optional[dict] = None
    with tempfile.TemporaryDirectory(prefix="sandbox_") as tmp_dir:
        code_path = Path(tmp_dir) / "user_code.py"
        code_path.write_text(code, encoding="utf-8")
        cmd = [
            "python3", "-I", str(RUNNER_PATH),
            "--code-path", str(code_path),
            "--cpu-seconds", str(EXEC_CPU_SECONDS),
            "--memory-mb", str(EXEC_MEMORY_MB),
        ]
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=EXEC_TIMEOUT_SECONDS, check=False,
            )
            if completed.stdout.strip():
                dynamic_result = json.loads(completed.stdout)
            else:
                dynamic_result = {
                    "ok": False,
                    "error_type": "SandboxRuntimeError",
                    "error_message": completed.stderr.strip() or _describe_termination(completed.returncode),
                }
        except subprocess.TimeoutExpired:
            dynamic_result = {
                "ok": False,
                "error_type": "TimeoutError",
                "error_message": f"Execution exceeded {EXEC_TIMEOUT_SECONDS} seconds.",
            }
        except json.JSONDecodeError:
            dynamic_result = {
                "ok": False,
                "error_type": "InvalidSandboxResponse",
                "error_message": "Sandbox returned non-JSON output.",
            }

    return {"ok": True, "static": static_result, "dynamic": dynamic_result}
