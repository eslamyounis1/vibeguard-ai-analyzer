"""Orchestration API: combines static security analysis with sandbox profiling.

This service is the only HTTP surface allowed to mix the two domains. The
``security`` API stays security-only and the ``sandbox`` API stays
metrics-only; cross-cutting endpoints (static + dynamic, before/after
comparisons) live here.
"""

import json
from typing import Any, List, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from fixers.engine import fix_source
from orchestrator.chat import generate_secure_code
from orchestrator.pipeline import analyze_and_profile, compare_fix

MAX_CODE_SIZE = 50_000

app = FastAPI(title="VibeGuard Orchestrator", version="0.1.0")


class ChatMessage(BaseModel):
    role: str = "user"
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    code: Optional[str] = None
    provider: str = "openai"
    model: Optional[str] = None
    refine: bool = True
    max_iterations: int = Field(default=3, ge=1, le=5)
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _extract_code(body: bytes, content_type: str) -> str:
    if not body:
        raise HTTPException(status_code=422, detail="Request body is required.")

    if "application/json" in content_type:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=422, detail="Invalid JSON body.") from exc
        code = parsed.get("code") if isinstance(parsed, dict) else (parsed if isinstance(parsed, str) else None)
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


@app.post("/fix")
async def fix_python_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example="import hashlib\nhashlib.md5(b'x').hexdigest()",
    ),
) -> Any:
    """Return safe auto-fixed code and the list of applied fixes."""
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)
    return {"ok": True, **fix_source(code).to_dict()}


@app.post("/analyze-profile")
async def analyze_and_profile_code(
    request: Request,
    payload: Any = Body(..., media_type="text/plain", example="print(sum(range(1000)))"),
) -> Any:
    """Static analysis plus dynamic profiling with performance corroboration."""
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)
    return {"ok": True, **analyze_and_profile(code)}


@app.post("/compare")
async def compare_fix_code(
    request: Request,
    payload: Any = Body(..., media_type="text/plain", example="import hashlib\nprint(hashlib.md5(b'x').hexdigest())"),
) -> Any:
    """Auto-fix the code and report before/after comparative metrics."""
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)
    return {"ok": True, **compare_fix(code)}


@app.post("/chat")
async def chat_generate(body: ChatRequest) -> Any:
    """Generate Python code from chat messages with OWASP/VibeGuard rule awareness."""
    if body.code and len(body.code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=422, detail=f"Code length exceeds {MAX_CODE_SIZE} characters.")
    try:
        result = generate_secure_code(
            [m.model_dump() for m in body.messages],
            code_context=body.code,
            provider=body.provider,
            model=body.model,
            refine=body.refine,
            max_iterations=body.max_iterations,
            temperature=body.temperature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"ok": True, **result}
