import json
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from pydantic import BaseModel

from vibeguard.core.scanner import Scanner
from vibeguard.models.finding import Severity

MAX_CODE_SIZE = 50_000

app = FastAPI(title="VibeGuard Static Analyzer", version="0.1.0")


class FindingModel(BaseModel):
    rule_id: str
    title: str
    message: str
    severity: str
    file: str
    line: int
    snippet: Optional[str]


class ParseErrorModel(BaseModel):
    file: str
    message: str


class AnalyzeResponse(BaseModel):
    ok: bool
    error_type: Optional[str]
    error_message: Optional[str]
    scanned_files: int
    findings: list[FindingModel]
    parse_errors: list[ParseErrorModel]
    summary: dict[str, int]


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


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_python_code(
    request: Request,
    payload: Any = Body(
        ...,
        media_type="text/plain",
        example='import random\ntoken = random.random()\neval(input())',
    ),
) -> Any:
    _ = payload
    body = await request.body()
    content_type = request.headers.get("content-type", "").lower()
    code = _extract_code(body=body, content_type=content_type)

    min_severity_header = request.headers.get("x-min-severity", "").upper()
    min_severity = Severity[min_severity_header] if min_severity_header in Severity.__members__ else None

    scanner = Scanner(min_severity=min_severity)
    try:
        result = scanner.scan_source(code)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "ok": False,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "scanned_files": 0,
                "findings": [],
                "parse_errors": [],
                "summary": {},
            },
        ) from exc

    d = result.to_dict()
    return {
        "ok": True,
        "error_type": None,
        "error_message": None,
        "scanned_files": d["scanned_files"],
        "findings": d["findings"],
        "parse_errors": d["parse_errors"],
        "summary": d["summary"],
    }
