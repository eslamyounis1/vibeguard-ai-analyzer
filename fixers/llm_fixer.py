"""LLM-powered auto-fixer for VibeGuard security findings (CWE coverage: all rules).

The deterministic engine (engine.py) can only fix the 6 rules that have hand-written
pattern-rewrite fixers. This module sends the complete source file plus all static
findings to an OpenAI model, which generates a holistically fixed version of the code.

Design
------
- One API call per file — the model sees all findings at once and can fix them
  coherently (e.g. a fix for CWE-79 may interact with a CWE-117 fix).
- Whole-file replacement — the LLM returns the complete fixed source, avoiding the
  complexity of extracting precise byte-level edits from natural-language output.
- Static acceptance gate: the fixed code must parse and must not introduce *new*
  findings. This gate does not establish functional or semantic safety; experiments
  use benchmark oracles to measure those outcomes separately.
- On-disk caching via the existing Provider infrastructure: repeated calls with the
  same (model, temperature, source + findings) do not re-bill the API.

Usage
-----
    from fixers.llm_fixer import llm_fix_source

    result = llm_fix_source(source_code, model="gpt-4o-mini")
    if result.changed and result.safe:
        print(result.unified_diff("example.py"))
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional

from security.core.scanner import Scanner
from security.models.finding import Finding
from fixers.engine import AppliedFix, FixResult
from fixers.safety import format_introduced_findings, introduced_findings


_CODE_FENCE = re.compile(r"```(?:python)?\s*\n(.*?)```", re.DOTALL)

_PROMPT_TEMPLATE = """\
You are an expert Python security engineer. The Python source code below has \
{n} security {plural} detected by static analysis. Fix ALL of them.

## Vulnerabilities to Fix

{findings_block}
## Original Source Code

```python
{source}
```

Return the complete fixed Python source code in a single ```python ... ``` block.
Preserve all function signatures, logic, comments, and formatting exactly. \
Only change what is necessary to fix each vulnerability listed above."""


def _build_prompt(source: str, findings: List[Finding]) -> str:
    parts: List[str] = []
    for i, f in enumerate(findings, 1):
        line = f"**{i}. {f.title}** — line {f.line}, rule `{f.rule_id}`\n"
        line += f"   Issue: {f.message}\n"
        if f.suggestion:
            line += f"   Fix: {f.suggestion}"
        parts.append(line)
    findings_block = "\n\n".join(parts) + "\n\n"
    return _PROMPT_TEMPLATE.format(
        n=len(findings),
        plural="vulnerability" if len(findings) == 1 else "vulnerabilities",
        findings_block=findings_block,
        source=source,
    )


def _extract_code(text: str) -> str:
    match = _CODE_FENCE.search(text)
    return (match.group(1) if match else text).strip()


def _cache_path(
    base_dir: str, model: str, temperature: float, prompt: str
) -> Path:
    key = hashlib.sha256(
        f"llm_fix|{model}|{temperature}|{prompt}".encode("utf-8")
    ).hexdigest()
    return Path(base_dir) / "llm_fix" / f"{key}.json"


def _call_llm(
    prompt: str,
    model: str,
    temperature: float,
    cache_dir: str,
    use_cache: bool,
) -> str:
    """Call the OpenAI model (with caching) and return the raw response text."""
    path = _cache_path(cache_dir, model, temperature, prompt)

    if use_cache and path.exists():
        return json.loads(path.read_text(encoding="utf-8"))["raw"]

    from openai import OpenAI

    client = OpenAI()
    response = client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.choices[0].message.content or ""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "requested_model": model,
            "resolved_model": response.model,
            "response_id": response.id,
            "created": response.created,
            "system_fingerprint": response.system_fingerprint,
            "usage": response.usage.model_dump() if response.usage else None,
            "temperature": temperature,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "prompt": prompt,
            "raw": raw,
        }, ensure_ascii=False),
        encoding="utf-8",
    )
    return raw


def llm_fix_source(
    code: str,
    filename: str = "<code>",
    model: str = "gpt-4o-mini",
    temperature: float = 0.0,
    cache_dir: str = "data/cache",
    use_cache: bool = True,
) -> FixResult:
    """Scan ``code`` for security findings and ask an LLM to fix all of them.

    Parameters
    ----------
    code:       Full Python source code to analyse and fix.
    filename:   Used in finding messages and the unified diff header.
    model:      OpenAI model ID (default: ``gpt-4o-mini``).
    temperature: Sampling temperature; use 0.0 for deterministic output.
    cache_dir:  Root of the on-disk response cache.
    use_cache:  If False, always call the API even if a cached response exists.

    Returns
    -------
    A :class:`FixResult` whose ``fixed_code`` is the LLM-repaired source when
    ``safe`` is True, or the original source when the static gate rejects it.
    ``safe`` does not imply functional or semantic correctness.
    """
    scanner = Scanner()
    before_result = scanner.scan_source(code, filename)

    if not before_result.ok:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before_result.findings),
            findings_after=len(before_result.findings),
            safe=False,
            note="Source did not parse; nothing fixed.",
        )

    # Filter to security findings only — enriched security findings have a CWE tag;
    # code-smell and performance findings have cwe=None and should not be sent to the LLM.
    security_findings = [
        f for f in before_result.findings
        if getattr(f, "cwe", None) is not None
    ]

    if not security_findings:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before_result.findings),
            findings_after=len(before_result.findings),
            safe=True,
            note="No security findings to fix.",
        )

    prompt = _build_prompt(code, security_findings)

    try:
        raw = _call_llm(prompt, model, temperature, cache_dir, use_cache)
    except Exception as exc:  # network error, missing API key, etc.
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before_result.findings),
            findings_after=len(before_result.findings),
            safe=False,
            note=f"LLM call failed: {exc}",
        )

    fixed_code = _extract_code(raw)

    # Verify 1: fixed code must be valid Python
    try:
        ast.parse(fixed_code)
    except SyntaxError as exc:
        return FixResult(
            original_code=code,
            fixed_code=code,
            findings_before=len(before_result.findings),
            findings_after=len(before_result.findings),
            safe=False,
            note=f"LLM produced unparseable Python: {exc}",
        )

    # Verify 2: fixed code must not introduce a new finding kind or instance.
    after_result = scanner.scan_source(fixed_code, filename)
    introduced = (
        introduced_findings(before_result.findings, after_result.findings)
        if after_result.ok
        else {}
    )
    safe = after_result.ok and not introduced

    note: Optional[str] = None
    if not safe:
        if not after_result.ok:
            note = "Fixed code did not scan cleanly; reverting to original."
            fixed_code = code
        elif introduced:
            note = (
                "LLM fix introduced new findings "
                f"({format_introduced_findings(introduced)}); "
                "reverting to original."
            )
            fixed_code = code

    applied = [
        AppliedFix(
            rule_id=f.rule_id,
            line=f.line,
            description=f"{f.title} (line {f.line})",
        )
        for f in security_findings
    ] if safe else []

    return FixResult(
        original_code=code,
        fixed_code=fixed_code,
        applied=applied,
        findings_before=len(before_result.findings),
        findings_after=(
            len(after_result.findings) if after_result.ok else len(before_result.findings)
        ),
        safe=safe,
        note=note,
    )
