"""Rule-aware secure code generation for the orchestrator chat API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from corpus.providers import get_provider
from corpus.providers.base import extract_code
from security.core.scanner import Scanner
from security.models.finding import Category
from security.rules.security.metadata import _METADATA_BY_RULE


def security_rules_prompt() -> str:
    lines = [
        "You are VibeGuard, an assistant that writes secure Python code.",
        "Follow OWASP Top 10 2021 and these VibeGuard rules:",
        "",
    ]
    for rule_id, meta in sorted(_METADATA_BY_RULE.items()):
        lines.append(
            f"- {rule_id} ({meta.cwe}, {meta.owasp}): avoid patterns that trigger this rule. {meta.impact}"
        )
    lines.extend(
        [
            "",
            "Requirements:",
            "- Return ONLY a fenced ```python code block with the complete solution.",
            "- No eval/exec, no shell=True, no pickle.loads on untrusted data.",
            "- Use parameterized SQL, safe YAML loading, TLS verification, secrets from env.",
            "- Validate and allow-list user/file/URL inputs; escape HTML output.",
            "- Prefer pathlib with resolved paths inside an allowed base directory.",
        ]
    )
    return "\n".join(lines)


def _security_findings(code: str) -> List[dict]:
    result = Scanner().scan_source(code)
    rows = []
    for finding in result.findings:
        if finding.category != Category.SECURITY:
            continue
        rows.append(
            {
                "rule_id": finding.rule_id,
                "line": finding.line,
                "message": finding.message,
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            }
        )
    return rows


def _build_prompt(
    messages: List[Dict[str, str]],
    code_context: Optional[str],
    findings: Optional[List[dict]] = None,
) -> str:
    parts = [security_rules_prompt(), ""]
    if code_context and code_context.strip():
        parts.extend(["Current editor code:", "```python", code_context.strip(), "```", ""])
    if findings:
        parts.append("Previous attempt still violates these rules — fix them:")
        for f in findings:
            parts.append(f"- [{f['rule_id']}] line {f.get('line')}: {f['message']} ({f.get('owasp', '')})")
        parts.append("")
    parts.append("Conversation:")
    for msg in messages:
        role = msg.get("role", "user").upper()
        parts.append(f"{role}: {msg.get('content', '').strip()}")
    parts.append("")
    parts.append("Respond with improved Python code only in a ```python fenced block.")
    return "\n".join(parts)


def generate_secure_code(
    messages: List[Dict[str, str]],
    *,
    code_context: Optional[str] = None,
    provider: str = "openai",
    model: Optional[str] = None,
    refine: bool = True,
    max_iterations: int = 3,
    temperature: float = 0.2,
    use_cache: bool = False,
) -> Dict[str, Any]:
    """Generate code from chat messages and optionally refine until security-clean."""
    if not messages:
        raise ValueError("messages must not be empty")

    provider_kwargs: Dict[str, Any] = {"temperature": temperature}
    if model:
        provider_kwargs["model"] = model
    llm = get_provider(provider, **provider_kwargs)

    iterations: List[dict] = []
    last_code = ""
    last_findings: List[dict] = []
    rounds = max(1, max_iterations if refine else 1)

    for attempt in range(rounds):
        prompt = _build_prompt(messages, code_context, last_findings if attempt > 0 else None)
        raw = llm._complete(prompt)  # noqa: SLF001 — chat bypasses corpus cache by design
        code = extract_code(raw)
        findings = _security_findings(code)
        iterations.append(
            {
                "attempt": attempt + 1,
                "findings_count": len(findings),
                "findings": findings,
            }
        )
        last_code = code
        last_findings = findings
        if not findings:
            break

    return {
        "code": last_code,
        "findings": last_findings,
        "clean": len(last_findings) == 0,
        "iterations": iterations,
        "provider": provider,
        "model": getattr(llm, "model", model),
        "rules_prompt_excerpt": security_rules_prompt().splitlines()[:8],
    }
