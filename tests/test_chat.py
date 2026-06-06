"""Tests for orchestrator chat helpers (no live LLM calls)."""

from orchestrator.chat import _build_prompt, _security_findings, security_rules_prompt


def test_security_rules_prompt_lists_owasp():
    text = security_rules_prompt()
    assert "OWASP Top 10 2021" in text
    assert "ssrf_unvalidated_url" in text
    assert "CWE-918" in text


def test_security_findings_detects_eval():
    findings = _security_findings("eval('1+1')")
    assert any(f["rule_id"] == "eval_exec_usage" for f in findings)


def test_build_prompt_includes_refinement_feedback():
    prompt = _build_prompt(
        [{"role": "user", "content": "write safe file reader"}],
        code_context="open(x)",
        findings=[{"rule_id": "path_traversal", "line": 1, "message": "bad path", "owasp": "A01"}],
    )
    assert "path_traversal" in prompt
    assert "write safe file reader" in prompt
