"""Tests for orchestrator chat helpers (no live LLM calls)."""

from unittest.mock import MagicMock, patch

from orchestrator.chat import _build_prompt, _security_findings, generate_secure_code, security_rules_prompt

# ---------------------------------------------------------------------------
# security_rules_prompt
# ---------------------------------------------------------------------------

def test_security_rules_prompt_lists_owasp() -> None:
    text = security_rules_prompt()
    assert "OWASP Top 10 2021" in text
    assert "ssrf_unvalidated_url" in text
    assert "CWE-918" in text


def test_security_rules_prompt_lists_all_owasp_categories() -> None:
    text = security_rules_prompt()
    # A06 (Vulnerable Components) has no static-analysis rule; all others are covered
    for category in ("A01", "A02", "A03", "A04", "A05", "A07", "A08", "A09", "A10"):
        assert category in text, f"OWASP category {category} missing from rules prompt"


def test_security_rules_prompt_includes_requirements() -> None:
    text = security_rules_prompt()
    assert "eval/exec" in text
    assert "parameterized SQL" in text
    assert "TLS" in text


# ---------------------------------------------------------------------------
# _security_findings
# ---------------------------------------------------------------------------

def test_security_findings_detects_eval() -> None:
    findings = _security_findings("eval('1+1')")
    assert any(f["rule_id"] == "eval_exec_usage" for f in findings)


def test_security_findings_returns_empty_for_clean_code() -> None:
    findings = _security_findings("x = 1 + 1\nprint(x)\n")
    assert findings == []


def test_security_findings_detects_multiple_issues() -> None:
    code = "import hashlib\nhashlib.md5(b'pw')\neval('x')\n"
    findings = _security_findings(code)
    rule_ids = [f["rule_id"] for f in findings]
    assert "weak_hash_algorithm" in rule_ids
    assert "eval_exec_usage" in rule_ids


def test_security_findings_handles_syntax_error_gracefully() -> None:
    findings = _security_findings("def broken(:\n    pass\n")
    assert isinstance(findings, list)


def test_security_findings_returns_security_category_only() -> None:
    findings = _security_findings("eval('x')")
    for f in findings:
        assert "rule_id" in f
        assert "line" in f
        assert "message" in f


# ---------------------------------------------------------------------------
# _build_prompt
# ---------------------------------------------------------------------------

def test_build_prompt_includes_refinement_feedback() -> None:
    prompt = _build_prompt(
        [{"role": "user", "content": "write safe file reader"}],
        code_context="open(x)",
        findings=[{"rule_id": "path_traversal", "line": 1, "message": "bad path", "owasp": "A01"}],
    )
    assert "path_traversal" in prompt
    assert "write safe file reader" in prompt


def test_build_prompt_no_findings_omits_refinement_section() -> None:
    prompt = _build_prompt(
        [{"role": "user", "content": "hello"}],
        code_context=None,
        findings=None,
    )
    assert "Previous attempt" not in prompt
    assert "hello" in prompt


def test_build_prompt_empty_code_context_omits_editor_section() -> None:
    prompt = _build_prompt(
        [{"role": "user", "content": "test"}],
        code_context="",
        findings=None,
    )
    assert "Current editor code" not in prompt


def test_build_prompt_includes_code_context_when_provided() -> None:
    prompt = _build_prompt(
        [{"role": "user", "content": "improve this"}],
        code_context="import os\nos.system('ls')",
        findings=None,
    )
    assert "Current editor code" in prompt
    assert "os.system" in prompt


def test_build_prompt_includes_system_rules() -> None:
    prompt = _build_prompt([{"role": "user", "content": "x"}], code_context=None)
    assert "VibeGuard" in prompt
    assert "OWASP" in prompt


# ---------------------------------------------------------------------------
# generate_secure_code
# ---------------------------------------------------------------------------

_CLEAN_RESPONSE = "```python\ndef safe_add(a, b):\n    return a + b\n```"
_INSECURE_RESPONSE = "```python\nresult = eval(user_input)\n```"


def _mock_provider(response: str) -> MagicMock:
    provider = MagicMock()
    provider._complete.return_value = response
    provider.model = "mock-model"
    return provider


def test_generate_secure_code_returns_code_on_clean_response() -> None:
    with patch("orchestrator.chat.get_provider", return_value=_mock_provider(_CLEAN_RESPONSE)):
        result = generate_secure_code(
            [{"role": "user", "content": "write an add function"}],
            provider="openai",
            refine=False,
        )
    assert "safe_add" in result["code"]
    assert result["clean"] is True
    assert result["iterations"][0]["attempt"] == 1


def test_generate_secure_code_refines_on_insecure_output() -> None:
    clean_on_second = [_INSECURE_RESPONSE, _CLEAN_RESPONSE]
    mock_prov = _mock_provider(_INSECURE_RESPONSE)
    mock_prov._complete.side_effect = clean_on_second

    with patch("orchestrator.chat.get_provider", return_value=mock_prov):
        result = generate_secure_code(
            [{"role": "user", "content": "write something"}],
            provider="openai",
            refine=True,
            max_iterations=3,
        )

    assert len(result["iterations"]) == 2
    assert result["iterations"][0]["findings_count"] > 0
    assert result["clean"] is True


def test_generate_secure_code_raises_on_empty_messages() -> None:
    import pytest
    with pytest.raises(ValueError, match="messages must not be empty"):
        generate_secure_code([], provider="openai")


def test_generate_secure_code_respects_max_iterations() -> None:
    mock_prov = _mock_provider(_INSECURE_RESPONSE)

    with patch("orchestrator.chat.get_provider", return_value=mock_prov):
        result = generate_secure_code(
            [{"role": "user", "content": "do something"}],
            provider="openai",
            refine=True,
            max_iterations=2,
        )

    assert len(result["iterations"]) <= 2
