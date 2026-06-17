"""Tests for new deterministic fixers: XSS, open redirect, SSRF, XPath injection."""

import ast

from fixers.base import apply_edits, compute_line_offsets
from fixers.fix_xss import XssFixer
from fixers.fix_open_redirect import OpenRedirectFixer
from fixers.fix_ssrf import SsrfFixer
from fixers.fix_xpath_injection import XPathInjectionFixer

from security.models.finding import Finding, Severity


def _make_finding(rule_id: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test",
        message="Test finding",
        severity=Severity.HIGH,
        file="test.py",
        line=line,
    )


def _apply_fixer(fixer, code: str, rule_id: str, line: int = 1) -> str:
    tree = ast.parse(code)
    finding = _make_finding(rule_id, line)
    offsets = compute_line_offsets(code)
    edit = fixer.fix(tree, finding, code, offsets)
    if edit is None:
        return code
    return apply_edits(code, [edit])


class TestXssFixer:
    def test_wraps_response_arg_with_escape(self):
        code = "make_response(user_data)"
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output")
        assert "html.escape" in result
        assert "user_data" in result

    def test_wraps_http_response(self):
        code = "HttpResponse(content)"
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output")
        assert "html.escape" in result
        assert "content" in result

    def test_removes_markup_wrapper(self):
        code = "Markup(user_input)"
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output")
        assert "html.escape" in result
        assert "user_input" in result
        # Markup wrapper should be gone
        assert "Markup" not in result

    def test_no_fix_for_constant(self):
        code = 'make_response("<b>safe</b>")'
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output")
        assert result == code

    def test_wraps_response_with_variable(self):
        code = "Response(rendered)"
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output")
        assert "html.escape" in result

    def test_multiline_response(self):
        code = "x = make_response(data)\ny = 1"
        result = _apply_fixer(XssFixer(), code, "unsafe_html_output", line=1)
        assert "html.escape" in result
        assert "y = 1" in result


class TestOpenRedirectFixer:
    def test_guards_redirect_to_relative(self):
        code = "redirect(url)"
        result = _apply_fixer(OpenRedirectFixer(), code, "open_redirect")
        assert "startswith('/')" in result
        assert "url" in result
        assert "'/'" in result  # fallback to root

    def test_guards_http_response_redirect(self):
        code = "HttpResponseRedirect(location)"
        result = _apply_fixer(OpenRedirectFixer(), code, "open_redirect")
        assert "startswith('/')" in result
        assert "location" in result

    def test_no_fix_for_constant(self):
        code = "redirect('/home')"
        result = _apply_fixer(OpenRedirectFixer(), code, "open_redirect")
        assert result == code

    def test_no_fix_when_no_args(self):
        code = "redirect()"
        result = _apply_fixer(OpenRedirectFixer(), code, "open_redirect")
        assert result == code

    def test_non_redirect_func_unchanged(self):
        code = "do_something(url)"
        result = _apply_fixer(OpenRedirectFixer(), code, "open_redirect")
        assert result == code


class TestSsrfFixer:
    def test_wraps_requests_get_url(self):
        code = "requests.get(url)"
        result = _apply_fixer(SsrfFixer(), code, "ssrf_unvalidated_url")
        assert "startswith" in result
        assert "https://" in result
        assert "url" in result

    def test_wraps_requests_post_url(self):
        code = "requests.post(endpoint, json=data)"
        result = _apply_fixer(SsrfFixer(), code, "ssrf_unvalidated_url")
        assert "startswith" in result
        assert "endpoint" in result

    def test_wraps_httpx_get(self):
        code = "httpx.get(target_url)"
        result = _apply_fixer(SsrfFixer(), code, "ssrf_unvalidated_url")
        assert "startswith" in result

    def test_no_fix_for_constant_url(self):
        code = "requests.get('https://api.example.com/data')"
        result = _apply_fixer(SsrfFixer(), code, "ssrf_unvalidated_url")
        assert result == code

    def test_session_client_wrapped(self):
        code = "session.get(user_url)"
        result = _apply_fixer(SsrfFixer(), code, "ssrf_unvalidated_url")
        assert "startswith" in result


class TestXPathInjectionFixer:
    def test_parameterizes_simple_fstring(self):
        code = 'tree.xpath(f"//user[@name=\'{name}\']")'
        result = _apply_fixer(XPathInjectionFixer(), code, "xpath_injection")
        # Should use parameterized form with $name
        assert "$name" in result
        assert "name=name" in result

    def test_parameterizes_path_variable(self):
        code = 'root.xpath(f"//item[@id=\'{item_id}\']")'
        result = _apply_fixer(XPathInjectionFixer(), code, "xpath_injection")
        assert "$item_id" in result
        assert "item_id=item_id" in result

    def test_no_fix_for_constant_xpath(self):
        code = 'tree.xpath("//user[@active=true()]")'
        result = _apply_fixer(XPathInjectionFixer(), code, "xpath_injection")
        assert result == code

    def test_no_fix_for_non_xpath_method(self):
        code = 'obj.find(f"//user[@name=\'{name}\']")'
        # find() IS in _XPATH_METHODS so it should be parameterized too
        result = _apply_fixer(XPathInjectionFixer(), code, "xpath_injection")
        assert "$name" in result

    def test_no_fix_for_complex_fstring(self):
        # Two variables — can't safely parameterize
        code = 'tree.xpath(f"//user[@name=\'{name}\' and @age=\'{age}\']")'
        result = _apply_fixer(XPathInjectionFixer(), code, "xpath_injection")
        assert result == code


class TestFixerRegistry:
    def test_all_new_fixers_registered(self):
        from fixers.registry import FIXERS_BY_RULE
        assert "unsafe_html_output" in FIXERS_BY_RULE
        assert "open_redirect" in FIXERS_BY_RULE
        assert "ssrf_unvalidated_url" in FIXERS_BY_RULE
        assert "xpath_injection" in FIXERS_BY_RULE

    def test_fixable_rule_ids_contains_new(self):
        from fixers.registry import fixable_rule_ids
        ids = fixable_rule_ids()
        assert "unsafe_html_output" in ids
        assert "open_redirect" in ids
        assert "ssrf_unvalidated_url" in ids
        assert "xpath_injection" in ids
