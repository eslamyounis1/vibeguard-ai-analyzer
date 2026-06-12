"""Tests for the taint-lite AST tracer (W6)."""

from __future__ import annotations

import pytest

from security.taint.tracer import TaintPath, trace_taint


class TestTaintTracer:

    def test_direct_ssrf_param_to_requests_get(self):
        code = """\
import requests

def fetch(url):
    return requests.get(url)
"""
        paths = trace_taint(code, sink_categories=["ssrf"])
        assert len(paths) >= 1
        assert paths[0].source_param == "url"
        assert paths[0].sink_call == "get"
        assert paths[0].sink_category == "ssrf"

    def test_ssrf_via_intermediate_variable(self):
        code = """\
import requests

def fetch_resource(user_url):
    target = user_url
    return requests.get(target)
"""
        paths = trace_taint(code, sink_categories=["ssrf"])
        assert len(paths) >= 1
        assert paths[0].source_param == "user_url"

    def test_xss_fstring_to_response(self):
        code = """\
def render(name):
    html = f"<h1>{name}</h1>"
    return make_response(html)
"""
        paths = trace_taint(code, sink_categories=["xss"])
        assert len(paths) >= 1
        assert paths[0].sink_call == "make_response"
        assert paths[0].sink_category == "xss"

    def test_log_injection_fstring(self):
        code = """\
import logging
logger = logging.getLogger(__name__)

def handle(user_input):
    msg = f"action: {user_input}"
    logger.info(msg)
"""
        paths = trace_taint(code, sink_categories=["log"])
        assert len(paths) >= 1
        assert paths[0].source_param == "user_input"
        assert paths[0].sink_category == "log"

    def test_no_taint_constant_only(self):
        code = """\
import requests

def fetch():
    return requests.get("https://example.com/api")
"""
        paths = trace_taint(code, sink_categories=["ssrf"])
        assert len(paths) == 0

    def test_concat_propagation(self):
        code = """\
import requests

def fetch(path):
    url = "https://base.com/" + path
    return requests.get(url)
"""
        paths = trace_taint(code, sink_categories=["ssrf"])
        assert len(paths) >= 1
        assert paths[0].source_param == "path"

    def test_no_params_returns_empty(self):
        code = """\
import requests

def fetch():
    url = "https://example.com"
    return requests.get(url)
"""
        paths = trace_taint(code)
        assert len(paths) == 0

    def test_syntax_error_returns_empty(self):
        paths = trace_taint("def broken(")
        assert paths == []

    def test_category_filter(self):
        code = """\
import requests
import logging
logger = logging.getLogger(__name__)

def process(data):
    logger.info(f"got: {data}")
    return requests.get(data)
"""
        ssrf_paths = trace_taint(code, sink_categories=["ssrf"])
        log_paths = trace_taint(code, sink_categories=["log"])
        assert any(p.sink_category == "ssrf" for p in ssrf_paths)
        assert any(p.sink_category == "log" for p in log_paths)

    def test_taint_path_str_representation(self):
        code = """\
import requests

def fetch(url):
    return requests.get(url)
"""
        paths = trace_taint(code)
        assert len(paths) >= 1
        s = str(paths[0])
        assert "url" in s
        assert "get" in s
