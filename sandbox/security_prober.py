"""Dynamic security probers — one per rule class.

Each probe wraps the suspicious function in a minimal test harness, executes
it in the existing sandbox (isolated subprocess), and analyses the output to
confirm or dismiss the static finding.

All probes inherit from SecurityProbe and must be safe to run. They never send
network requests or touch real files outside the subprocess sandbox.
"""

from __future__ import annotations

import ast
import json
import os
import tempfile
import textwrap
from typing import Any, Dict, Optional

from sandbox.probe_base import ProbeResult, ProbeStatus, SecurityProbe
from sandbox.profiler import profile_code
from security.models.finding import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TIMEOUT = 10  # seconds per probe execution


def _run_harness(harness_code: str) -> Dict[str, Any]:
    """Run *harness_code* in the sandbox and return parsed stdout JSON."""
    result = profile_code(
        harness_code,
        cpu_seconds=5,
        memory_mb=128,
        timeout_seconds=_TIMEOUT,
        mode="measure",
    )
    return result


def _write_source_tempfile(source: str) -> str:
    """Write *source* to a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="vg_probe_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(source)
    except Exception:
        os.unlink(path)
        raise
    return path


def _extract_target_function(source: str, lineno: int) -> Optional[str]:
    """Return the name of the innermost function that contains *lineno*."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= lineno <= getattr(node, "end_lineno", node.lineno + 100)
    ]
    if not candidates:
        return None
    # Return the innermost (largest start lineno)
    return max(candidates, key=lambda n: n.lineno).name


# ---------------------------------------------------------------------------
# SQL Injection probe
# ---------------------------------------------------------------------------

class SqlInjectionProbe(SecurityProbe):
    rule_id = "sql_query_construction"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, sqlite3
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _conn = sqlite3.connect(":memory:")
                _cur = _conn.cursor()
                _calls = []
                class _TrackingCursor:
                    def __init__(self, inner):
                        self._inner = inner
                    def execute(self, query, params=None):
                        _calls.append({{"query": str(query), "parameterized": params is not None}})
                        if params is None:
                            return self._inner.execute(query)
                        return self._inner.execute(query, params)
                    def __getattr__(self, name):
                        return getattr(self._inner, name)
                _tracked = _TrackingCursor(_cur)
                try:
                    _cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
                    _cur.execute("INSERT INTO users VALUES (1, 'alice')")
                    _conn.commit()
                except Exception:
                    pass

                _payload = "' OR '1'='1"
                _safe = "alice"
                _result = {{"sql_injection_probe": "run"}}
                try:
                    {func_name}(_tracked, _safe)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False
                    _result["safe_err"] = str(e)
                try:
                    _calls.clear()
                    {func_name}(_tracked, _payload)
                    _result["injection_ok"] = True
                except Exception as e:
                    _result["injection_ok"] = False
                    _result["injection_err"] = str(e)
                _result["unsafe_query"] = any(
                    _payload in call["query"] and not call["parameterized"]
                    for call in _calls
                )
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("unsafe_query") and data.get("safe_ok"):
            return self._confirmed(finding, "Payload was interpolated into SQL text")
        if data.get("safe_ok") and not data.get("unsafe_query"):
            return self._dismissed(finding, "Payload remained separated from SQL text")
        return self._unknown(finding, "Could not confirm via dynamic probe")


# ---------------------------------------------------------------------------
# Path Traversal probe
# ---------------------------------------------------------------------------

class PathTraversalProbe(SecurityProbe):
    rule_id = "path_traversal"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, os, tempfile, pathlib, builtins
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"path_traversal_probe": "run"}}
                _opened = []
                class _FakeFile:
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                    def read(self): return "probe"
                def _tracking_open(path, *args, **kwargs):
                    _opened.append(str(path))
                    return _FakeFile()
                def _tracking_read_text(path, *args, **kwargs):
                    _opened.append(str(path))
                    return "probe"
                builtins.open = _tracking_open
                pathlib.Path.read_text = _tracking_read_text
                _traversal = "../VG_OUTSIDE"
                try:
                    {func_name}(_traversal)
                    _result["traversal_ok"] = True
                except Exception as e:
                    _result["traversal_ok"] = False
                _result["opened"] = _opened
                _result["escaped"] = any(".." in pathlib.Path(path).parts for path in _opened)
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("escaped"):
            return self._confirmed(finding, "Path traversal probe escaped base directory")
        if data.get("traversal_ok") is False:
            return self._dismissed(finding, "Traversal path raised exception (likely guarded)")
        return self._unknown(finding, "Could not confirm via dynamic probe")


# ---------------------------------------------------------------------------
# Command Injection probe
# ---------------------------------------------------------------------------

class CommandInjectionProbe(SecurityProbe):
    rule_id = "subprocess_shell_true"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, subprocess, os, tempfile
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"cmd_injection_probe": "run"}}
                _marker = tempfile.mktemp(prefix="vg_cmd_probe_")
                _payload = "echo safe; touch " + _marker
                _safe = "echo safe"
                try:
                    out = {func_name}(_safe)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False

                try:
                    out2 = {func_name}(_payload)
                    _result["injection_ok"] = True
                    _result["injected"] = os.path.exists(_marker)
                except Exception as e:
                    _result["injection_ok"] = False
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("injected"):
            return self._confirmed(finding, "Command injection probe succeeded")
        return self._unknown(finding, "Could not confirm via dynamic probe")


# ---------------------------------------------------------------------------
# Deserialization probe
# ---------------------------------------------------------------------------

class DeserializationProbe(SecurityProbe):
    rule_id = "unsafe_deserialization"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, pickle, io
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"deser_probe": "run"}}
                _safe_data = pickle.dumps({{"key": "value"}})
                try:
                    out = {func_name}(_safe_data)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False
                    _result["safe_err"] = str(e)

                # Craft a pickle that runs code on load
                _triggered = []
                class _Evil:
                    def __reduce__(self):
                        import os
                        return (os.getpid, ())
                _evil_data = pickle.dumps(_Evil())
                try:
                    out2 = {func_name}(_evil_data)
                    _result["evil_accepted"] = True
                except Exception as e:
                    _result["evil_accepted"] = False
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("evil_accepted") and data.get("safe_ok"):
            return self._confirmed(finding, "Unsafe deserialization probe: arbitrary pickle accepted")
        return self._unknown(finding, "Could not confirm via dynamic probe")


# ---------------------------------------------------------------------------
# ReDoS probe
# ---------------------------------------------------------------------------

class ReDoSProbe(SecurityProbe):
    rule_id = "redos_vulnerability"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, time, re
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"redos_probe": "run"}}
                _evil_input = "a" * 30 + "!"  # classic ReDoS trigger
                _t0 = time.monotonic()
                try:
                    {func_name}(_evil_input)
                    _result["ok"] = True
                except Exception as e:
                    _result["ok"] = False
                _elapsed = time.monotonic() - _t0
                _result["elapsed_ms"] = round(_elapsed * 1000, 1)
                _result["slow"] = _elapsed > 1.0
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("slow"):
            return self._confirmed(finding, f"ReDoS probe took {data.get('elapsed_ms')}ms on 30-char input")
        return self._unknown(finding, f"Pattern did not exhibit slowness ({data.get('elapsed_ms')}ms)")


# ---------------------------------------------------------------------------
# Input Validation / URL Domain Bypass probe (CWE-020)
# ---------------------------------------------------------------------------

class InputValidationProbe(SecurityProbe):
    rule_id = "url_validation_bypass"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json
                from urllib.parse import urlparse
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"input_validation_probe": "run"}}
                # Legitimate URL
                _legit_url = "https://trusted.com/path"
                # Suffix-attack URL: passes endswith("trusted.com") but is a different domain
                _evil_url = "https://eviltrusted.com/path"
                try:
                    r1 = {func_name}(_legit_url)
                    _result["legit_accepted"] = bool(r1) if r1 is not None else True
                except Exception:
                    _result["legit_accepted"] = False
                try:
                    r2 = {func_name}(_evil_url)
                    _result["evil_accepted"] = bool(r2) if r2 is not None else True
                except Exception:
                    _result["evil_accepted"] = False
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("evil_accepted") and data.get("legit_accepted"):
            return self._confirmed(finding, "Suffix-attack URL accepted alongside legitimate URL")
        if data.get("evil_accepted") is False and data.get("legit_accepted"):
            return self._dismissed(finding, "Suffix-attack URL correctly rejected")
        return self._unknown(finding, "Could not determine validation behaviour")


# ---------------------------------------------------------------------------
# XSS probe (CWE-079)
# ---------------------------------------------------------------------------

class XssProbe(SecurityProbe):
    rule_id = "unsafe_html_output"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"xss_probe": "run"}}
                _payload = "<script>alert(1)</script>"
                _safe_input = "hello world"
                try:
                    out = {func_name}(_payload)
                    _result["payload_ok"] = True
                    _result["unescaped"] = ("<script>" in str(out)) if out is not None else False
                except Exception as e:
                    _result["payload_ok"] = False
                    _result["error"] = str(e)
                try:
                    out2 = {func_name}(_safe_input)
                    _result["safe_ok"] = True
                except Exception:
                    _result["safe_ok"] = False
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("unescaped") and data.get("safe_ok"):
            return self._confirmed(finding, "XSS payload appears unescaped in return value")
        if data.get("payload_ok") and not data.get("unescaped"):
            return self._dismissed(finding, "XSS payload was escaped in output")
        return self._unknown(finding, "Could not confirm XSS via dynamic probe")


# ---------------------------------------------------------------------------
# HTTP Header Injection probe (CWE-113)
# ---------------------------------------------------------------------------

class HeaderInjectionProbe(SecurityProbe):
    rule_id = "http_header_injection"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"header_injection_probe": "run"}}
                _safe_val = "application/json"
                _evil_val = "text/html\\r\\nX-Injected: evil"
                try:
                    out1 = {func_name}(_safe_val)
                    _result["safe_ok"] = True
                except Exception:
                    _result["safe_ok"] = False
                try:
                    out2 = {func_name}(_evil_val)
                    _result["evil_ok"] = True
                    # Check if newline survived in the response
                    out_str = str(out2) if out2 is not None else ""
                    _result["newline_survived"] = ("\\r\\n" in out_str or "\\n" in out_str or "X-Injected" in out_str)
                except Exception as e:
                    _result["evil_ok"] = False
                    _result["error"] = str(e)
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("newline_survived") and data.get("safe_ok"):
            return self._confirmed(finding, "Newline character survived in header value")
        if data.get("evil_ok") is False:
            return self._dismissed(finding, "Header injection payload raised exception (likely guarded)")
        return self._unknown(finding, "Could not confirm header injection via dynamic probe")


# ---------------------------------------------------------------------------
# Log Injection probe (CWE-117)
# ---------------------------------------------------------------------------

class LogInjectionProbe(SecurityProbe):
    rule_id = "log_injection"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json, io, logging
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"log_injection_probe": "run"}}
                # Capture log output
                _log_buf = io.StringIO()
                _handler = logging.StreamHandler(_log_buf)
                logging.getLogger().addHandler(_handler)
                logging.getLogger().setLevel(logging.DEBUG)

                _safe_msg = "normal login event"
                _evil_msg = "user\\nINFO: fake_log_entry forged"
                try:
                    {func_name}(_safe_msg)
                    _result["safe_ok"] = True
                except Exception:
                    _result["safe_ok"] = False
                try:
                    {func_name}(_evil_msg)
                    _result["evil_ok"] = True
                except Exception as e:
                    _result["evil_ok"] = False
                    _result["error"] = str(e)

                _log_output = _log_buf.getvalue()
                _result["newline_in_log"] = "\\n" in _log_output and "fake_log_entry" in _log_output
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("newline_in_log") and data.get("safe_ok"):
            return self._confirmed(finding, "Newline injection reached log output (fake entry forged)")
        if data.get("evil_ok") is False:
            return self._dismissed(finding, "Log injection payload raised exception")
        return self._unknown(finding, "Could not confirm log injection via dynamic probe")


# ---------------------------------------------------------------------------
# Weak Crypto Key probe (CWE-326)
# ---------------------------------------------------------------------------

class WeakKeyProbe(SecurityProbe):
    rule_id = "weak_crypto_key"

    def probe(self, source: str, finding: Finding) -> ProbeResult:
        func_name = _extract_target_function(source, finding.line or 0)
        if not func_name:
            return self._unknown(finding, "Could not find enclosing function")

        src_path = _write_source_tempfile(source)
        try:
            harness = textwrap.dedent(f"""
                import sys, json
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"weak_key_probe": "run"}}
                try:
                    key = {func_name}()
                    _result["key_generated"] = True
                    # Apply the bit threshold only to RSA/DSA keys, not EC keys.
                    key_size = None
                    if hasattr(key, "key_size"):
                        key_size = key.key_size
                    elif hasattr(key, "private_numbers"):
                        try:
                            key_size = key.key_size
                        except Exception:
                            pass
                    key_type = type(key).__name__.lower()
                    key_module = type(key).__module__.lower()
                    _result["key_size"] = key_size
                    _result["key_type"] = key_type
                    _result["applicable"] = any(
                        token in key_type or token in key_module
                        for token in ("rsa", "dsa", "elgamal")
                    )
                    _result["weak"] = (
                        _result["applicable"]
                        and key_size is not None
                        and key_size < 2048
                    )
                except Exception as e:
                    _result["key_generated"] = False
                    _result["error"] = str(e)
                print(json.dumps(_result))
            """)
            res = _run_harness(harness)
        finally:
            os.unlink(src_path)
        stdout = res.get("stdout") or ""
        try:
            data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return self._unknown(finding, f"Non-JSON output: {stdout[:200]}")
        if data.get("weak") and data.get("key_generated"):
            return self._confirmed(finding, f"Key generated with size {data.get('key_size')} bits (< 2048)")
        if data.get("key_generated") and not data.get("applicable"):
            return self._dismissed(finding, f"Key type {data.get('key_type')} is not RSA/DSA")
        if data.get("key_generated") and data.get("key_size") is not None and not data.get("weak"):
            return self._dismissed(finding, f"Key size {data.get('key_size')} bits meets minimum")
        return self._unknown(finding, "Could not inspect key size via dynamic probe")
