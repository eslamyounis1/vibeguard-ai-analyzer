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
                    {func_name}(_cur, _safe)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False
                    _result["safe_err"] = str(e)
                try:
                    {func_name}(_cur, _payload)
                    _result["injection_ok"] = True
                except Exception as e:
                    _result["injection_ok"] = False
                    _result["injection_err"] = str(e)
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
        if data.get("injection_ok") and data.get("safe_ok"):
            return self._confirmed(finding, "Injection payload executed without error")
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
                import sys, json, os, tempfile, pathlib
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"path_traversal_probe": "run"}}
                _safe_dir = tempfile.mkdtemp()
                _safe_path = os.path.join(_safe_dir, "safe.txt")
                open(_safe_path, "w").write("safe content")
                _traversal = "../../../etc/passwd"
                try:
                    out = {func_name}(_safe_path)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False

                try:
                    out2 = {func_name}(_traversal)
                    _result["traversal_ok"] = True
                    # Check if path escaped base dir
                    if out2 and "/etc/passwd" in str(out2):
                        _result["escaped"] = True
                except Exception as e:
                    _result["traversal_ok"] = False
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
                import sys, json, subprocess
                exec(open({repr(src_path)}, encoding='utf-8').read())

                _result = {{"cmd_injection_probe": "run"}}
                _payload = "echo safe; echo INJECTED"
                _safe = "echo safe"
                try:
                    out = {func_name}(_safe)
                    _result["safe_ok"] = True
                except Exception as e:
                    _result["safe_ok"] = False

                try:
                    out2 = {func_name}(_payload)
                    _result["injection_ok"] = True
                    if out2 and "INJECTED" in str(out2):
                        _result["injected"] = True
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
