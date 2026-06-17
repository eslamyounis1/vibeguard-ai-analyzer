"""RQ7 — Mutation-based probe validation (W4).

For each probeable rule, define 3 vulnerable variants + 3 safe variants.
Run each through the corresponding probe, then report:
  - Probe TP rate: confirmed on vulnerable variants
  - Probe FP rate: confirmed on safe variants
  - Accuracy per probe and overall

Outputs:
  results/probe_accuracy/probe_accuracy.csv
  results/probe_accuracy/probe_accuracy.json

Paper claim: "We self-validate our dynamic probes using mutation testing — a
methodology absent from prior work."
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List

from sandbox.probe_base import ProbeStatus
from sandbox.probe_registry import PROBES_BY_RULE
from security.models.finding import Category, Finding, Severity


def _finding(rule_id: str, line: int = 3) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="test",
        message="test",
        severity=Severity.HIGH,
        file="<probe_accuracy>",
        line=line,
        category=Category.SECURITY,
    )


# ---------------------------------------------------------------------------
# Fixture snippets per probe rule_id
# 3 vulnerable variants + 3 safe variants
# ---------------------------------------------------------------------------

FIXTURES: Dict[str, Dict[str, List[str]]] = {
    "sql_query_construction": {
        "vulnerable": [
            # V1: string concatenation
            """\
import sqlite3
def run_query(cur, user_input):
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
""",
            # V2: f-string interpolation
            """\
import sqlite3
def run_query(cur, user_input):
    cur.execute(f"SELECT * FROM orders WHERE id = {user_input}")
""",
            # V3: % formatting
            """\
import sqlite3
def run_query(cur, user_input):
    cur.execute("SELECT * FROM items WHERE name = '%s'" % user_input)
""",
        ],
        "safe": [
            # S1: parameterized query
            """\
import sqlite3
def run_query(cur, user_input):
    cur.execute("SELECT * FROM users WHERE name = ?", (user_input,))
""",
            # S2: integer cast
            """\
import sqlite3
def run_query(cur, user_input):
    safe_id = int(user_input)
    cur.execute("SELECT * FROM items WHERE id = ?", (safe_id,))
""",
            # S3: allowlist validation
            """\
import sqlite3
_ALLOWED = {"alice", "bob"}
def run_query(cur, user_input):
    if user_input not in _ALLOWED:
        raise ValueError("not allowed")
    cur.execute("SELECT * FROM users WHERE name = ?", (user_input,))
""",
        ],
    },

    "path_traversal": {
        "vulnerable": [
            # V1: open without validation
            """\
def read_file(path):
    with open(path) as f:
        return f.read()
""",
            # V2: os.path.join without base check
            """\
import os
BASE = "/tmp/data"
def read_file(path):
    full = os.path.join(BASE, path)
    with open(full) as f:
        return f.read()
""",
            # V3: pathlib without resolve check
            """\
from pathlib import Path
BASE = Path("/tmp/data")
def read_file(path):
    target = BASE / path
    return target.read_text()
""",
        ],
        "safe": [
            # S1: realpath + startswith guard
            """\
import os
BASE = "/tmp/safe_files"
def read_file(path):
    real = os.path.realpath(path)
    if not real.startswith(BASE + "/"):
        raise ValueError("traversal detected")
    with open(real) as f:
        return f.read()
""",
            # S2: pathlib resolve + is_relative_to
            """\
from pathlib import Path
BASE = Path("/tmp/safe_files")
def read_file(path):
    target = (BASE / path).resolve()
    if not str(target).startswith(str(BASE)):
        raise ValueError("outside base")
    return target.read_text()
""",
            # S3: filename basename only
            """\
import os
BASE = "/tmp/safe_files"
def read_file(path):
    safe = os.path.basename(path)
    full = os.path.join(BASE, safe)
    with open(full) as f:
        return f.read()
""",
        ],
    },

    "subprocess_shell_true": {
        "vulnerable": [
            # V1: shell=True with user input
            """\
import subprocess
def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
""",
            # V2: os.system
            """\
import os
def run_command(cmd):
    return os.system(cmd)
""",
            # V3: subprocess.Popen with shell=True
            """\
import subprocess
def run_command(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return p.communicate()[0]
""",
        ],
        "safe": [
            # S1: list form, no shell
            """\
import subprocess
def run_command(cmd):
    return subprocess.run(cmd.split(), capture_output=True, text=True).stdout
""",
            # S2: shlex + no shell
            """\
import subprocess, shlex
def run_command(cmd):
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True).stdout
""",
            # S3: explicit allowlist
            """\
import subprocess
_ALLOWED = {"ls", "pwd", "date"}
def run_command(cmd):
    if cmd not in _ALLOWED:
        raise ValueError("not allowed")
    return subprocess.run([cmd], capture_output=True, text=True).stdout
""",
        ],
    },

    "unsafe_deserialization": {
        "vulnerable": [
            # V1: pickle.loads
            """\
import pickle
def load_data(data):
    return pickle.loads(data)
""",
            # V2: pickle.load from file
            """\
import pickle, io
def load_data(data):
    return pickle.load(io.BytesIO(data))
""",
            # V3: marshal.loads
            """\
import marshal
def load_data(data):
    return marshal.loads(data)
""",
        ],
        "safe": [
            # S1: json.loads
            """\
import json
def load_data(data):
    return json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
""",
            # S2: json with validation
            """\
import json
def load_data(data):
    obj = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
    if not isinstance(obj, dict):
        raise ValueError("expected dict")
    return obj
""",
            # S3: explicit rejection of pickle
            """\
import json
def load_data(data):
    if isinstance(data, bytes) and data[:2] == b'\\x80\\x04':
        raise ValueError("pickle not allowed")
    return json.loads(data)
""",
        ],
    },

    "redos_vulnerability": {
        "vulnerable": [
            # V1: exponential backtracking (a+)+
            """\
import re
def check_input(text):
    return bool(re.match(r'^(a+)+$', text))
""",
            # V2: nested quantifiers
            """\
import re
def check_input(text):
    return bool(re.match(r'^([a-zA-Z]+)*$', text))
""",
            # V3: overlapping quantifiers
            """\
import re
def check_input(text):
    return bool(re.match(r'^(a|aa)+$', text))
""",
        ],
        "safe": [
            # S1: possessive-equivalent (atomic via simple pattern)
            """\
import re
def check_input(text):
    return bool(re.match(r'^[a-z]{1,64}$', text))
""",
            # S2: simple fixed-length
            """\
import re
def check_input(text):
    return bool(re.match(r'^\\d{4}-\\d{2}-\\d{2}$', text))
""",
            # S3: length check before regex
            """\
import re
def check_input(text):
    if len(text) > 64:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]+$', text))
""",
        ],
    },

    "url_validation_bypass": {
        "vulnerable": [
            # V1: endswith on netloc
            """\
from urllib.parse import urlparse
def is_trusted(url):
    parsed = urlparse(url)
    return parsed.netloc.endswith("trusted.com")
""",
            # V2: endswith on hostname
            """\
from urllib.parse import urlparse
def is_trusted(url):
    parsed = urlparse(url)
    return parsed.hostname.endswith("trusted.com")
""",
            # V3: 'in' check (also bypassable)
            """\
from urllib.parse import urlparse
def is_trusted(url):
    parsed = urlparse(url)
    return "trusted.com" in parsed.netloc
""",
        ],
        "safe": [
            # S1: exact match
            """\
from urllib.parse import urlparse
def is_trusted(url):
    parsed = urlparse(url)
    return parsed.netloc == "trusted.com"
""",
            # S2: dot-prefixed endswith
            """\
from urllib.parse import urlparse
def is_trusted(url):
    parsed = urlparse(url)
    return parsed.netloc == "trusted.com" or parsed.netloc.endswith(".trusted.com")
""",
            # S3: allowlist
            """\
from urllib.parse import urlparse
_ALLOWED = {"trusted.com", "api.trusted.com"}
def is_trusted(url):
    parsed = urlparse(url)
    return parsed.netloc in _ALLOWED
""",
        ],
    },

    "unsafe_html_output": {
        "vulnerable": [
            # V1: return raw user input in HTML context
            """\
def render_greeting(name):
    return f"<h1>Hello, {name}!</h1>"
""",
            # V2: string concat
            """\
def render_greeting(name):
    return "<h1>Hello, " + name + "!</h1>"
""",
            # V3: format
            """\
def render_greeting(name):
    return "<p>{}</p>".format(name)
""",
        ],
        "safe": [
            # S1: html.escape
            """\
import html
def render_greeting(name):
    return f"<h1>Hello, {html.escape(name)}!</h1>"
""",
            # S2: markupsafe escape
            """\
try:
    from markupsafe import escape
except ImportError:
    import html
    escape = html.escape
def render_greeting(name):
    return f"<h1>Hello, {escape(name)}!</h1>"
""",
            # S3: constant only
            """\
def render_greeting(name):
    return "<h1>Hello, world!</h1>"
""",
        ],
    },

    "http_header_injection": {
        "vulnerable": [
            # V1: set_header with dynamic value
            """\
class MockResponse:
    def __init__(self):
        self._headers = {}
    def set_header(self, name, value):
        self._headers[name] = value
        return self._headers

_resp = MockResponse()
def set_content_type(value):
    return _resp.set_header("Content-Type", value)
""",
            # V2: add_header with dynamic
            """\
class MockResponse:
    def __init__(self):
        self._headers = {}
    def add_header(self, name, value):
        self._headers[name] = value
        return self._headers

_resp = MockResponse()
def add_custom_header(value):
    return _resp.add_header("X-Custom", value)
""",
            # V3: direct header dict assignment from user input
            """\
class MockResponse:
    def __init__(self):
        self.headers = {}
    def set_header(self, name, value):
        self.headers[name] = value
        return self.headers

_resp = MockResponse()
def set_header(value):
    return _resp.set_header("Location", value)
""",
        ],
        "safe": [
            # S1: strip newlines
            """\
class MockResponse:
    def __init__(self):
        self._headers = {}
    def set_header(self, name, value):
        self._headers[name] = value
        return self._headers

_resp = MockResponse()
def set_content_type(value):
    safe_value = value.replace("\\r", "").replace("\\n", "")
    return _resp.set_header("Content-Type", safe_value)
""",
            # S2: allowlist
            """\
_ALLOWED = {"application/json", "text/html", "text/plain"}

class MockResponse:
    def __init__(self):
        self._headers = {}
    def set_header(self, name, value):
        self._headers[name] = value
        return self._headers

_resp = MockResponse()
def set_content_type(value):
    if value not in _ALLOWED:
        raise ValueError("unknown content type")
    return _resp.set_header("Content-Type", value)
""",
            # S3: reject if newline present
            """\
class MockResponse:
    def __init__(self):
        self._headers = {}
    def set_header(self, name, value):
        self._headers[name] = value
        return self._headers

_resp = MockResponse()
def set_content_type(value):
    if "\\n" in value or "\\r" in value:
        raise ValueError("header injection detected")
    return _resp.set_header("Content-Type", value)
""",
        ],
    },

    "log_injection": {
        "vulnerable": [
            # V1: f-string in log.info
            """\
import logging
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    logger.info(f"User action: {user_input}")
""",
            # V2: string concat in log.warning
            """\
import logging
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    logger.warning("Action: " + user_input)
""",
            # V3: format in log.debug
            """\
import logging
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    logger.debug("Input: {}".format(user_input))
""",
        ],
        "safe": [
            # S1: % formatting (safe — deferred interpolation)
            """\
import logging
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    logger.info("User action: %s", user_input)
""",
            # S2: strip newlines before logging
            """\
import logging
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    safe = user_input.replace("\\n", " ").replace("\\r", " ")
    logger.info(f"User action: {safe}")
""",
            # S3: escape control chars
            """\
import logging, re
logger = logging.getLogger(__name__)

def log_user_action(user_input):
    safe = re.sub(r'[\\r\\n\\t]', '_', user_input)
    logger.info(f"User action: {safe}")
""",
        ],
    },

    "weak_crypto_key": {
        "vulnerable": [
            # V1: 1024-bit RSA
            """\
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend(),
    )
""",
            # V2: 1536-bit RSA
            """\
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1536,
        backend=default_backend(),
    )
""",
            # V3: 512-bit DSA
            """\
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
def make_key():
    params = dsa.generate_parameters(key_size=1024, backend=default_backend())
    return params.generate_private_key()
""",
        ],
        "safe": [
            # S1: 2048-bit RSA (current 112-bit security floor)
            """\
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
""",
            # S2: 3072-bit RSA (exactly minimum)
            """\
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend(),
    )
""",
            # S3: EC key (not RSA/DSA key_size)
            """\
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
def make_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())
""",
        ],
    },
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_rq7(out_dir: Path | str = "results/probe_accuracy") -> List[dict]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    per_probe_rows = []
    summary_rows = []

    for rule_id, snippets in FIXTURES.items():
        probe = PROBES_BY_RULE.get(rule_id)
        if probe is None:
            print(f"  [skip] No probe registered for rule_id={rule_id}")
            continue

        vuln_confirmed = 0
        vuln_total = len(snippets["vulnerable"])
        safe_confirmed = 0
        safe_total = len(snippets["safe"])

        for i, code in enumerate(snippets["vulnerable"]):
            f = _finding(rule_id, line=3)
            try:
                result = probe.probe(code, f)
            except Exception as exc:
                result_status = "error"
                print(f"  [error] {rule_id} V{i+1}: {exc}")
                per_probe_rows.append({
                    "rule_id": rule_id,
                    "variant": f"V{i+1}_vuln",
                    "status": "error",
                    "is_tp": False,
                    "evidence": str(exc),
                })
                continue
            is_tp = result.status == ProbeStatus.CONFIRMED
            vuln_confirmed += int(is_tp)
            per_probe_rows.append({
                "rule_id": rule_id,
                "variant": f"V{i+1}_vuln",
                "status": result.status.value,
                "is_tp": is_tp,
                "evidence": result.evidence[:120],
            })
            print(f"  {rule_id} V{i+1} (vuln): {result.status.value}")

        for i, code in enumerate(snippets["safe"]):
            f = _finding(rule_id, line=3)
            try:
                result = probe.probe(code, f)
            except Exception as exc:
                per_probe_rows.append({
                    "rule_id": rule_id,
                    "variant": f"S{i+1}_safe",
                    "status": "error",
                    "is_tp": False,
                    "evidence": str(exc),
                })
                continue
            is_fp = result.status == ProbeStatus.CONFIRMED
            safe_confirmed += int(is_fp)
            per_probe_rows.append({
                "rule_id": rule_id,
                "variant": f"S{i+1}_safe",
                "status": result.status.value,
                "is_tp": False,
                "evidence": result.evidence[:120],
            })
            print(f"  {rule_id} S{i+1} (safe): {result.status.value}")

        tp_rate = vuln_confirmed / vuln_total if vuln_total else 0.0
        fp_rate = safe_confirmed / safe_total if safe_total else 0.0
        accuracy = (vuln_confirmed + (safe_total - safe_confirmed)) / (vuln_total + safe_total) if (vuln_total + safe_total) else 0.0

        summary_rows.append({
            "rule_id": rule_id,
            "vuln_variants": vuln_total,
            "tp_confirmed": vuln_confirmed,
            "tp_rate": round(tp_rate, 3),
            "safe_variants": safe_total,
            "fp_confirmed": safe_confirmed,
            "fp_rate": round(fp_rate, 3),
            "accuracy": round(accuracy, 3),
        })

    # Write CSVs
    _write_csv(out_dir / "probe_accuracy_per_variant.csv", per_probe_rows)
    _write_csv(out_dir / "probe_accuracy.csv", summary_rows)

    # Write JSON
    output = {
        "per_probe": summary_rows,
        "per_variant": per_probe_rows,
        "overall": _overall(summary_rows),
    }
    (out_dir / "probe_accuracy.json").write_text(
        json.dumps(output, indent=2), encoding="utf-8"
    )

    print("\n=== Probe Accuracy Summary ===")
    for row in summary_rows:
        print(f"  {row['rule_id']:35s}  TP={row['tp_rate']:.3f}  FP={row['fp_rate']:.3f}  Acc={row['accuracy']:.3f}")
    overall = output["overall"]
    print(f"\n  Overall TP rate: {overall['mean_tp_rate']:.3f}")
    print(f"  Overall FP rate: {overall['mean_fp_rate']:.3f}")
    print(f"  Overall accuracy: {overall['mean_accuracy']:.3f}")

    return summary_rows


def _overall(rows: List[dict]) -> dict:
    if not rows:
        return {"mean_tp_rate": 0.0, "mean_fp_rate": 0.0, "mean_accuracy": 0.0}
    return {
        "mean_tp_rate": round(sum(r["tp_rate"] for r in rows) / len(rows), 3),
        "mean_fp_rate": round(sum(r["fp_rate"] for r in rows) / len(rows), 3),
        "mean_accuracy": round(sum(r["accuracy"] for r in rows) / len(rows), 3),
        "probes_tested": len(rows),
    }


def _write_csv(path: Path, rows: List[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="RQ7 — Probe accuracy via mutation testing")
    p.add_argument("--out-dir", default="results/probe_accuracy")
    args = p.parse_args()
    run_rq7(args.out_dir)
