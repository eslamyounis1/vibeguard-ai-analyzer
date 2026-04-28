"""
VibeGuard benchmark dataset — labeled AI-generated code samples.

Each Sample carries:
  id              : unique identifier
  label           : short human-readable name
  source          : "ai-generated" | "human-written"
  description     : what the code does
  code            : the Python source string
  expected_rules  : set of rule_ids the static analyzer MUST detect
  forbidden_rules : set of rule_ids the analyzer must NOT emit (false-positive guard)
  tags            : free-form tags for grouping (e.g. "security", "performance", "smell")

Ground-truth expected_rules reflect deliberate flaws planted in each sample.
They are used by the benchmark runner to compute Precision, Recall, and F1.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Sample:
    id: str
    label: str
    source: str
    description: str
    code: str
    expected_rules: set[str] = field(default_factory=set)
    forbidden_rules: set[str] = field(default_factory=set)
    tags: list[str] = field(default_factory=list)


# ─── AI-generated samples with known flaws ────────────────────────────────────

SAMPLES: list[Sample] = [

    # ── S01: Hardcoded secret + eval ──────────────────────────────────────────
    Sample(
        id="S01",
        label="Hardcoded API key + eval injection",
        source="ai-generated",
        description="Typical LLM output for a 'quick script' that hardcodes credentials and uses eval.",
        tags=["security", "critical"],
        expected_rules={"hardcoded_secret", "eval_exec_usage"},
        code="""
import requests

api_key = "sk-abc123supersecretkey9999"
base_url = "https://api.example.com"

def fetch_data(endpoint, params=""):
    url = f"{base_url}/{endpoint}"
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.get(url, headers=headers, params=eval(params))
    return resp.json()

print(fetch_data("users", "{'page': 1}"))
""",
    ),

    # ── S02: Nested O(n²) loop + string concat in loop ───────────────────────
    Sample(
        id="S02",
        label="O(n²) nested loop + string concat",
        source="ai-generated",
        description="Classic AI-generated brute-force with quadratic complexity and string concat anti-pattern.",
        tags=["performance"],
        expected_rules={"nested_loop", "string_concat_in_loop"},
        code="""
def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                if items[i] not in duplicates:
                    duplicates.append(items[i])
    return duplicates


def build_report(entries):
    report = ""
    for entry in entries:
        report += f"Entry: {entry}\\n"
    return report
""",
    ),

    # ── S03: subprocess shell=True + os.system ────────────────────────────────
    Sample(
        id="S03",
        label="Shell injection via subprocess + os.system",
        source="ai-generated",
        description="LLM-generated utility that passes user input directly to the shell.",
        tags=["security"],
        expected_rules={"subprocess_shell_true", "os_shell_execution"},
        code="""
import subprocess
import os

def run_lint(filepath):
    os.system(f"pylint {filepath}")

def compress_file(filepath, level=6):
    result = subprocess.run(
        f"gzip -{level} {filepath}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
""",
    ),

    # ── S04: Weak MD5 password hashing ────────────────────────────────────────
    Sample(
        id="S04",
        label="MD5 password hashing",
        source="ai-generated",
        description="Classic AI mistake: using MD5 to 'hash' passwords.",
        tags=["security", "cryptography"],
        expected_rules={"weak_hash_algorithm"},
        code="""
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash

users = {
    "alice": hash_password("hunter2"),
    "bob": hash_password("password123"),
}
""",
    ),

    # ── S05: Long function + deep nesting + high complexity ───────────────────
    Sample(
        id="S05",
        label="God function with deep nesting",
        source="ai-generated",
        description="LLM-generated monolith that does everything in one function.",
        tags=["smell", "complexity"],
        expected_rules={"long_function", "deep_nesting", "high_complexity"},
        code="""
def process_order(order, inventory, user, discount_code=None, shipping=None, tax_rate=0.1):
    if order and inventory and user:
        if user.get("verified"):
            if order.get("items"):
                total = 0
                for item in order["items"]:
                    if item["sku"] in inventory:
                        stock = inventory[item["sku"]]
                        if stock > 0:
                            if item["qty"] <= stock:
                                price = item["price"]
                                if discount_code:
                                    if discount_code == "SAVE10":
                                        price = price * 0.9
                                    elif discount_code == "SAVE20":
                                        price = price * 0.8
                                    elif discount_code == "SAVE30":
                                        price = price * 0.7
                                    elif discount_code == "SAVE40":
                                        price = price * 0.6
                                    elif discount_code == "SAVE50":
                                        price = price * 0.5
                                    else:
                                        price = price
                                if item.get("taxable", True):
                                    item_tax = price * tax_rate
                                else:
                                    item_tax = 0
                                total += (price + item_tax) * item["qty"]
                            else:
                                return {"error": "insufficient stock", "sku": item["sku"]}
                        else:
                            return {"error": "out of stock", "sku": item["sku"]}
                    else:
                        return {"error": "unknown sku", "sku": item["sku"]}
                if shipping:
                    if shipping == "express":
                        total += 15
                    elif shipping == "standard":
                        total += 5
                    elif shipping == "overnight":
                        total += 35
                    elif shipping == "economy":
                        total += 2
                    else:
                        total += 0
                if user.get("loyalty_points", 0) > 1000:
                    total = total * 0.95
                if total > 500:
                    total = total - 20
                if total > 0:
                    return {"ok": True, "total": round(total, 2)}
                else:
                    return {"error": "zero total"}
            else:
                return {"error": "no items"}
        else:
            return {"error": "unverified user"}
    else:
        return {"error": "missing data"}
""",
    ),

    # ── S06: pickle deserialization ───────────────────────────────────────────
    Sample(
        id="S06",
        label="Unsafe pickle deserialization",
        source="ai-generated",
        description="AI-generated caching layer that deserializes untrusted pickle data.",
        tags=["security"],
        expected_rules={"unsafe_deserialization"},
        code="""
import pickle
import os

CACHE_DIR = "/tmp/cache"

def save_to_cache(key, obj):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(f"{CACHE_DIR}/{key}.pkl", "wb") as f:
        pickle.dump(obj, f)

def load_from_cache(key):
    path = f"{CACHE_DIR}/{key}.pkl"
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.loads(f.read())
    return None
""",
    ),

    # ── S07: assert for input validation ──────────────────────────────────────
    Sample(
        id="S07",
        label="assert used for input validation",
        source="ai-generated",
        description="LLM uses assert for runtime guards that disappear under -O.",
        tags=["security", "smell"],
        expected_rules={"assert_used_for_validation"},
        code="""
def transfer_funds(amount, from_account, to_account):
    assert amount > 0, "Amount must be positive"
    assert from_account != to_account, "Cannot transfer to same account"
    assert len(from_account) == 16, "Invalid account number"
    from_account["balance"] -= amount
    to_account["balance"] += amount
    return True
""",
    ),

    # ── S08: duplicate code block ─────────────────────────────────────────────
    Sample(
        id="S08",
        label="Duplicate code blocks",
        source="ai-generated",
        description="AI copy-pastes the same validation block in two places.",
        tags=["smell"],
        expected_rules={"duplicate_code_block"},
        code="""
def validate_user_input(data):
    if not data:
        raise ValueError("Data cannot be empty")
    if not isinstance(data, dict):
        raise TypeError("Data must be a dict")
    if "name" not in data:
        raise KeyError("name field required")
    if "email" not in data:
        raise KeyError("email field required")
    return True

def validate_admin_input(data):
    if not data:
        raise ValueError("Data cannot be empty")
    if not isinstance(data, dict):
        raise TypeError("Data must be a dict")
    if "name" not in data:
        raise KeyError("name field required")
    if "email" not in data:
        raise KeyError("email field required")
    if "role" not in data:
        raise KeyError("role field required")
    return True
""",
    ),

    # ── S09: too many parameters ──────────────────────────────────────────────
    Sample(
        id="S09",
        label="Function with too many parameters",
        source="ai-generated",
        description="LLM exposes every internal option as a top-level parameter.",
        tags=["smell"],
        expected_rules={"too_many_params"},
        code="""
def create_user(first_name, last_name, email, phone, address,
                city, state, zip_code, country, role, permissions,
                is_active=True, send_welcome_email=True):
    return {
        "name": f"{first_name} {last_name}",
        "email": email,
        "phone": phone,
        "address": f"{address}, {city}, {state} {zip_code}, {country}",
        "role": role,
        "permissions": permissions,
        "active": is_active,
    }
""",
    ),

    # ── S10: Clean baseline — no expected findings ────────────────────────────
    Sample(
        id="S10",
        label="Clean baseline (well-written code)",
        source="human-written",
        description="Reference implementation with no deliberate flaws. Used to measure false-positive rate.",
        tags=["baseline"],
        expected_rules=set(),
        forbidden_rules={"eval_exec_usage", "hardcoded_secret", "subprocess_shell_true",
                         "weak_hash_algorithm", "unsafe_deserialization"},
        code="""
from __future__ import annotations
import secrets
from dataclasses import dataclass


@dataclass
class UserProfile:
    user_id: str
    display_name: str
    email: str


def generate_token(length: int = 32) -> str:
    return secrets.token_hex(length)


def find_common_elements(list_a: list, list_b: list) -> list:
    set_b = set(list_b)
    return [item for item in list_a if item in set_b]


def build_report(entries: list[str]) -> str:
    return "\\n".join(f"Entry: {e}" for e in entries)
""",
    ),
]

SAMPLES_BY_ID: dict[str, Sample] = {s.id: s for s in SAMPLES}
