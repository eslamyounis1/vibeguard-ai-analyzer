"""CWE family groupings for family-level precision/recall evaluation.

Reduces label-mismatch false positives caused by related CWEs being reported
under different identifiers (e.g. CWE-94 vs CWE-95 for code injection).
"""

from typing import Dict, Optional

# Maps each CWE to a canonical family name.
# CWEs in the same family are treated as equivalent for evaluation purposes.
CWE_FAMILY: Dict[str, str] = {
    # ── Injection (code / OS / template) ─────────────────────────────────────
    "CWE-78":  "injection",   # OS command
    "CWE-88":  "injection",   # argument injection
    "CWE-89":  "injection",   # SQL
    "CWE-90":  "injection",   # LDAP
    "CWE-91":  "injection",   # XML/XPath
    "CWE-94":  "injection",   # code injection
    "CWE-95":  "injection",   # eval injection
    "CWE-99":  "injection",   # resource injection
    "CWE-116": "injection",   # improper encoding (output injection vector)
    "CWE-943": "injection",   # improper neutralization in data query logic

    # ── XSS / HTML output ─────────────────────────────────────────────────────
    "CWE-79":  "xss",
    "CWE-80":  "xss",         # basic XSS (script in attribute)

    # ── Path traversal ────────────────────────────────────────────────────────
    "CWE-22":  "path_traversal",
    "CWE-23":  "path_traversal",
    "CWE-36":  "path_traversal",
    "CWE-73":  "path_traversal",

    # ── Cryptography ──────────────────────────────────────────────────────────
    "CWE-326": "crypto",      # weak key size
    "CWE-327": "crypto",      # broken algorithm
    "CWE-328": "crypto",      # reversible one-way hash
    "CWE-329": "crypto",      # weak RNG seed
    "CWE-330": "crypto",      # insufficient randomness
    "CWE-331": "crypto",      # insufficient entropy
    "CWE-338": "crypto",      # insecure PRNG
    "CWE-759": "crypto",      # unsalted hash
    "CWE-760": "crypto",      # predictable salt
    "CWE-1204": "crypto",     # weak IV generation

    # ── JWT / token verification ───────────────────────────────────────────────
    "CWE-347": "jwt",         # improper signature verification
    "CWE-345": "jwt",

    # ── TLS / certificate validation ──────────────────────────────────────────
    "CWE-295": "tls",
    "CWE-296": "tls",
    "CWE-297": "tls",
    "CWE-298": "tls",
    "CWE-319": "tls",         # cleartext transmission

    # ── Deserialization ───────────────────────────────────────────────────────
    "CWE-502": "deserialization",

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "CWE-918": "ssrf",

    # ── HTTP header / response splitting ─────────────────────────────────────
    "CWE-113": "header_injection",
    "CWE-74":  "header_injection",  # injection into downstream component

    # ── Log injection ─────────────────────────────────────────────────────────
    "CWE-117": "log_injection",

    # ── Input validation ──────────────────────────────────────────────────────
    "CWE-20":  "input_validation",
    "CWE-1284": "input_validation",

    # ── Open redirect ─────────────────────────────────────────────────────────
    "CWE-601": "open_redirect",

    # ── XXE ───────────────────────────────────────────────────────────────────
    "CWE-611": "xxe",
    "CWE-776": "xxe",         # DTD recursion (billion laughs)
    "CWE-827": "xxe",

    # ── XPath injection ───────────────────────────────────────────────────────
    "CWE-643": "xpath",

    # ── ReDoS / resource exhaustion ───────────────────────────────────────────
    "CWE-400": "redos",
    "CWE-730": "redos",
    "CWE-1333": "redos",

    # ── Hardcoded secrets / credentials ──────────────────────────────────────
    "CWE-259": "hardcoded_secrets",
    "CWE-321": "hardcoded_secrets",
    "CWE-798": "hardcoded_secrets",

    # ── Sensitive data exposure ───────────────────────────────────────────────
    "CWE-200": "sensitive_data",
    "CWE-209": "sensitive_data",  # error info exposure
    "CWE-215": "sensitive_data",  # debug info
    "CWE-312": "sensitive_data",  # cleartext storage

    # ── Privileges / access control ───────────────────────────────────────────
    "CWE-250": "privileges",
    "CWE-269": "privileges",
    "CWE-283": "privileges",
    "CWE-285": "privileges",
    "CWE-306": "privileges",  # missing auth
    "CWE-352": "csrf",        # CSRF is distinct enough to keep separate
    "CWE-425": "privileges",  # direct request / forced browsing

    # ── File operations ───────────────────────────────────────────────────────
    "CWE-377": "tmpfile",
    "CWE-379": "tmpfile",
    "CWE-434": "file_upload",
    "CWE-732": "file_perms",

    # ── Cookie security ───────────────────────────────────────────────────────
    "CWE-614": "cookie",

    # ── Password storage ──────────────────────────────────────────────────────
    "CWE-522": "password_storage",
    "CWE-521": "password_storage",  # weak password requirements

    # ── Miscellaneous ─────────────────────────────────────────────────────────
    "CWE-252": "error_handling",  # unchecked return value
    "CWE-703": "error_handling",  # improper check / handling
    "CWE-193": "off_by_one",
    "CWE-369": "divide_by_zero",
    "CWE-476": "null_deref",
    "CWE-835": "infinite_loop",
    "CWE-841": "improper_enforcement",
    "CWE-406": "resource_mgmt",
    "CWE-414": "resource_mgmt",
    "CWE-348": "auth",
    "CWE-385": "timing_attack",
    "CWE-208": "timing_attack",
    "CWE-595": "type_confusion",
    "CWE-462": "duplicate_key",
    "CWE-477": "deprecated_function",
    "CWE-454": "init_unsafe",
    "CWE-641": "improper_restriction",
    "CWE-605": "multiple_binds",
    "CWE-941": "incorrect_behavior",
    "CWE-1236": "csv_injection",
    "CWE-176": "unicode",
}


def cwe_to_family(cwe: str) -> str:
    """Return the family name for a CWE, or the CWE itself if unmapped."""
    return CWE_FAMILY.get(cwe, cwe)


def cwes_to_families(cwes) -> set:
    """Map a set of CWE strings to their family names."""
    return {cwe_to_family(c) for c in cwes}
