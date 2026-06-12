from dataclasses import dataclass

from security.models.finding import Confidence, Finding


@dataclass(frozen=True)
class SecurityMetadata:
    confidence: Confidence
    risk_score: int
    cwe: str
    owasp: str
    impact: str


_METADATA_BY_RULE: dict[str, SecurityMetadata] = {
    "eval_exec_usage": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=95,
        cwe="CWE-95",
        owasp="A03:2021 Injection",
        impact="User-controlled code execution can compromise the host process.",
    ),
    "exec_usage": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=95,
        cwe="CWE-95",
        owasp="A03:2021 Injection",
        impact="User-controlled code execution can compromise the host process.",
    ),
    "hardcoded_secret": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=85,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        impact="Committed credentials can be reused by attackers and are difficult to rotate safely.",
    ),
    "insecure_random": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=55,
        cwe="CWE-338",
        owasp="A02:2021 Cryptographic Failures",
        impact="Predictable randomness can weaken tokens, session IDs, or security decisions.",
    ),
    "subprocess_shell_true": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="Shell execution can allow command injection when arguments include user-controlled data.",
    ),
    "unsafe_deserialization": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=90,
        cwe="CWE-502",
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Unsafe deserialization can instantiate attacker-controlled objects or execute code.",
    ),
    "assert_used_for_validation": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=50,
        cwe="CWE-617",
        owasp="A04:2021 Insecure Design",
        impact="Validation can disappear when Python runs with optimizations enabled.",
    ),
    "weak_hash_algorithm": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=78,
        cwe="CWE-327",
        owasp="A02:2021 Cryptographic Failures",
        impact="Broken hash algorithms make integrity checks and password storage easier to attack.",
    ),
    "os_shell_execution": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="Direct shell execution can run attacker-controlled commands.",
    ),
    "unsafe_yaml_load": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=82,
        cwe="CWE-502",
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Unsafe YAML loading can construct arbitrary Python objects from untrusted data.",
    ),
    "tls_verification_disabled": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=80,
        cwe="CWE-295",
        owasp="A02:2021 Cryptographic Failures",
        impact="Disabled certificate validation exposes HTTPS traffic to interception.",
    ),
    "debug_mode_enabled": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=60,
        cwe="CWE-489",
        owasp="A05:2021 Security Misconfiguration",
        impact="Debug mode can expose stack traces, internals, or interactive debugging surfaces.",
    ),
    "sql_query_construction": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=86,
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        impact="Interpolated SQL can allow attackers to read or modify database records.",
    ),
    "path_traversal": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=84,
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        impact="Attacker-controlled paths may read or write files outside the intended directory.",
    ),
    "ssrf_unvalidated_url": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=88,
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        impact="Server may be coerced to request internal or cloud metadata endpoints.",
    ),
    "unsafe_html_output": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=82,
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        impact="Unescaped HTML output can execute attacker scripts in users' browsers.",
    ),
    "xpath_injection": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=80,
        cwe="CWE-643",
        owasp="A03:2021 Injection",
        impact="Manipulated XPath can bypass authorization or exfiltrate XML data.",
    ),
    "open_redirect": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=55,
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        impact="Users can be redirected to attacker-controlled sites for phishing.",
    ),
    "unvalidated_user_input": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=70,
        cwe="CWE-20",
        owasp="A04:2021 Insecure Design",
        impact="Missing input validation enables injection and logic bypass in downstream sinks.",
    ),
    "weak_crypto_key": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=80,
        cwe="CWE-326",
        owasp="A02:2021 Cryptographic Failures",
        impact="Undersized keys can be factored; encrypted data or signatures may be compromised.",
    ),
    "log_injection": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=60,
        cwe="CWE-117",
        owasp="A09:2021 Security Logging and Monitoring Failures",
        impact="Attackers can forge log entries or inject escape sequences to manipulate log viewers.",
    ),
    "http_header_injection": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=82,
        cwe="CWE-113",
        owasp="A03:2021 Injection",
        impact="Header injection enables response splitting, cache poisoning, and XSS via headers.",
    ),
    "weak_rng_seed": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=65,
        cwe="CWE-329",
        owasp="A02:2021 Cryptographic Failures",
        impact="Predictable PRNG output weakens tokens, session IDs, and security decisions.",
    ),
    "redos_vulnerability": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=70,
        cwe="CWE-400",
        owasp="A04:2021 Insecure Design",
        impact="Crafted input can cause catastrophic backtracking, leading to denial of service.",
    ),
    "url_validation_bypass": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=75,
        cwe="CWE-20",
        owasp="A01:2021 Broken Access Control",
        impact="Suffix attacks bypass domain allow-listing, enabling SSRF or open redirect.",
    ),
    "xxe_vulnerability": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-611",
        owasp="A05:2021 Security Misconfiguration",
        impact="XXE can read arbitrary server files and trigger SSRF to internal services.",
    ),
    "insecure_cookie": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=65,
        cwe="CWE-614",
        owasp="A02:2021 Cryptographic Failures",
        impact="Cookies without Secure flag can be intercepted over HTTP connections.",
    ),
    "csrf_missing_protection": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=72,
        cwe="CWE-352",
        owasp="A01:2021 Broken Access Control",
        impact="Attackers can trick authenticated users into performing unintended state changes.",
    ),
    "insecure_tmpfile": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=76,
        cwe="CWE-377",
        owasp="A04:2021 Insecure Design",
        impact="Race condition between temp file creation and use enables symlink attacks.",
    ),
    "cleartext_credentials": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=83,
        cwe="CWE-312",
        owasp="A02:2021 Cryptographic Failures",
        impact="Plaintext credentials in storage can be read by anyone with file/DB access.",
    ),
    "unnecessary_privileges": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=85,
        cwe="CWE-250",
        owasp="A04:2021 Insecure Design",
        impact="Running as root amplifies the blast radius of any other vulnerability in the process.",
    ),
    "none_dereference": SecurityMetadata(
        confidence=Confidence.LOW,
        risk_score=45,
        cwe="CWE-476",
        owasp="A04:2021 Insecure Design",
        impact="Unchecked None access causes AttributeError crashes that may be triggerable by user input.",
    ),
    "unrestricted_file_upload": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=87,
        cwe="CWE-434",
        owasp="A04:2021 Insecure Design",
        impact="Unrestricted uploads allow server-side code execution or malware hosting.",
    ),
    "weak_password_storage": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=85,
        cwe="CWE-522",
        owasp="A02:2021 Cryptographic Failures",
        impact="MD5/SHA1 password hashes can be cracked with precomputed rainbow tables.",
    ),
    "sensitive_data_in_log": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=75,
        cwe="CWE-200",
        owasp="A09:2021 Security Logging and Monitoring Failures",
        impact="Sensitive fields in logs can be read by log aggregators, sysadmins, or attackers.",
    ),
    "xml_injection": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=78,
        cwe="CWE-91",
        owasp="A03:2021 Injection",
        impact="XML injection can modify document structure, bypass authentication, or exfiltrate data.",
    ),
    "improper_output_encoding": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=65,
        cwe="CWE-116",
        owasp="A03:2021 Injection",
        impact="Improper encoding allows injection of unexpected characters in HTTP responses.",
    ),
    "jwt_signature_not_verified": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=95,
        cwe="CWE-347",
        owasp="A02:2021 Cryptographic Failures",
        impact="Without signature verification, anyone can forge JWTs and bypass authentication.",
    ),
    "incorrect_file_permissions": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=72,
        cwe="CWE-732",
        owasp="A01:2021 Broken Access Control",
        impact="World-writable files can be modified by any local user, enabling privilege escalation.",
    ),
    "divide_by_zero": SecurityMetadata(
        confidence=Confidence.LOW,
        risk_score=50,
        cwe="CWE-369",
        owasp="A04:2021 Insecure Design",
        impact="Division by user-controlled zero causes uncaught exceptions leading to DoS.",
    ),
}


def enrich_security_finding(finding: Finding) -> Finding:
    metadata = _METADATA_BY_RULE.get(finding.rule_id)
    if not metadata:
        return finding
    finding.confidence = metadata.confidence
    finding.risk_score = metadata.risk_score
    finding.cwe = metadata.cwe
    finding.owasp = metadata.owasp
    finding.impact = metadata.impact
    return finding
