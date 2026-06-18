import ast
from typing import List

from security.models.finding import Finding
from security.rules.security.base import SecurityRule
from security.rules.security.vg001_eval import EvalUsageRule
from security.rules.security.vg002_exec import ExecUsageRule
from security.rules.security.vg003_hardcoded_secrets import HardcodedSecretsRule
from security.rules.security.vg004_insecure_random import InsecureRandomRule
from security.rules.security.vg005_subprocess import SubprocessShellRule
from security.rules.security.vg006_pickle import PickleRule
from security.rules.security.vg007_assert import SecurityAssertRule
from security.rules.security.vg008_weak_hash import WeakHashRule
from security.rules.security.vg009_os_shell import OsShellRule
from security.rules.security.vg010_yaml_load import UnsafeYamlLoadRule
from security.rules.security.vg011_tls_verify import DisabledTlsVerificationRule
from security.rules.security.vg012_debug_mode import DebugModeRule
from security.rules.security.vg013_sql_injection import SqlInjectionRule
from security.rules.security.vg014_path_traversal import PathTraversalRule
from security.rules.security.vg015_ssrf import SsrfRule
from security.rules.security.vg016_xss import UnsafeHtmlOutputRule
from security.rules.security.vg017_xpath_injection import XPathInjectionRule
from security.rules.security.vg018_open_redirect import OpenRedirectRule
from security.rules.security.vg019_unvalidated_input import UnvalidatedInputRule
from security.rules.security.vg020_weak_crypto_key import WeakCryptoKeyRule
from security.rules.security.vg021_log_injection import LogInjectionRule
from security.rules.security.vg022_http_header_injection import HttpHeaderInjectionRule
from security.rules.security.vg023_weak_rng_seed import WeakRngSeedRule
from security.rules.security.vg024_redos import ReDoSRule
from security.rules.security.vg024_regex_dos import RegexDosRule
from security.rules.security.vg025_url_validation_bypass import UrlValidationBypassRule
from security.rules.security.vg026_xxe import XxeRule
from security.rules.security.vg027_insecure_cookie import InsecureCookieRule
from security.rules.security.vg028_csrf import CsrfRule
from security.rules.security.vg029_insecure_tmpfile import InsecureTmpFileRule
from security.rules.security.vg030_cleartext_credentials import CleartextCredentialsRule
from security.rules.security.vg031_unnecessary_privileges import UnnecessaryPrivilegesRule
from security.rules.security.vg032_none_dereference import NoneDereferenceRule
from security.rules.security.vg033_unrestricted_upload import UnrestrictedUploadRule
from security.rules.security.vg034_weak_password_storage import WeakPasswordStorageRule
from security.rules.security.vg035_sensitive_data_log import SensitiveDataLogRule
from security.rules.security.vg036_xml_injection import XmlInjectionRule
from security.rules.security.vg037_improper_output_encoding import ImproperOutputEncodingRule
from security.rules.security.vg038_jwt_no_verify import JwtNoVerifyRule
from security.rules.security.vg039_insecure_file_permissions import InsecureFilePermissionsRule
from security.rules.security.vg040_divide_by_zero import DivideByZeroRule
from security.rules.security.metadata import enrich_security_finding

_DEFAULT_RULES: List[SecurityRule] = [
    EvalUsageRule(),
    ExecUsageRule(),
    HardcodedSecretsRule(),
    InsecureRandomRule(),
    SubprocessShellRule(),
    PickleRule(),
    SecurityAssertRule(),
    WeakHashRule(),
    OsShellRule(),
    UnsafeYamlLoadRule(),
    DisabledTlsVerificationRule(),
    DebugModeRule(),
    SqlInjectionRule(),
    PathTraversalRule(),
    SsrfRule(),
    UnsafeHtmlOutputRule(),
    XPathInjectionRule(),
    OpenRedirectRule(),
    UnvalidatedInputRule(),
    WeakCryptoKeyRule(),
    LogInjectionRule(),
    HttpHeaderInjectionRule(),
    WeakRngSeedRule(),
    ReDoSRule(),
    RegexDosRule(),
    UrlValidationBypassRule(),
    XxeRule(),
    InsecureCookieRule(),
    CsrfRule(),
    InsecureTmpFileRule(),
    CleartextCredentialsRule(),
    UnnecessaryPrivilegesRule(),
    NoneDereferenceRule(),
    UnrestrictedUploadRule(),
    WeakPasswordStorageRule(),
    SensitiveDataLogRule(),
    XmlInjectionRule(),
    ImproperOutputEncodingRule(),
    JwtNoVerifyRule(),
    InsecureFilePermissionsRule(),
    DivideByZeroRule(),
]


class SecurityAnalyzer:
    def __init__(self, rules: List[SecurityRule] | None = None) -> None:
        self.rules = rules if rules is not None else _DEFAULT_RULES

    def analyze(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(enrich_security_finding(finding) for finding in rule.check(tree, file_path, source_lines))
        return findings
