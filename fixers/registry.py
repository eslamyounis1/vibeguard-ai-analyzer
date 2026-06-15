"""Maps rule IDs to the deterministic fixers that can remediate them."""

from __future__ import annotations

from typing import Dict, List

from fixers.base import Fixer
from fixers.fix_assert import AssertFixer
from fixers.fix_membership_in_loop import MembershipInLoopFixer
from fixers.fix_string_concat import StringConcatFixer
from fixers.fix_tls_verify import TlsVerifyFixer
from fixers.fix_weak_hash import WeakHashFixer
from fixers.fix_yaml_load import YamlLoadFixer
from fixers.fix_sql_injection import SqlInjectionFixer
from fixers.fix_subprocess_shell import SubprocessShellFixer
from fixers.fix_insecure_random import InsecureRandomFixer
from fixers.fix_hardcoded_secret import HardcodedSecretFixer
from fixers.fix_insecure_cookie import InsecureCookieFixer
from fixers.fix_xxe import XxeFixer
from fixers.fix_insecure_tmpfile import InsecureTmpFileFixer
from fixers.fix_file_permissions import FilePermissionsFixer

_FIXERS: List[Fixer] = [
    WeakHashFixer(),
    YamlLoadFixer(),
    TlsVerifyFixer(),
    AssertFixer(),
    StringConcatFixer(),
    MembershipInLoopFixer(),
    SqlInjectionFixer(),
    SubprocessShellFixer(),
    InsecureRandomFixer(),
    HardcodedSecretFixer(),
    InsecureCookieFixer(),
    XxeFixer(),
    InsecureTmpFileFixer(),
    FilePermissionsFixer(),
]

FIXERS_BY_RULE: Dict[str, List[Fixer]] = {}
for _fixer in _FIXERS:
    FIXERS_BY_RULE.setdefault(_fixer.rule_id, []).append(_fixer)


def fixable_rule_ids() -> set[str]:
    return set(FIXERS_BY_RULE.keys())
