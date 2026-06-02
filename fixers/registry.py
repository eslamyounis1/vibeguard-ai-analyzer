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

_FIXERS: List[Fixer] = [
    WeakHashFixer(),
    YamlLoadFixer(),
    TlsVerifyFixer(),
    AssertFixer(),
    StringConcatFixer(),
    MembershipInLoopFixer(),
]

FIXERS_BY_RULE: Dict[str, List[Fixer]] = {}
for _fixer in _FIXERS:
    FIXERS_BY_RULE.setdefault(_fixer.rule_id, []).append(_fixer)


def fixable_rule_ids() -> set[str]:
    return set(FIXERS_BY_RULE.keys())
