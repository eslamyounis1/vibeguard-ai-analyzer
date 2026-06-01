"""CWE scoping for fair baseline metrics.

VibeGuard covers a subset of CWE classes. When comparing against CWEval or
SeCodePLT ground truth, metrics should be scoped to CWEs our rules actually
target so recall is not penalized for out-of-scope vulnerability classes.
"""

from __future__ import annotations

from typing import Iterable, Set

from security.rules.security.metadata import _METADATA_BY_RULE


def supported_cwes() -> Set[str]:
    """CWE IDs mapped by at least one VibeGuard security rule."""
    return {meta.cwe for meta in _METADATA_BY_RULE.values()}


def supported_rule_ids() -> Set[str]:
    return set(_METADATA_BY_RULE.keys())


def filter_labels_to_supported(labels: Iterable[str]) -> Set[str]:
    """Keep CWE strings and rule IDs that fall within VibeGuard coverage."""
    supported = supported_cwes()
    rules = supported_rule_ids()
    out: Set[str] = set()
    for label in labels:
        if label in supported or label in rules:
            out.add(label)
        elif label.startswith("CWE-"):
            if label in supported:
                out.add(label)
    return out


def in_scope_cwe(cwe: str) -> bool:
    return cwe in supported_cwes()
