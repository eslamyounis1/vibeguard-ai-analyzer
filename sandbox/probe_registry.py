"""Maps rule_id to SecurityProbe implementations."""

from __future__ import annotations

from typing import Dict, Optional

from sandbox.probe_base import SecurityProbe
from sandbox.security_prober import (
    CommandInjectionProbe,
    DeserializationProbe,
    HeaderInjectionProbe,
    InputValidationProbe,
    LogInjectionProbe,
    PathTraversalProbe,
    ReDoSProbe,
    SqlInjectionProbe,
    WeakKeyProbe,
    XssProbe,
)

_PROBES: list[SecurityProbe] = [
    SqlInjectionProbe(),
    PathTraversalProbe(),
    CommandInjectionProbe(),
    DeserializationProbe(),
    ReDoSProbe(),
    InputValidationProbe(),
    XssProbe(),
    HeaderInjectionProbe(),
    LogInjectionProbe(),
    WeakKeyProbe(),
]

PROBES_BY_RULE: Dict[str, SecurityProbe] = {p.rule_id: p for p in _PROBES}


def get_probe(rule_id: str) -> Optional[SecurityProbe]:
    """Return the probe for *rule_id*, or None if no probe is registered."""
    return PROBES_BY_RULE.get(rule_id)


def probeable_rule_ids() -> set[str]:
    """Return the set of rule IDs that have a registered dynamic probe."""
    return set(PROBES_BY_RULE.keys())
