"""Energy measurement backends and selection.

Use :func:`get_meter` to obtain a meter. ``preference="auto"`` picks the most
credible available backend (RAPL > CodeCarbon > powermetrics > linear proxy).
"""

from __future__ import annotations

from typing import List, Type

from sandbox.energy.base import EnergyMeter, EnergySample
from sandbox.energy.codecarbon_meter import CodeCarbonMeter
from sandbox.energy.linear_proxy import LinearProxyMeter
from sandbox.energy.powermetrics import PowermetricsMeter
from sandbox.energy.rapl import RaplMeter

# Ordered most-credible to least-credible.
_ORDER: List[Type[EnergyMeter]] = [
    RaplMeter,
    CodeCarbonMeter,
    PowermetricsMeter,
    LinearProxyMeter,
]
_BY_NAME = {cls.name: cls for cls in _ORDER}


def available_backends() -> List[str]:
    return [cls.name for cls in _ORDER if cls.available()]


def get_meter(preference: str = "auto") -> EnergyMeter:
    if preference and preference != "auto":
        cls = _BY_NAME.get(preference)
        if cls is None:
            raise ValueError(f"Unknown energy backend: {preference!r}. Known: {sorted(_BY_NAME)}")
        return cls()
    for cls in _ORDER:
        if cls.available():
            return cls()
    return LinearProxyMeter()


__all__ = [
    "EnergyMeter",
    "EnergySample",
    "get_meter",
    "available_backends",
    "RaplMeter",
    "CodeCarbonMeter",
    "PowermetricsMeter",
    "LinearProxyMeter",
]
