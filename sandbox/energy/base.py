"""Pluggable energy-measurement abstraction.

All runtime energy estimates flow through an :class:`EnergyMeter`. Concrete
backends (RAPL, CodeCarbon, powermetrics, linear proxy) implement the same
interface so callers can swap measurement strategy without code changes. Each
:class:`EnergySample` records *which* backend produced it, which is essential
for honest reporting in a paper.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Iterator, Optional


@dataclass
class EnergySample:
    backend: str
    wall_seconds: float
    energy_joules: Optional[float] = None
    pkg_joules: Optional[float] = None
    dram_joules: Optional[float] = None
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class EnergyMeter(ABC):
    """Context-manager base: ``with meter.measure(): ...`` then read ``result``."""

    name: str = "base"

    @classmethod
    def available(cls) -> bool:
        """Whether this backend can run on the current machine."""
        return False

    @abstractmethod
    def _begin(self) -> None:
        ...

    @abstractmethod
    def _end(self) -> EnergySample:
        ...

    @contextmanager
    def measure(self) -> Iterator["EnergyMeter"]:
        self._wall = 0.0
        self._result: Optional[EnergySample] = None
        start = time.perf_counter()
        self._begin()
        try:
            yield self
        finally:
            self._wall = time.perf_counter() - start
            self._result = self._end()

    @property
    def result(self) -> EnergySample:
        if self._result is None:
            raise RuntimeError("measure() context has not completed yet.")
        return self._result
