"""Linear CPU-time energy proxy (always-available fallback).

energy(J) = cpu_seconds * CPU_POWER_WATTS. This is a coarse estimate that
ignores frequency scaling, memory power, and measurement overhead. It exists so
the system always has *a* number, but results should be labelled as estimates
and superseded by RAPL/CodeCarbon where available.
"""

from __future__ import annotations

import time

from sandbox.energy.base import EnergyMeter, EnergySample

CPU_POWER_WATTS = 50.0


class LinearProxyMeter(EnergyMeter):
    name = "linear_proxy"

    @classmethod
    def available(cls) -> bool:
        return True

    def _begin(self) -> None:
        self._cpu0 = time.process_time()

    def _end(self) -> EnergySample:
        cpu = max(0.0, time.process_time() - self._cpu0)
        return EnergySample(
            backend=self.name,
            wall_seconds=self._wall,
            energy_joules=round(cpu * CPU_POWER_WATTS, 6),
            note=f"estimate: cpu_seconds * {CPU_POWER_WATTS}W (low fidelity)",
        )
