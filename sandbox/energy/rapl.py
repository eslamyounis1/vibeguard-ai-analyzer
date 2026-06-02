"""Intel/AMD RAPL energy backend (Linux), via the optional ``pyRAPL`` package.

This is the most credible backend for a paper: it reads hardware energy
counters (package + DRAM) rather than estimating. Requires Linux with RAPL
exposed under ``/sys/class/powercap`` and appropriate read permissions.
"""

from __future__ import annotations

from sandbox.energy.base import EnergyMeter, EnergySample


class RaplMeter(EnergyMeter):
    name = "rapl"

    @classmethod
    def available(cls) -> bool:
        try:
            import pyRAPL
        except Exception:
            return False
        try:
            pyRAPL.setup()
            return True
        except Exception:
            return False

    def _begin(self) -> None:
        import pyRAPL

        pyRAPL.setup()
        self._measurement = pyRAPL.Measurement("vibeguard")
        self._measurement.begin()

    def _end(self) -> EnergySample:
        self._measurement.end()
        result = self._measurement.result
        # pyRAPL reports per-socket energy in microjoules.
        pkg = sum(v for v in (result.pkg or []) if v is not None) / 1e6 if result.pkg else None
        dram = sum(v for v in (result.dram or []) if v is not None) / 1e6 if result.dram else None
        total = None
        if pkg is not None or dram is not None:
            total = (pkg or 0.0) + (dram or 0.0)
        return EnergySample(
            backend=self.name,
            wall_seconds=self._wall,
            energy_joules=round(total, 6) if total is not None else None,
            pkg_joules=round(pkg, 6) if pkg is not None else None,
            dram_joules=round(dram, 6) if dram is not None else None,
            note="RAPL hardware counters (package + DRAM)",
        )
