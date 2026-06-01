"""CodeCarbon energy backend (cross-platform estimate).

CodeCarbon models energy from CPU/GPU/RAM utilisation and hardware power
tables. Less precise than RAPL but portable (works on macOS), which makes it a
good default when hardware counters are unavailable. The CodeCarbon API has
shifted across versions, so energy extraction is defensive.
"""

from __future__ import annotations

from sandbox.energy.base import EnergyMeter, EnergySample

_KWH_TO_JOULES = 3_600_000.0


class CodeCarbonMeter(EnergyMeter):
    name = "codecarbon"

    @classmethod
    def available(cls) -> bool:
        try:
            import codecarbon  # noqa: F401
            return True
        except Exception:
            return False

    def _begin(self) -> None:
        from codecarbon import EmissionsTracker

        self._tracker = EmissionsTracker(
            save_to_file=False,
            log_level="error",
            measure_power_secs=1,
        )
        self._tracker.start()

    def _end(self) -> EnergySample:
        kwh = None
        try:
            self._tracker.stop()
            total = getattr(self._tracker, "_total_energy", None)
            if total is not None:
                kwh = getattr(total, "kWh", None) or getattr(total, "kwh", None)
        except Exception:
            kwh = None
        joules = round(kwh * _KWH_TO_JOULES, 6) if kwh else None
        return EnergySample(
            backend=self.name,
            wall_seconds=self._wall,
            energy_joules=joules,
            note="CodeCarbon estimate (kWh -> J)",
        )
