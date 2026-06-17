"""macOS ``powermetrics`` energy backend (CPU power sampling).

``powermetrics`` requires root, so it cannot run inside the locked-down sandbox
child process. It is therefore gated behind the ``VIBEGUARD_POWERMETRICS=1``
environment variable and is intended for harness-level (outside-sandbox)
measurement on macOS. When enabled it samples CPU power for the duration of the
run and integrates power x time into an energy estimate.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import tempfile

from sandbox.energy.base import EnergyMeter, EnergySample

_POWER_RE = re.compile(r"CPU Power:\s*([\d.]+)\s*mW", re.IGNORECASE)
# macOS system binary — absolute path so it works even after os.environ.clear() wipes PATH.
_POWERMETRICS_BIN = shutil.which("powermetrics") or "/usr/bin/powermetrics"


class PowermetricsMeter(EnergyMeter):
    name = "powermetrics"

    @classmethod
    def available(cls) -> bool:
        return (
            platform.system() == "Darwin"
            and os.path.isfile(_POWERMETRICS_BIN)
            and os.environ.get("VIBEGUARD_POWERMETRICS") == "1"
        )

    def _begin(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(prefix="vg_pm_", suffix=".txt", delete=False)
        self._tmp.close()
        try:
            self._proc = subprocess.Popen(
                [_POWERMETRICS_BIN, "--samplers", "cpu_power", "-i", "100", "-o", self._tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            self._proc = None

    def _end(self) -> EnergySample:
        powers_mw: list[float] = []
        if getattr(self, "_proc", None) is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                pass
            try:
                with open(self._tmp.name, "r", encoding="utf-8", errors="replace") as handle:
                    powers_mw = [float(m.group(1)) for m in _POWER_RE.finditer(handle.read())]
            except Exception:
                powers_mw = []
        try:
            os.unlink(self._tmp.name)
        except Exception:
            pass

        joules = None
        note = "powermetrics unavailable or no samples (needs sudo)"
        if powers_mw:
            avg_watts = (sum(powers_mw) / len(powers_mw)) / 1000.0
            joules = round(avg_watts * self._wall, 6)
            note = f"powermetrics avg CPU power {avg_watts:.2f}W x {self._wall:.3f}s"
        return EnergySample(
            backend=self.name,
            wall_seconds=self._wall,
            energy_joules=joules,
            note=note,
        )
